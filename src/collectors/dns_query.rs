//! DNS resolution probes: query each server for each domain and record the
//! response time and result.
//!
//! A minimal DNS client (RFC 1035): one UDP query with recursion desired,
//! and a reply is accepted only if its ID, QR bit and echoed question match.
//! All queries of all `[[inputs.dns_query]]` blocks run concurrently.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::collector::Collector;

/// One `[[inputs.dns_query]]` block. All blocks share one collector and run on
/// the agent interval.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub servers: Vec<IpAddr>,
    pub domains: Vec<String>,
    #[serde(default = "default_record_type")]
    pub record_type: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_record_type() -> String {
    "NS".to_owned()
}

fn default_port() -> u16 {
    53
}

fn default_timeout() -> Duration {
    Duration::from_secs(2)
}

pub fn describe() {
    describe_histogram!(
        "dns_query_duration_seconds",
        "Time from sending the query to receiving the matching reply (replies only)."
    );
    describe_counter!(
        "dns_query_total",
        "Queries by result (success = NOERROR, rcode = other response code, timeout, error)."
    );
    describe_gauge!(
        "dns_query_success",
        "1 if the last query got a NOERROR reply, 0 otherwise."
    );
    describe_gauge!("dns_query_answers", "Answer records in the last reply.");
}

/// Query types by name (RFC 1035 and successors).
fn qtype(name: &str) -> Option<u16> {
    Some(match name.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        _ => return None,
    })
}

fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".to_owned(),
        1 => "FORMERR".to_owned(),
        2 => "SERVFAIL".to_owned(),
        3 => "NXDOMAIN".to_owned(),
        4 => "NOTIMP".to_owned(),
        5 => "REFUSED".to_owned(),
        other => format!("RCODE{other}"),
    }
}

/// Encodes the question section: QNAME labels, QTYPE, QCLASS IN.
fn question(domain: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut q = Vec::with_capacity(domain.len() + 6);
    for label in domain.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|&l| (1..=63).contains(&l));
        let Some(len) = len else {
            bail!("invalid domain {domain:?}");
        };
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    if q.len() > 260 {
        bail!("domain {domain:?} is too long");
    }
    Ok(q)
}

/// A query message with recursion desired.
fn query(id: u16, question: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(12 + question.len());
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&[0; 6]); // AN/NS/ARCOUNT
    msg.extend_from_slice(question);
    msg
}

/// rcode and answer count of a reply to (`id`, `question`), or `None` if the
/// datagram isn't a reply to our query (e.g. a stray or spoofed packet).
fn parse_reply(reply: &[u8], id: u16, question: &[u8]) -> Option<(u8, u16)> {
    let header = reply.get(..12)?;
    let qr = header[2] & 0x80 != 0;
    let qdcount = u16::from_be_bytes([header[4], header[5]]);
    if u16::from_be_bytes([header[0], header[1]]) != id || !qr || qdcount != 1 {
        return None;
    }
    // Servers echo the question; compare case-insensitively (0x20 encoding).
    let echoed = reply.get(12..12 + question.len())?;
    if !echoed.eq_ignore_ascii_case(question) {
        return None;
    }
    Some((header[3] & 0x0f, u16::from_be_bytes([header[6], header[7]])))
}

#[derive(Debug)]
enum Outcome {
    Reply {
        rcode: u8,
        answers: u16,
        elapsed: Duration,
    },
    Timeout,
    Error(String),
}

async fn probe(server: SocketAddr, id: u16, question: Vec<u8>, limit: Duration) -> Outcome {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("valid");
    let attempt = async {
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(server).await?;
        let start = Instant::now();
        socket.send(&query(id, &question)).await?;
        let mut buf = [0u8; 4096];
        loop {
            let n = socket.recv(&mut buf).await?;
            if let Some((rcode, answers)) = parse_reply(&buf[..n], id, &question) {
                return Ok::<_, std::io::Error>(Outcome::Reply {
                    rcode,
                    answers,
                    elapsed: start.elapsed(),
                });
            }
        }
    };
    match tokio::time::timeout(limit, attempt).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err)) => Outcome::Error(err.to_string()),
        Err(_) => Outcome::Timeout,
    }
}

struct Probe {
    server: SocketAddr,
    domain: String,
    record_type: String,
    question: Vec<u8>,
    timeout: Duration,
}

pub struct DnsQuery {
    probes: Vec<Probe>,
    ids: RandomState,
    counter: u64,
}

impl DnsQuery {
    pub fn new(configs: &[Config]) -> Result<Self> {
        let mut probes = Vec::new();
        for config in configs {
            let record_type = config.record_type.to_ascii_uppercase();
            let Some(qt) = qtype(&record_type) else {
                bail!(
                    "dns_query: unsupported record_type {:?}",
                    config.record_type
                );
            };
            if config.servers.is_empty() || config.domains.is_empty() {
                bail!("dns_query needs at least one server and one domain");
            }
            for &server in &config.servers {
                for domain in &config.domains {
                    probes.push(Probe {
                        server: SocketAddr::new(server, config.port),
                        domain: domain.clone(),
                        record_type: record_type.clone(),
                        question: question(domain, qt)?,
                        timeout: config.timeout,
                    });
                }
            }
        }
        Ok(Self {
            probes,
            ids: RandomState::new(),
            counter: 0,
        })
    }

    /// Unpredictable query IDs (keyed hash of a counter), so off-path replies
    /// are unlikely to be accepted.
    fn next_id(&mut self) -> u16 {
        self.counter += 1;
        let mut h = self.ids.build_hasher();
        h.write_u64(self.counter);
        (h.finish() & 0xffff) as u16
    }
}

impl Collector for DnsQuery {
    fn name(&self) -> &'static str {
        "dns_query"
    }

    fn describe(&self) {
        describe();
    }

    async fn collect(&mut self) -> Result<()> {
        let mut tasks = JoinSet::new();
        for i in 0..self.probes.len() {
            let id = self.next_id();
            let p = &self.probes[i];
            let (server, question, timeout) = (p.server, p.question.clone(), p.timeout);
            tasks.spawn(async move { (i, probe(server, id, question, timeout).await) });
        }
        while let Some(joined) = tasks.join_next().await {
            let (i, outcome) = joined?;
            let p = &self.probes[i];
            let labels = [
                ("server", p.server.ip().to_string()),
                ("domain", p.domain.clone()),
                ("record_type", p.record_type.clone()),
            ];
            let (result, rcode, success) = match outcome {
                Outcome::Reply {
                    rcode,
                    answers,
                    elapsed,
                } => {
                    histogram!("dns_query_duration_seconds", &labels).record(elapsed.as_secs_f64());
                    gauge!("dns_query_answers", &labels).set(f64::from(answers));
                    let result = if rcode == 0 { "success" } else { "rcode" };
                    (result, rcode_name(rcode), rcode == 0)
                }
                Outcome::Timeout => ("timeout", String::new(), false),
                Outcome::Error(err) => {
                    tracing::debug!(server = %p.server, domain = %p.domain, error = %err, "dns query failed");
                    ("error", String::new(), false)
                }
            };
            gauge!("dns_query_success", &labels).set(f64::from(u8::from(success)));
            let mut with_result = labels.to_vec();
            with_result.push(("result", result.to_owned()));
            with_result.push(("rcode", rcode));
            counter!("dns_query_total", &with_result).increment(1);
        }
        // Individual probe failures are results, not collector errors.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_question() {
        let q = question("ip.thaller.ws.", 28).unwrap();
        assert_eq!(q, b"\x02ip\x07thaller\x02ws\x00\x00\x1c\x00\x01");
        assert!(question("a..b", 1).is_err());
        assert!(question(&"x".repeat(64), 1).is_err());
    }

    #[test]
    fn builds_query_header() {
        let msg = query(0xbeef, &question("a.b", 1).unwrap());
        assert_eq!(
            &msg[..12],
            &[0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    fn reply(id: u16, flags: u16, ancount: u16, question: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&ancount.to_be_bytes());
        r.extend_from_slice(&[0; 4]);
        r.extend_from_slice(question);
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        r
    }

    #[test]
    fn accepts_only_matching_replies() {
        let q = question("ip.thaller.ws", 1).unwrap();
        assert_eq!(parse_reply(&reply(7, 0x8180, 1, &q), 7, &q), Some((0, 1)));
        assert_eq!(
            parse_reply(&reply(7, 0x8183, 0, &q), 7, &q),
            Some((3, 0)),
            "NXDOMAIN"
        );
        assert_eq!(
            parse_reply(&reply(8, 0x8180, 1, &q), 7, &q),
            None,
            "wrong id"
        );
        assert_eq!(
            parse_reply(&reply(7, 0x0100, 1, &q), 7, &q),
            None,
            "not a reply"
        );
        let other = question("evil.example", 1).unwrap();
        assert_eq!(
            parse_reply(&reply(7, 0x8180, 1, &other), 7, &q),
            None,
            "wrong question"
        );
        let upper = question("IP.Thaller.WS", 1).unwrap();
        assert_eq!(
            parse_reply(&reply(7, 0x8180, 1, &upper), 7, &q),
            Some((0, 1)),
            "0x20 case"
        );
    }

    #[test]
    fn validates_config() {
        let ok: Config =
            toml::from_str("servers = ['1.1.1.1']\ndomains = ['a.b']\nrecord_type = 'aaaa'")
                .unwrap();
        assert!(DnsQuery::new(&[ok]).is_ok());
        let bad: Config =
            toml::from_str("servers = ['1.1.1.1']\ndomains = ['a.b']\nrecord_type = 'XYZ'")
                .unwrap();
        assert!(DnsQuery::new(&[bad]).is_err());
    }

    /// Live query against a public resolver; run with `--ignored`.
    #[tokio::test]
    #[ignore = "needs network"]
    async fn queries_public_resolver() {
        let q = question("example.com", 1).unwrap();
        let outcome = probe(
            "1.1.1.1:53".parse().unwrap(),
            4242,
            q,
            Duration::from_secs(2),
        )
        .await;
        assert!(
            matches!(
                outcome,
                Outcome::Reply {
                    rcode: 0,
                    answers: 1..,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }
}
