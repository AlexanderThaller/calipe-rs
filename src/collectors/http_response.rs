//! HTTP(S) probes: fetch each URL and record latency, status, size, result
//! and the TLS certificate's expiry.
//!
//! Every probe opens a fresh connection (no keep-alive pool), so the latency
//! covers DNS, TCP, TLS and the full body, like a first-time visitor.
//! TLS uses rustls with the ring provider and the system trust store
//! (`/etc/ssl/cert.pem` on FreeBSD). All URLs of all `[[inputs.http_response]]`
//! blocks are probed concurrently.

use std::collections::BTreeMap;
use std::error::Error as _;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use regex::Regex;
use serde::Deserialize;
use tokio::task::JoinSet;

use crate::collector::Collector;

/// One `[[inputs.http_response]]` block (Telegraf's option names). All blocks
/// share one collector on the agent interval.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub urls: Vec<String>,
    #[serde(default = "default_method")]
    pub method: String,
    /// Limit for the whole request including the body.
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub response_timeout: Duration,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    /// Regex the body must match for the probe to succeed.
    pub response_string_match: Option<String>,
    /// Status code required for the probe to succeed (default: any response).
    pub response_status_code: Option<u16>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

fn default_method() -> String {
    "GET".to_owned()
}

fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

pub fn describe() {
    describe_histogram!(
        "http_response_duration_seconds",
        "Time to a complete response (connect, TLS, headers and body); responses only."
    );
    describe_counter!(
        "http_response_total",
        "Probes by result: success, response_status_code_mismatch, response_string_mismatch, \
         body_read_error, timeout, dns_error, tls_error, connection_failed, error."
    );
    describe_gauge!(
        "http_response_success",
        "1 if the last probe succeeded, 0 otherwise."
    );
    describe_gauge!(
        "http_response_status_code",
        "HTTP status code of the last response."
    );
    describe_gauge!(
        "http_response_content_length_bytes",
        "Body size of the last response."
    );
    describe_gauge!(
        "http_response_tls_cert_expiry_seconds",
        "Unix time the server's TLS certificate expires (notAfter)."
    );
}

/// `notAfter` of a DER X.509 certificate as Unix time.
///
/// Walks `Certificate.tbsCertificate` to `validity` (RFC 5280 4.1): optional
/// `[0] version`, `serialNumber`, `signature`, `issuer`, then `validity`.
pub fn cert_not_after(der: &[u8]) -> Option<i64> {
    let (tag, cert, _) = read_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, mut tbs, _) = read_tlv(cert)?;
    if tag != 0x30 {
        return None;
    }
    // Skip the explicit version, if present.
    if tbs.first() == Some(&0xa0) {
        tbs = read_tlv(tbs)?.2;
    }
    for expected in [0x02, 0x30, 0x30] {
        let (tag, _, rest) = read_tlv(tbs)?;
        if tag != expected {
            return None;
        }
        tbs = rest;
    }
    let (tag, validity, _) = read_tlv(tbs)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _, rest) = read_tlv(validity)?; // notBefore
    let (tag, not_after, _) = read_tlv(rest)?;
    parse_time(tag, not_after)
}

/// One DER element: (tag, contents, remaining input).
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = input.get(2..2 + n)?;
        (
            bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b)),
            2 + n,
        )
    };
    let contents = input.get(header..header.checked_add(len)?)?;
    Some((tag, contents, &input[header + len..]))
}

/// `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) as Unix time.
fn parse_time(tag: u8, value: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(value).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if text.len() == 12 => {
            let yy: i64 = text[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        0x18 if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    let field = |i: usize| rest.get(i..i + 2)?.parse::<i64>().ok();
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Errors in `err`'s source chain. `std::io::Error::source()` skips the
/// error it wraps, and hyper/tokio-rustls nest `rustls::Error` in two
/// `io::Error`s, so those are unwrapped explicitly.
fn error_chain(err: &reqwest::Error) -> Vec<&(dyn std::error::Error + 'static)> {
    let mut chain: Vec<&(dyn std::error::Error + 'static)> = Vec::new();
    let mut next = err.source();
    while let Some(e) = next {
        chain.push(e);
        // Descend into what an io::Error wraps (possibly nested io::Errors).
        next = match e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    chain
}

/// Telegraf-style result for a failed request, from reqwest's error chain.
fn classify(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        return "timeout";
    }
    for e in error_chain(err) {
        if e.downcast_ref::<rustls::Error>().is_some() {
            return "tls_error";
        }
        if e.to_string().contains("dns error") {
            return "dns_error";
        }
    }
    if err.is_connect() {
        "connection_failed"
    } else {
        "error"
    }
}

/// The error and its causes, for logs.
fn describe_error(err: &reqwest::Error) -> String {
    std::iter::once(err.to_string())
        .chain(error_chain(err).iter().map(ToString::to_string))
        .collect::<Vec<_>>()
        .join(": ")
}

struct Target {
    url: String,
    method: reqwest::Method,
    client: reqwest::Client,
    headers: reqwest::header::HeaderMap,
    body: Option<String>,
    string_match: Option<Regex>,
    status_code: Option<u16>,
}

#[derive(Debug)]
struct Outcome {
    result: &'static str,
    status: Option<u16>,
    elapsed: Option<Duration>,
    content_length: Option<u64>,
    cert_expiry: Option<i64>,
}

async fn probe(target: &Target) -> Outcome {
    let mut req = target
        .client
        .request(target.method.clone(), &target.url)
        .headers(target.headers.clone());
    if let Some(body) = &target.body {
        req = req.body(body.clone());
    }
    let start = Instant::now();
    let mut response = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::debug!(url = %target.url, error = %describe_error(&err), "http probe failed");
            return Outcome {
                result: classify(&err),
                status: None,
                elapsed: None,
                content_length: None,
                cert_expiry: None,
            };
        }
    };
    let status = response.status().as_u16();
    let cert_expiry = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .and_then(cert_not_after);

    // Read the body (needed for the timing to include it); only keep it when
    // a string match is configured.
    let mut length = 0u64;
    let mut kept = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                length += chunk.len() as u64;
                if target.string_match.is_some() {
                    kept.extend_from_slice(&chunk);
                }
            }
            Ok(None) => break,
            Err(err) => {
                let result = if err.is_timeout() {
                    "timeout"
                } else {
                    "body_read_error"
                };
                return Outcome {
                    result,
                    status: Some(status),
                    elapsed: None,
                    content_length: None,
                    cert_expiry,
                };
            }
        }
    }
    let elapsed = start.elapsed();
    let result = if target.status_code.is_some_and(|want| want != status) {
        "response_status_code_mismatch"
    } else if target
        .string_match
        .as_ref()
        .is_some_and(|re| !re.is_match(&String::from_utf8_lossy(&kept)))
    {
        "response_string_mismatch"
    } else {
        "success"
    };
    Outcome {
        result,
        status: Some(status),
        elapsed: Some(elapsed),
        content_length: Some(length),
        cert_expiry,
    }
}

pub struct HttpResponse {
    targets: Vec<std::sync::Arc<Target>>,
}

impl HttpResponse {
    pub fn new(configs: &[Config]) -> Result<Self> {
        // reqwest is built without a bundled crypto provider; use ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut targets = Vec::new();
        for config in configs {
            if config.urls.is_empty() {
                bail!("http_response needs at least one url");
            }
            let client = reqwest::Client::builder()
                .user_agent(concat!("calipers/", env!("CARGO_PKG_VERSION")))
                .timeout(config.response_timeout)
                // A fresh connection per probe: latency includes DNS, TCP and TLS.
                .pool_max_idle_per_host(0)
                .redirect(if config.follow_redirects {
                    reqwest::redirect::Policy::limited(10)
                } else {
                    reqwest::redirect::Policy::none()
                })
                .tls_danger_accept_invalid_certs(config.insecure_skip_verify)
                .tls_info(true)
                .build()
                .context("building HTTP client")?;
            let method = reqwest::Method::from_bytes(config.method.to_ascii_uppercase().as_bytes())
                .with_context(|| format!("http_response: invalid method {:?}", config.method))?;
            let mut headers = reqwest::header::HeaderMap::new();
            for (name, value) in &config.headers {
                headers.insert(
                    reqwest::header::HeaderName::from_bytes(name.as_bytes())
                        .with_context(|| format!("invalid header name {name:?}"))?,
                    value
                        .parse()
                        .with_context(|| format!("invalid value for header {name:?}"))?,
                );
            }
            let string_match = config
                .response_string_match
                .as_deref()
                .map(Regex::new)
                .transpose()
                .context("http_response: invalid response_string_match")?;
            for url in &config.urls {
                reqwest::Url::parse(url)
                    .with_context(|| format!("http_response: invalid url {url:?}"))?;
                targets.push(std::sync::Arc::new(Target {
                    url: url.clone(),
                    method: method.clone(),
                    client: client.clone(),
                    headers: headers.clone(),
                    body: config.body.clone(),
                    string_match: string_match.clone(),
                    status_code: config.response_status_code,
                }));
            }
        }
        Ok(Self { targets })
    }
}

impl Collector for HttpResponse {
    fn name(&self) -> &'static str {
        "http_response"
    }

    fn describe(&self) {
        describe();
    }

    async fn collect(&mut self) -> Result<()> {
        let mut tasks = JoinSet::new();
        for target in &self.targets {
            let target = target.clone();
            tasks.spawn(async move {
                let outcome = probe(&target).await;
                (target, outcome)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            let (target, o) = joined?;
            let labels = [
                ("url", target.url.clone()),
                ("method", target.method.to_string()),
            ];
            if let Some(elapsed) = o.elapsed {
                histogram!("http_response_duration_seconds", &labels).record(elapsed.as_secs_f64());
            }
            if let Some(status) = o.status {
                gauge!("http_response_status_code", &labels).set(f64::from(status));
            }
            if let Some(length) = o.content_length {
                gauge!("http_response_content_length_bytes", &labels).set(length as f64);
            }
            if let Some(expiry) = o.cert_expiry {
                gauge!("http_response_tls_cert_expiry_seconds", "url" => target.url.clone())
                    .set(expiry as f64);
            }
            gauge!("http_response_success", &labels)
                .set(f64::from(u8::from(o.result == "success")));
            let mut with_result = labels.to_vec();
            with_result.push(("result", o.result.to_owned()));
            with_result.push((
                "status_code",
                o.status.map_or_else(String::new, |s| s.to_string()),
            ));
            counter!("http_response_total", &with_result).increment(1);
        }
        // Failed probes are results, not collector errors.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_certificate_expiry() {
        // *.thaller.ws, notAfter=Jan  1 03:21:26 2027 GMT (openssl x509 -enddate).
        let der = include_bytes!("testdata/ip.thaller.ws.der");
        assert_eq!(cert_not_after(der), Some(1_798_773_686));
        assert_eq!(cert_not_after(&der[..100]), None, "truncated");
        assert_eq!(cert_not_after(b"not a certificate"), None);
    }

    #[test]
    fn parses_asn1_times() {
        assert_eq!(parse_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(
            parse_time(0x17, b"491231235959Z"),
            Some(2_524_607_999),
            "YY < 50 is 20YY"
        );
        assert_eq!(parse_time(0x18, b"20270101032126Z"), Some(1_798_773_686));
        assert_eq!(parse_time(0x17, b"700101000000"), None, "no Z");
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    #[test]
    fn validates_config() {
        let ok: Config = toml::from_str("urls = ['https://example.com/']").unwrap();
        assert!(HttpResponse::new(&[ok]).is_ok());
        let bad_url: Config = toml::from_str("urls = ['not a url']").unwrap();
        assert!(HttpResponse::new(&[bad_url]).is_err());
        let bad_re: Config =
            toml::from_str("urls = ['http://a/']\nresponse_string_match = '('").unwrap();
        assert!(HttpResponse::new(&[bad_re]).is_err());
    }

    fn target(url: &str) -> Target {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Target {
            url: url.to_owned(),
            method: reqwest::Method::GET,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .tls_info(true)
                .build()
                .unwrap(),
            headers: reqwest::header::HeaderMap::new(),
            body: None,
            string_match: None,
            status_code: None,
        }
    }

    /// Live probes; run with `--ignored`.
    #[tokio::test]
    #[ignore = "needs network"]
    async fn probes_live_urls() {
        let o = probe(&target("https://www.google.de/")).await;
        assert_eq!(o.result, "success", "{o:?}");
        assert!(o.cert_expiry.is_some_and(|t| t > 1_700_000_000));
        let o = probe(&target("https://does-not-exist.invalid/")).await;
        assert_eq!(o.result, "dns_error", "{o:?}");
        let o = probe(&target("https://expired.badssl.com/")).await;
        assert_eq!(o.result, "tls_error", "{o:?}");
    }
}
