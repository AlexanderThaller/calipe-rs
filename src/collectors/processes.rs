//! Process counts by state (`[inputs.processes]`) and per-process resource
//! usage for selected processes (`[[inputs.procstat]]`).
//!
//! Both come from one `kern.proc.proc` read per interval (one `kinfo_proc`
//! per process). States follow ps(1)'s `state` column. procstat queries
//! select processes like pgrep(1): `exe` is a regex on the process name,
//! `pattern` a regex on the full command line, `user` the owner's name.
//!
//! Process names in `kinfo_proc` are cut to 19 characters (`COMMLEN`); for
//! names at that limit the full name is taken from `argv[0]` when it starts
//! with the truncated one, so `exe = "http_responsetime_exporter"` matches.
//!
//! With `tag_with = ["pid"]` every process is its own series. Otherwise
//! matching processes are summed per `(query, process_name, user)`. Counters
//! in that mode are accumulated from per-process increments, so a process
//! exiting doesn't make the totals drop.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use metrics::{describe_counter, describe_gauge};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessesConfig {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

/// One `[[inputs.procstat]]` query. procstat runs on the `processes`
/// interval (or the agent's), since both share the process table read.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcstatConfig {
    /// Regex matched against the process name.
    pub exe: Option<String>,
    /// Regex matched against the full command line.
    pub pattern: Option<String>,
    /// Owner's user name.
    pub user: Option<String>,
    /// Extra labels per process; only `"pid"` is supported.
    #[serde(default)]
    pub tag_with: Vec<String>,
}

pub fn describe() {
    describe_gauge!(
        "processes",
        "Processes by state, as in ps(1) (idle = sleeping for more than 20s)."
    );
    describe_gauge!("processes_threads", "Threads in all processes.");
    describe_gauge!(
        "procstat_lookup_pids",
        "Processes matching the procstat query."
    );
    describe_gauge!(
        "procstat_cpu_seconds_total",
        "CPU time by mode. Cumulative; use rate()."
    );
    describe_gauge!("procstat_memory_rss_bytes", "Resident memory.");
    describe_gauge!("procstat_memory_virtual_bytes", "Virtual memory size.");
    describe_gauge!("procstat_threads", "Threads.");
    describe_gauge!("procstat_open_fds", "Open file descriptors.");
    describe_gauge!(
        "procstat_start_time_seconds",
        "Unix time the (oldest) process started."
    );
    describe_counter!(
        "procstat_context_switches_total",
        "Voluntary and involuntary context switches."
    );
    describe_counter!(
        "procstat_block_io_total",
        "Block input/output operations (filesystem reads/writes)."
    );
    describe_counter!(
        "procstat_page_faults_total",
        "Major (needing I/O) and minor page faults."
    );
}

/// ps(1) state letters and the label names used for them.
pub const STATES: [(char, &str); 8] = [
    ('R', "running"),
    ('S', "sleeping"),
    ('I', "idle"),
    ('D', "blocked"),
    ('T', "stopped"),
    ('Z', "zombie"),
    ('W', "waiting"),
    ('L', "lock"),
];

/// `state()` from `bin/ps/print.c`, first letter only.
pub fn state_char(stat: i8, tdflags: i64, slptime: u32) -> char {
    const SIDL: i8 = 1;
    const SRUN: i8 = 2;
    const SSLEEP: i8 = 3;
    const SSTOP: i8 = 4;
    const SZOMB: i8 = 5;
    const SWAIT: i8 = 6;
    const SLOCK: i8 = 7;
    const TDF_SINTR: i64 = 0x8;
    /// `MAXSLP` from `sys/vmmeter.h`.
    const MAXSLP: u32 = 20;
    match stat {
        SSTOP => 'T',
        SSLEEP if tdflags & TDF_SINTR != 0 => {
            if slptime >= MAXSLP {
                'I'
            } else {
                'S'
            }
        }
        SSLEEP => 'D',
        SRUN | SIDL => 'R',
        SWAIT => 'W',
        SLOCK => 'L',
        SZOMB => 'Z',
        _ => '?',
    }
}

/// `COMMLEN` from `sys/param.h`.
pub const COMMLEN: usize = 19;

/// The untruncated name: `argv[0]`'s basename if `comm` was cut at
/// [`COMMLEN`] and is a prefix of it.
pub fn full_name<'a>(comm: &'a str, argv0: Option<&'a str>) -> &'a str {
    if comm.len() < COMMLEN {
        return comm;
    }
    match argv0.map(|a| a.rsplit('/').next().unwrap_or(a)) {
        Some(base) if base.starts_with(comm) => base,
        _ => comm,
    }
}

/// One process, platform-independent.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Proc {
    pub pid: i32,
    pub name: String,
    pub cmdline: Option<String>,
    pub user: String,
    pub threads: u32,
    pub rss_bytes: u64,
    pub virtual_bytes: u64,
    /// Unix time.
    pub start_time: f64,
    pub open_fds: Option<u64>,
    pub cpu_user: f64,
    pub cpu_system: f64,
    pub counters: [u64; COUNTERS.len()],
}

/// Integer counters per process: (metric, label name, label value).
pub const COUNTERS: [(&str, &str, &str); 6] = [
    ("procstat_context_switches_total", "type", "voluntary"),
    ("procstat_context_switches_total", "type", "involuntary"),
    ("procstat_block_io_total", "op", "read"),
    ("procstat_block_io_total", "op", "write"),
    ("procstat_page_faults_total", "type", "major"),
    ("procstat_page_faults_total", "type", "minor"),
];

#[derive(Debug)]
pub struct Query {
    /// Value of the `query` label, e.g. `exe=nginx`.
    pub label: String,
    exe: Option<Regex>,
    pattern: Option<Regex>,
    user: Option<String>,
    pub tag_pid: bool,
}

impl Query {
    pub fn new(config: &ProcstatConfig) -> Result<Self> {
        let mut parts = Vec::new();
        let mut regex = |field: &str, value: &Option<String>| -> Result<Option<Regex>> {
            value
                .as_ref()
                .map(|v| {
                    parts.push(format!("{field}={v}"));
                    Regex::new(v).map_err(|e| anyhow::anyhow!("procstat {field} {v:?}: {e}"))
                })
                .transpose()
        };
        let exe = regex("exe", &config.exe)?;
        let pattern = regex("pattern", &config.pattern)?;
        if let Some(user) = &config.user {
            parts.push(format!("user={user}"));
        }
        if parts.is_empty() {
            bail!("procstat needs at least one of exe, pattern or user");
        }
        for tag in &config.tag_with {
            if tag != "pid" {
                bail!("procstat tag_with: only \"pid\" is supported, not {tag:?}");
            }
        }
        Ok(Self {
            label: parts.join(","),
            exe,
            pattern,
            user: config.user.clone(),
            tag_pid: config.tag_with.iter().any(|t| t == "pid"),
        })
    }

    pub fn needs_cmdline(&self) -> bool {
        self.pattern.is_some()
    }

    pub fn matches(&self, p: &Proc) -> bool {
        self.exe.as_ref().is_none_or(|re| re.is_match(&p.name))
            && self
                .pattern
                .as_ref()
                .is_none_or(|re| p.cmdline.as_deref().is_some_and(|c| re.is_match(c)))
            && self.user.as_ref().is_none_or(|u| *u == p.user)
    }
}

/// Retention for aggregation state of groups that stopped matching.
const GROUP_RETENTION: Duration = Duration::from_secs(3600);

/// Sums per `(query, name, user)` with counters accumulated from
/// per-process increments.
#[derive(Debug, Default)]
pub struct Aggregator {
    groups: HashMap<(String, String, String), Group>,
}

/// Cumulative values of one process (or totals of a group).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Cumulative {
    /// User and system CPU seconds.
    pub cpu: [f64; 2],
    /// Values for [`COUNTERS`].
    pub counts: [u64; COUNTERS.len()],
}

impl Cumulative {
    fn of(p: &Proc) -> Self {
        Self {
            cpu: [p.cpu_user, p.cpu_system],
            counts: p.counters,
        }
    }

    /// Adds the increase from `previous` to `current`; values never decrease
    /// within one process.
    fn add_increase(&mut self, previous: &Self, current: &Self) {
        for (total, (now, prev)) in self
            .cpu
            .iter_mut()
            .zip(current.cpu.iter().zip(previous.cpu))
        {
            *total += (now - prev).max(0.0);
        }
        for (total, (now, prev)) in self
            .counts
            .iter_mut()
            .zip(current.counts.iter().zip(previous.counts))
        {
            *total += now.saturating_sub(prev);
        }
    }
}

#[derive(Debug)]
struct Group {
    totals: Cumulative,
    /// Last values per process, keyed by pid and start time (detects reuse).
    procs: HashMap<(i32, u64), Cumulative>,
    seen: Instant,
}

/// Summed values of one group, ready to export.
#[derive(Debug, PartialEq)]
pub struct GroupValues {
    pub query: String,
    pub name: String,
    pub user: String,
    pub processes: usize,
    pub totals: Cumulative,
    pub rss_bytes: u64,
    pub virtual_bytes: u64,
    pub threads: u64,
    pub open_fds: Option<u64>,
    pub start_time: f64,
}

impl Aggregator {
    pub fn update(&mut self, query: &str, procs: &[&Proc], now: Instant) -> Vec<GroupValues> {
        let mut by_group: HashMap<(String, String, String), Vec<&Proc>> = HashMap::new();
        for p in procs {
            by_group
                .entry((query.to_owned(), p.name.clone(), p.user.clone()))
                .or_default()
                .push(p);
        }
        let mut out = Vec::new();
        for (key, members) in by_group {
            let group = self.groups.entry(key.clone()).or_insert_with(|| Group {
                totals: Cumulative::default(),
                procs: HashMap::new(),
                seen: now,
            });
            let mut current = HashMap::new();
            for p in &members {
                let id = (p.pid, p.start_time.to_bits());
                let values = Cumulative::of(p);
                // A process seen for the first time contributes everything
                // it has accumulated so far.
                let previous = group.procs.get(&id).copied().unwrap_or_default();
                group.totals.add_increase(&previous, &values);
                current.insert(id, values);
            }
            group.procs = current;
            group.seen = now;
            out.push(GroupValues {
                query: key.0,
                name: key.1,
                user: key.2,
                processes: members.len(),
                totals: group.totals,
                rss_bytes: members.iter().map(|p| p.rss_bytes).sum(),
                virtual_bytes: members.iter().map(|p| p.virtual_bytes).sum(),
                threads: members.iter().map(|p| u64::from(p.threads)).sum(),
                open_fds: members.iter().map(|p| p.open_fds).sum(),
                start_time: members
                    .iter()
                    .map(|p| p.start_time)
                    .fold(f64::INFINITY, f64::min),
            });
        }
        out
    }

    pub fn prune(&mut self, now: Instant) {
        self.groups
            .retain(|_, g| now.duration_since(g.seen) < GROUP_RETENTION);
    }
}

/// Counts descriptors (`kf_fd >= 0`) in packed `kinfo_file` records.
pub fn count_fds(buf: &[u8]) -> Option<u64> {
    let int_at = |at: usize| {
        buf.get(at..at + 4)
            .map(|b| i32::from_ne_bytes(b.try_into().expect("4")))
    };
    let mut count = 0;
    let mut pos = 0;
    while pos < buf.len() {
        let size = usize::try_from(int_at(pos)?).ok().filter(|&s| s >= 12)?;
        if int_at(pos + 8)? >= 0 {
            count += 1;
        }
        pos += size;
    }
    Some(count)
}

/// Builds the queries, dropping exact duplicates (which would export the
/// same series twice).
pub fn queries(configs: &[ProcstatConfig]) -> Result<Vec<Query>> {
    let mut out: Vec<Query> = Vec::new();
    for config in configs {
        let query = Query::new(config)?;
        if out
            .iter()
            .any(|q| q.label == query.label && q.tag_pid == query.tag_pid)
        {
            tracing::warn!(query = %query.label, "duplicate procstat query ignored");
            continue;
        }
        out.push(query);
    }
    Ok(out)
}

#[cfg(not(target_os = "freebsd"))]
pub struct Processes;

#[cfg(not(target_os = "freebsd"))]
impl Processes {
    pub fn new(_states: bool, _procstat: &[ProcstatConfig]) -> Result<Self> {
        bail!("the processes and procstat inputs are only supported on FreeBSD")
    }
}

#[cfg(not(target_os = "freebsd"))]
impl crate::collector::Collector for Processes {
    fn name(&self) -> &'static str {
        "processes"
    }

    async fn collect(&mut self) -> Result<()> {
        unreachable!("constructor always fails on this platform")
    }
}

#[cfg(target_os = "freebsd")]
pub use freebsd::Processes;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::time::Instant;

    use anyhow::{Context, Result, bail};
    use metrics::{counter, gauge};

    use super::{
        Aggregator, COUNTERS, Proc, ProcstatConfig, Query, STATES, count_fds, describe, full_name,
        queries, state_char,
    };
    use crate::collector::Collector;
    use crate::counter::Monotonic;
    use crate::sys::freebsd::{Mib, cast_slice};
    use crate::sys::{page_size, timeval_secs};

    /// `P_SYSTEM`: kernel processes have no argv.
    const P_SYSTEM: libc::c_long = 0x200;

    pub struct Processes {
        states: bool,
        queries: Vec<Query>,
        page_size: u64,
        buf: Vec<u8>,
        args_buf: Vec<u8>,
        users: HashMap<u32, String>,
        aggregator: Aggregator,
        counters: Monotonic,
    }

    impl Processes {
        pub fn new(states: bool, procstat: &[ProcstatConfig]) -> Result<Self> {
            Ok(Self {
                states,
                queries: queries(procstat)?,
                page_size: page_size(),
                buf: Vec::new(),
                args_buf: Vec::new(),
                users: HashMap::new(),
                aggregator: Aggregator::default(),
                counters: Monotonic::default(),
            })
        }

        /// All processes (one `kinfo_proc` each, threads folded in).
        fn read_table(&mut self) -> Result<Vec<libc::kinfo_proc>> {
            Mib::from_raw(&[libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PROC, 0])
                .read_into(&mut self.buf)
                .context("reading kern.proc.proc")?;
            let procs: Vec<libc::kinfo_proc> = cast_slice(&self.buf)?;
            if let Some(first) = procs.first() {
                let size = usize::try_from(first.ki_structsize).unwrap_or(0);
                if size != size_of::<libc::kinfo_proc>() {
                    bail!(
                        "kinfo_proc is {size} bytes, expected {}",
                        size_of::<libc::kinfo_proc>()
                    );
                }
            }
            Ok(procs)
        }

        /// argv joined by spaces, or `None` (kernel process, exited, no access).
        fn cmdline(&mut self, pid: i32) -> Option<String> {
            Mib::from_raw(&[libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ARGS, pid])
                .read_into(&mut self.args_buf)
                .ok()?;
            let args: Vec<_> = self
                .args_buf
                .split(|&b| b == 0)
                .filter(|a| !a.is_empty())
                .map(String::from_utf8_lossy)
                .collect();
            (!args.is_empty()).then(|| args.join(" "))
        }

        fn user_name(&mut self, uid: u32) -> String {
            self.users
                .entry(uid)
                .or_insert_with(|| lookup_user(uid))
                .clone()
        }
    }

    fn lookup_user(uid: u32) -> String {
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buf = [0 as libc::c_char; 1024];
        let mut result = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the given sizes.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return uid.to_string();
        }
        // SAFETY: getpwuid_r succeeded, so pw_name points into `buf`.
        unsafe { CStr::from_ptr((*result).pw_name) }
            .to_string_lossy()
            .into_owned()
    }

    fn cstr(chars: &[libc::c_char]) -> &str {
        // SAFETY: c_char and u8 have the same size and alignment.
        let bytes: &[u8] = unsafe { &*(std::ptr::from_ref(chars) as *const [u8]) };
        CStr::from_bytes_until_nul(bytes)
            .ok()
            .and_then(|s| s.to_str().ok())
            .unwrap_or("")
    }

    /// Open descriptors from `kern.proc.filedesc.<pid>` (what `procstat -f`
    /// reads): packed `kinfo_file` records starting with `kf_structsize`,
    /// `kf_type`, `kf_fd`. Negative `kf_fd`s are cwd, root, jail, text etc.
    fn open_fds(pid: i32, buf: &mut Vec<u8>) -> Option<u64> {
        Mib::from_raw(&[
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_FILEDESC,
            pid,
        ])
        .read_into(buf)
        .ok()?;
        count_fds(buf)
    }

    impl Processes {
        fn export_states(table: &[libc::kinfo_proc]) {
            let mut counts = [0u64; STATES.len()];
            let mut threads = 0u64;
            for kp in table {
                let c = state_char(kp.ki_stat, kp.ki_tdflags, kp.ki_slptime);
                if let Some(i) = STATES.iter().position(|(s, _)| *s == c) {
                    counts[i] += 1;
                }
                threads += u64::try_from(kp.ki_numthreads).unwrap_or(0);
            }
            for ((_, state), count) in STATES.iter().zip(counts) {
                gauge!("processes", "state" => *state).set(count as f64);
            }
            gauge!("processes_threads").set(threads as f64);
        }

        /// Converts the table into [`Proc`]s, fetching argv only where needed:
        /// for `pattern` queries and to restore truncated names.
        fn snapshot(&mut self, table: &[libc::kinfo_proc]) -> Vec<Proc> {
            let want_cmdline = self.queries.iter().any(Query::needs_cmdline);
            let mut procs = Vec::with_capacity(table.len());
            for kp in table {
                let comm = cstr(&kp.ki_comm).to_owned();
                let kernel = kp.ki_flag & P_SYSTEM != 0;
                let truncated = comm.len() >= super::COMMLEN;
                let cmdline = if !kernel && (want_cmdline || truncated) {
                    self.cmdline(kp.ki_pid)
                } else {
                    None
                };
                let argv0 = cmdline.as_deref().and_then(|c| c.split(' ').next());
                let name = full_name(&comm, argv0).to_owned();
                let ru = &kp.ki_rusage;
                let count = |v: libc::c_long| u64::try_from(v).unwrap_or(0);
                procs.push(Proc {
                    pid: kp.ki_pid,
                    name,
                    cmdline,
                    user: self.user_name(kp.ki_uid),
                    threads: u32::try_from(kp.ki_numthreads).unwrap_or(0),
                    rss_bytes: u64::try_from(kp.ki_rssize).unwrap_or(0) * self.page_size,
                    virtual_bytes: kp.ki_size as u64,
                    start_time: timeval_secs(kp.ki_start),
                    open_fds: None,
                    cpu_user: timeval_secs(ru.ru_utime),
                    cpu_system: timeval_secs(ru.ru_stime),
                    counters: [
                        count(ru.ru_nvcsw),
                        count(ru.ru_nivcsw),
                        count(ru.ru_inblock),
                        count(ru.ru_oublock),
                        count(ru.ru_majflt),
                        count(ru.ru_minflt),
                    ],
                });
            }
            procs
        }

        /// One series per process (`tag_with = ["pid"]`).
        fn export_per_pid(&mut self, query: &str, matched: &[Proc]) {
            for p in matched {
                let labels = [
                    ("query", query.to_owned()),
                    ("process_name", p.name.clone()),
                    ("user", p.user.clone()),
                    ("pid", p.pid.to_string()),
                ];
                export_gauges(&labels, &Gauges::of(p));
                let id = format!("{query}\0{}\0{}", p.pid, p.name);
                for ((metric, key, value), raw) in COUNTERS.iter().zip(p.counters) {
                    // The pid may be reused by a new process with the same name.
                    let v = self
                        .counters
                        .correct(&format!("{id}\0{metric}\0{value}"), raw);
                    counter!(*metric, with_label(&labels, key, value).as_slice()).absolute(v);
                }
            }
        }

        /// Sums per (query, process name, user).
        fn export_aggregated(&mut self, query: &str, matched: &[Proc], now: Instant) {
            let refs: Vec<&Proc> = matched.iter().collect();
            for g in self.aggregator.update(query, &refs, now) {
                let labels = [
                    ("query", g.query.clone()),
                    ("process_name", g.name.clone()),
                    ("user", g.user.clone()),
                ];
                export_gauges(
                    &labels,
                    &Gauges {
                        cpu: g.totals.cpu,
                        rss: g.rss_bytes,
                        virt: g.virtual_bytes,
                        threads: g.threads,
                        fds: g.open_fds,
                        start_time: g.start_time,
                    },
                );
                for ((metric, key, value), total) in COUNTERS.iter().zip(g.totals.counts) {
                    counter!(*metric, with_label(&labels, key, value).as_slice()).absolute(total);
                }
            }
        }
    }

    impl Collector for Processes {
        fn name(&self) -> &'static str {
            "processes"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let table = self.read_table()?;
            if self.states {
                Self::export_states(&table);
            }
            if self.queries.is_empty() {
                return Ok(());
            }
            let procs = self.snapshot(&table);
            let now = Instant::now();
            let queries = std::mem::take(&mut self.queries);
            for query in &queries {
                let mut matched: Vec<Proc> =
                    procs.iter().filter(|p| query.matches(p)).cloned().collect();
                for p in &mut matched {
                    p.open_fds = open_fds(p.pid, &mut self.args_buf);
                }
                gauge!("procstat_lookup_pids", "query" => query.label.clone())
                    .set(matched.len() as f64);
                if query.tag_pid {
                    self.export_per_pid(&query.label, &matched);
                } else {
                    self.export_aggregated(&query.label, &matched, now);
                }
            }
            self.queries = queries;
            self.aggregator.prune(now);
            self.counters.prune();
            Ok(())
        }
    }

    /// Point-in-time values exported as gauges.
    struct Gauges {
        cpu: [f64; 2],
        rss: u64,
        virt: u64,
        threads: u64,
        fds: Option<u64>,
        start_time: f64,
    }

    impl Gauges {
        fn of(p: &Proc) -> Self {
            Self {
                cpu: [p.cpu_user, p.cpu_system],
                rss: p.rss_bytes,
                virt: p.virtual_bytes,
                threads: u64::from(p.threads),
                fds: p.open_fds,
                start_time: p.start_time,
            }
        }
    }

    fn with_label(
        labels: &[(&'static str, String)],
        key: &'static str,
        value: &str,
    ) -> Vec<(&'static str, String)> {
        labels
            .iter()
            .cloned()
            .chain([(key, value.to_owned())])
            .collect()
    }

    fn export_gauges(labels: &[(&'static str, String)], g: &Gauges) {
        gauge!(
            "procstat_cpu_seconds_total",
            with_label(labels, "mode", "user").as_slice()
        )
        .set(g.cpu[0]);
        gauge!(
            "procstat_cpu_seconds_total",
            with_label(labels, "mode", "system").as_slice()
        )
        .set(g.cpu[1]);
        gauge!("procstat_memory_rss_bytes", labels).set(g.rss as f64);
        gauge!("procstat_memory_virtual_bytes", labels).set(g.virt as f64);
        gauge!("procstat_threads", labels).set(g.threads as f64);
        if let Some(fds) = g.fds {
            gauge!("procstat_open_fds", labels).set(fds as f64);
        }
        gauge!("procstat_start_time_seconds", labels).set(g.start_time);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_states_like_ps() {
        assert_eq!(state_char(2, 0, 0), 'R');
        assert_eq!(state_char(1, 0, 0), 'R');
        assert_eq!(state_char(3, 0x8, 5), 'S');
        assert_eq!(state_char(3, 0x8, 20), 'I');
        assert_eq!(state_char(3, 0, 0), 'D');
        assert_eq!(state_char(4, 0, 0), 'T');
        assert_eq!(state_char(5, 0, 0), 'Z');
        assert_eq!(state_char(6, 0, 0), 'W');
        assert_eq!(state_char(7, 0, 0), 'L');
    }

    #[test]
    fn counts_fds_in_packed_records() {
        let record = |size: i32, fd: i32| {
            let mut r = vec![0u8; usize::try_from(size).unwrap()];
            r[..4].copy_from_slice(&size.to_ne_bytes());
            r[8..12].copy_from_slice(&fd.to_ne_bytes());
            r
        };
        // cwd (-1), root (-2), then fds 0, 1, 2 with varying record sizes.
        let buf = [
            record(24, -1),
            record(24, -2),
            record(32, 0),
            record(40, 1),
            record(24, 2),
        ]
        .concat();
        assert_eq!(count_fds(&buf), Some(3));
        assert_eq!(count_fds(&[]), Some(0));
        let mut tiny = 8i32.to_ne_bytes().to_vec();
        tiny.resize(12, 0);
        assert_eq!(count_fds(&tiny), None, "record smaller than its header");
    }

    #[test]
    fn restores_truncated_names() {
        let comm = "http_responsetime_e";
        assert_eq!(comm.len(), COMMLEN);
        assert_eq!(
            full_name(comm, Some("/usr/local/bin/http_responsetime_exporter")),
            "http_responsetime_exporter"
        );
        assert_eq!(
            full_name(comm, Some("something_else")),
            comm,
            "argv[0] can be rewritten"
        );
        assert_eq!(full_name(comm, None), comm);
        assert_eq!(
            full_name("nginx", Some("nginx: worker process")),
            "nginx",
            "short names are used as is"
        );
    }

    fn proc(pid: i32, name: &str, cmdline: &str, user: &str) -> Proc {
        Proc {
            pid,
            name: name.into(),
            cmdline: Some(cmdline.into()),
            user: user.into(),
            ..Default::default()
        }
    }

    fn config(toml_text: &str) -> ProcstatConfig {
        toml::from_str(toml_text).unwrap()
    }

    #[test]
    fn matches_like_pgrep() {
        let exe = Query::new(&config("exe = 'nginx'")).unwrap();
        assert_eq!(exe.label, "exe=nginx");
        assert!(exe.matches(&proc(1, "nginx", "nginx: master", "root")));
        assert!(
            !exe.matches(&proc(2, "sh", "sh -c nginx", "root")),
            "exe ignores the command line"
        );

        let pattern = Query::new(&config("pattern = 'Plex'")).unwrap();
        assert!(pattern.matches(&proc(
            3,
            "python3.11",
            "/usr/local/share/plexmediaserver/Plex Script Host",
            "plex"
        )));
        assert!(
            !pattern.matches(&Proc {
                cmdline: None,
                ..proc(4, "Plex", "", "plex")
            }),
            "no argv, no match"
        );

        let both = Query::new(&config("exe = '^nginx$'\nuser = 'www'")).unwrap();
        assert_eq!(both.label, "exe=^nginx$,user=www");
        assert!(both.matches(&proc(5, "nginx", "", "www")));
        assert!(!both.matches(&proc(6, "nginx", "", "root")));
    }

    #[test]
    fn validates_queries() {
        assert!(Query::new(&config("")).is_err());
        assert!(Query::new(&config("exe = '('")).is_err());
        assert!(Query::new(&config("exe = 'x'\ntag_with = ['cmdline']")).is_err());
        assert!(
            Query::new(&config("exe = 'x'\ntag_with = ['pid']"))
                .unwrap()
                .tag_pid
        );
        let dup = [
            config("exe = 'a'"),
            config("exe = 'a'"),
            config("exe = 'a'\ntag_with = ['pid']"),
        ];
        assert_eq!(queries(&dup).unwrap().len(), 2);
    }

    #[test]
    fn aggregated_counters_survive_process_exit() {
        let mut agg = Aggregator::default();
        let now = Instant::now();
        let mut first = proc(10, "w", "", "u");
        let mut second = proc(11, "w", "", "u");
        first.cpu_user = 5.0;
        second.cpu_user = 3.0;
        first.counters[0] = 100;
        second.counters[0] = 50;
        let g = &agg.update("q", &[&first, &second], now)[0];
        assert_eq!(
            (g.processes, g.totals.cpu[0], g.totals.counts[0]),
            (2, 8.0, 150)
        );

        // The second process exits, the first keeps running.
        first.cpu_user = 6.0;
        first.counters[0] = 110;
        let g = &agg.update("q", &[&first], now)[0];
        assert_eq!(
            (g.processes, g.totals.cpu[0], g.totals.counts[0]),
            (1, 9.0, 160),
            "no drop on exit"
        );

        // pid 11 reused by a new process: counted from zero, not as a decrease.
        let mut reused = proc(11, "w", "", "u");
        reused.start_time = 1000.0;
        reused.cpu_user = 0.5;
        let g = &agg.update("q", &[&first, &reused], now)[0];
        assert!((g.totals.cpu[0] - 9.5).abs() < 1e-9);
    }
}
