#!/usr/bin/env python3
"""Generate the calipers overview dashboard.

    python3 resources/grafana/generate.py > resources/grafana/calipers.json
"""
from dashlib import *  # noqa: F403

# Shared expressions, aggregated per host.
cpu_busy = (f'1 - sum by (host) (rate(cpu_all_seconds_total{{{S}, mode="idle"}}[{RI}]))'
            f' / sum by (host) (rate(cpu_all_seconds_total{{{S}}}[{RI}]))')
mem_used = (f'1 - sum by (host) (mem_available_bytes{{{S}}})'
            f' / sum by (host) (mem_physical_bytes{{{S}}})')
swap_used = (f'sum by (host) (swap_used_bytes{{{S}}})'
             f' / sum by (host) (swap_total_bytes{{{S}}} > 0)')
fs_used = (f'(disk_total_bytes{{{S}}} - disk_free_bytes{{{S}}})'
           f' / (disk_total_bytes{{{S}}} - disk_free_bytes{{{S}}} + disk_avail_bytes{{{S}}})')
pool_used = f'zfs_pool_allocated_bytes{{{S}}} / zfs_pool_size_bytes{{{S}}}'
NET = f'{S}, interface!~"lo[0-9]*"'
rx = f'sum by (host) (rate(net_received_bytes_total{{{NET}}}[{RI}])) * 8'
tx = f'sum by (host) (rate(net_sent_bytes_total{{{NET}}}[{RI}])) * 8'
pools_bad = f'zfs_pool_health{{{S}, state!="ONLINE"}} == 1'
vdevs_bad = f'zfs_vdev_state{{{S}, state!="ONLINE"}} == 1'
smart_bad = f'smart_device_healthy{{{S}}} == 0'
http_bad = f'http_response_success{{{S}}} == 0'
dns_bad = f'dns_query_success{{{S}}} == 0'
chrony_bad = f'chrony_synchronized{{{S}}} == 0'



# ---------------------------------------------------------------- Fleet summary
row("Overview: all selected hosts")
add(
    stat("Hosts", f'count(count by (host) (calipers_build_info{{{S}}}))', x=0, w=2,
         desc="Hosts that reported calipers_build_info."),
    stat("Targets down", f'count(up{{job=~"$job"}} == 0) or vector(0)', x=2, w=2,
         thresholds=BAD_IF_ANY, desc="Scrape targets of the selected jobs that are down."),
    stat("CPUs", f'sum(system_cpus{{{S}}})', x=4, w=2, desc="Logical CPUs across the selected hosts."),
    stat("CPU busy", f'1 - sum(rate(cpu_all_seconds_total{{{S}, mode="idle"}}[{RI}]))'
                     f' / sum(rate(cpu_all_seconds_total{{{S}}}[{RI}]))',
         unit="percentunit", x=6, w=2, thresholds=PCT, decimals=1,
         desc="Non-idle share of all CPUs on the selected hosts."),
    stat("Memory used", f'1 - sum(mem_available_bytes{{{S}}}) / sum(mem_physical_bytes{{{S}}})',
         unit="percentunit", x=8, w=2, thresholds=PCT, decimals=1,
         desc="1 - available / physical. ARC counts as available."),
    stat("Memory", f'sum(mem_physical_bytes{{{S}}})', unit="bytes", x=10, w=2,
         desc="Physical memory across the selected hosts."),
    stat("Network in", f'sum(rate(net_received_bytes_total{{{NET}}}[{RI}])) * 8', unit="bps",
         x=12, w=2, desc="All interfaces except loopback."),
    stat("Network out", f'sum(rate(net_sent_bytes_total{{{NET}}}[{RI}])) * 8', unit="bps",
         x=14, w=2, desc="All interfaces except loopback."),
    stat("Fullest filesystem", f'max({fs_used})', unit="percentunit", x=16, w=2,
         thresholds=PCT, decimals=1, desc="Highest used share of any monitored filesystem."),
    stat("Fullest pool", f'max({pool_used})', unit="percentunit", x=18, w=2,
         thresholds=PCT, decimals=1, desc="Highest allocated share of any ZFS pool."),
    stat("Problems",
         f'{count0(pools_bad)} + {count0(vdevs_bad)} + {count0(smart_bad)}'
         f' + {count0(http_bad)} + {count0(dns_bad)} + {count0(chrony_bad)}',
         x=20, w=2, thresholds=BAD_IF_ANY,
         desc="ZFS pools and vdevs not ONLINE, unhealthy SMART devices, failing HTTP and DNS probes "
              "and unsynchronized clocks. Details in the Health row."),
    stat("Collector errors", f'sum(increase(calipers_collector_errors_total{{{S}}}[$__range])) or vector(0)',
         x=22, w=2, thresholds=BAD_IF_ANY, decimals=0,
         desc="Failed collector runs in the selected time range."),
)

# ---------------------------------------------------------------- Per-host table
add(table("Hosts", [
    (f'time() - max by (host) (system_boot_time_seconds{{{S}}})', "Uptime", "dtdurations", None, None),
    (f'max by (host) (system_cpus{{{S}}})', "CPUs", "short", None, None),
    (cpu_busy, "CPU", "percentunit", PCT, "gauge"),
    (f'max by (host) (system_load1{{{S}}}) / max by (host) (system_cpus{{{S}}})', "Load / CPU",
     "short", steps((1, "orange"), (2, "red")), None),
    (mem_used, "Memory", "percentunit", PCT, "gauge"),
    (f'max by (host) (mem_physical_bytes{{{S}}})', "RAM", "bytes", None, None),
    (swap_used, "Swap", "percentunit", steps((0.2, "orange"), (0.5, "red")), None),
    (f'max by (host) ({fs_used})', "Fullest FS", "percentunit", PCT, None),
    (f'max by (host) ({pool_used})', "Fullest pool", "percentunit", PCT, None),
    (rx, "Net in", "bps", None, None),
    (tx, "Net out", "bps", None, None),
    (f'count by (host) ({pools_bad} or {vdevs_bad}) or count by (host) (calipers_build_info{{{S}}}) * 0',
     "ZFS issues", "short", BAD_IF_ANY, None),
    (f'count by (host) ({smart_bad}) or count by (host) (calipers_build_info{{{S}}}) * 0',
     "SMART issues", "short", BAD_IF_ANY, None),
    (f'max by (host, version) (calipers_build_info{{{S}}})', "calipers", "short", None, None),
], h=7, sort="CPU", hide=("calipers",), labels=("host", "version"),
    desc="One row per host at the end of the time range. Click a host name to show only that host."))

# ---------------------------------------------------------------- CPU and load
row("CPU and load")
add(
    ts("CPU busy by host", [(cpu_busy, "{{host}}")], unit="percentunit", x=0, w=8, minv=0, maxv=1,
       desc="Non-idle share of all CPUs per host."),
    ts("CPU by mode (selected hosts)",
       [(f'sum by (mode) (rate(cpu_all_seconds_total{{{S}, mode!="idle"}}[{RI}]))'
         f' / scalar(sum(rate(cpu_all_seconds_total{{{S}}}[{RI}])))', "{{mode}}")],
       unit="percentunit", x=8, w=8, stack=True, minv=0,
       desc="Share of all CPUs on the selected hosts, by mode."),
    ts("Load (1m) per CPU by host",
       [(f'max by (host) (system_load1{{{S}}}) / max by (host) (system_cpus{{{S}}})', "{{host}}")],
       x=16, w=8, thresholds=steps((1, "red")),
       desc="1-minute load average divided by logical CPUs; above 1 means runnable threads wait."),
)
add(
    ts("Hottest CPU core by host", [(f'max by (host) (cpu_temperature_celsius{{{S}}})', "{{host}}")],
       unit="celsius", x=0, w=8),
    ts("Context switches and interrupts (selected hosts)", [
        (f'sum(rate(kernel_context_switches_total{{{S}}}[{RI}]))', "context switches"),
        (f'sum by (type) (rate(kernel_interrupts_total{{{S}}}[{RI}]))', "{{type}} interrupts"),
        (f'sum(rate(kernel_syscalls_total{{{S}}}[{RI}]))', "syscalls"),
    ], unit="ops", x=8, w=8),
    ts("Processes by state (selected hosts)",
       [(f'sum by (state) (processes{{{S}, state!~"sleeping|idle"}})', "{{state}}")], x=16, w=8,
       desc="Sleeping and idle (kernel threads) left out, they dwarf the rest."),
)

# ---------------------------------------------------------------- Memory
row("Memory")
add(
    ts("Memory used by host", [(mem_used, "{{host}}")], unit="percentunit", x=0, w=8, minv=0, maxv=1,
       desc="1 - available / physical. ARC counts as available."),
    ts("Memory by state (selected hosts)", [
        (f'sum by (state) (mem_bytes{{{S}}})', "{{state}}"),
    ], unit="bytes", x=8, w=8, stack=True,
       desc="FreeBSD page queues. ZFS ARC is part of wired, see the next panel."),
    ts("ZFS ARC and swap by host", [
        (f'sum by (host) (mem_zfs_arc_bytes{{{S}}})', "{{host}} ARC"),
        (f'sum by (host) (swap_used_bytes{{{S}}})', "{{host}} swap used"),
    ], unit="bytes", x=16, w=8),
)

# ---------------------------------------------------------------- Storage
row("Storage")
add(
    ts("Filesystem and pool usage", [
        (f'{fs_used}', "{{host}} {{path}}"),
        (f'{pool_used}', "{{host}} pool {{pool}}"),
    ], unit="percentunit", x=0, w=8, minv=0, maxv=1, thresholds=steps((0.9, "red"))),
    ts("Disk throughput by host", [
        (f'sum by (host) (rate(diskio_bytes_total{{{S}, type="read"}}[{RI}]))', "{{host}} read"),
        (f'sum by (host) (rate(diskio_bytes_total{{{S}, type="write"}}[{RI}]))', "{{host}} write"),
    ], unit="Bps", x=8, w=8, mirror="B", desc="Reads up, writes down. Sum over all disks."),
    ts("Busiest disk by host",
       [(f'max by (host) (rate(diskio_busy_seconds_total{{{S}}}[{RI}]))', "{{host}}")],
       unit="percentunit", x=16, w=8, minv=0, maxv=1,
       desc="Busy share of the busiest disk per host (devstat busy time)."),
)
add(
    ts("Disk operations by host", [
        (f'sum by (host) (rate(diskio_operations_total{{{S}, type="read"}}[{RI}]))', "{{host}} read"),
        (f'sum by (host) (rate(diskio_operations_total{{{S}, type="write"}}[{RI}]))', "{{host}} write"),
    ], unit="iops", x=0, w=8, mirror="B", desc="Reads up, writes down."),
    ts("Disk latency by device", [
        (f'sum by (host, device) (rate(diskio_time_seconds_total{{{S}, type=~"read|write"}}[{RI}]))'
         f' / sum by (host, device) (rate(diskio_operations_total{{{S}, type=~"read|write"}}[{RI}]) > 0)',
         "{{host}} {{device}}"),
    ], unit="s", x=8, w=8, desc="Average time per read or write operation."),
    ts("ZFS pool I/O by host", [
        (f'sum by (host, pool) (rate(zfs_pool_bytes_total{{{S}, type="read"}}[{RI}]))', "{{host}} {{pool}} read"),
        (f'sum by (host, pool) (rate(zfs_pool_bytes_total{{{S}, type="write"}}[{RI}]))', "{{host}} {{pool}} write"),
    ], unit="Bps", x=16, w=8, mirror="B", desc="Reads up, writes down."),
)

# ---------------------------------------------------------------- Network
row("Network")
add(
    ts("Traffic by host", [
        (rx, "{{host}} in"),
        (f'{tx}', "{{host}} out"),
    ], unit="bps", x=0, w=8, mirror="B", desc="All interfaces except loopback. In up, out down."),
    ts("Errors and drops by host", [
        (f'sum by (host) (rate(net_receive_errors_total{{{NET}}}[{RI}]) + rate(net_send_errors_total{{{NET}}}[{RI}]))',
         "{{host}} errors"),
        (f'sum by (host) (rate(net_receive_drops_total{{{NET}}}[{RI}]) + rate(net_send_drops_total{{{NET}}}[{RI}]))',
         "{{host}} drops"),
    ], unit="pps", x=8, w=8),
    ts("TCP connections and pf states by host", [
        (f'sum by (host) (netstat_tcp_connections{{{S}, state="ESTABLISHED"}})', "{{host}} established"),
        (f'sum by (host) (netstat_tcp_connections{{{S}}})', "{{host}} all TCP"),
        (f'sum by (host) (pf_states{{{S}}})', "{{host}} pf states"),
    ], x=16, w=8),
)

# ---------------------------------------------------------------- Health
row("Health")
problems = " or ".join([
    f'label_replace(label_join({pools_bad}, "subject", " ", "pool", "state"), "check", "ZFS pool", "", "")',
    f'label_replace(label_join({vdevs_bad}, "subject", " ", "pool", "vdev", "state"), "check", "ZFS vdev", "", "")',
    f'label_replace(label_join({smart_bad}, "subject", " ", "device"), "check", "SMART", "", "")',
    f'label_replace(label_join({http_bad}, "subject", " ", "method", "url"), "check", "HTTP", "", "")',
    f'label_replace(label_join({dns_bad}, "subject", " ", "server", "domain", "record_type"), "check", "DNS", "", "")',
    f'label_replace(label_replace({chrony_bad}, "subject", "not synchronized", "", ""), "check", "chrony", "", "")',
])
add(
    table("Problems", [(f'max by (host, check, subject) ({problems})', "value", "short", None, None)],
          x=0, w=12, h=8, hide=("value",), labels=("host", "check", "subject"),
          desc="Everything that is unhealthy right now: ZFS pools and vdevs not ONLINE, failing SMART "
               "health, failing HTTP and DNS probes, unsynchronized clocks. Empty means all good."),
    table("Disks", [
        (f'max by (host, device) (smart_device_healthy{{{S}}})', "Health", "short", None, "color-text"),
        (f'max by (host, device) (smart_device_standby{{{S}}})', "Power", "short", None, None),
        (f'max by (host, device) (smart_temperature_celsius{{{S}}})', "Temp", "celsius",
         steps((50, "orange"), (60, "red")), None),
        (f'max by (host, device) (smart_power_on_seconds{{{S}}})', "Power on", "dtdurations", None, None),
        (f'max by (host, device) (smart_nvme_percentage_used_ratio{{{S}}})', "NVMe wear", "percentunit",
         steps((0.8, "orange"), (0.95, "red")), None),
        (f'max by (host, device) (smart_nvme_media_errors{{{S}}})', "Media errors", "short", BAD_IF_ANY, None),
    ], x=12, w=12, h=8, sort="Temp", labels=("host", "device"),
        extra_overrides=[
            {"matcher": {"id": "byName", "options": "Health"}, "properties": [
                {"id": "mappings", "value": [{"type": "value", "options": {
                    "0": {"text": "FAILING", "color": "red"}, "1": {"text": "OK", "color": "green"}}}]}]},
            {"matcher": {"id": "byName", "options": "Power"}, "properties": [
                {"id": "mappings", "value": [{"type": "value", "options": {
                    "0": {"text": "active"}, "1": {"text": "standby"}}}]}]}],
        desc="SMART health per drive. Drives in standby are not woken up and keep their last values."),
)
add(
    ts("Clock offset by host", [
        (f'max by (host) (chrony_last_offset_seconds{{{S}}})', "{{host}} last offset"),
        (f'max by (host) (chrony_system_time_correction_seconds{{{S}}})', "{{host}} correction"),
    ], unit="s", x=0, w=8),
    ts("Disk temperature", [(f'max by (host, device) (smart_temperature_celsius{{{S}}})', "{{host}} {{device}}")],
       unit="celsius", x=8, w=8),
    ts("ZFS and disk errors", [
        (f'sum by (host, pool, vdev) (zfs_vdev_errors{{{S}}}) > 0', "{{host}} {{vdev}}"),
        (f'sum by (host, pool) (zfs_pool_scan_errors{{{S}}}) > 0', "{{host}} {{pool}} scrub"),
        (f'max by (host, device) (smart_nvme_media_errors{{{S}}}) > 0', "{{host}} {{device}} media"),
    ], x=16, w=8, no_value="No errors", desc="Only series with errors appear."),
)

# ---------------------------------------------------------------- Probes (collapsed)
row("Probes")
add(
    table("HTTP probes", [
        (f'max by (host, method, url) (http_response_success{{{S}}})', "Up", "short", None, "color-text"),
        (f'max by (host, method, url) (http_response_status_code{{{S}}})', "Status", "short", None, None),
        (f'histogram_sum(sum by (host, method, url) (rate(http_response_duration_seconds{{{S}}}[$__range])))'
         f' / histogram_count(sum by (host, method, url) (rate(http_response_duration_seconds{{{S}}}[$__range])))',
         "Avg latency", "s", steps((0.5, "orange"), (2, "red")), None),
        (f'max by (host, method, url) (http_response_tls_cert_expiry_seconds{{{S}}}) - time()', "Cert expires in",
         "dtdurations", [{"color": "red", "value": None}, {"color": "orange", "value": 14 * 86400},
                         {"color": "green", "value": 30 * 86400}], None),
    ], x=0, w=12, h=9, sort="Avg latency", labels=("host", "method", "url"),
        extra_overrides=[{"matcher": {"id": "byName", "options": "Up"},
                          "properties": [{"id": "mappings", "value": UPDOWN}]}],
        desc="Latency averaged over the selected time range."),
    table("DNS probes", [
        (f'max by (host, server, domain, record_type) (dns_query_success{{{S}}})', "Up", "short", None, "color-text"),
        (f'histogram_sum(sum by (host, server, domain, record_type) (rate(dns_query_duration_seconds{{{S}}}[$__range])))'
         f' / histogram_count(sum by (host, server, domain, record_type) (rate(dns_query_duration_seconds{{{S}}}[$__range])))',
         "Avg latency", "s", steps((0.1, "orange"), (1, "red")), None),
        (f'max by (host, server, domain, record_type) (dns_query_answers{{{S}}})', "Answers", "short", None, None),
    ], x=12, w=12, h=9, sort="Avg latency", labels=("host", "server", "domain", "record_type"),
        extra_overrides=[{"matcher": {"id": "byName", "options": "Up"},
                          "properties": [{"id": "mappings", "value": UPDOWN}]}],
        desc="Latency averaged over the selected time range."),
)
add(
    ts("HTTP latency p95", [
        (f'histogram_quantile(0.95, sum by (host, url) (rate(http_response_duration_seconds{{{S}}}[{RI}])))',
         "{{host}} {{url}}")], unit="s", x=0, w=12),
    ts("DNS latency p95", [
        (f'histogram_quantile(0.95, sum by (host, server) (rate(dns_query_duration_seconds{{{S}}}[{RI}])))',
         "{{host}} {{server}}")], unit="s", x=12, w=12),
)

# ---------------------------------------------------------------- Processes (collapsed)
row("Monitored processes")
add(
    ts("CPU by process", [
        (f'sum by (host, process_name) (rate(procstat_cpu_seconds_total{{{S}}}[{RI}]))', "{{host}} {{process_name}}")],
       unit="percentunit", x=0, w=8, desc="Summed over all PIDs and modes; 1 = one full CPU."),
    ts("Resident memory by process", [
        (f'sum by (host, process_name) (procstat_memory_rss_bytes{{{S}}})', "{{host}} {{process_name}}")],
       unit="bytes", x=8, w=8),
    ts("Open files by process", [
        (f'sum by (host, process_name) (procstat_open_fds{{{S}}})', "{{host}} {{process_name}}")],
       x=16, w=8),
)

# ---------------------------------------------------------------- Agent (collapsed)
row("calipers agent")
add(
    ts("Collector duration p99", [
        (f'histogram_quantile(0.99, sum by (collector) (rate(calipers_collector_duration_seconds{{{S}}}[{RI}])))',
         "{{collector}}")], unit="s", x=0, w=8, desc="Slowest hosts dominate."),
    ts("Collector errors", [
        (f'sum by (host, collector) (increase(calipers_collector_errors_total{{{S}}}[{RI}])) > 0',
         "{{host}} {{collector}}")], x=8, w=8, no_value="No errors", desc="Only collectors with errors appear."),
    ts("calipers CPU and memory by host", [
        (f'sum by (host) (rate(calipers_cpu_seconds_total{{{S}}}[{RI}]))', "{{host}} CPU"),
        (f'max by (host) (calipers_memory_rss_bytes{{{S}}})', "{{host}} RSS"),
    ], unit="percentunit", x=16, w=8,
       overrides=[{"matcher": {"id": "byRegexp", "options": ".* RSS$"},
                   "properties": [{"id": "unit", "value": "bytes"},
                                  {"id": "custom.axisPlacement", "value": "right"}]}]),
)


dashboard("calipers-overview", "calipers",
          "Overview of hosts monitored by calipers: fleet totals, one row per host, "
          "and time series per host. Select hosts with the host variable.",
          ["calipers", "freebsd", "node"],
          collapse={"Probes", "Monitored processes", "calipers agent"})
