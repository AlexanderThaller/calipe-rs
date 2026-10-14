#!/usr/bin/env python3
"""Generate the calipers probes dashboard (http_response and dns_query).

    python3 resources/grafana/generate_probes.py > resources/grafana/calipers-probes.json
"""
from dashlib import *  # noqa: F403

HS = f'{S}, url=~"$url"'
DQ = f'{S}, server=~"$server"'
HTTP_DUR = "http_response_duration_seconds"
DNS_DUR = "dns_query_duration_seconds"


def quantile(q, metric, sel, by, window=RI):
    return f'histogram_quantile({q}, sum by ({by}) (rate({metric}{{{sel}}}[{window}])))'


def avg(metric, sel, by, window=RI):
    return (f'histogram_sum(sum by ({by}) (rate({metric}{{{sel}}}[{window}])))'
            f' / histogram_count(sum by ({by}) (rate({metric}{{{sel}}}[{window}])))')


def success_ratio(metric, sel, by=None, window="$__range"):
    agg = f"sum by ({by})" if by else "sum"
    return (f'{agg} (increase({metric}{{{sel}, result="success"}}[{window}]))'
            f' / {agg} (increase({metric}{{{sel}}}[{window}]))')


def heatmap(title, expr, x=0, w=12, h=9, desc=""):
    """Latency distribution of a native histogram over time. Grafana turns
    native histogram results into heatmap cells; no client-side bucketing."""
    return {
        "type": "heatmap", "id": nid(), "title": title, "description": desc, "datasource": DS,
        "gridPos": place(w, h, x),
        "targets": [target(expr)],
        "fieldConfig": {"defaults": {"custom": {
            "scaleDistribution": {"type": "log", "log": 2},
            "hideFrom": {"legend": False, "tooltip": False, "viz": False},
        }}, "overrides": []},
        "options": {
            "calculate": False,
            "cellGap": 1,
            "color": {"mode": "scheme", "scheme": "Spectral", "reverse": True, "scale": "exponential",
                      "exponent": 0.5, "steps": 64, "fill": "dark-orange"},
            "yAxis": {"axisPlacement": "left", "unit": "s", "reverse": False},
            "rowsFrame": {"layout": "auto"},
            "filterValues": {"le": 1e-9},
            "showValue": "never",
            "legend": {"show": True},
            "tooltip": {"mode": "single", "yHistogram": True, "showColorScale": True},
            "exemplars": {"color": "rgba(255,0,255,0.7)"},
        },
    }


def latency_ts(title, metric, sel, by, legend, x=12, w=12, h=9, desc=""):
    return ts(title, [
        (quantile(0.5, metric, sel, by), f"{legend}p50"),
        (quantile(0.9, metric, sel, by), f"{legend}p90"),
        (quantile(0.99, metric, sel, by), f"{legend}p99"),
        (avg(metric, sel, by), f"{legend}avg"),
    ], unit="s", x=x, w=w, h=h, desc=desc)


def repeat_row(title, var):
    p = row(title)
    p["repeat"] = var
    return p


# ---------------------------------------------------------------- Summary
row("Summary")
add(
    stat("HTTP probes failing", count0(f'http_response_success{{{HS}}} == 0'), x=0, w=4,
         thresholds=BAD_IF_ANY, desc="URLs whose last probe failed."),
    stat("HTTP success", success_ratio("http_response_total", HS), unit="percentunit", x=4, w=4,
         decimals=2, thresholds=[{"color": "red", "value": None}, {"color": "orange", "value": 0.95},
                                 {"color": "green", "value": 0.999}],
         desc="Successful HTTP probes in the selected time range."),
    stat("Slowest HTTP p95", f'max({quantile(0.95, HTTP_DUR, HS, "host, url", "$__range")})', unit="s",
         x=8, w=4, thresholds=steps((0.5, "orange"), (2, "red")),
         desc="p95 over the selected time range of the slowest URL."),
    stat("DNS probes failing", count0(f'dns_query_success{{{DQ}}} == 0'), x=12, w=4,
         thresholds=BAD_IF_ANY, desc="Server/domain/record type combinations whose last query failed."),
    stat("DNS success", success_ratio("dns_query_total", DQ), unit="percentunit", x=16, w=4,
         decimals=2, thresholds=[{"color": "red", "value": None}, {"color": "orange", "value": 0.95},
                                 {"color": "green", "value": 0.999}],
         desc="Successful DNS queries in the selected time range."),
    stat("Slowest DNS p95", f'max({quantile(0.95, DNS_DUR, DQ, "host, server", "$__range")})', unit="s",
         x=20, w=4, thresholds=steps((0.1, "orange"), (1, "red")),
         desc="p95 over the selected time range of the slowest server."),
)

# ---------------------------------------------------------------- HTTP
row("HTTP")
HB = "host, method, url"
add(table("HTTP probes", [
    (f'max by ({HB}) (http_response_success{{{HS}}})', "Up", "short", None, "color-text"),
    (f'max by ({HB}) (http_response_status_code{{{HS}}})', "Status", "short", None, None),
    (success_ratio("http_response_total", HS, HB), "Success", "percentunit",
     [{"color": "red", "value": None}, {"color": "orange", "value": 0.95}, {"color": "green", "value": 0.999}],
     None),
    (quantile(0.5, HTTP_DUR, HS, HB, "$__range"), "p50", "s", None, None),
    (quantile(0.95, HTTP_DUR, HS, HB, "$__range"), "p95", "s", steps((0.5, "orange"), (2, "red")), None),
    (quantile(0.99, HTTP_DUR, HS, HB, "$__range"), "p99", "s", None, None),
    (f'max by ({HB}) (http_response_tls_cert_expiry_seconds{{{HS}}}) - time()', "Cert expires in",
     "dtdurations", [{"color": "red", "value": None}, {"color": "orange", "value": 14 * 86400},
                     {"color": "green", "value": 30 * 86400}], None),
], h=9, sort="p95", labels=("host", "method", "url"),
    extra_overrides=[{"matcher": {"id": "byName", "options": "Up"},
                      "properties": [{"id": "mappings", "value": UPDOWN}]}],
    desc="Success and latency quantiles over the selected time range."))
add(
    ts("HTTP latency p95", [(quantile(0.95, HTTP_DUR, HS, "host, url"), "{{host}} {{url}}")],
       unit="s", x=0, w=12),
    ts("HTTP failures", [
        (f'sum by (host, url, result) (increase(http_response_total{{{HS}, result!="success"}}[{RI}])) > 0',
         "{{host}} {{url}} {{result}}")],
       x=12, w=12, no_value="No failures", desc="Failed probes by result; only failing URLs appear."),
)

repeat_row("HTTP $url", "url")
U = f'{S}, url="$url"'
add(
    heatmap("Latency distribution", f'sum(rate({HTTP_DUR}{{{U}}}[{RI}]))', x=0,
            desc="DNS + TCP + TLS + full body. Hover a column for the distribution at that time."),
    latency_ts("Latency quantiles", HTTP_DUR, U, "url", "", x=12),
)

# ---------------------------------------------------------------- DNS
row("DNS")
DB = "host, server, domain, record_type"
add(table("DNS probes", [
    (f'max by ({DB}) (dns_query_success{{{DQ}}})', "Up", "short", None, "color-text"),
    (success_ratio("dns_query_total", DQ, DB), "Success", "percentunit",
     [{"color": "red", "value": None}, {"color": "orange", "value": 0.95}, {"color": "green", "value": 0.999}],
     None),
    (quantile(0.5, DNS_DUR, DQ, DB, "$__range"), "p50", "s", None, None),
    (quantile(0.95, DNS_DUR, DQ, DB, "$__range"), "p95", "s", steps((0.1, "orange"), (1, "red")), None),
    (quantile(0.99, DNS_DUR, DQ, DB, "$__range"), "p99", "s", None, None),
    (f'max by ({DB}) (dns_query_answers{{{DQ}}})', "Answers", "short", None, None),
], h=9, sort="p95", labels=("host", "server", "domain", "record_type"),
    extra_overrides=[{"matcher": {"id": "byName", "options": "Up"},
                      "properties": [{"id": "mappings", "value": UPDOWN}]}],
    desc="Success and latency quantiles over the selected time range."))
add(
    ts("DNS latency p95", [(quantile(0.95, DNS_DUR, DQ, "host, server"), "{{host}} {{server}}")],
       unit="s", x=0, w=12),
    ts("DNS failures", [
        (f'sum by (host, server, result, rcode) (increase(dns_query_total{{{DQ}, result!="success"}}[{RI}])) > 0',
         "{{host}} {{server}} {{result}} {{rcode}}")],
       x=12, w=12, no_value="No failures", desc="Failed queries by result; only failing servers appear."),
)

repeat_row("DNS $server", "server")
V = f'{S}, server="$server"'
add(
    heatmap("Latency distribution", f'sum(rate({DNS_DUR}{{{V}}}[{RI}]))', x=0,
            desc="All domains and record types of this server. Replies only; timeouts are not included."),
    latency_ts("Latency quantiles by record type", DNS_DUR, V, "record_type", "{{record_type}} ", x=12),
)


dashboard("calipers-probes", "calipers probes",
          "HTTP and DNS probes of calipers: success, latency quantiles and native histogram "
          "heatmaps per URL and per DNS server.",
          ["calipers", "probes"],
          variables=[
              var_query("url", "URL", 'label_values(http_response_success{job=~"$job", realm=~"$realm", '
                                      'host=~"$host"}, url)'),
              var_query("server", "DNS server", 'label_values(dns_query_success{job=~"$job", realm=~"$realm", '
                                                'host=~"$host"}, server)'),
          ])
