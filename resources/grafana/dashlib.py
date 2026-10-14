"""Panel builders shared by the calipers dashboard generators."""
import json
import sys

S = 'job=~"$job", realm=~"$realm", host=~"$host"'
RI = "$__rate_interval"
DS = {"type": "prometheus", "uid": "${datasource}"}

panels = []
_id = 0
y = 0


def nid():
    global _id
    _id += 1
    return _id


def target(expr, legend="", ref="A", instant=False, fmt=None):
    t = {"datasource": DS, "expr": expr, "refId": ref, "legendFormat": legend or "__auto"}
    if instant:
        t["instant"] = True
        t["range"] = False
    if fmt:
        t["format"] = fmt
    return t


def place(w, h, x):
    return {"h": h, "w": w, "x": x, "y": y}


def row(title, collapsed=False, children=None):
    global y
    p = {"type": "row", "id": nid(), "title": title, "collapsed": collapsed,
         "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []}
    y += 1
    if collapsed:
        p["panels"] = children or []
    panels.append(p)
    return p


def stat(title, expr, unit="short", x=0, w=3, h=4, thresholds=None, desc="", decimals=None,
         color_mode="value", mappings=None):
    p = {
        "type": "stat", "id": nid(), "title": title, "description": desc, "datasource": DS,
        "gridPos": place(w, h, x),
        "targets": [target(expr, instant=True)],
        "fieldConfig": {"defaults": {
            "unit": unit,
            "thresholds": {"mode": "absolute", "steps": thresholds or [{"color": "green", "value": None}]},
            "color": {"mode": "thresholds"},
            "mappings": mappings or [],
        }, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": color_mode, "graphMode": "none", "textMode": "value",
                    "justifyMode": "center", "orientation": "auto"},
    }
    if decimals is not None:
        p["fieldConfig"]["defaults"]["decimals"] = decimals
    return p


def ts(title, targets, unit="short", x=0, w=12, h=8, desc="", stack=False, minv=None, maxv=None,
       overrides=None, thresholds=None, mirror=None, no_value=None):
    custom = {"drawStyle": "line", "lineWidth": 1, "fillOpacity": 0, "showPoints": "never",
              "spanNulls": False, "axisSoftMin": 0}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
        custom["fillOpacity"] = 40
    if thresholds:
        custom["thresholdsStyle"] = {"mode": "dashed"}
    d = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if thresholds:
        d["thresholds"] = {"mode": "absolute", "steps": thresholds}
    if no_value:
        d["noValue"] = no_value
    overrides = list(overrides or [])
    if mirror:
        overrides.append({"matcher": {"id": "byFrameRefID", "options": mirror},
                          "properties": [{"id": "custom.transform", "value": "negative-Y"}]})
    if minv is not None:
        d["min"] = minv
    if maxv is not None:
        d["max"] = maxv
    return {
        "type": "timeseries", "id": nid(), "title": title, "description": desc, "datasource": DS,
        "gridPos": place(w, h, x),
        "targets": [target(e, l, chr(65 + i)) for i, (e, l) in enumerate(targets)],
        "fieldConfig": {"defaults": d, "overrides": overrides},
        "options": {"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "lastNotNull"],
                               "sortBy": "Max", "sortDesc": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def table(title, columns, x=0, w=24, h=8, desc="", sort=None, extra_overrides=None, host_link=True,
          hide=(), labels=("host",)):
    """columns: list of (expr, display name, unit, thresholds or None, cell type or None)."""
    targets = []
    overrides = []
    rename = {}
    hidden = []
    for i, (expr, name, unit, thr, cell) in enumerate(columns):
        ref = chr(65 + i)
        targets.append(target(expr, ref=ref, instant=True, fmt="table"))
        rename[f"Value #{ref}"] = name
        if len(columns) == 1:
            rename["Value"] = name
        if name in hide:
            hidden += [f"Value #{ref}", "Value"]
        props = [{"id": "unit", "value": unit}]
        if thr:
            props.append({"id": "thresholds", "value": {"mode": "absolute", "steps": thr}})
            props.append({"id": "custom.cellOptions", "value": {"type": cell or "color-text"}})
        elif cell:
            props.append({"id": "custom.cellOptions", "value": {"type": cell}})
        overrides.append({"matcher": {"id": "byName", "options": name}, "properties": props})
    if host_link:
        overrides.append({"matcher": {"id": "byName", "options": "host"}, "properties": [
            {"id": "links", "value": [{
                "title": "Show only ${__value.raw}",
                "url": "/d/calipers-overview/calipers?${job:queryparam}&${realm:queryparam}"
                       "&var-host=${__value.raw}&${__url_time_range}&${datasource:queryparam}",
            }]}]})
    overrides += extra_overrides or []
    exclude = {"Time": True, "job": True, "realm": True, "role": True, "instance": True,
               "__name__": True}
    exclude.update({h: True for h in hidden})
    return {
        "type": "table", "id": nid(), "title": title, "description": desc, "datasource": DS,
        "gridPos": place(w, h, x),
        "targets": targets,
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {
                "excludeByName": exclude, "renameByName": rename,
                "indexByName": {**{l: i for i, l in enumerate(labels)},
                                **{f"Value #{chr(65 + i)}": len(labels) + i for i in range(len(columns))}}}},
        ],
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                                     "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]}},
                        "overrides": overrides},
        "options": {"showHeader": True, "cellHeight": "sm",
                    "sortBy": [{"displayName": sort, "desc": True}] if sort else []},
    }


def add(*ps, h=None):
    """Append panels laid out left to right and advance y by the tallest."""
    global y
    for p in ps:
        panels.append(p)
    y += h or max(p["gridPos"]["h"] for p in ps)


def at(p, x):
    p["gridPos"]["x"] = x
    return p


GREEN = {"color": "green", "value": None}


def steps(*pairs):
    return [GREEN] + [{"color": c, "value": v} for v, c in pairs]


PCT = steps((0.8, "orange"), (0.9, "red"))
BAD_IF_ANY = steps((1, "red"))

def count0(e):
    return f'count({e}) or vector(0)'


UPDOWN = [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red"}, "1": {"text": "UP", "color": "green"}}}]


def var_query(name, label, query, multi=True, include_all=True, all_value=".*", hide=0):
    return {
        "type": "query", "name": name, "label": label, "datasource": DS,
        "query": {"query": query, "refId": "StandardVariableQuery"},
        "definition": query, "refresh": 2, "sort": 1, "multi": multi,
        "includeAll": include_all, "allValue": all_value,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]} if include_all else {},
        "hide": hide, "regex": "", "options": [],
    }



def dashboard(uid, title, description, tags, collapse=(), variables=()):
    """Write the dashboard built from `panels` to stdout. Panels after a row
    whose title is in `collapse` move into that row."""
    out = []
    current = None
    for p in panels:
        if p["type"] == "row":
            current = p if p["title"] in collapse else None
            if current:
                current["collapsed"] = True
            out.append(p)
        elif current is not None:
            current["panels"].append(p)
        else:
            out.append(p)
    d = {
        "uid": uid,
        "title": title,
        "description": description,
        "tags": tags,
        "timezone": "browser",
        "editable": True,
        "graphTooltip": 1,
        "refresh": "1m",
        "schemaVersion": 39,
        "time": {"from": "now-6h", "to": "now"},
        "fiscalYearStartMonth": 0,
        "liveNow": False,
        "links": [],
        "annotations": {"list": [
            {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True,
             "hide": True, "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"},
            {"datasource": DS, "enable": False, "hide": False, "iconColor": "orange", "name": "calipers restarts",
             "expr": f'changes(calipers_start_time_seconds{{{S}}}[2m]) > 0', "step": "1m",
             "titleFormat": "calipers restarted", "textFormat": "{{host}}"},
        ]},
        "templating": {"list": [
            {"type": "datasource", "name": "datasource", "label": "Data source", "query": "prometheus",
             "current": {}, "hide": 0, "refresh": 1, "regex": "", "options": []},
            var_query("job", "Job", 'label_values(calipers_build_info, job)', all_value=None),
            var_query("realm", "Realm", 'label_values(calipers_build_info{job=~"$job"}, realm)'),
            var_query("host", "Host", 'label_values(calipers_build_info{job=~"$job", realm=~"$realm"}, host)'),
            *variables,
        ]},
        "panels": out,
    }
    json.dump(d, sys.stdout, indent=2)
    sys.stdout.write("\n")
