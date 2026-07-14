"""Prometheus /metrics — a text-format snapshot for scraping. No new dependency:
we render the exposition format by hand from the DB + runtime state. The endpoint
(web.py) is gated: loopback, a metrics token, or an already-open LAN dashboard —
never unauthenticated on a public interface.
"""
import time

from . import __version__, cluster, config


def _esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def _fmt(name, typ, help_, samples):
    out = [f"# HELP {name} {help_}", f"# TYPE {name} {typ}"]
    for labels, val in samples:
        lbl = ""
        if labels:
            lbl = "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items()) + "}"
        out.append(f"{name}{lbl} {val}")
    return out


def render(conn):
    """Return the Prometheus exposition text for this node."""
    now = time.time()
    node = getattr(config, "DEVICE", None) or config.CLUSTER_NAME
    lines = []
    lines += _fmt("secwatch_up", "gauge", "1 if the monitor is serving", [({}, 1)])
    lines += _fmt("secwatch_build_info", "gauge", "Build/version info (always 1)",
                  [({"version": __version__, "node": node}, 1)])

    # ---- events ----
    total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    lines += _fmt("secwatch_events_total", "counter", "Events recorded (all time)",
                  [({}, total)])
    rows = conn.execute("SELECT severity, COUNT(*) c FROM events WHERE ts>=? GROUP BY severity",
                        (now - 86400,)).fetchall()
    lines += _fmt("secwatch_events_recent", "gauge", "Events in the last 24h by severity",
                  [({"severity": r["severity"]}, r["c"]) for r in rows] or [({"severity": "none"}, 0)])
    hi = conn.execute("SELECT COUNT(*) c FROM events WHERE severity='high' AND ts>=?",
                      (now - 86400,)).fetchone()["c"]
    lines += _fmt("secwatch_high_events_24h", "gauge", "High-severity events in the last 24h",
                  [({}, hi)])
    last = conn.execute("SELECT MAX(ts) m FROM events").fetchone()["m"]
    lines += _fmt("secwatch_last_event_age_seconds", "gauge",
                  "Seconds since the most recent event (log-source liveness)",
                  [({}, round(now - last, 1) if last else -1)])

    # ---- bans ----
    active = conn.execute("SELECT COUNT(*) c FROM bans WHERE expires>?", (now,)).fetchone()["c"]
    lines += _fmt("secwatch_bans_active", "gauge", "Currently-active bans", [({}, active)])
    buckets = {}
    for r in conn.execute("SELECT banned_by FROM bans WHERE expires>?", (now,)).fetchall():
        bb = r["banned_by"] or "auto"
        kind = "cluster" if bb.startswith("cluster:") else ("community" if bb == "community" else "local")
        buckets[kind] = buckets.get(kind, 0) + 1
    lines += _fmt("secwatch_bans_by_source", "gauge", "Active bans by source",
                  [({"source": k}, v) for k, v in buckets.items()] or [({"source": "local"}, 0)])

    # ---- vulnerabilities ----
    vr = conn.execute("SELECT severity, in_kev, COUNT(*) c FROM vulnerabilities "
                      "GROUP BY severity, in_kev").fetchall()
    lines += _fmt("secwatch_vulnerabilities", "gauge",
                  "Known CVE findings by severity and KEV (actively-exploited) flag",
                  [({"severity": r["severity"] or "UNKNOWN",
                     "kev": "true" if r["in_kev"] else "false"}, r["c"]) for r in vr]
                  or [({"severity": "none", "kev": "false"}, 0)])

    # ---- cluster ----
    if config.CLUSTER_ENABLED:
        roles = {}
        for p in cluster.load_peers():
            role = p.get("role", "peer")
            roles[role] = roles.get(role, 0) + 1
        lines += _fmt("secwatch_cluster_peers", "gauge", "Known cluster peers by role",
                      [({"role": k}, v) for k, v in roles.items()] or [({"role": "none"}, 0)])

    return "\n".join(lines) + "\n"
