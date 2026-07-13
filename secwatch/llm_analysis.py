"""LLM-driven traffic analysis.

Aggregates real recent traffic into a compact "evidence pack", enriches the top
source IPs with reverse-DNS, and asks a local (or remote) OpenAI-compatible LLM to characterize the traffic:
what it is, what's concerning, what to tighten.

Everything the model sees is derived data (counts, top-N, hostnames) — never a
credential or payload. The call is best-effort: if the endpoint is down or busy,
the analysis is skipped, never crashing the collectors.
"""
import ipaddress
import json
import logging
import re
import socket
import time
import urllib.request
from collections import Counter, defaultdict

from . import config, detect

log = logging.getLogger("secwatch.llm")

SYSTEM_PROMPT = (
    "You are a pragmatic edge-security analyst reviewing a small self-hosted "
    "server that runs several web apps behind a Traefik reverse proxy "
    "(various web apps). You are given AGGREGATED evidence "
    "about recent HTTP traffic and the events an automated monitor already "
    "flagged. Your job: explain what this traffic actually is, separate ordinary "
    "background noise from things that genuinely matter, and give specific, "
    "proportionate hardening advice. Be concrete and cite the IPs/paths/UAs in "
    "the evidence. Do not invent data you were not given. Do not overstate: the "
    "public internet constantly scans every server, so blanket 'you are under "
    "attack' language is unhelpful — distinguish targeted/effective activity "
    "from harmless noise. Traffic matching `known_legitimate_endpoints` is "
    "expected and pre-vetted — never flag it, recommend restricting it, or "
    "count it as suspicious. Do NOT recommend any mitigation already listed in "
    "`active_mitigations` — those defenses exist; suggest only NEW actions. "
    "Each item in `monitor_flagged_events` has `last_seen_minutes_ago` and a "
    "`status`: an event with status 'resolved/historical' or last seen many "
    "minutes/hours ago (especially a one-off) is PAST — describe it in the past "
    "tense as resolved, do NOT report it as active or happening now, and do not "
    "raise the threat level for it. "
    "Reply with ONLY a JSON object, no prose around it."
)

# Response contract the model must fill.
SCHEMA_HINT = {
    "threat_level": "one of: low | guarded | elevated | high | critical",
    "headline": "one sentence (<=140 chars) summarizing the window",
    "traffic_summary": "2-4 sentences: what the bulk of this traffic is",
    "findings": [
        {
            "severity": "info | low | medium | high",
            "title": "short",
            "evidence": "the specific IPs/paths/UAs/counts this is based on",
            "assessment": "why it does or does not matter",
        }
    ],
    "hardening_recommendations": [
        {
            "priority": "now | soon | consider",
            "action": "specific, actionable step",
            "rationale": "what it mitigates",
        }
    ],
    "watch_items": ["short strings — things to keep an eye on but not act on yet"],
}

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


# --------------------------------------------------------------------------
# evidence pack
# --------------------------------------------------------------------------

def _tail_lines(path, max_bytes):
    """Return decoded complete lines from the last max_bytes of a file."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            start = max(0, size - max_bytes)
            f.seek(start)
            data = f.read()
    except OSError:
        return []
    if start > 0:
        data = data.split(b"\n", 1)[-1]  # drop the partial first line
    return data.decode("utf-8", "replace").splitlines()


def _rdns(ip, cache):
    if ip in cache:
        return cache[ip]
    result = None
    try:
        if not detect.is_trusted(ip) and ipaddress.ip_address(ip).is_global:
            socket.setdefaulttimeout(config.LLM_RDNS_TIMEOUT)
            result = socket.gethostbyaddr(ip)[0]
    except (OSError, ValueError):
        result = None
    finally:
        socket.setdefaulttimeout(None)
    cache[ip] = result
    return result


def build_evidence(conn, hours=None, now=None):
    from . import parser  # local import: avoid cycle at module load

    hours = hours or config.LLM_ANALYSIS_HOURS
    now = now or time.time()
    lines = _tail_lines(config.ACCESS_LOG, config.LLM_EVIDENCE_TAIL_BYTES)

    total = 0
    status_mix = Counter()
    host_hits = Counter()
    path_hits = Counter()
    ua_hits = Counter()
    per_ip = defaultdict(lambda: {
        "n": 0, "4xx": 0, "5xx": 0,
        "paths": Counter(), "uas": Counter(), "hosts": Counter(), "methods": Counter(),
    })

    for ln in lines:
        rec = parser.parse_line(ln)
        if not rec:
            continue
        total += 1
        st = rec["status"]
        bucket = f"{st // 100}xx" if st else "0xx"
        status_mix[bucket] += 1
        host_hits[rec["host"]] += 1
        path_hits[rec["path"][:80]] += 1
        ua_hits[(rec["ua"] or "(none)")[:80]] += 1
        d = per_ip[rec["ip"]]
        d["n"] += 1
        if 400 <= st < 500:
            d["4xx"] += 1
        elif st >= 500:
            d["5xx"] += 1
        d["paths"][rec["path"][:80]] += 1
        d["uas"][(rec["ua"] or "(none)")[:70]] += 1
        d["hosts"][rec["host"]] += 1
        d["methods"][rec["method"]] += 1

    def _legit_note(host, paths):
        for e in config.KNOWN_LEGIT_ENDPOINTS:
            if host == e["host"] and any(p.startswith(e["path_prefix"]) for p in paths):
                return e["note"]
        return None

    rdns_cache = {}
    talkers = []
    for ip, d in sorted(per_ip.items(), key=lambda kv: kv[1]["n"], reverse=True)[
        : config.LLM_MAX_TALKERS
    ]:
        top_paths = [p for p, _ in d["paths"].most_common(6)]
        talker = {
            "ip": ip,
            "rdns": _rdns(ip, rdns_cache),
            "trusted": detect.is_trusted(ip),
            "requests": d["n"],
            "pct_4xx": round(100 * d["4xx"] / d["n"]) if d["n"] else 0,
            "methods": dict(d["methods"].most_common(4)),
            "top_hosts": [h for h, _ in d["hosts"].most_common(3)],
            "top_paths": top_paths,
            "user_agents": [u for u, _ in d["uas"].most_common(2)],
        }
        note = _legit_note(talker["top_hosts"][0] if talker["top_hosts"] else "", top_paths)
        if note:
            talker["known_legitimate"] = note
        talkers.append(talker)

    # what the monitor already decided, from the DB
    since = now - hours * 3600
    events_by_rule = [
        {"rule": r["rule"], "severity": r["severity"], "count": r["c"],
         "distinct_ips": r["ips"], "sample_detail": r["detail"],
         "last_seen_minutes_ago": round((now - r["last_ts"]) / 60),
         "spans_minutes": round((r["last_ts"] - r["first_ts"]) / 60),
         "status": ("ongoing" if now - r["last_ts"] < 900
                    else "not seen recently — likely resolved/historical")}
        for r in conn.execute(
            "SELECT rule, severity, COUNT(*) c, COUNT(DISTINCT ip) ips, "
            "MAX(detail) detail, MIN(ts) first_ts, MAX(ts) last_ts "
            "FROM events WHERE ts >= ? AND severity != 'info' "
            "GROUP BY rule, severity ORDER BY c DESC", (since,))
    ]
    active_bans = [
        {"ip": r["ip"], "rule": r["rule"]} for r in conn.execute(
            "SELECT ip, rule FROM bans WHERE expires > ? ORDER BY created DESC LIMIT 30",
            (now,))
    ]
    ssh_events = [
        dict(r) for r in conn.execute(
            "SELECT ip, rule, severity, detail FROM events WHERE ts >= ? "
            "AND host IN ('ssh','host') AND severity != 'info' "
            "ORDER BY ts DESC LIMIT 15", (since,))
    ]

    return {
        "window_hours": hours,
        "log_sample": {
            "requests_analyzed": total,
            "note": "aggregated from the most recent slice of the access log, "
                    "not necessarily the full window",
            "status_mix": dict(status_mix),
            "unique_source_ips": len(per_ip),
        },
        "top_talkers": talkers,
        "top_requested_paths": [
            {"path": p, "count": c} for p, c in path_hits.most_common(config.LLM_MAX_PATHS)
        ],
        "top_user_agents": [
            {"ua": u, "count": c} for u, c in ua_hits.most_common(config.LLM_MAX_UAS)
        ],
        "requests_per_vhost": dict(host_hits.most_common(15)),
        "known_legitimate_endpoints": config.KNOWN_LEGIT_ENDPOINTS,
        "active_mitigations": config.ACTIVE_MITIGATIONS,
        "monitor_flagged_events": events_by_rule,
        "active_bans": active_bans,
        "host_and_ssh_events": ssh_events,
        "response_schema": SCHEMA_HINT,
    }


# --------------------------------------------------------------------------
# LLM call
# --------------------------------------------------------------------------

def _call_llm(evidence):
    """Blocking HTTP call to the OpenAI-compatible endpoint. Runs in a worker thread."""
    body = json.dumps({
        "model": config.LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content":
                "Analyze this evidence and fill the response_schema exactly.\n\n"
                + json.dumps(evidence, ensure_ascii=False)},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
        "response_format": {"type": "json_object"},
    }).encode()
    headers = {"Content-Type": "application/json"}
    if config.LLM_API_KEY:
        headers["Authorization"] = "Bearer " + config.LLM_API_KEY
    req = urllib.request.Request(
        config.LLM_BASE_URL.rstrip("/") + "/chat/completions",
        data=body, headers=headers,
    )
    with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT) as resp:
        payload = json.load(resp)
    content = payload["choices"][0]["message"]["content"]
    usage = payload.get("usage", {})
    return content, usage


def _parse(content):
    try:
        return json.loads(content)
    except ValueError:
        m = _JSON_RE.search(content)
        if not m:
            raise
        return json.loads(m.group(0))


def run_analysis(conn, hours=None, now=None):
    """Build evidence, call the model, persist. Returns the stored row dict.

    Raises on hard failure (endpoint down, bad response) — caller decides how
    loud to be about it.
    """
    now = now or time.time()
    evidence = build_evidence(conn, hours=hours, now=now)
    content, usage = _call_llm(evidence)
    result = _parse(content)

    threat = str(result.get("threat_level", "")).lower().strip()
    if threat not in config.THREAT_RANK:
        threat = "guarded"
    headline = str(result.get("headline", ""))[:200]
    result["_meta"] = {
        "generated": now,
        "model": config.LLM_MODEL,
        "requests_analyzed": evidence["log_sample"]["requests_analyzed"],
        "window_hours": evidence["window_hours"],
        "tokens": usage,
    }
    conn.execute(
        "INSERT INTO analyses(ts,hours,ok,threat_level,headline,json) "
        "VALUES(?,?,1,?,?,?)",
        (now, evidence["window_hours"], threat, headline,
         json.dumps(result, ensure_ascii=False)),
    )
    conn.commit()
    log.info("analysis stored: threat=%s tokens=%s", threat, usage)
    return {"ts": now, "threat_level": threat, "headline": headline, "result": result}
