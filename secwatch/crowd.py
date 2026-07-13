"""Crowd-sourced threat-intel client (opt-in).

Shares confirmed bans (attacker IP + rule + timestamp ONLY) with a self-hostable
aggregator, and pulls its consensus community blocklist to pre-emptively block
IPs many installs have flagged. Nothing about your traffic, hosts, or data ever
leaves. Everything here is a no-op unless `crowd.enabled` is set.
"""
import collections
import json
import logging
import time
import urllib.request
import uuid

from . import config

log = logging.getLogger("secwatch.crowd")

_outbox = collections.deque(maxlen=2000)
_reporter = None


def reporter_id():
    """A stable, opaque per-install id (not tied to any host identity)."""
    global _reporter
    if _reporter:
        return _reporter
    path = config.BASE_DIR / "data" / "reporter_id"
    try:
        if path.exists():
            _reporter = path.read_text().strip()
        else:
            _reporter = uuid.uuid4().hex
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_reporter)
    except OSError:
        _reporter = uuid.uuid4().hex
    return _reporter


def report(ip, rule):
    """Queue a ban to share upstream (attacker IP + rule only). Sync-safe."""
    if config.CROWD_ENABLED and config.CROWD_SHARE and config.CROWD_URL:
        _outbox.append({"reporter": reporter_id(), "ip": ip, "rule": rule,
                        "ts": time.time()})


def _req(path, data=None):
    url = config.CROWD_URL.rstrip("/") + path
    headers = {"Content-Type": "application/json",
               "X-Secwatch-Token": config.CROWD_TOKEN}
    req = urllib.request.Request(
        url, data=json.dumps(data).encode() if data is not None else None,
        headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def ship_outbox():
    """POST any queued reports (called from a worker thread)."""
    sent = 0
    while _outbox:
        item = _outbox.popleft()
        try:
            _req("/report", item)
            sent += 1
        except Exception as exc:
            log.debug("report failed, dropping: %s", exc)
    return sent


def fetch_blocklist():
    """Return list of {ip, reporters, last} from the aggregator, or []."""
    try:
        return _req("/blocklist").get("ips", [])
    except Exception as exc:
        log.warning("blocklist fetch failed: %s", exc)
        return []
