"""Self-maintenance: periodic health checks + update awareness.

Answers "is secwatch actually still working?" without you having to look — checks
the DB, feed freshness, disk, and the ban actuator, alerts on degradation, and
exposes the result at /api/health. Also checks (best-effort) whether a newer
secwatch version has been published and surfaces it — it never auto-updates its
own code (that stays a deliberate, manual step).
"""
import asyncio
import logging
import os
import re
import shutil
import time
import urllib.request

from . import __version__, config, db

log = logging.getLogger("secwatch.health")

# latest computed health, served by /api/health
STATE = {"status": "starting", "checks": {}, "version": __version__,
         "update_available": False, "latest_version": None, "checked": 0}

_UPDATE_CACHE = {"ts": 0.0, "latest": None}


def _check_feed_fresh(conn):
    row = conn.execute("SELECT MAX(minute)*60 m FROM traffic").fetchone()
    if not row or not row["m"]:
        return True, "no traffic yet"
    age = int(time.time() - row["m"])
    # only a problem if the edge should be busy; edge_silence owns the hard alert
    return True, f"last edge activity {age}s ago"


def _check_disk():
    try:
        u = shutil.disk_usage(str(config.BASE_DIR))
        free_pct = round(100 * u.free / u.total)
        ok = free_pct >= config.HEALTH_DISK_MIN_PCT
        return ok, f"{free_pct}% free"
    except OSError as exc:
        return True, f"unknown ({exc})"


def _check_kev():
    if not config.CVE_SCAN:
        return True, "cve scan disabled"
    try:
        age_h = (time.time() - config.KEV_CACHE.stat().st_mtime) / 3600
        return age_h < 72, f"KEV feed {age_h:.0f}h old"
    except OSError:
        return True, "KEV not fetched yet"


def _check_ban_actuator():
    if config.BAN_ACTUATOR != "traefik":
        return True, f"actuator={config.BAN_ACTUATOR}"
    parent = config.BANS_FILE.parent
    return os.access(parent, os.W_OK), f"bans dir writable: {os.access(parent, os.W_OK)}"


def _fetch_latest_version():
    now = time.time()
    if now - _UPDATE_CACHE["ts"] < 12 * 3600 and _UPDATE_CACHE["latest"]:
        return _UPDATE_CACHE["latest"]
    try:
        req = urllib.request.Request(config.UPDATE_VERSION_URL,
                                     headers={"User-Agent": "secwatch"})
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode()
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)', text)
        latest = m.group(1) if m else None
    except Exception as exc:
        log.debug("update check failed: %s", exc)
        latest = None
    _UPDATE_CACHE.update(ts=now, latest=latest)
    return latest


def _newer(latest, current):
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)]
    try:
        return parts(latest) > parts(current)
    except (ValueError, TypeError):
        return False


class HealthWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn
        self._degraded = False

    async def run(self):
        while True:
            try:
                await asyncio.to_thread(self.check)
            except Exception:
                log.exception("health check failed")
            await asyncio.sleep(config.HEALTH_INTERVAL)

    def check(self, now=None):
        now = now or time.time()
        checks = {}
        try:
            self.conn.execute("SELECT 1")
            checks["db"] = {"ok": True, "detail": "reachable"}
        except Exception as exc:
            checks["db"] = {"ok": False, "detail": str(exc)[:80]}
        for name, fn in (("disk", _check_disk), ("kev_feed", _check_kev),
                         ("ban_actuator", _check_ban_actuator)):
            ok, detail = fn()
            checks[name] = {"ok": ok, "detail": detail}
        ok, detail = _check_feed_fresh(self.conn)
        checks["edge_feed"] = {"ok": ok, "detail": detail}

        failing = [n for n, c in checks.items() if not c["ok"]]
        status = "ok" if not failing else "degraded"

        latest = _fetch_latest_version() if config.UPDATE_CHECK else None
        update = bool(latest and _newer(latest, __version__))

        STATE.update(status=status, checks=checks, version=__version__,
                     update_available=update, latest_version=latest, checked=now)

        if failing and not self._degraded:
            self._degraded = True
            self.engine.emit("", "health_degraded", "high",
                             "secwatch self-check degraded: "
                             + "; ".join(f"{n}: {checks[n]['detail']}" for n in failing),
                             host="secwatch", now=now)
        elif not failing and self._degraded:
            self._degraded = False
            self.engine.emit("", "health_recovered", "info",
                             "secwatch self-check back to healthy", host="secwatch", now=now)
        if update:
            log.info("secwatch update available: %s → %s", __version__, latest)
