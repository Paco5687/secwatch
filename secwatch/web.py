"""FastAPI app: JSON API + single-page dashboard, plus the background pipeline."""
import asyncio
import contextlib
import json
import logging
import os
import socket
import time
from pathlib import Path

import ipaddress

from fastapi import Body, FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import (__version__, alert, auth, auditwatch, authwatch, ban, config,
               cvewatch, db, detect, dockerwatch, fimwatch, healthwatch,
               hostwatch, llm_analysis, logsources, parser, procwatch, tailer)

log = logging.getLogger("secwatch.web")

alert_queue: asyncio.Queue = asyncio.Queue(maxsize=200)

# LLM analysis single-flight state
analysis_state = {"running": False, "last_error": None, "last_run": 0.0}


def _blocking_analysis():
    conn = db.connect()  # own connection, lives entirely on the worker thread
    try:
        return llm_analysis.run_analysis(conn)
    finally:
        conn.close()


async def run_analysis_bg(reason="manual"):
    """Kick off one analysis in the background if none is running. Returns
    immediately — the ops proxy has a 15s timeout, analyses take longer."""
    if analysis_state["running"] or not config.LLM_ANALYSIS:
        return {"started": False, "running": analysis_state["running"]}
    analysis_state["running"] = True

    async def worker():
        try:
            out = await asyncio.to_thread(_blocking_analysis)
            analysis_state["last_error"] = None
            analysis_state["last_run"] = out["ts"]
            log.info("analysis (%s): threat=%s", reason, out["threat_level"])
            if (config.THREAT_RANK.get(out["threat_level"], 1)
                    >= config.THREAT_RANK.get(config.LLM_ALERT_THREAT, 2)):
                await asyncio.to_thread(alert.send_analysis_alert, out)
        except Exception as exc:  # endpoint down/busy, bad response, etc.
            analysis_state["last_error"] = str(exc)[:300]
            log.error("analysis (%s) failed: %s", reason, exc)
        finally:
            analysis_state["running"] = False

    asyncio.create_task(worker())
    return {"started": True, "running": True}


def _blocking_cve_scan():
    conn = db.connect()
    try:
        engine = detect.Engine(conn, _queue_alert)  # emit-only, no ban
        return cvewatch.run_scan(conn, engine=engine)
    finally:
        conn.close()


async def cve_task():
    if not config.CVE_SCAN:
        return
    await asyncio.sleep(120)  # let the box settle after boot before a heavy scan
    while True:
        try:
            summary = await asyncio.to_thread(_blocking_cve_scan)
            if summary.get("kev"):
                log.warning("CVE scan: %d KEV-listed (actively exploited) findings",
                            summary["kev"])
        except Exception as exc:
            log.error("cve scan failed: %s", exc)
        await asyncio.sleep(config.CVE_SCAN_INTERVAL)


async def analysis_task():
    if not config.LLM_ANALYSIS:
        return
    await asyncio.sleep(90)  # let some traffic accumulate after boot
    while True:
        await run_analysis_bg("scheduled")
        await asyncio.sleep(config.LLM_ANALYSIS_INTERVAL)


# A path that no real backend has, but a catch-all SPA will 200 with its shell.
_CATCHALL_PROBE = "/secwatch-catchall-probe-3f9c2a-not-a-real-path"


async def _host_is_catchall(host):
    """True if `host` returns 2xx for a guaranteed-nonexistent path (SPA shell),
    False if it 404s like a real backend, None if the check couldn't run."""
    proc = await asyncio.create_subprocess_exec(
        "curl", "-sk", "--max-time", "6", "--resolve", f"{host}:443:127.0.0.1",
        f"https://{host}{_CATCHALL_PROBE}", "-o", "/dev/null", "-w", "%{http_code}",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    out, _ = await proc.communicate()
    try:
        code = int(out.decode().strip())
    except ValueError:
        return None
    return 200 <= code < 300


async def crowd_task():
    """Ship queued ban reports upstream and pull + apply the community blocklist
    (opt-in; a no-op unless crowd.enabled)."""
    if not config.CROWD_ENABLED or not config.CROWD_URL:
        return
    from . import crowd
    log.info("crowd intel on: %s (share=%s consume=%s)",
             config.CROWD_URL, config.CROWD_SHARE, config.CROWD_CONSUME)
    last_pull = 0.0
    while True:
        await asyncio.sleep(30)
        try:
            if config.CROWD_SHARE:
                await asyncio.to_thread(crowd.ship_outbox)
            if config.CROWD_CONSUME and time.time() - last_pull >= config.CROWD_PULL_INTERVAL:
                last_pull = time.time()
                ips = await asyncio.to_thread(crowd.fetch_blocklist)
                if ips:
                    conn = db.connect()
                    try:
                        applied = 0
                        for entry in ips:
                            ok, _ = ban.add(conn, entry["ip"], rule="community",
                                            reason=f"community blocklist "
                                                   f"({entry.get('reporters', '?')} reporters)",
                                            ttl_hours=config.CROWD_BAN_TTL_HOURS,
                                            banned_by="community")
                            applied += 1 if ok else 0
                        log.info("crowd: applied %d/%d community IPs", applied, len(ips))
                    finally:
                        conn.close()
        except Exception as exc:
            log.error("crowd task: %s", exc)


async def edge_silence_task(engine):
    """Alert if the Traefik access log stops advancing — proxy down, or an
    attacker who owns Traefik disabled logging to blind the monitor."""
    engine.last_log_line_ts = engine.last_log_line_ts or time.time()
    alerted = False
    while True:
        await asyncio.sleep(60)
        silent = time.time() - engine.last_log_line_ts
        if silent >= config.LOG_SILENCE_ALERT_SECS:
            if not alerted:
                engine.emit(
                    "", "edge_silent", "high",
                    f"Traefik access log silent for {int(silent // 60)} min — the "
                    f"edge proxy is down or access logging was disabled (secwatch is "
                    f"blind while this persists). Verify Traefik and its accesslog.",
                    host="traefik")
                alerted = True
        elif alerted:
            engine.emit("", "edge_recovered", "info",
                        "Traefik access log resumed after a silence.", host="traefik")
            alerted = False


async def catchall_task(engine):
    """Classify hosts that served a 200 to a probe path, so probe 'hits' on
    SPA catch-all hosts are downgraded from high (alert+ban) to low (noise)."""
    while True:
        await asyncio.sleep(15)
        for host in list(engine.catchall_pending):
            engine.catchall_pending.discard(host)
            if not host:
                continue
            verdict = await _host_is_catchall(host)
            if verdict is not None:
                engine.catchall[host] = verdict
                log.info("catch-all classification: %s -> %s", host,
                         "SPA (probe-200s = noise)" if verdict else "real backend")


async def tail_task(engine, source):
    """Tail one log source (path + format) into the shared engine."""
    conn = engine.conn
    key = source["path"]
    parse = parser.parser_for(source["type"], source.get("regex", ""))
    st = engine.source_status.setdefault(key, {"records": 0, "last_ts": 0.0})
    # resume: per-source key, falling back to the legacy 'tail' key for the primary
    state = db.meta_get(conn, f"tail:{key}")
    if not state and source.get("primary"):
        state = db.meta_get(conn, "tail")
    initial = None
    if state and ":" in state:
        ino, off = state.split(":")
        initial = (int(ino), int(off))
    async for line, ino, off in tailer.follow(source["path"], initial):
        if line:
            rec = parse(line)
            if rec:
                engine.feed(rec)
                st["records"] += 1
                st["last_ts"] = time.time()
        engine.tail_states[key] = (ino, off)
        engine.maybe_flush()


def _queue_alert(event):
    try:
        alert_queue.put_nowait(event)
    except asyncio.QueueFull:
        log.warning("alert queue full, dropping alert for %s", event["ip"])


async def alert_task():
    while True:
        event = await alert_queue.get()
        await asyncio.to_thread(alert.send_discord, event)


async def maintenance_task():
    while True:
        await asyncio.sleep(300)
        await tailer.rotate_if_needed()
        conn = db.connect()
        try:
            now = time.time()
            ban.expire_and_sync(conn)
            conn.execute("DELETE FROM events WHERE ts < ?",
                         (now - config.EVENT_RETENTION_DAYS * 86400,))
            conn.execute("DELETE FROM ip_minute WHERE minute < ?",
                         (int(now // 60) - config.IP_MINUTE_RETENTION_HOURS * 60,))
            conn.execute("DELETE FROM traffic WHERE minute < ?",
                         (int(now // 60) - config.EVENT_RETENTION_DAYS * 1440,))
            conn.commit()
        finally:
            conn.close()


def _watch(task: asyncio.Task):
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        log.error("background task %r died: %r", task.get_name(), exc, exc_info=exc)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    conn = db.connect()  # shared writer connection, single event loop
    if os.environ.get("SECWATCH_TRACE_SQL"):
        _trace = open("/tmp/secwatch-sql-trace.log", "a", buffering=1)
        conn.set_trace_callback(
            lambda sql: _trace.write(f"{time.time():.3f} {sql[:120]}\n"))
    ban.expire_and_sync(conn)  # make traefik ban file match the DB at boot

    def _ban_cb(ip, rule, detail):
        ban.add(conn, ip, rule=rule, reason=detail, banned_by="auto")

    engine = detect.Engine(conn, _queue_alert, ban_cb=_ban_cb)
    app.state.engine = engine   # for the login route to emit lockout events

    def _spawn_tail(source):
        task = asyncio.create_task(tail_task(engine, source),
                                   name=f"tail:{source['name']}")
        task.add_done_callback(_watch)
        return task

    manager = logsources.Manager(engine, _spawn_tail)
    app.state.logsources = manager

    # Core always runs edge detection + web/CVE/LLM/alerting + ban. Host-level
    # collectors run here only in "all" mode; in "core" mode they come from a
    # separate agent via /api/ingest (so the core can be an isolated container).
    tasks = [
        asyncio.create_task(alert_task(), name="alerts"),
        asyncio.create_task(maintenance_task(), name="maintenance"),
        asyncio.create_task(analysis_task(), name="analysis"),
        asyncio.create_task(cve_task(), name="cve"),
        asyncio.create_task(catchall_task(engine), name="catchall"),
        asyncio.create_task(edge_silence_task(engine), name="edge_silence"),
        asyncio.create_task(healthwatch.HealthWatcher(engine, conn).run(), name="health"),
        asyncio.create_task(crowd_task(), name="crowd"),
    ]
    if config.MODE == "all":
        tasks += [
            asyncio.create_task(authwatch.AuthWatcher(engine, conn).run(), name="auth"),
            asyncio.create_task(hostwatch.HostWatcher(engine, conn).run(), name="host"),
            asyncio.create_task(dockerwatch.DockerWatcher(engine, conn).run(), name="docker"),
            asyncio.create_task(fimwatch.FimWatcher(engine, conn).run(), name="fim"),
            asyncio.create_task(procwatch.ProcWatcher(engine, conn).run(), name="proc"),
            asyncio.create_task(auditwatch.AuditWatcher(engine, conn).run(), name="audit"),
        ]
    else:
        log.info("mode=%s — host collectors expected from a separate agent",
                 config.MODE)
    for t in tasks:
        t.add_done_callback(_watch)
    # one tail task per configured log source (proxy + internal apps + …),
    # tracked by the manager so the dashboard can add/remove sources live
    for src in config.LOG_SOURCES:
        manager.register(src["path"], _spawn_tail(src))
    log.info("tailing %d log source(s): %s", len(config.LOG_SOURCES),
             ", ".join(f"{s['name']}({s['type']})" for s in config.LOG_SOURCES))
    yield
    for t in tasks + list(manager.tasks.values()):
        t.cancel()
    await asyncio.gather(*tasks, *manager.tasks.values(), return_exceptions=True)
    conn.close()


app = FastAPI(title="secwatch", lifespan=lifespan)

# ---- standalone auth (only active when config.AUTH_ENABLED) --------------
_AUTH_OPEN_PATHS = {"/healthz", "/login", "/auth/login", "/auth/logout", "/favicon.ico"}
_login_fails = {}   # ip -> [fail_count, locked_until]


def _trust_nets():
    nets = []
    for c in config.AUTH_TRUST_PROXY_FROM:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return nets


_TRUST_NETS = _trust_nets()


def _source_trusted(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _TRUST_NETS)


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    if not config.AUTH_ENABLED:
        return await call_next(request)
    path = request.url.path
    if path in _AUTH_OPEN_PATHS:
        return await call_next(request)
    # a fronting proxy that already authenticated the user (e.g. localhost)
    if _source_trusted(request.client.host if request.client else ""):
        return await call_next(request)
    token = request.cookies.get(auth.COOKIE_NAME, "")
    if token and auth.verify_token(token):
        return await call_next(request)
    # unauthenticated: API → 401, browser → login page
    if path.startswith("/api/"):
        return Response('{"detail":"authentication required"}', status_code=401,
                        media_type="application/json")
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form():
    if not config.AUTH_ENABLED:
        return RedirectResponse("/", status_code=303)
    return auth.login_page()


@app.post("/auth/login")
def do_login(request: Request, username: str = Form(""), password: str = Form("")):
    ip = request.client.host if request.client else "?"
    now = time.time()
    fails = _login_fails.get(ip, [0, 0])
    if fails[1] > now:
        return HTMLResponse(auth.login_page("Too many attempts — locked out briefly."),
                            status_code=429)
    ok = (username == config.AUTH_USERNAME and config.AUTH_PASSWORD_HASH
          and auth.verify_password(password, config.AUTH_PASSWORD_HASH))
    if not ok:
        fails[0] += 1
        if fails[0] >= config.AUTH_MAX_FAILS:
            fails[1] = now + config.AUTH_LOCKOUT_SECS
            fails[0] = 0
            eng = getattr(app.state, "engine", None)
            if eng:
                eng.emit(ip, "dashboard_bruteforce", "high",
                         f"{config.AUTH_MAX_FAILS} failed secwatch dashboard logins "
                         f"— locked out {config.AUTH_LOCKOUT_SECS}s", host="secwatch")
        _login_fails[ip] = fails
        return HTMLResponse(auth.login_page("Invalid username or password."),
                            status_code=401)
    _login_fails.pop(ip, None)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(auth.COOKIE_NAME, auth.make_token(username), httponly=True,
                    samesite="lax", max_age=config.AUTH_SESSION_TTL,
                    secure=request.url.scheme == "https")
    return resp


@app.post("/auth/logout")
def do_logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


@app.get("/api/summary")
def summary(hours: int = Query(24, ge=1, le=336)):
    conn = db.connect(readonly=True)
    try:
        now = time.time()
        since_min = int(now // 60) - hours * 60
        since_ts = now - hours * 3600

        totals = conn.execute(
            "SELECT COALESCE(SUM(requests),0) r, COALESCE(SUM(s4xx),0) e4, "
            "COALESCE(SUM(s5xx),0) e5 FROM traffic WHERE minute >= ?",
            (since_min,),
        ).fetchone()
        uniq = conn.execute(
            "SELECT COUNT(DISTINCT ip) c FROM ip_minute WHERE minute >= ?",
            (since_min,),
        ).fetchone()["c"]
        sev = {r["severity"]: r["c"] for r in conn.execute(
            "SELECT severity, COUNT(*) c FROM events WHERE ts >= ? GROUP BY severity",
            (since_ts,),
        )}
        # bucket size scales with the window so the chart stays ~96 bars
        bucket = max(1, (hours * 60) // 96)
        series = [
            {"t": r["b"] * bucket * 60, "r": r["r"], "e": r["e"]}
            for r in conn.execute(
                "SELECT minute/? b, SUM(requests) r, SUM(s4xx)+SUM(s5xx) e "
                "FROM traffic WHERE minute >= ? GROUP BY b ORDER BY b",
                (bucket, since_min),
            )
        ]
        top_ips = [dict(r) for r in conn.execute(
            "SELECT ip, SUM(requests) requests, SUM(s4xx) s4xx FROM ip_minute "
            "WHERE minute >= ? GROUP BY ip ORDER BY requests DESC LIMIT 10",
            (since_min,),
        )]
        offenders = [dict(r) for r in conn.execute(
            "SELECT ip, COUNT(*) events, MAX(severity='high') has_high, "
            "GROUP_CONCAT(DISTINCT rule) rules FROM events "
            "WHERE ts >= ? AND severity != 'info' "
            "GROUP BY ip ORDER BY has_high DESC, events DESC LIMIT 10",
            (since_ts,),
        )]
        return {
            "hours": hours, "bucket_minutes": bucket, "requests": totals["r"],
            "errors4xx": totals["e4"], "errors5xx": totals["e5"],
            "unique_ips": uniq, "severities": sev, "series": series,
            "top_ips": top_ips, "offenders": offenders, "generated": now,
            "auth": config.AUTH_ENABLED,
        }
    finally:
        conn.close()


def _rule_category(rule):
    """Bucket a rule into a dashboard category: edge / host / files / cve / system.
    Unknown rules (custom endpoint_rules) are access-log based → edge."""
    r = rule or ""
    if r in ("webshell_dropped", "ransomware_canary") or r.startswith("fim"):
        return "files"
    if r.startswith("cve"):
        return "cve"
    if r.startswith("health"):
        return "system"
    if (r.startswith(("ssh", "host_", "docker_", "egress", "exec_", "proc",
                      "audit", "persist"))
            or r in ("sudo", "new_user", "priv_group", "unit_failed")):
        return "host"
    return "edge"


@app.get("/api/events")
def events(hours: int = Query(24, ge=1, le=336),
           severity: str = Query("", pattern="^(|info|low|medium|high)$"),
           ip: str = Query(""), rule: str = Query(""), q: str = Query(""),
           cat: str = Query(""), limit: int = Query(200, ge=1, le=1000)):
    conn = db.connect(readonly=True)
    try:
        sql = "SELECT * FROM events WHERE ts >= ?"
        params = [time.time() - hours * 3600]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if ip:
            sql += " AND ip = ?"
            params.append(ip)
        if rule:
            sql += " AND rule = ?"
            params.append(rule)
        if q:
            sql += " AND (path LIKE ? OR detail LIKE ? OR host LIKE ? OR rule LIKE ?)"
            params += [f"%{q}%"] * 4
        sql += " ORDER BY ts DESC LIMIT ?"
        # category is derived from rule names in python, so over-fetch then trim
        cats = {c.strip() for c in cat.split(",") if c.strip()}
        params.append(limit * 5 if cats else limit)
        rows = [dict(r) for r in conn.execute(sql, params)]
        if cats:
            rows = [r for r in rows if _rule_category(r["rule"]) in cats][:limit]
        return {"events": rows}
    finally:
        conn.close()


@app.get("/api/bans")
def list_bans():
    conn = db.connect(readonly=True)
    try:
        return {"bans": ban.active(conn), "autoban": config.AUTOBAN}
    finally:
        conn.close()


@app.post("/api/ban")
def ban_ip(payload: dict = Body(...)):
    ip = str(payload.get("ip", "")).strip()
    ttl = float(payload.get("ttl_hours") or config.BAN_TTL_HOURS)
    conn = db.connect()
    try:
        ok, msg = ban.add(conn, ip, rule="manual",
                          reason=str(payload.get("reason", ""))[:300],
                          ttl_hours=ttl, banned_by="manual")
        return {"ok": ok, "message": msg}
    finally:
        conn.close()


@app.post("/api/unban")
def unban_ip(payload: dict = Body(...)):
    ip = str(payload.get("ip", "")).strip()
    conn = db.connect()
    try:
        return {"ok": ban.remove(conn, ip)}
    finally:
        conn.close()


@app.get("/api/logsources")
def list_logsources():
    mgr = getattr(app.state, "logsources", None)
    if mgr is None:
        return {"sources": [], "types": sorted(logsources.VALID_TYPES)}
    return {"sources": mgr.status(), "types": sorted(logsources.VALID_TYPES)}


@app.post("/api/logsources")
async def add_logsource(payload: dict = Body(...)):
    # async so mgr.add() runs on the event loop (it spawns a tail task)
    mgr = getattr(app.state, "logsources", None)
    if mgr is None:
        return {"ok": False, "message": "not ready"}
    ok, msg = mgr.add(str(payload.get("name", "")), str(payload.get("path", "")),
                      str(payload.get("type", "traefik")),
                      str(payload.get("regex", "")))
    return {"ok": ok, "message": msg}


@app.post("/api/logsources/scan")
async def scan_logsources():
    """Auto-discover watchable access logs on the host (review queue)."""
    cands = await asyncio.to_thread(logsources.scan)
    return {"candidates": cands}


@app.post("/api/logsources/remove")
async def remove_logsource(payload: dict = Body(...)):
    mgr = getattr(app.state, "logsources", None)
    if mgr is None:
        return {"ok": False, "message": "not ready"}
    ok, msg = mgr.remove(str(payload.get("path", "")))
    return {"ok": ok, "message": msg}


@app.get("/api/vulnerabilities")
def vulnerabilities():
    conn = db.connect(readonly=True)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT cve,image,pkg,installed,fixed,severity,in_kev,title,last_seen "
            "FROM vulnerabilities ORDER BY in_kev DESC, "
            "CASE severity WHEN 'CRITICAL' THEN 0 ELSE 1 END, cve LIMIT 500")]
        kev = sum(1 for r in rows if r["in_kev"])
        return {"vulnerabilities": rows, "total": len(rows), "kev": kev}
    finally:
        conn.close()


@app.get("/api/analysis/latest")
def analysis_latest():
    conn = db.connect(readonly=True)
    try:
        row = conn.execute(
            "SELECT ts, hours, threat_level, headline, json FROM analyses "
            "ORDER BY ts DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    out = {
        "running": analysis_state["running"],
        "last_error": analysis_state["last_error"],
        "enabled": config.LLM_ANALYSIS,
    }
    if row:
        out.update({
            "ts": row["ts"], "hours": row["hours"],
            "threat_level": row["threat_level"], "headline": row["headline"],
            "result": json.loads(row["json"]),
        })
    return out


@app.post("/api/analysis/run")
async def analysis_run():
    return await run_analysis_bg("manual")


@app.post("/api/ingest")
async def ingest(request: Request, payload: dict = Body(...)):
    """Receive an event from a host agent (agent→core split). Token-gated."""
    if not config.INGEST_TOKEN:
        return Response('{"detail":"ingest disabled"}', status_code=403,
                        media_type="application/json")
    if request.headers.get("x-secwatch-token", "") != config.INGEST_TOKEN:
        return Response('{"detail":"forbidden"}', status_code=403,
                        media_type="application/json")
    eng = getattr(app.state, "engine", None)
    if eng is None:
        return Response('{"detail":"not ready"}', status_code=503,
                        media_type="application/json")
    rec = {"host": payload.get("host", ""), "path": payload.get("path", ""),
           "ua": payload.get("ua", "")}
    eng._event(payload.get("ts") or time.time(), payload.get("ip", "-"),
               payload["rule"], payload.get("severity", "info"), rec,
               payload.get("detail", ""), count=payload.get("count", 1))
    eng.maybe_flush(force=True)
    return {"ok": True}


# ---- Settings page (Common + safe scope) --------------------------------
# Schema drives the UI. type: bool|int|float|text|secret|list|select.
# live=True → hot-swapped on save; live=False → needs a restart to take effect.
# readonly=True → shown for reference but edited only in secwatch.yaml.
SETTINGS_SCHEMA = [
    {"title": "Detection & bans", "fields": [
        {"key": "ban.enabled", "label": "Auto-ban hostile IPs", "type": "bool", "live": True,
         "help": "Master switch for enforcing bans at the proxy/firewall."},
        {"key": "thresholds.secret_probe_ban", "label": "Instant-ban secret-file probes",
         "type": "bool", "live": True, "help": "Ban on first /.env, /.git, … probe."},
        {"key": "thresholds.rate_limit", "label": "Flood: requests/min per IP", "type": "int", "live": True},
        {"key": "thresholds.scan_4xx_limit", "label": "Scan: 4xx/min per IP", "type": "int", "live": True},
        {"key": "thresholds.bot_min_reqs", "label": "Bot volume: reqs in window", "type": "int", "live": True},
        {"key": "thresholds.stuff_limit", "label": "Credential-stuffing threshold", "type": "int", "live": True},
    ]},
    {"title": "Alerting", "fields": [
        {"key": "alerting.discord_webhook_url", "label": "Discord webhook URL", "type": "secret", "live": True,
         "help": "Where high-severity alerts are pushed. Stored encrypted."},
        {"key": "alerting.min_severity", "label": "Minimum severity to alert", "type": "select", "live": True,
         "options": ["info", "low", "medium", "high"]},
        {"key": "alerting.quiet_rules", "label": "Quiet rules (ban+log, no alert)", "type": "list", "live": True,
         "help": "Routine scanner noise. Comma-separated rule names."},
        {"key": "alerting.quiet_except_private", "label": "…but still alert from internal IPs",
         "type": "bool", "live": True},
    ]},
    {"title": "LLM analysis", "fields": [
        {"key": "llm.enabled", "label": "Enable scheduled LLM analysis", "type": "bool", "live": False,
         "help": "Turning the scheduled loop on/off needs a restart."},
        {"key": "llm.base_url", "label": "Endpoint base URL", "type": "text", "live": True,
         "help": "Any OpenAI-compatible /chat/completions endpoint."},
        {"key": "llm.model", "label": "Model", "type": "text", "live": True},
        {"key": "llm.api_key", "label": "API key (hosted providers)", "type": "secret", "live": True,
         "help": "Sent as Bearer token. Stored encrypted. Blank for local runners."},
        {"key": "llm.json_mode", "label": "Request JSON mode (response_format)", "type": "bool", "live": True,
         "help": "Turn off if your provider 400s on it."},
        {"key": "llm.temperature", "label": "Temperature", "type": "float", "live": True},
        {"key": "llm.max_tokens", "label": "Max tokens", "type": "int", "live": True},
        {"key": "llm.alert_threat", "label": "Alert at threat level ≥", "type": "select", "live": True,
         "options": ["low", "guarded", "elevated", "high", "critical"]},
    ]},
    {"title": "Vulnerability scanning", "fields": [
        {"key": "cve.enabled", "label": "Enable image CVE scanning", "type": "bool", "live": False,
         "help": "Needs Docker. Toggling the scan loop needs a restart."},
        {"key": "cve.severities", "label": "Severities to report", "type": "text", "live": True},
    ]},
    {"title": "Security-critical (edit in secwatch.yaml)", "readonly": True, "fields": [
        {"key": "network.trusted_nets", "label": "Trusted networks", "type": "list", "readonly": True},
        {"key": "ban.actuator", "label": "Ban actuator", "type": "text", "readonly": True},
        {"key": "auth.enabled", "label": "Dashboard login", "type": "bool", "readonly": True},
        {"key": "mode", "label": "Deployment mode", "type": "text", "readonly": True},
    ]},
]

# dotted key -> current live value (secrets excluded — never returned)
_SETTING_VALUE = {
    "ban.enabled": lambda: config.AUTOBAN,
    "thresholds.secret_probe_ban": lambda: config.SECRET_PROBE_BAN,
    "thresholds.rate_limit": lambda: config.RATE_LIMIT,
    "thresholds.scan_4xx_limit": lambda: config.SCAN_4XX_LIMIT,
    "thresholds.bot_min_reqs": lambda: config.BOT_MIN_REQS,
    "thresholds.stuff_limit": lambda: config.STUFF_LIMIT,
    "alerting.min_severity": lambda: config.ALERT_MIN_SEVERITY,
    "alerting.quiet_rules": lambda: sorted(config.ALERT_QUIET_RULES),
    "alerting.quiet_except_private": lambda: config.ALERT_QUIET_EXCEPT_PRIVATE,
    "llm.enabled": lambda: config.LLM_ANALYSIS,
    "llm.base_url": lambda: config.LLM_BASE_URL,
    "llm.model": lambda: config.LLM_MODEL,
    "llm.json_mode": lambda: config.LLM_JSON_MODE,
    "llm.temperature": lambda: config.LLM_TEMPERATURE,
    "llm.max_tokens": lambda: config.LLM_MAX_TOKENS,
    "llm.alert_threat": lambda: config.LLM_ALERT_THREAT,
    "cve.enabled": lambda: config.CVE_SCAN,
    "cve.severities": lambda: config.CVE_SEVERITIES,
    "network.trusted_nets": lambda: config.TRUSTED_NETS,
    "ban.actuator": lambda: config.BAN_ACTUATOR,
    "auth.enabled": lambda: config.AUTH_ENABLED,
    "mode": lambda: config.MODE,
}
_EDITABLE_FIELDS = {f["key"]: f for sec in SETTINGS_SCHEMA if not sec.get("readonly")
                    for f in sec["fields"] if not f.get("readonly")}


def _coerce_setting(field, value):
    """Validate + coerce an incoming value to the field's type. Raises ValueError."""
    t = field["type"]
    if t == "bool":
        return bool(value)
    if t == "int":
        return int(value)
    if t == "float":
        return float(value)
    if t == "select":
        v = str(value)
        if v not in field["options"]:
            raise ValueError(f"must be one of {field['options']}")
        return v
    if t == "list":
        if isinstance(value, list):
            return [str(x).strip() for x in value if str(x).strip()]
        return [x.strip() for x in str(value).split(",") if x.strip()]
    # text / secret
    return str(value)


@app.get("/api/settings")
def get_settings():
    from . import settings as st
    secret_set = st.secret_status()
    sections = []
    for sec in SETTINGS_SCHEMA:
        fields = []
        for f in sec["fields"]:
            item = {k: f[k] for k in ("key", "label", "type", "help", "options", "live")
                    if k in f}
            item["readonly"] = bool(sec.get("readonly") or f.get("readonly"))
            if f["type"] == "secret":
                item["is_set"] = secret_set.get(f["key"], False)   # value never sent
            else:
                getter = _SETTING_VALUE.get(f["key"])
                item["value"] = getter() if getter else None
            fields.append(item)
        sections.append({"title": sec["title"], "readonly": bool(sec.get("readonly")),
                         "fields": fields})
    return {"sections": sections, "crypto_available": st.crypto_available()}


@app.post("/api/settings")
def save_settings(payload: dict = Body(...)):
    from . import settings as st
    updates = payload.get("updates")
    if not isinstance(updates, dict) or not updates:
        return {"ok": False, "message": "no updates provided"}
    coerced = {}
    for key, raw in updates.items():
        field = _EDITABLE_FIELDS.get(key)
        if field is None:                       # not an editable key → reject
            return {"ok": False, "message": f"'{key}' is not an editable setting"}
        try:
            coerced[key] = _coerce_setting(field, raw)
        except (ValueError, TypeError) as exc:
            return {"ok": False, "message": f"{field['label']}: {exc}"}
    try:
        for key, val in coerced.items():
            st.set_value(key, val)
    except RuntimeError as exc:                  # e.g. crypto missing for a secret
        return {"ok": False, "message": str(exc)}
    config.reload_live()
    restart = sorted(k for k in coerced if k not in config.SETTING_LIVE_KEYS)
    return {"ok": True, "applied_live": [k for k in coerced if k in config.SETTING_LIVE_KEYS],
            "restart_required": restart,
            "message": ("Saved." if not restart else
                        "Saved — restart secwatch to apply: " + ", ".join(restart))}


@app.get("/api/uiconfig")
def uiconfig():
    """Boot config for the SPA (mutation header, features, version)."""
    return {
        "version": __version__,
        "mut_header": config.PROXY_MUTATION_HEADER,
        "auth": config.AUTH_ENABLED,
        "llm": config.LLM_ANALYSIS,
        "cve": config.CVE_SCAN,
        "crowd": config.CROWD_ENABLED,
        "audit": config.AUDIT_ENABLED,
        "mode": config.MODE,
        "ban_actuator": config.BAN_ACTUATOR,
        "autoban": config.AUTOBAN,
        "sources": len(config.LOG_SOURCES),
        "update_available": healthwatch.STATE.get("update_available", False),
    }


@app.get("/api/overview")
def overview(hours: int = Query(24, ge=1, le=336)):
    """Category roll-up + threat level for the Overview status board."""
    conn = db.connect(readonly=True)
    try:
        now = time.time()
        since = now - hours * 3600
        cats = {k: {"count": 0, "high": 0, "medium": 0, "low": 0, "top": ""}
                for k in ("edge", "host", "files", "cve", "system")}
        top_rule = {}
        for r in conn.execute(
                "SELECT rule, severity, COUNT(*) c FROM events "
                "WHERE ts >= ? AND severity != 'info' GROUP BY rule, severity",
                (since,)):
            c = cats[_rule_category(r["rule"])]
            c["count"] += r["c"]
            c[r["severity"]] = c.get(r["severity"], 0) + r["c"]
            key = _rule_category(r["rule"])
            top_rule.setdefault(key, {})
            top_rule[key][r["rule"]] = top_rule[key].get(r["rule"], 0) + r["c"]
        for k, rules in top_rule.items():
            cats[k]["top"] = max(rules, key=rules.get)
        bans_n = conn.execute("SELECT COUNT(*) c FROM bans WHERE expires > ?",
                              (now,)).fetchone()["c"]
        kev = conn.execute(
            "SELECT COUNT(*) c FROM vulnerabilities WHERE in_kev = 1").fetchone()["c"]
        recent = [dict(r) for r in conn.execute(
            "SELECT ts, ip, rule, severity FROM events WHERE ts >= ? AND "
            "severity != 'info' ORDER BY ts DESC LIMIT 8", (since,))]
        # threat level: recent LLM verdict if available, else derived from events
        threat = {"level": "low", "headline": "", "source": "derived"}
        row = conn.execute("SELECT ts, threat_level, headline FROM analyses "
                           "ORDER BY ts DESC LIMIT 1").fetchone()
        if row and now - row["ts"] < 24 * 3600:
            threat = {"level": row["threat_level"], "headline": row["headline"],
                      "source": "analysis", "ts": row["ts"]}
        else:
            highs = sum(c["high"] for c in cats.values())
            meds = sum(c["medium"] for c in cats.values())
            if highs:
                threat = {"level": "elevated", "source": "derived",
                          "headline": f"{highs} high-severity event"
                                      f"{'s' if highs > 1 else ''} in the last "
                                      f"{hours}h — review Events."}
            elif meds:
                threat = {"level": "guarded", "source": "derived",
                          "headline": f"{meds} medium-severity event"
                                      f"{'s' if meds > 1 else ''} in the last "
                                      f"{hours}h; nothing high."}
            else:
                threat["headline"] = "No notable security events in the window."
        return {"hours": hours, "categories": cats, "threat": threat,
                "bans": bans_n, "kev": kev,
                "health_ok": healthwatch.STATE.get("status") in ("ok", "starting"),
                "recent": recent}
    finally:
        conn.close()


@app.get("/api/ipinfo")
async def ipinfo(ip: str = Query(..., min_length=3, max_length=64)):
    """Everything we know about one IP — the drill-down dossier."""
    def _lookup():
        conn = db.connect(readonly=True)
        try:
            now = time.time()
            since_min = int(now // 60) - 24 * 60
            mins = conn.execute(
                "SELECT minute, requests, s4xx FROM ip_minute "
                "WHERE ip = ? AND minute >= ? ORDER BY minute",
                (ip, since_min)).fetchall()
            # 15-minute buckets for the sparkline
            buckets = {}
            req = err = 0
            for m in mins:
                b = m["minute"] // 15
                cur = buckets.setdefault(b, [0, 0])
                cur[0] += m["requests"]; cur[1] += m["s4xx"]
                req += m["requests"]; err += m["s4xx"]
            series = [{"t": b * 900, "r": v[0], "e": v[1]}
                      for b, v in sorted(buckets.items())]
            evs = [dict(r) for r in conn.execute(
                "SELECT ts, rule, severity, host, path, detail, count "
                "FROM events WHERE ip = ? ORDER BY ts DESC LIMIT 60", (ip,))]
            brow = conn.execute(
                "SELECT * FROM bans WHERE ip = ? AND expires > ?",
                (ip, now)).fetchone()
            last = max([m["minute"] * 60 for m in mins[-1:]] +
                       [e["ts"] for e in evs[:1]] + [0])
            return {"ip": ip, "hours": 24, "requests": req, "s4xx": err,
                    "series": series, "events": evs,
                    "ban": dict(brow) if brow else None,
                    "trusted": detect.is_trusted(ip), "last_seen": last}
        finally:
            conn.close()

    out = await asyncio.to_thread(_lookup)
    try:
        host, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip), timeout=1.5)
        out["rdns"] = host
    except (OSError, asyncio.TimeoutError):
        out["rdns"] = ""
    return out


@app.get("/api/health")
def api_health():
    return healthwatch.STATE


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---- static SPA (secwatch/static/) ---------------------------------------
_STATIC_DIR = Path(__file__).resolve().parent / "static"
# version-stamped at import so asset URLs (?v=) bust browser caches on upgrade
_INDEX_HTML = (_STATIC_DIR / "index.html").read_text().replace("__V__", __version__)


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(_INDEX_HTML, headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

