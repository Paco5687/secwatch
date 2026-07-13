"""FastAPI app: JSON API + single-page dashboard, plus the background pipeline."""
import asyncio
import contextlib
import json
import logging
import os
import time

import ipaddress

from fastapi import Body, FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import (alert, auth, auditwatch, authwatch, ban, config, cvewatch, db,
               detect, dockerwatch, fimwatch, healthwatch, hostwatch,
               llm_analysis, parser, procwatch, tailer)

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


async def tail_task(engine):
    conn = engine.conn
    state = db.meta_get(conn, "tail")
    initial = None
    if state and ":" in state:
        ino, off = state.split(":")
        initial = (int(ino), int(off))
    async for line, ino, off in tailer.follow(config.ACCESS_LOG, initial):
        if line:
            rec = parser.parse_line(line)
            if rec:
                engine.feed(rec)
        engine.tail_state = (ino, off)
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

    def _watch(task: asyncio.Task):
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            log.error("background task %r died: %r", task.get_name(), exc,
                      exc_info=exc)

    # Core always runs edge detection + web/CVE/LLM/alerting + ban. Host-level
    # collectors run here only in "all" mode; in "core" mode they come from a
    # separate agent via /api/ingest (so the core can be an isolated container).
    tasks = [
        asyncio.create_task(tail_task(engine), name="tail"),
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
    yield
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
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


@app.get("/api/events")
def events(hours: int = Query(24, ge=1, le=336),
           severity: str = Query("", pattern="^(|info|low|medium|high)$"),
           limit: int = Query(200, ge=1, le=1000)):
    conn = db.connect(readonly=True)
    try:
        q = "SELECT * FROM events WHERE ts >= ?"
        params = [time.time() - hours * 3600]
        if severity:
            q += " AND severity = ?"
            params.append(severity)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return {"events": [dict(r) for r in conn.execute(q, params)]}
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


@app.get("/api/health")
def api_health():
    return healthwatch.STATE


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return DASHBOARD_HTML


@app.get("/app.js")
def dashboard_js():
    mut = ({config.PROXY_MUTATION_HEADER: "1"}
           if config.PROXY_MUTATION_HEADER else {})
    js = DASHBOARD_JS.replace("__MUT__", json.dumps(mut))
    return Response(js, media_type="text/javascript")


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secwatch</title>
<style>
:root {
  --surface: #fcfcfb; --plane: #f9f9f7;
  --ink: #0b0b0b; --ink2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --baseline: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --series: #2a78d6;
  --crit: #d03b3b; --serious: #ec835a; --warn: #fab219; --good: #0ca30c;
}
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1a1a19; --plane: #0d0d0d;
    --ink: #ffffff; --ink2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --baseline: #383835; --ring: rgba(255,255,255,0.10);
    --series: #3987e5;
  }
}
* { box-sizing: border-box; margin: 0; }
body {
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
  background: var(--plane); color: var(--ink); padding: 20px;
}
h1 { font-size: 17px; font-weight: 650; }
h1 span { color: var(--muted); font-weight: 400; }
header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
header .spacer { flex: 1; }
select {
  font: inherit; color: var(--ink); background: var(--surface);
  border: 1px solid var(--ring); border-radius: 8px; padding: 5px 8px;
}
.card {
  background: var(--surface); border: 1px solid var(--ring);
  border-radius: 12px; padding: 14px 16px;
}
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 12px; }
.tile .v { font-size: 26px; font-weight: 650; margin-top: 2px; }
.tile .l { color: var(--ink2); font-size: 12px; }
.tile .s { color: var(--muted); font-size: 12px; margin-top: 2px; }
.grid2 { display: grid; grid-template-columns: 2fr 1fr; gap: 12px; margin-bottom: 12px; }
@media (max-width: 900px) { .grid2 { grid-template-columns: 1fr; } }
.card h2 { font-size: 13px; font-weight: 600; color: var(--ink2); margin-bottom: 10px; }
svg text { font: 11px system-ui, sans-serif; fill: var(--muted); }
.bar { fill: var(--series); }
.bar:hover { opacity: 0.8; }
#tooltip {
  position: fixed; pointer-events: none; display: none; z-index: 10;
  background: var(--surface); border: 1px solid var(--ring); border-radius: 8px;
  padding: 6px 10px; font-size: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.18);
}
#tooltip .t { color: var(--muted); }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
     color: var(--muted); font-weight: 600; padding: 6px 8px; border-bottom: 1px solid var(--grid); }
td { padding: 6px 8px; border-bottom: 1px solid var(--grid); vertical-align: top; }
tr:last-child td { border-bottom: none; }
td.path { max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
          font-family: ui-monospace, monospace; font-size: 12px; color: var(--ink2); }
.chip { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 600; }
.chip i { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.sev-high i { background: var(--crit); } .sev-high { color: var(--crit); }
.sev-medium i { background: var(--serious); } .sev-medium { color: var(--serious); }
.sev-low i { background: var(--warn); } .sev-low { color: var(--warn); }
.sev-info i { background: var(--muted); } .sev-info { color: var(--muted); }
.list { display: flex; flex-direction: column; gap: 6px; }
.list .row { display: flex; justify-content: space-between; gap: 8px; font-size: 13px; }
.list .row b { font-weight: 600; font-family: ui-monospace, monospace; font-size: 12px; }
.list .row .n { color: var(--ink2); font-variant-numeric: tabular-nums; }
.list .rules { color: var(--muted); font-size: 11px; }
.empty { color: var(--muted); font-size: 13px; padding: 12px 0; }
button {
  font: inherit; font-size: 12px; color: var(--ink2); background: none;
  border: 1px solid var(--ring); border-radius: 6px; padding: 2px 8px; cursor: pointer;
}
button:hover { color: var(--crit); border-color: var(--crit); }
.banform { display: flex; gap: 6px; margin-top: 8px; }
.banform input {
  flex: 1; min-width: 0; font: inherit; font-size: 12px; color: var(--ink);
  background: var(--plane); border: 1px solid var(--ring); border-radius: 6px; padding: 4px 8px;
}
.analysis-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
.threat { display: inline-flex; align-items: center; gap: 6px; font-weight: 650; font-size: 13px;
          padding: 3px 10px; border-radius: 999px; border: 1px solid var(--ring); }
.threat i { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.threat-low i { background: var(--good); } .threat-low { color: var(--good); }
.threat-guarded i { background: var(--warn); } .threat-guarded { color: var(--warn); }
.threat-elevated i { background: var(--serious); } .threat-elevated { color: var(--serious); }
.threat-high i, .threat-critical i { background: var(--crit); }
.threat-high, .threat-critical { color: var(--crit); }
.analysis-head .when { color: var(--muted); font-size: 12px; }
.analysis-head button:hover { color: var(--series); border-color: var(--series); }
.headline { font-size: 15px; font-weight: 600; margin: 4px 0 6px; }
.summary { color: var(--ink2); margin-bottom: 12px; }
.finding { border-left: 3px solid var(--muted); padding: 2px 0 2px 10px; margin-bottom: 9px; }
.finding.sev-high { border-color: var(--crit); } .finding.sev-medium { border-color: var(--serious); }
.finding.sev-low { border-color: var(--warn); } .finding.sev-info { border-color: var(--muted); }
.finding .ft { font-weight: 600; }
.finding .fe { color: var(--muted); font-size: 12px; font-family: ui-monospace, monospace; }
.finding .fa { color: var(--ink2); font-size: 13px; }
.recs { list-style: none; padding: 0; }
.recs li { padding: 5px 0; border-bottom: 1px solid var(--grid); display: flex; gap: 8px; }
.recs li:last-child { border: none; }
.pri { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em;
       padding: 1px 6px; border-radius: 5px; height: fit-content; white-space: nowrap; }
.pri-now { background: var(--crit); color: #fff; } .pri-soon { background: var(--serious); color: #fff; }
.pri-consider { background: var(--grid); color: var(--ink2); }
.subhead { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase;
           letter-spacing: .04em; margin: 12px 0 6px; }
.ai-note { color: var(--muted); font-size: 11px; margin-top: 10px; }
footer { color: var(--muted); font-size: 12px; margin-top: 14px; }
</style>
</head>
<body>
<header>
  <h1>secwatch <span>· edge security monitor</span></h1>
  <div class="spacer"></div>
  <select id="hours">
    <option value="6">Last 6 hours</option>
    <option value="24" selected>Last 24 hours</option>
    <option value="72">Last 3 days</option>
    <option value="168">Last 7 days</option>
  </select>
  <select id="sevFilter">
    <option value="">All severities</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <form method="post" action="auth/logout" id="logoutForm" style="display:none;margin:0">
    <button type="submit" title="Sign out">Sign out</button>
  </form>
</header>

<div class="tiles">
  <div class="card tile"><div class="l">Requests</div><div class="v" id="tReq">–</div><div class="s" id="tErr"></div></div>
  <div class="card tile"><div class="l">Unique IPs</div><div class="v" id="tIps">–</div><div class="s">&nbsp;</div></div>
  <div class="card tile"><div class="l">Security events</div><div class="v" id="tEv">–</div><div class="s" id="tEvS"></div></div>
  <div class="card tile"><div class="l">High severity</div><div class="v" id="tHigh">–</div><div class="s" id="tHighS"></div></div>
</div>

<div class="card" id="cveCard" style="margin-bottom:12px">
  <div class="analysis-head">
    <span class="threat threat-low" id="cveBadge"><i></i>—</span>
    <h2 style="margin:0">Vulnerabilities (running images)</h2>
    <span class="when" id="cveWhen"></span>
  </div>
  <div id="cveBody"><div class="empty">No scan yet.</div></div>
</div>

<div class="card" id="analysisCard" style="margin-bottom:12px">
  <div class="analysis-head">
    <span class="threat threat-guarded" id="threat"><i></i>—</span>
    <h2 style="margin:0">AI traffic analysis</h2>
    <span class="when" id="analysisWhen"></span>
    <div class="spacer" style="flex:1"></div>
    <button id="analyzeBtn">Analyze now</button>
  </div>
  <div id="analysisBody"><div class="empty">No analysis yet — click “Analyze now”.</div></div>
</div>

<div class="grid2">
  <div class="card">
    <h2 id="chartTitle">Requests</h2>
    <svg id="chart" width="100%" height="180" role="img" aria-label="Requests over time"></svg>
  </div>
  <div class="card">
    <h2>Top offenders</h2>
    <div class="list" id="offenders"><div class="empty">No events yet.</div></div>
    <h2 style="margin-top:14px">Top talkers</h2>
    <div class="list" id="talkers"><div class="empty">–</div></div>
    <h2 style="margin-top:14px">Active bans <span id="autobanState" style="font-weight:400"></span></h2>
    <div class="list" id="bans"><div class="empty">–</div></div>
    <div class="banform">
      <input id="banIp" placeholder="IP to ban" spellcheck="false">
      <button id="banBtn">Ban 24h</button>
    </div>
  </div>
</div>

<div class="card">
  <h2>Events</h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>IP</th><th>Host</th><th>Path</th><th>Detail</th><th>N</th></tr></thead>
    <tbody id="eventRows"><tr><td colspan="8" class="empty">Loading…</td></tr></tbody>
  </table>
  </div>
</div>

<div id="tooltip"></div>
<footer id="foot"></footer>

<script src="app.js" defer></script>
</body>
</html>
"""

# Served as a separate file: a strict-CSP proxy (script-src 'self')
# forbids inline scripts, so the dashboard must not rely on any.
DASHBOARD_JS = """
const MUT = __MUT__;   // optional header added to mutating requests (proxy CSRF)
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const fmtN = n => n >= 1e6 ? (n/1e6).toFixed(1)+"M" : n >= 1e4 ? Math.round(n/1e3)+"k" : n >= 1000 ? (n/1e3).toFixed(1)+"k" : String(n);
const fmtT = ts => new Date(ts*1000).toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"});

function chip(sev) { return `<span class="chip sev-${esc(sev)}"><i></i>${esc(sev)}</span>`; }

function drawChart(series, hours) {
  const svg = $("chart"), W = svg.clientWidth || 700, H = 180;
  const padL = 36, padR = 6, padT = 8, padB = 20;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  if (!series.length) { svg.innerHTML = `<text x="${W/2}" y="${H/2}" text-anchor="middle">no traffic data yet</text>`; return; }
  const max = Math.max(...series.map(d => d.r), 1);
  const iw = W - padL - padR, ih = H - padT - padB;
  const n = series.length, bw = Math.max(2, iw/n - 2);
  let g = "";
  const ticks = 3;
  for (let i = 1; i <= ticks; i++) {
    const v = max * i / ticks, y = padT + ih - ih * i / ticks;
    g += `<line x1="${padL}" y1="${y}" x2="${W-padR}" y2="${y}" stroke="var(--grid)" stroke-width="1"/>`;
    g += `<text x="${padL-6}" y="${y+4}" text-anchor="end">${fmtN(Math.round(v))}</text>`;
  }
  const t0 = series[0].t, t1 = series[n-1].t, span = Math.max(t1 - t0, 1);
  series.forEach(d => {
    const x = padL + (n === 1 ? 0 : (d.t - t0) / span * (iw - bw));
    const h = Math.max(d.r > 0 ? 2 : 0, d.r / max * ih);
    g += `<rect class="bar" x="${x}" y="${padT+ih-h}" width="${bw}" height="${h}" rx="2"
           data-t="${d.t}" data-r="${d.r}" data-e="${d.e}"/>`;
  });
  g += `<line x1="${padL}" y1="${padT+ih}" x2="${W-padR}" y2="${padT+ih}" stroke="var(--baseline)" stroke-width="1"/>`;
  const labelEvery = Math.ceil(n / 6);
  series.forEach((d, i) => {
    if (i % labelEvery) return;
    const x = padL + (n === 1 ? 0 : (d.t - t0) / span * (iw - bw));
    const opts = hours > 48 ? {month:"short", day:"numeric"} : {hour:"2-digit", minute:"2-digit"};
    g += `<text x="${x}" y="${H-4}">${new Date(d.t*1000).toLocaleString([], opts)}</text>`;
  });
  svg.innerHTML = g;
  const tip = $("tooltip");
  svg.querySelectorAll(".bar").forEach(b => {
    b.addEventListener("mousemove", e => {
      tip.style.display = "block";
      tip.style.left = Math.min(e.clientX + 12, window.innerWidth - 180) + "px";
      tip.style.top = (e.clientY - 40) + "px";
      tip.innerHTML = `<div class="t">${fmtT(+b.dataset.t)}</div>` +
        `<b>${(+b.dataset.r).toLocaleString()}</b> requests` +
        (+b.dataset.e ? ` · ${(+b.dataset.e).toLocaleString()} errors` : "");
    });
    b.addEventListener("mouseleave", () => tip.style.display = "none");
  });
}

async function refresh() {
  const hours = $("hours").value, sev = $("sevFilter").value;
  try {
    const [s, ev, bn] = await Promise.all([
      fetch(`api/summary?hours=${hours}`).then(r => r.json()),
      fetch(`api/events?hours=${hours}&severity=${sev}&limit=300`).then(r => r.json()),
      fetch(`api/bans`).then(r => r.json()),
    ]);
    $("autobanState").textContent = bn.autoban ? "· auto-ban on" : "· auto-ban OFF";
    $("bans").innerHTML = bn.bans.length ? bn.bans.map(b =>
      `<div class="row"><span><b>${esc(b.ip)}</b> <span class="rules">${esc(b.rule)}` +
      ` · until ${fmtT(b.expires)}</span></span>` +
      `<button data-unban="${esc(b.ip)}">unban</button></div>`).join("")
      : `<div class="empty">None.</div>`;
    if (s.auth) $("logoutForm").style.display = "block";
    $("tReq").textContent = s.requests.toLocaleString();
    $("tErr").textContent = `${s.errors4xx.toLocaleString()} × 4xx · ${s.errors5xx.toLocaleString()} × 5xx`;
    $("tIps").textContent = s.unique_ips.toLocaleString();
    const sv = s.severities, tot = Object.values(sv).reduce((a,b) => a+b, 0);
    $("tEv").textContent = tot.toLocaleString();
    $("tEvS").textContent = ["medium","low","info"].filter(k => sv[k]).map(k => `${sv[k]} ${k}`).join(" · ") || " ";
    $("tHigh").textContent = (sv.high || 0).toLocaleString();
    $("tHigh").style.color = sv.high ? "var(--crit)" : "";
    $("tHighS").textContent = sv.high ? "needs review" : "all clear";
    $("chartTitle").textContent = `Requests · ${s.bucket_minutes}-min buckets`;
    drawChart(s.series, +hours);

    $("offenders").innerHTML = s.offenders.length ? s.offenders.map(o =>
      `<div class="row"><span><b>${esc(o.ip)}</b> <span class="rules">${esc(o.rules)}</span></span>` +
      `<span class="n">${o.events} ev</span></div>`).join("")
      : `<div class="empty">No events in window.</div>`;
    $("talkers").innerHTML = s.top_ips.length ? s.top_ips.map(t =>
      `<div class="row"><b>${esc(t.ip)}</b><span class="n">${fmtN(t.requests)} req` +
      (t.s4xx ? ` · ${fmtN(t.s4xx)} 4xx` : "") + `</span></div>`).join("")
      : `<div class="empty">–</div>`;

    $("eventRows").innerHTML = ev.events.length ? ev.events.map(e =>
      `<tr><td style="white-space:nowrap">${fmtT(e.ts)}</td><td>${chip(e.severity)}</td>` +
      `<td>${esc(e.rule)}</td><td style="font-family:ui-monospace,monospace;font-size:12px">${esc(e.ip)}</td>` +
      `<td>${esc(e.host)}</td><td class="path" title="${esc(e.path)}">${esc(e.path)}</td>` +
      `<td>${esc(e.detail)}${e.alerted ? " 🔔" : ""}</td><td>${e.count}</td></tr>`).join("")
      : `<tr><td colspan="8" class="empty">No events — quiet out there.</td></tr>`;
    $("foot").textContent = `Updated ${new Date().toLocaleTimeString()} · refreshes every 30s`;
  } catch (err) {
    $("foot").textContent = `Refresh failed: ${err}`;
  }
}
$("bans").addEventListener("click", async (e) => {
  const ip = e.target.dataset && e.target.dataset.unban;
  if (!ip) return;
  await fetch("api/unban", {method: "POST",
    headers: {"Content-Type": "application/json", ...MUT},
    body: JSON.stringify({ip})});
  refresh();
});
$("banBtn").addEventListener("click", async () => {
  const ip = $("banIp").value.trim();
  if (!ip) return;
  const res = await fetch("api/ban", {method: "POST",
    headers: {"Content-Type": "application/json", ...MUT},
    body: JSON.stringify({ip})}).then(r => r.json());
  if (!res.ok) alert(res.message);
  $("banIp").value = "";
  refresh();
});
const THREAT_LABEL = {low:"Low", guarded:"Guarded", elevated:"Elevated", high:"High", critical:"Critical"};
function renderAnalysis(a) {
  if (a && a.enabled === false) {   // LLM analysis is optional / disabled
    const c = $("analysisCard"); if (c) c.style.display = "none";
    return;
  }
  const badge = $("threat");
  const lvl = a.threat_level || "guarded";
  badge.className = "threat threat-" + lvl;
  badge.innerHTML = `<i></i>${THREAT_LABEL[lvl] || lvl}`;
  $("analysisWhen").textContent = a.running ? "analyzing…"
    : a.ts ? "as of " + fmtT(a.ts) : "";
  $("analyzeBtn").disabled = !!a.running;
  $("analyzeBtn").textContent = a.running ? "Analyzing…" : "Analyze now";
  if (!a.result) {
    $("analysisBody").innerHTML = a.last_error
      ? `<div class="empty">Last run failed: ${esc(a.last_error)}</div>`
      : `<div class="empty">No analysis yet — click “Analyze now”.</div>`;
    return;
  }
  const r = a.result, m = r._meta || {};
  const findings = (r.findings || []).map(f =>
    `<div class="finding sev-${esc(f.severity || "info")}">
       <div class="ft">${esc(f.title || "")}</div>
       <div class="fa">${esc(f.assessment || "")}</div>
       <div class="fe">${esc(f.evidence || "")}</div>
     </div>`).join("");
  const recs = (r.hardening_recommendations || []).map(x =>
    `<li><span class="pri pri-${esc(x.priority || "consider")}">${esc(x.priority || "")}</span>
       <span><b>${esc(x.action || "")}</b>${x.rationale ? " — " + esc(x.rationale) : ""}</span></li>`).join("");
  const watch = (r.watch_items || []).map(w => `<li>${esc(w)}</li>`).join("");
  $("analysisBody").innerHTML =
    `<div class="headline">${esc(r.headline || a.headline || "")}</div>` +
    `<div class="summary">${esc(r.traffic_summary || "")}</div>` +
    (findings ? `<div class="subhead">Findings</div>${findings}` : "") +
    (recs ? `<div class="subhead">Hardening recommendations</div><ul class="recs">${recs}</ul>` : "") +
    (watch ? `<div class="subhead">Watch items</div><ul class="recs">${watch.replace(/<li>/g,'<li><span></span>')}</ul>` : "") +
    `<div class="ai-note">Model: ${esc(m.model || "local")} · ${m.requests_analyzed || "?"} requests analyzed · `
      + `${m.window_hours || "?"}h window. LLM-generated; verify before acting.</div>`;
}

async function loadVulns() {
  try {
    const v = await fetch("api/vulnerabilities").then(r => r.json());
    const badge = $("cveBadge");
    badge.className = "threat " + (v.kev ? "threat-high" : "threat-low");
    badge.innerHTML = `<i></i>${v.kev ? v.kev + " actively exploited" : "none exploited"}`;
    if (!v.total) { $("cveBody").innerHTML = `<div class="empty">No findings (or scan pending).</div>`; return; }
    const byImg = {};
    for (const r of v.vulnerabilities) {
      byImg[r.image] = byImg[r.image] || {n: 0, crit: 0, kev: 0};
      byImg[r.image].n++; if (r.severity === "CRITICAL") byImg[r.image].crit++; if (r.in_kev) byImg[r.image].kev++;
    }
    const kevRows = v.vulnerabilities.filter(r => r.in_kev).slice(0, 8).map(r =>
      `<div class="finding sev-high"><div class="ft">${esc(r.cve)} — ${esc(r.image)}</div>
       <div class="fa">${esc(r.pkg)} ${esc(r.installed)} · ${r.fixed ? "fix: " + esc(r.fixed) : "no fix yet"}</div></div>`).join("");
    const imgRows = Object.entries(byImg).sort((a, b) => b[1].kev - a[1].kev || b[1].crit - a[1].crit)
      .map(([img, s]) => `<div class="row"><span><b style="font-weight:600">${esc(img)}</b></span>
        <span class="n">${s.n} findings${s.crit ? " · " + s.crit + " critical" : ""}${s.kev ? " · <b style='color:var(--crit)'>" + s.kev + " KEV</b>" : ""}</span></div>`).join("");
    $("cveBody").innerHTML =
      `<div class="summary">${v.total} high/critical findings across running images · ` +
      `<b>${v.kev}</b> on the CISA KEV list (actively exploited in the wild).</div>` +
      (kevRows ? `<div class="subhead">Actively exploited — patch first</div>${kevRows}` : "") +
      `<div class="subhead">By image</div><div class="list">${imgRows}</div>` +
      `<div class="ai-note">Trivy scan cross-referenced with CISA KEV. KEV findings alert; the rest are informational.</div>`;
  } catch (e) { /* leave prior */ }
}

async function loadAnalysis() {
  try {
    const a = await fetch("api/analysis/latest").then(r => r.json());
    renderAnalysis(a);
    return a;
  } catch (e) { /* leave prior state */ return null; }
}

let analysisPoll = null;
$("analyzeBtn").addEventListener("click", async () => {
  $("analyzeBtn").disabled = true;
  $("analyzeBtn").textContent = "Analyzing…";
  await fetch("api/analysis/run", {method: "POST",
    headers: {...MUT}});
  const started = Date.now();
  if (analysisPoll) clearInterval(analysisPoll);
  analysisPoll = setInterval(async () => {
    const a = await loadAnalysis();
    // stop when the worker clears, or after 4 min as a safety valve
    if ((a && !a.running) || Date.now() - started > 240000) {
      clearInterval(analysisPoll); analysisPoll = null;
    }
  }, 4000);
});

$("hours").addEventListener("change", refresh);
$("sevFilter").addEventListener("change", refresh);
refresh();
loadAnalysis();
loadVulns();
setInterval(refresh, 30000);
setInterval(loadAnalysis, 60000);
setInterval(loadVulns, 300000);
window.addEventListener("resize", () => refresh());
"""
