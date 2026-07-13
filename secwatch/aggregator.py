"""secwatch community aggregator — a small, self-hostable service that collects
opt-in ban reports from secwatch installs and publishes a *consensus* community
blocklist (an IP that many independent installs flagged).

Threat model (v1, trusted-group): access is gated by a shared token you
distribute to the installs you trust. Consensus (an IP must be reported by N
distinct reporters) blunts single-reporter poisoning; per-reporter and global
rate limits blunt flooding; only public IPs are accepted. Stronger Sybil
resistance (per-reporter identity/vouching) is future work — run this among
installs you trust.

Run:  SECWATCH_AGG_TOKEN=<shared-secret> python -m secwatch.aggregator
Privacy: it only ever stores attacker IP + rule + timestamp + an opaque reporter
id. No victim traffic, hostnames, or PII is transmitted or stored.
"""
import ipaddress
import logging
import sqlite3
import time

import uvicorn
from fastapi import Body, FastAPI, Request, Response

from . import config

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("secwatch.aggregator")

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports(
  reporter TEXT NOT NULL,
  ip TEXT NOT NULL,
  rule TEXT,
  ts REAL NOT NULL,
  PRIMARY KEY (reporter, ip)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_reports_ip ON reports(ip);
CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(ts);
"""

app = FastAPI(title="secwatch-aggregator")
_rate = {}   # reporter -> [window_start, count]


def _db():
    conn = sqlite3.connect(config.AGG_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def _authed(request):
    return (config.AGG_TOKEN
            and request.headers.get("x-secwatch-token", "") == config.AGG_TOKEN)


def _public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved
                    or a.is_link_local or a.is_multicast)
    except ValueError:
        return False


@app.post("/report")
def report(request: Request, payload: dict = Body(...)):
    if not _authed(request):
        return Response('{"detail":"forbidden"}', 403, media_type="application/json")
    reporter = str(payload.get("reporter", ""))[:64]
    ip = str(payload.get("ip", ""))
    if not reporter or not _public_ip(ip):
        return Response('{"detail":"bad report"}', 400, media_type="application/json")
    now = time.time()
    win = _rate.setdefault(reporter, [now, 0])
    if now - win[0] > 60:
        win[0], win[1] = now, 0
    win[1] += 1
    if win[1] > config.AGG_MAX_REPORTS_PER_MIN:
        return Response('{"detail":"rate limited"}', 429, media_type="application/json")
    conn = _db()
    try:
        conn.execute(
            "INSERT INTO reports(reporter,ip,rule,ts) VALUES(?,?,?,?) "
            "ON CONFLICT(reporter,ip) DO UPDATE SET ts=excluded.ts, rule=excluded.rule",
            (reporter, ip, str(payload.get("rule", ""))[:40], now))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.get("/blocklist")
def blocklist(request: Request):
    if not _authed(request):
        return Response('{"detail":"forbidden"}', 403, media_type="application/json")
    since = time.time() - config.AGG_WINDOW_DAYS * 86400
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT ip, COUNT(DISTINCT reporter) n, MAX(ts) last FROM reports "
            "WHERE ts >= ? GROUP BY ip HAVING n >= ? ORDER BY n DESC",
            (since, config.AGG_CONSENSUS)).fetchall()
    finally:
        conn.close()
    return {"generated": time.time(), "consensus": config.AGG_CONSENSUS,
            "count": len(rows),
            "ips": [{"ip": r["ip"], "reporters": r["n"], "last": r["last"]}
                    for r in rows]}


@app.get("/healthz")
def healthz():
    return {"ok": True}


def main():
    if not config.AGG_TOKEN:
        log.error("SECWATCH_AGG_TOKEN is required to run the aggregator")
        raise SystemExit(1)
    log.info("secwatch aggregator on :%d (consensus=%d over %dd)",
             config.AGG_PORT, config.AGG_CONSENSUS, config.AGG_WINDOW_DAYS)
    uvicorn.run(app, host="0.0.0.0", port=config.AGG_PORT, log_level="warning")


if __name__ == "__main__":
    main()
