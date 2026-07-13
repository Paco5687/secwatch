"""Auto-ban: DB-tracked ban list; enforcement is delegated to the configured
actuator (see banactuators.py — traefik / nftables / nginx / none).

Fail-open by design: if secwatch dies, the last actuator state stays in place;
nothing else depends on secwatch being up.
"""
import ipaddress
import logging
import time

from . import banactuators, config, detect

log = logging.getLogger("secwatch.ban")

EXEMPT = [ipaddress.ip_network(n) for n in config.BAN_EXEMPT_NETS]


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _exempt(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in EXEMPT)


def add(conn, ip, rule="manual", reason="", ttl_hours=None, banned_by="auto"):
    """Ban an IP. Refuses trusted networks and invalid addresses."""
    if not _valid_ip(ip):
        return False, "not a valid IP address"
    if detect.is_trusted(ip):
        return False, f"{ip} is in a trusted network; refusing to ban"
    if _exempt(ip):
        return False, f"{ip} is a shared proxy edge (Cloudflare); refusing to ban"
    now = time.time()
    ttl = (ttl_hours if ttl_hours is not None else config.BAN_TTL_HOURS) * 3600
    conn.execute(
        "INSERT INTO bans(ip,rule,reason,created,expires,banned_by) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
        "expires=excluded.expires, rule=excluded.rule, reason=excluded.reason",
        (ip, rule, reason[:300], now, now + ttl, banned_by),
    )
    conn.commit()
    write_file(conn)
    log.info("banned %s (%s) for %.1fh", ip, rule, ttl / 3600)
    # share upstream (opt-in) — but never re-report community-sourced bans (loop)
    if banned_by != "community":
        from . import crowd
        crowd.report(ip, rule)
    return True, "banned"


def remove(conn, ip):
    cur = conn.execute("DELETE FROM bans WHERE ip=?", (ip,))
    conn.commit()
    if cur.rowcount:
        write_file(conn)
        log.info("unbanned %s", ip)
    return cur.rowcount > 0


def active(conn):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM bans WHERE expires > ? ORDER BY created DESC",
        (time.time(),),
    )]


def expire_and_sync(conn):
    """Drop expired bans and make the traefik file match the DB. Called at
    startup and periodically from the maintenance loop."""
    cur = conn.execute("DELETE FROM bans WHERE expires <= ?", (time.time(),))
    conn.commit()
    if cur.rowcount:
        log.info("expired %d ban(s)", cur.rowcount)
    write_file(conn)


def write_file(conn):
    """Reconcile the edge with the current ban list via the configured actuator
    (traefik / nftables / nginx / none). Name kept for callers."""
    ips = [b["ip"] for b in active(conn)]
    banactuators.sync(ips)
