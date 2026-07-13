"""Discord webhook alerting (stdlib only, called via asyncio.to_thread)."""
import json
import logging
import time
import urllib.request

from . import config

log = logging.getLogger("secwatch.alert")

SEVERITY_COLOR = {
    "high": 0xD03B3B,      # critical red
    "medium": 0xEC835A,    # serious orange
    "low": 0xFAB219,       # warning amber
    "info": 0x898781,
}

RULE_TITLE = {
    "probe": "Vulnerability probe",
    "scan": "Path scanning",
    "flood": "Request flood",
    "scripted": "Scripted client",
    "crawler": "Aggressive crawler",
    "cred_stuff": "Possible credential stuffing",
    "secret_probe": "Secret/credential-file probe",
    "login_bruteforce": "App login brute force",
    "privileged_access": "Unauthorized privileged-endpoint access",
    "data_api_scraping": "Data API scraping",
    "portfolio_enumeration": "Portfolio ID enumeration (IDOR)",
    "edge_silent": "Edge proxy silent — monitoring blind spot",
    "edge_recovered": "Edge proxy logging resumed",
    "host_traefikcfg": "Traefik route config changed",
    "host_systemd": "systemd unit added/changed (persistence?)",
    "host_suid": "SUID/SGID binary set changed",
    "host_ldpreload": "ld.so.preload changed (rootkit hook)",
    "host_boothook": "boot/login hook changed",
    "host_shellrc": "shell rc file changed",
    "host_uid0": "New root-equivalent (UID 0) account",
    "webshell_dropped": "Webshell / script dropped in web dir",
    "ransomware_canary": "Canary file tampered (ransomware?)",
    "reverse_shell": "Reverse/interactive shell detected",
    "crypto_miner": "Crypto-miner process detected",
    "dropper": "Download-and-execute dropper detected",
    "exec_suspicious": "Process running from temp dir",
    "exec_deleted": "Process running a deleted binary",
    "egress_new": "New outbound connection (egress)",
    "cve_kev": "Actively-exploited CVE (CISA KEV) on a running image",
    "cve_new": "New high/critical CVE on a running image",
    "dashboard_bruteforce": "secwatch dashboard login brute force",
    "health_degraded": "secwatch self-check degraded",
    "health_recovered": "secwatch self-check recovered",
    "ssh_brute": "SSH brute force",
    "ssh_login": "SSH login from new IP",
    "new_user": "System user created",
    "priv_group": "Privileged group change",
    "host_authkeys": "authorized_keys modified",
    "host_users": "Login accounts changed",
    "host_ports": "Listening ports changed",
    "host_cron": "Cron configuration changed",
    "docker_new": "New docker container",
    "docker_image": "Container image changed",
    "docker_restart_loop": "Container restart loop",
    "unit_failed": "Systemd unit failed",
}


THREAT_COLOR = {
    "critical": 0xD03B3B, "high": 0xD03B3B, "elevated": 0xEC835A,
    "guarded": 0xFAB219, "low": 0x0CA30C,
}


def send_analysis_alert(out: dict) -> bool:
    """Post an LLM analysis summary to Discord (used when threat is elevated+)."""
    url = config.discord_webhook_url()
    if not url:
        return False
    result = out.get("result", {})
    recs = result.get("hardening_recommendations", [])[:3]
    rec_txt = "\n".join(f"• [{r.get('priority','')}] {r.get('action','')}" for r in recs)
    payload = {
        "username": "secwatch",
        "embeds": [{
            "title": f"[{out['threat_level'].upper()}] Traffic analysis",
            "description": out.get("headline", "")[:300],
            "color": THREAT_COLOR.get(out["threat_level"], 0x898781),
            "fields": (
                [{"name": "Summary", "value": result.get("traffic_summary", "—")[:900]}]
                + ([{"name": "Top recommendations", "value": rec_txt[:900]}] if rec_txt else [])
            ),
            "footer": {"text": f"model analysis · {config.DASHBOARD_URL}"},
        }],
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "secwatch/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        log.error("analysis alert failed: %s", exc)
        return False


def send_discord(event: dict) -> bool:
    url = config.discord_webhook_url()
    if not url:
        log.warning("no Discord webhook configured; dropping alert %s", event["rule"])
        return False
    title = RULE_TITLE.get(event["rule"], event["rule"])
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(event["ts"]))
    payload = {
        "username": "secwatch",
        "embeds": [{
            "title": f"[{event['severity'].upper()}] {title} — {event['ip']}",
            "description": event["detail"],
            "color": SEVERITY_COLOR.get(event["severity"], 0x898781),
            "fields": [
                {"name": "Host", "value": event["host"] or "—", "inline": True},
                {"name": "Count", "value": str(event["count"]), "inline": True},
                {"name": "Path", "value": f"`{event['path'][:200] or '—'}`"},
                {"name": "User-Agent", "value": event["ua"][:200] or "—"},
            ],
            "footer": {"text": f"{ts} · {config.DASHBOARD_URL}"},
        }],
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "secwatch/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:  # network errors must never kill the pipeline
        log.error("Discord alert failed: %s", exc)
        return False
