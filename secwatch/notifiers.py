"""Alert delivery to one or more targets. Discord keeps its rich embed; ntfy,
Gotify, Telegram, and a generic webhook get a plain title+body. Targets come from
`alerting.targets` (a list); a bare Discord webhook stays supported as an implicit
target. stdlib only; every send is best-effort and never raises into the pipeline.
"""
import json
import logging
import urllib.request

from . import alert, config

log = logging.getLogger("secwatch.notify")

# severity -> (ntfy 1-5, gotify 0-10)
_PRIO = {"high": (5, 8), "medium": (4, 6), "low": (3, 4), "info": (2, 2)}


def _post(url, data, headers=None, timeout=10):
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": "secwatch/0.1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return 200 <= r.status < 300


def _plain(event):
    title = alert.RULE_TITLE.get(event["rule"], event["rule"])
    head = f"[{event['severity'].upper()}] {title} — {event['ip']}"
    body = event.get("detail", "") or ""
    extra = []
    if event.get("host"):
        extra.append(f"host: {event['host']}")
    if event.get("path"):
        extra.append(f"path: {event['path'][:200]}")
    if event.get("count"):
        extra.append(f"count: {event['count']}")
    if extra:
        body = (body + "\n" + " · ".join(extra)).strip()
    return head, body


def _targets():
    targets = list(config.ALERT_TARGETS or [])
    # back-compat: a bare Discord webhook (url/file/env) is an implicit target
    if config.discord_webhook_url() and not any(t.get("type") == "discord" for t in targets):
        targets.append({"type": "discord"})
    return targets


def _discord_text(t, title, body):
    url = t.get("url") or config.discord_webhook_url()
    if not url:
        return False
    return _post(url, json.dumps({"username": "secwatch", "content": f"**{title}**\n{body}"}).encode(),
                 {"Content-Type": "application/json"})


def _send_one(t, event, title, body, severity="info"):
    typ = t.get("type")
    if typ == "discord":
        return alert.send_discord(event) if event is not None else _discord_text(t, title, body)
    if typ == "ntfy":
        url = t["url"].rstrip("/")
        if t.get("topic"):
            url = f"{url}/{t['topic']}"
        h = {"Title": title, "Priority": str(_PRIO.get(severity, (3, 4))[0]), "Tags": "shield"}
        if t.get("token"):
            h["Authorization"] = f"Bearer {t['token']}"
        return _post(url, body.encode(), h)
    if typ == "gotify":
        url = f"{t['url'].rstrip('/')}/message?token={t['token']}"
        return _post(url, json.dumps({"title": title, "message": body,
                                      "priority": _PRIO.get(severity, (3, 4))[1]}).encode(),
                     {"Content-Type": "application/json"})
    if typ == "telegram":
        url = f"https://api.telegram.org/bot{t['bot_token']}/sendMessage"
        return _post(url, json.dumps({"chat_id": t["chat_id"], "text": f"{title}\n{body}"}).encode(),
                     {"Content-Type": "application/json"})
    if typ == "webhook":
        payload = event if event is not None else {"title": title, "body": body}
        return _post(t["url"], json.dumps(payload).encode(), {"Content-Type": "application/json"})
    log.warning("unknown notifier type: %r", typ)
    return False


def dispatch(event):
    """Deliver an event to every configured target. Returns the count delivered."""
    title, body = _plain(event)
    sent = 0
    for t in _targets():
        try:
            if _send_one(t, event, title, body, event.get("severity", "info")):
                sent += 1
        except Exception as exc:   # a target failing must never kill the pipeline
            log.error("notify %s failed: %s", t.get("type"), exc)
    if not sent:
        log.warning("alert %s delivered to 0 targets (none configured / all failed)",
                    event.get("rule"))
    return sent


def dispatch_analysis(out):
    """Deliver an LLM analysis summary: Discord gets the card, others a text line."""
    title = f"[{out['threat_level'].upper()}] Traffic analysis"
    body = out.get("headline", "")
    sent = 0
    for t in _targets():
        try:
            if t.get("type") == "discord":
                sent += 1 if alert.send_analysis_alert(out) else 0
            else:
                sent += 1 if _send_one(t, None, title, body, out.get("threat_level", "info")) else 0
        except Exception as exc:
            log.error("notify analysis %s failed: %s", t.get("type"), exc)
    return sent


def test_target(t):
    """Send a test message to one target (for the 'send test' button). (ok, message)."""
    try:
        ok = _send_one(t, None, "secwatch test alert",
                       "If you can read this, secwatch alerts are wired up correctly.", "low")
        return ok, ("delivered" if ok else "target returned non-2xx or is misconfigured")
    except Exception as exc:
        return False, str(exc)[:200]
