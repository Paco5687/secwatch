"""Alert mutes — targeted suppression of *alerting* for known false positives,
created from an event row in the dashboard. Unlike alerting.quiet_rules (which
silences a whole rule), a mute is scoped: by IP, by host, by a substring of the
detail (e.g. your own `curl | bash` installer URL), or the whole rule as a last
resort. Muted events are still recorded — they just don't fire a notification.

Persisted next to the DB; checked in detect.Engine._event.
"""
import json
import logging
import os
import time

from . import config

log = logging.getLogger("secwatch.mutes")

_FIELDS = ("ip", "host", "detail", "*")


def _path():
    return config.MUTES_FILE


def load():
    try:
        d = json.loads(_path().read_text())
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _save(entries):
    _path().parent.mkdir(parents=True, exist_ok=True)
    tmp = _path().with_suffix(".json.tmp")
    tmp.write_text(json.dumps(entries, indent=2))
    os.replace(tmp, _path())


def add(rule, field="*", value=""):
    rule = (rule or "").strip()
    if not rule:
        return False, "a rule is required"
    if field not in _FIELDS:
        return False, f"field must be one of {_FIELDS}"
    if field != "*" and not str(value).strip():
        return False, f"a {field} value is required"
    entry = {"rule": rule, "field": field, "value": str(value).strip(),
             "added": int(time.time())}
    entries = [e for e in load()
               if not (e["rule"] == entry["rule"] and e["field"] == entry["field"]
                       and e["value"] == entry["value"])]
    entries.append(entry)
    _save(entries)
    log.info("muted alerts: rule=%s %s=%r", rule, field, value)
    return True, "muted"


def remove(rule, field, value=""):
    entries = [e for e in load()
               if not (e["rule"] == rule and e["field"] == field
                       and e["value"] == str(value))]
    _save(entries)
    return True


def is_muted(rule, ip="", host="", detail=""):
    """True if an alert for this event should be suppressed."""
    for m in load():
        if m["rule"] not in (rule, "*"):
            continue
        f, v = m["field"], m.get("value", "")
        if f == "*":
            return True
        if f == "ip" and ip and ip == v:
            return True
        if f == "host" and host and host == v:
            return True
        if f == "detail" and v and v in (detail or ""):
            return True
    return False
