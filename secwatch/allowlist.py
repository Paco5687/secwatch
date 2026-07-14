"""Runtime never-ban allowlist — IPs/CIDRs the operator has explicitly protected
(e.g. after an over-eager ban). Separate from network.trusted_nets (YAML, structural
trust): this is a lightweight, dashboard-editable list persisted next to the DB.
Checked in ban.add so an allowlisted address is never (re-)banned by any source.
"""
import ipaddress
import json
import logging
import os

from . import config

log = logging.getLogger("secwatch.allowlist")


def _path():
    return config.ALLOWLIST_FILE


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


def _norm(entry):
    """Normalize to a canonical IP or CIDR string, or None if unparseable."""
    entry = (entry or "").strip()
    try:
        if "/" in entry:
            return str(ipaddress.ip_network(entry, strict=False))
        return str(ipaddress.ip_address(entry))
    except ValueError:
        return None


def add(entry):
    e = _norm(entry)
    if not e:
        return False, "not a valid IP or CIDR"
    entries = load()
    if e in entries:
        return True, "already allowlisted"
    entries.append(e)
    _save(entries)
    log.info("allowlisted %s (never-ban)", e)
    return True, "added"


def remove(entry):
    e = _norm(entry) or (entry or "").strip()
    entries = [x for x in load() if x != e]
    _save(entries)
    return True


def matches(ip):
    """True if ip is covered by any allowlist entry (exact IP or containing CIDR)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for e in load():
        try:
            if "/" in e:
                if addr in ipaddress.ip_network(e, strict=False):
                    return True
            elif str(addr) == e:
                return True
        except ValueError:
            continue
    return False
