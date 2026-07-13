"""File-integrity monitoring: webshell/dropped-script detection in web-served
dirs, plus ransomware/tamper canaries in valuable trees.

- Webshell: any file with a server-executable extension or the exec bit that
  appears in a static/upload dir is flagged (these dirs should hold only assets).
  A content-marker heuristic escalates obvious webshells.
- Canary: fixed files planted in key trees; any modification/deletion → critical
  (ransomware encrypting a tree, or an attacker tampering, hits these first).

State lives in the fim_baseline table (separate from host_baseline so hostwatch
doesn't try to diff it). First run populates silently.
"""
import asyncio
import glob
import hashlib
import logging
import os
import time
from pathlib import Path

from . import config

log = logging.getLogger("secwatch.fim")

CANARY_NAME = ".secwatch-canary-DO-NOT-DELETE.xlsx"
CANARY_BODY = (
    b"SECWATCH CANARY FILE - DO NOT DELETE OR MODIFY.\n"
    b"This file is monitored for tampering/ransomware. Changing it raises a "
    b"critical security alert. It is intentionally placed here by secwatch.\n"
)


def _sha(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return None


def _looks_like_webshell(path):
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        return False
    return any(m in head for m in config.FIM_WEBSHELL_MARKERS)


def _scan_suspicious(root):
    """Return {relpath: 'hash'|'exec'} for script/executable files under root."""
    found = {}
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            n += 1
            if n > config.FIM_MAX_SCAN_FILES:
                log.warning("FIM scan of %s hit %d-file cap", root,
                            config.FIM_MAX_SCAN_FILES)
                return found
            full = os.path.join(dirpath, fn)
            ext = os.path.splitext(fn)[1].lower()
            suspicious = ext in config.FIM_SCRIPT_EXTS
            if not suspicious:
                try:
                    if os.stat(full).st_mode & 0o111:  # any exec bit
                        suspicious = True
                except OSError:
                    continue
            if suspicious:
                found[os.path.relpath(full, root)] = _sha(full) or "unreadable"
    return found


class FimWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn

    async def run(self):
        # plant canaries once at startup, then loop
        try:
            self._plant_canaries()
        except Exception:
            log.exception("canary planting failed")
        while True:
            try:
                self.check()
            except Exception:
                log.exception("FIM scan failed")
            await asyncio.sleep(config.FIM_INTERVAL)

    # ---- canaries --------------------------------------------------------

    def _plant_canaries(self, now=None):
        now = now or time.time()
        for d in config.FIM_CANARY_DIRS:
            d = d.strip()
            if not d or not os.path.isdir(d):
                continue
            path = os.path.join(d, CANARY_NAME)
            key = f"canary:{path}"
            try:
                if not os.path.exists(path):
                    with open(path, "wb") as f:
                        f.write(CANARY_BODY)
                    try:
                        os.chmod(path, 0o444)
                    except OSError:
                        pass
                    log.info("planted canary %s", path)
                h = _sha(path)
                self.conn.execute(
                    "INSERT INTO fim_baseline(key,value,updated) VALUES(?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, h, now))
            except OSError as exc:
                log.warning("canary %s: %s", path, exc)
        self.conn.commit()

    # ---- scan + diff -----------------------------------------------------

    def check(self, now=None):
        now = now or time.time()
        baseline = {r["key"]: r["value"] for r in self.conn.execute(
            "SELECT key, value FROM fim_baseline")}
        first_run = not baseline
        seen = set()

        # 1. canaries: any change/deletion = critical
        for key, expected in baseline.items():
            if not key.startswith("canary:"):
                continue
            seen.add(key)
            path = key.split(":", 1)[1]
            cur = _sha(path) if os.path.exists(path) else None
            if cur is None:
                self.engine.emit("", "ransomware_canary", "high",
                                 f"CANARY DELETED: {path} — possible ransomware "
                                 f"or tampering in this tree", host="host", now=now)
            elif cur != expected:
                self.engine.emit("", "ransomware_canary", "high",
                                 f"CANARY MODIFIED: {path} — possible ransomware "
                                 f"encryption or tampering", host="host", now=now)
                self.conn.execute("UPDATE fim_baseline SET value=? WHERE key=?",
                                  (cur, key))

        # 2. webshell / dropped-script scan of served dirs
        for root in config.FIM_WATCH_DIRS:
            root = root.strip()
            if not root or not os.path.isdir(root):
                continue
            key = f"fim:{root}"
            seen.add(key)
            current = _scan_suspicious(root)   # {relpath: hash}
            prev = set((baseline.get(key) or "").split("|")) - {""}
            prev_files = {p.rsplit("::", 1)[0] for p in prev}
            for rel, h in current.items():
                if rel in prev_files:
                    continue
                if not first_run:
                    full = os.path.join(root, rel)
                    marker = _looks_like_webshell(full)
                    sev = "high"
                    detail = (f"new server-executable file in web dir: "
                              f"{full}" + (" — contains webshell code markers "
                                           "(eval/base64_decode/system/$_POST)"
                                           if marker else ""))
                    self.engine.emit("", "webshell_dropped", sev, detail,
                                     host="host", path=full, now=now)
            self.conn.execute(
                "INSERT INTO fim_baseline(key,value,updated) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=?",
                (key, "|".join(f"{r}::{h}" for r, h in sorted(current.items())),
                 now, now))

        self.conn.commit()
        if first_run:
            log.info("FIM baseline initialized (%d watch keys)", len(seen))
