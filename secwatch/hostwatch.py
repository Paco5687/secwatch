"""Host baseline monitoring: snapshot security-relevant host state, diff
against the stored baseline, alert on changes, then absorb them.

First run populates the baseline silently. After a change is reported once,
the new state becomes the baseline (the event log keeps the history).
"""
import asyncio
import glob
import hashlib
import logging
import os
import time
from pathlib import Path

from . import config, db

log = logging.getLogger("secwatch.host")

SEVERITY = {
    "authkeys": "high",   # ~/.ssh/authorized_keys changed
    "users": "high",      # login-capable account added/removed
    "ports": "medium",    # new listening socket
    "cron": "medium",     # system cron changed
    "traefikcfg": "high",  # edge route config changed (route injection?)
    # v4 persistence / foothold vectors:
    "systemd": "high",     # new/changed systemd unit file (service persistence)
    "suid": "high",        # SUID/SGID binary set changed (privesc vector)
    "ldpreload": "high",   # /etc/ld.so.preload — classic rootkit hook
    "boothook": "high",    # rc.local / profile.d / update-motd.d
    "shellrc": "high",     # shell rc file changed (login persistence)
    "uid0": "high",        # a second UID-0 (root-equivalent) account
}

NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/bin/false", "/usr/bin/false", "/sbin/nologin")


def _sha(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    except OSError:
        return "unreadable"


def _listen_ports():
    ports = set()
    for proc in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(proc).read_text().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            parts = ln.split()
            if len(parts) > 3 and parts[3] == "0A":  # TCP LISTEN
                port = int(parts[1].rsplit(":", 1)[1], 16)
                if port < config.EPHEMERAL_PORT_MIN:
                    ports.add(port)
    return ",".join(str(p) for p in sorted(ports))


def _login_users():
    users = []
    try:
        for ln in Path("/etc/passwd").read_text().splitlines():
            f = ln.split(":")
            if len(f) >= 7 and f[6] not in NOLOGIN_SHELLS and f[6].strip():
                users.append(f[0])
    except OSError:
        pass
    return ",".join(sorted(users))


SUID_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin",
             "/usr/local/bin", "/usr/local/sbin")
SYSTEMD_DIRS = ("/etc/systemd/system", "/run/systemd/system")
SYSTEMD_EXTS = (".service", ".timer", ".socket", ".path")


def _suid_set():
    out = []
    for d in SUID_DIRS:
        for f in glob.glob(d + "/*"):
            try:
                mode = os.stat(f).st_mode
            except OSError:
                continue
            if mode & 0o6000:  # setuid or setgid
                tag = ("u" if mode & 0o4000 else "") + ("g" if mode & 0o2000 else "")
                out.append(f"{os.path.basename(f)}:{tag}")
    return ",".join(sorted(out))


def _uid0_accounts():
    accts = []
    try:
        for ln in Path("/etc/passwd").read_text().splitlines():
            f = ln.split(":")
            if len(f) >= 3 and f[2] == "0":
                accts.append(f[0])
    except OSError:
        pass
    return ",".join(sorted(accts))


def snapshot():
    snap = {
        "ports": _listen_ports(),
        "users": _login_users(),
        "cron": ",".join(
            f"{p}:{_sha(p)}" for p in sorted(
                ["/etc/crontab"] + glob.glob("/etc/cron.d/*")
                + glob.glob("/etc/cron.hourly/*") + glob.glob("/etc/cron.daily/*")
                + glob.glob("/etc/cron.weekly/*") + glob.glob("/etc/cron.monthly/*"))),
        # --- v4 persistence vectors ---
        "suid": _suid_set(),
        "uid0": _uid0_accounts(),
        "ldpreload": _sha("/etc/ld.so.preload")
        if os.path.exists("/etc/ld.so.preload") else "absent",
    }
    for ak in sorted(glob.glob("/home/*/.ssh/authorized_keys")):
        snap[f"authkeys:{ak}"] = _sha(ak)
    for cfg in sorted(glob.glob(str(config.TRAEFIK_DYNAMIC_DIR / "*.yml"))):
        name = os.path.basename(cfg)
        if name in config.TRAEFIK_CONFIG_SELF_MANAGED or ".bak" in name:
            continue
        snap[f"traefikcfg:{name}"] = _sha(cfg)
    # systemd unit files (system + this user) — new/changed = service persistence
    unit_globs = []
    for base in list(SYSTEMD_DIRS) + [str(Path.home() / ".config/systemd/user")]:
        for ext in SYSTEMD_EXTS:
            unit_globs += glob.glob(f"{base}/*{ext}")
    for u in sorted(unit_globs):
        snap[f"systemd:{u}"] = _sha(u)
    # boot/login hooks
    for p in (["/etc/rc.local"] + sorted(glob.glob("/etc/profile.d/*"))
              + sorted(glob.glob("/etc/update-motd.d/*"))):
        if os.path.exists(p):
            snap[f"boothook:{p}"] = _sha(p)
    # shell rc files (readable ones; unreadable root files hash as 'unreadable')
    for rc in sorted(glob.glob("/home/*/.bashrc") + glob.glob("/home/*/.profile")
                     + glob.glob("/home/*/.bash_profile") + glob.glob("/home/*/.zshrc")
                     + ["/root/.bashrc", "/root/.profile"]):
        if os.path.exists(rc):
            snap[f"shellrc:{rc}"] = _sha(rc)
    return snap


class HostWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn

    async def run(self):
        while True:
            try:
                self.check()
            except Exception:
                log.exception("host snapshot failed")
            await asyncio.sleep(config.HOST_SNAPSHOT_INTERVAL)

    def check(self, now=None):
        now = now or time.time()
        snap = snapshot()
        # only this watcher's keys — docker:/unit: belong to dockerwatch
        baseline = {r["key"]: r["value"] for r in self.conn.execute(
            "SELECT key, value FROM host_baseline WHERE key NOT LIKE 'docker:%' "
            "AND key NOT LIKE 'unit:%'")}
        first_run = not baseline
        # key classes already tracked; introducing a NEW class (e.g. the first
        # time traefikcfg is added) must absorb silently, not alert on every
        # existing file — but a genuinely new file in an already-tracked class
        # still alerts.
        known_kinds = {k.split(":", 1)[0] for k in baseline}

        for key, value in snap.items():
            old = baseline.get(key)
            if old == value:
                continue
            kind = key.split(":", 1)[0]
            introducing_class = old is None and kind not in known_kinds
            if not first_run and not introducing_class:
                sev = SEVERITY.get(kind, "medium")
                self.engine.emit(
                    "", f"host_{kind}", sev,
                    self._describe(key, old, value), host="host", now=now)
            self.conn.execute(
                "INSERT INTO host_baseline(key,value,updated) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated=excluded.updated", (key, value, now))
        for key in set(baseline) - set(snap):
            self.engine.emit("", f"host_{key.split(':', 1)[0]}", "medium",
                             f"{key} disappeared from host snapshot",
                             host="host", now=now)
            self.conn.execute("DELETE FROM host_baseline WHERE key=?", (key,))
        self.conn.commit()
        if first_run:
            log.info("host baseline initialized (%d keys)", len(snap))

    @staticmethod
    def _describe(key, old, new):
        if key == "ports":
            o, n = set((old or "").split(",")) - {""}, set(new.split(",")) - {""}
            added, gone = sorted(n - o, key=int), sorted(o - n, key=int)
            bits = []
            if added:
                bits.append("new listening port(s): " + ", ".join(added))
            if gone:
                bits.append("port(s) no longer listening: " + ", ".join(gone))
            return "; ".join(bits) or "listening ports changed"
        if key == "users":
            o, n = set((old or "").split(",")) - {""}, set(new.split(",")) - {""}
            bits = []
            if n - o:
                bits.append("account(s) added: " + ", ".join(sorted(n - o)))
            if o - n:
                bits.append("account(s) removed: " + ", ".join(sorted(o - n)))
            return "; ".join(bits) or "login-capable accounts changed"
        if key.startswith("authkeys:"):
            return f"{key.split(':', 1)[1]} was modified"
        if key == "cron":
            return "system cron configuration changed"
        if key.startswith("traefikcfg:"):
            return (f"Traefik edge route config {key.split(':', 1)[1]} changed — "
                    f"verify this is an intended change, not route injection")
        if key == "suid":
            o, n = set((old or "").split(",")) - {""}, set(new.split(",")) - {""}
            bits = []
            if n - o:
                bits.append("NEW SUID/SGID binary: " + ", ".join(sorted(n - o)))
            if o - n:
                bits.append("SUID/SGID removed: " + ", ".join(sorted(o - n)))
            return "; ".join(bits) + " (privilege-escalation vector)"
        if key == "uid0":
            o, n = set((old or "").split(",")) - {""}, set(new.split(",")) - {""}
            if n - o:
                return ("NEW root-equivalent (UID 0) account(s): "
                        + ", ".join(sorted(n - o)) + " — likely backdoor")
            return "UID-0 account set changed: " + new
        if key == "ldpreload":
            return ("/etc/ld.so.preload changed (" + new + ") — classic rootkit "
                    "library-injection hook; investigate immediately")
        if key.startswith("systemd:"):
            return (f"systemd unit {key.split(':', 1)[1]} was added or modified — "
                    f"verify it's an intended service, not persistence")
        if key.startswith("boothook:"):
            return f"boot/login hook {key.split(':', 1)[1]} was added or modified"
        if key.startswith("shellrc:"):
            return f"shell rc file {key.split(':', 1)[1]} was modified (login persistence?)"
        return f"{key} changed"
