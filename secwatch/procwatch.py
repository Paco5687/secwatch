"""Process + egress / C2 detection (EDR-lite, poll-based, no kernel modules).

Runs non-root, so it uses what is readable for ALL processes — /proc/<pid>/cmdline
and the global connection table — plus best-effort /proc/<pid>/exe. Detects:
  - reverse / interactive shells and crypto-miners by cmdline signature
  - processes executing from /tmp, /dev/shm, /var/tmp, or a deleted binary
  - new external egress destinations (C2 / exfil awareness) vs a learned baseline
"""
import asyncio
import glob
import ipaddress
import logging
import os
import re
import socket
import struct
import time

from . import config, db, detect

log = logging.getLogger("secwatch.proc")

REVSHELL_RE = re.compile(
    # NOTE: no bare "bash -i" — it matches normal interactive/login shells. The
    # unambiguous network-shell signatures below are what indicate a real revshell.
    r"/dev/(?:tcp|udp)/"                              # bash /dev/tcp redirect
    r"|\bnc(?:at)?\b[^|]*\s-[a-z]*e"                  # nc -e
    # python one-liner that pulls in sockets AND a shell/exec primitive (any order)
    r"|\bpython[0-9.]*\b\s+-c\b(?=.*socket)(?=.*(?:subprocess|pty|os\.dup2|/bin/(?:sh|bash)))"
    r"|\bsocat\b.*(?:exec|system)"
    r"|\bperl\b\s+-e.*(?:Socket|exec)"
    r"|\bruby\b\s+-r?socket",
    re.I)
MINER_RE = re.compile(
    r"\b(xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|xmr-stak|ethminer|nbminer|"
    r"phoenixminer|t-rex|lolminer|cgminer|bfgminer|nanominer|teamredminer|"
    r"stratum\+tcp)\b", re.I)
SUSPICIOUS_EXE_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
# A "(deleted)" binary under these paths is almost always a benign apt/upgrade
# artifact (long-running process whose package was updated), not malware.
SYSTEM_EXE_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/", "/snap/")


def scan_process(pid, cmdline, exe):
    """Return (rule, severity, detail) or None for one process's attributes."""
    if not cmdline:
        cmdline = ""
    # The Claude Code / agent shell wraps every command as `bash -c source
    # <.claude/shell-snapshots/...>`; its cmdline echoes whatever command is
    # running (including security tests), so skip that operator wrapper to avoid
    # self-flagging. A real attacker's shell is not wrapped this way.
    if "/.claude/shell-snapshots/" in cmdline:
        return None
    if REVSHELL_RE.search(cmdline):
        return ("reverse_shell", "high",
                f"reverse/interactive-shell pattern in pid {pid}: {cmdline[:160]}")
    if MINER_RE.search(cmdline):
        return ("crypto_miner", "high",
                f"crypto-miner signature in pid {pid}: {cmdline[:160]}")
    if exe:
        deleted = exe.endswith(" (deleted)")
        path = exe[:-10] if deleted else exe   # strip " (deleted)"
        if any(path.startswith(d) for d in SUSPICIOUS_EXE_DIRS):
            return ("exec_suspicious", "high",
                    f"pid {pid} executing from a temp dir: {path} — {cmdline[:120]}")
        if deleted and not any(path.startswith(d) for d in SYSTEM_EXE_DIRS):
            # deleted binary OUTSIDE system dirs — malware anti-forensics
            return ("exec_deleted", "high",
                    f"pid {pid} running a DELETED binary ({path}) outside system "
                    f"dirs — possible malware: {cmdline[:120]}")
    return None


def iter_procs():
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            cmdline = ""
        exe = None
        try:
            exe = os.readlink(f"/proc/{pid}/exe")   # may be PermissionError for other uids
        except OSError:
            exe = None
        yield pid, cmdline, exe


def _parse_proc_net(path):
    """Yield remote (ip, port) for ESTABLISHED (state 01) connections."""
    try:
        lines = open(path).read().splitlines()[1:]
    except OSError:
        return
    v6 = path.endswith("6")
    for ln in lines:
        p = ln.split()
        if len(p) < 4 or p[3] != "01":   # 01 = ESTABLISHED
            continue
        rem = p[2]
        hexip, hexport = rem.rsplit(":", 1)
        port = int(hexport, 16)
        try:
            if v6:
                b = bytes.fromhex(hexip)
                # /proc stores each 32-bit word little-endian
                words = struct.unpack("<4I", b)
                ip = str(ipaddress.IPv6Address(struct.pack(">4I", *words)))
            else:
                ip = str(ipaddress.IPv4Address(struct.unpack("<I", bytes.fromhex(hexip))[0]))
        except (ValueError, struct.error):
            continue
        yield ip, port


def external_dests(allow_nets):
    """Set of external destination IPs from current established connections."""
    allow = [ipaddress.ip_network(n) for n in allow_nets]
    dests = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for ip, port in _parse_proc_net(path):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast:
                continue
            if any(a in n for n in allow):
                continue
            dests.add(ip)
    return dests


class ProcWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn
        self.seen_proc = set()      # (pid, rule) already alerted
        self.egress_seen = set()
        self.egress_primed = False

    async def run(self):
        # reload learned egress baseline
        stored = db.meta_get(self.conn, "egress_seen") or ""
        self.egress_seen = set(x for x in stored.split(",") if x)
        self.egress_primed = bool(self.egress_seen)
        while True:
            try:
                self.check()
            except Exception:
                log.exception("procwatch poll failed")
            await asyncio.sleep(config.PROC_INTERVAL)

    def check(self, now=None):
        now = now or time.time()

        # --- processes ---
        live = set()
        for pid, cmdline, exe in iter_procs():
            hit = scan_process(pid, cmdline, exe)
            if not hit:
                continue
            rule, sev, detail = hit
            key = (pid, rule)
            live.add(key)
            if key not in self.seen_proc:
                self.engine.emit("", rule, sev, detail, host="host", now=now)
        # only keep what's still live, so an exited-then-reused PID can re-alert
        self.seen_proc = live

        # --- egress ---
        dests = external_dests(config.EGRESS_ALLOWLIST_NETS)
        if not self.egress_primed:
            # first observation: learn silently
            self.egress_seen |= dests
            self.egress_primed = True
            db.meta_set(self.conn, "egress_seen", ",".join(sorted(self.egress_seen)))
            self.conn.commit()
            return
        new = dests - self.egress_seen
        for ip in sorted(new):
            self.engine.emit("", "egress_new", "medium",
                             f"new outbound connection to external host {ip}"
                             + (f" ({self._rdns(ip)})" if self._rdns(ip) else "")
                             + " — verify this is expected app traffic",
                             host="egress", now=now)
        if new:
            self.egress_seen |= new
            db.meta_set(self.conn, "egress_seen", ",".join(sorted(self.egress_seen)))
            self.conn.commit()

    @staticmethod
    def _rdns(ip):
        try:
            socket.setdefaulttimeout(1.0)
            return socket.gethostbyaddr(ip)[0]
        except (OSError, ValueError):
            return None
        finally:
            socket.setdefaulttimeout(None)
