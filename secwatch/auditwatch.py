"""Real-time process-exec monitoring via the Linux audit subsystem.

The /proc poll (procwatch) can miss a process that lives for less than one poll
interval — e.g. a 2-second reverse shell. The audit subsystem records EVERY
execve as it happens, with the full path, argv, and uid. This collector installs
an execve audit rule (if root), tails the audit log, reconstructs each exec, and
runs the same signatures as procwatch — so short-lived processes are caught with
full detail. If the audit log isn't available (no auditd, or non-root), it stays
dormant and the /proc poll remains the fallback.
"""
import logging
import os
import re
import subprocess

from . import config, procwatch, tailer

log = logging.getLogger("secwatch.audit")

_EVENT_RE = re.compile(r"msg=audit\((?P<id>[\d.]+:\d+)\)")
# key=value where value is either "quoted" or bare; bare group wins when present.
_FIELD_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _fields(line):
    return {k: (bare if bare else quoted)
            for k, quoted, bare in _FIELD_RE.findall(line)}


def available():
    """True if we can actually read the audit log (else the poll is the fallback)."""
    return os.access(config.AUDIT_LOG, os.R_OK)


def ensure_rule():
    """Add an execve audit rule if we're root and auditctl exists (idempotent)."""
    if not config.AUDIT_SET_RULE or os.geteuid() != 0:
        return
    if not _which("auditctl"):
        return
    existing = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
    if config.AUDIT_KEY in (existing.stdout or ""):
        return
    for arch in ("b64", "b32"):
        subprocess.run(["auditctl", "-a", "always,exit", "-F", f"arch={arch}",
                        "-S", "execve", "-F", f"key={config.AUDIT_KEY}"],
                       capture_output=True, text=True)
    log.info("installed execve audit rule (key=%s)", config.AUDIT_KEY)


def _which(cmd):
    return subprocess.run(["sh", "-c", f"command -v {cmd}"],
                          capture_output=True).returncode == 0


def _decode_arg(v):
    """An EXECVE arg is either "quoted" or bare hex (auditd hex-encodes args with
    spaces/special chars)."""
    if v.startswith('"'):
        return v[1:-1]
    if re.fullmatch(r"[0-9A-Fa-f]+", v) and len(v) % 2 == 0:
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def parse_execve_events(lines):
    """Correlate SYSCALL(execve) + EXECVE records by audit event id → list of
    {exe, cmdline, uid, pid}. Testable, pure."""
    events = {}
    order = []
    for line in lines:
        m = _EVENT_RE.search(line)
        if not m:
            continue
        eid = m.group("id")
        if eid not in events:
            events[eid] = {}
            order.append(eid)
        ev = events[eid]
        fields = _fields(line)
        if line.startswith("type=SYSCALL") and fields.get("syscall") in ("59", "execve"):
            ev["exe"] = fields.get("exe", "")
            ev["uid"] = fields.get("uid", "")
            ev["pid"] = fields.get("pid", "")
            ev["comm"] = fields.get("comm", "")
            ev["is_exec"] = True
        elif line.startswith("type=EXECVE"):
            argc = int(fields.get("argc", "0") or 0)
            args = []
            for i in range(argc):
                if f"a{i}" in fields:
                    args.append(_decode_arg(fields[f"a{i}"]))
            ev["cmdline"] = " ".join(args)
    out = []
    for eid in order:
        ev = events[eid]
        if ev.get("is_exec"):
            out.append({"exe": ev.get("exe", ""), "cmdline": ev.get("cmdline", ""),
                        "uid": ev.get("uid", ""), "pid": ev.get("pid", "?")})
    return out


class AuditWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn
        self.seen = set()   # (pid, rule) dedup with procwatch's poll

    async def run(self):
        if not config.AUDIT_ENABLED:
            return
        try:
            ensure_rule()
        except Exception:
            log.debug("could not set audit rule", exc_info=True)
        if not available():
            log.info("audit log not readable (%s) — real-time exec monitoring off; "
                     "the /proc poll remains the fallback", config.AUDIT_LOG)
            return
        log.info("real-time exec monitoring via audit log %s", config.AUDIT_LOG)
        buf = []
        async for line, _ino, _off in tailer.follow(config.AUDIT_LOG, start_at_end=True):
            if line:
                buf.append(line)
                if len(buf) < 64 and not line.startswith("type=PROCTITLE"):
                    continue
            if buf:
                self._process(buf)
                buf = []

    def _process(self, lines):
        for ev in parse_execve_events(lines):
            hit = procwatch.scan_process(ev["pid"], ev["cmdline"], ev["exe"])
            if not hit:
                continue
            rule, sev, detail = hit
            self.engine.emit("", rule, sev, f"[realtime] {detail}", host="host")
