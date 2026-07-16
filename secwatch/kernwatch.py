"""kernwatch — host hang/crash early-warning + self-heal.

Watches for anything that tends to precede an unresponsive hang:
  • kernel-log fault classes (IOMMU/DMA, MCE/EDAC, soft/hard lockups, rcu stalls,
    OOM, storage/nvme/ata errors, PCIe AER, thermal, NIC hangs, oops/BUG), and
  • resource precursors (root fs near-full, RAM exhaustion, runaway load, a pile of
    stuck uninterruptible-I/O processes, dangerous temps).

A hard freeze can't be repaired live, so the highest-value action is capturing a
FORENSIC SNAPSHOT the instant a precursor appears — turning the usual "it hung and
left no logs" into a file you can read. On top of that:
  • SAFE remediations (disk cleanup, restart failed units) — OPT-IN (kernwatch.autofix),
  • ADVISORY recommendations for hardware faults nothing can fix live (e.g. IOMMU →
    "update kernel/BIOS or try iommu=pt").

Every detection + action is written to the `remediations` audit table (and emitted as
a secwatch event), including a re-check of whether it actually resolved the condition.
"""
import logging
import os
import re
import shutil
import subprocess
import time

from . import config

log = logging.getLogger("secwatch.kernwatch")

# (compiled regex, category, severity, advisory-recommendation)
_S = lambda p: re.compile(p, re.I)  # noqa: E731
SIGNATURES = [
    (_S(r"AMD-Vi.*(timed out|completion-wait)|DMAR.*fault|IO_PAGE_FAULT|iommu.*fault"),
     "iommu", "high", "IOMMU/DMA fault — update the kernel & BIOS/AGESA; if it recurs try 'iommu=pt' (or 'amd_iommu=off' if no VFIO passthrough)."),
    (_S(r"\bmce:|\[Hardware Error\]|machine check|EDAC.*(UE|CE|error)|mce_|uncorrected.*(memory|cpu|cache) error"),
     "mce", "high", "CPU/memory machine-check — run memtest86+; check RAM seating/XMP and BIOS. Uncorrected errors mean failing hardware."),
    (_S(r"soft lockup|hard lockup|hung task|rcu.*(stall|self-detected)|watchdog:.*BUG|blocked for more than \d+ seconds"),
     "lockup", "high", "CPU/task lockup — often a driver or I/O stall; capture the snapshot's D-state list and dmesg."),
    (_S(r"kernel BUG|general protection fault|\bOops\b|kernel panic|scheduling while atomic|BUG: unable to handle"),
     "oops", "high", "Kernel bug/oops — note the call trace; usually a driver. A newer kernel often fixes it."),
    (_S(r"Out of memory:.*Killed process|oom-kill|invoked oom-killer"),
     "oom", "high", "Out-of-memory kill — a process ballooned. Find the culprit in the snapshot; add memory limits or restart it."),
    (_S(r"I/O error|EXT4-fs error|Aborting journal|remounting.*read-only|nvme.*(timeout|reset|controller is down|not ready)|ata\d+.*(failed|exception|hard resetting)|task abort"),
     "storage", "high", "Storage/filesystem error — check SMART (smartctl), cabling/power; a failing NVMe/SSD can hang the whole box."),
    (_S(r"PCIe Bus Error|AER:.*(Uncorrected|Corrected)|pcieport.*error|link is down"),
     "pcie", "medium", "PCIe error — reseat the card; try 'pcie_aspm=off' (already set here) and a BIOS update."),
    (_S(r"thermal.*(critical|shutdown)|temperature above threshold|Package temperature above|Core temperature above"),
     "thermal", "high", "Thermal event — check cooling/fans/paste and airflow immediately; sustained heat forces shutdowns."),
    (_S(r"Detected Hardware Unit Hang|NETDEV WATCHDOG|tx hang|transmit queue.*timed out|nic.*reset"),
     "network", "medium", "NIC hang — update the network driver/firmware; a wedged NIC can stall the network stack."),
    (_S(r"page allocation failure|cannot allocate memory|fork.*Cannot allocate"),
     "memory", "medium", "Memory allocation failure — memory fragmentation/pressure; watch for an impending OOM."),
]

# ---- circuit breakers (module state) -------------------------------------
_last_action = {}     # action -> last-run ts (min interval between same action)
_seen_kernel = set()  # dedup kernel-line hashes within a run
_last_snapshot = 0.0


def _run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


# ---- kernel-log reading (cursor-based, only new lines) -------------------

def _kernel_lines():
    cur = str(config.KERNWATCH_CURSOR)
    if not os.path.exists(cur):
        _run(["journalctl", "-k", "-n", "0", "--cursor-file", cur])   # seed at 'now'
        return []
    rc, out, _ = _run(["journalctl", "-k", "-o", "short-iso", "-q", "--cursor-file", cur])
    return [ln for ln in out.splitlines() if ln.strip()] if rc == 0 else []


def scan_kernel():
    """New kernel-log fault findings since the last poll."""
    findings = []
    for ln in _kernel_lines():
        msg = ln.split(": ", 1)[-1]
        for rx, cat, sev, rec in SIGNATURES:
            if rx.search(msg):
                h = hash((cat, msg[:120]))
                if h in _seen_kernel:
                    break
                _seen_kernel.add(h)
                findings.append({"category": cat, "severity": sev,
                                 "trigger": msg[:280], "rec": rec})
                break
    return findings


# ---- resource precursors -------------------------------------------------

def _meminfo():
    d = {}
    try:
        for ln in open("/proc/meminfo"):
            k, _, v = ln.partition(":")
            d[k] = int(v.split()[0])   # kB
    except OSError:
        pass
    return d


def _dstate_count():
    n = 0
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                st = open(f"/proc/{pid}/stat").read().split(") ", 1)[1][0]
                if st == "D":
                    n += 1
            except (OSError, IndexError):
                continue
    except OSError:
        pass
    return n


def _max_temp():
    hi = 0.0
    try:
        base = "/sys/class/thermal"
        for z in os.listdir(base):
            if z.startswith("thermal_zone"):
                try:
                    t = int(open(f"{base}/{z}/temp").read().strip()) / 1000.0
                    hi = max(hi, t)
                except (OSError, ValueError):
                    continue
    except OSError:
        pass
    return hi


def check_resources():
    findings = []
    du = shutil.disk_usage("/")
    disk_pct = round(du.used / du.total * 100)
    if disk_pct >= config.KERNWATCH_DISK_PCT:
        findings.append({"category": "disk_full", "severity": "high",
                         "trigger": f"root fs {disk_pct}% used (>= {config.KERNWATCH_DISK_PCT}%)",
                         "rec": "Free space: journald vacuum, apt clean, prune docker, rotate/trim large logs.",
                         "fix": "disk_cleanup"})
    mi = _meminfo()
    if mi.get("MemTotal"):
        avail_pct = round(mi.get("MemAvailable", 0) / mi["MemTotal"] * 100)
        if avail_pct <= config.KERNWATCH_MEM_AVAIL_PCT:
            findings.append({"category": "mem_pressure", "severity": "high",
                             "trigger": f"only {avail_pct}% RAM available (<= {config.KERNWATCH_MEM_AVAIL_PCT}%)",
                             "rec": "Identify the ballooning process in the snapshot; restart it or add a memory limit."})
    try:
        load1 = float(open("/proc/loadavg").read().split()[0])
    except (OSError, ValueError):
        load1 = 0.0
    cores = os.cpu_count() or 1
    dstate = _dstate_count()
    if load1 > cores * config.KERNWATCH_LOAD_FACTOR and dstate >= config.KERNWATCH_DSTATE:
        findings.append({"category": "io_stall", "severity": "high",
                         "trigger": f"load {load1:.0f} on {cores} cores with {dstate} uninterruptible (D-state) procs",
                         "rec": "Storage/NFS stall likely — check the snapshot's D-state list and storage health."})
    temp = _max_temp()
    if temp and temp >= config.KERNWATCH_TEMP_WARN:
        findings.append({"category": "thermal", "severity": "high",
                         "trigger": f"max thermal zone {temp:.0f}°C (>= {config.KERNWATCH_TEMP_WARN}°C)",
                         "rec": "Check cooling immediately — approaching a thermal shutdown."})
    return findings


# ---- forensic snapshot (the always-safe, highest-value action) -----------

def capture_snapshot(reason):
    """Dump host state to a file so a subsequent hang isn't a black hole."""
    d = config.KERNWATCH_SNAPSHOT_DIR
    d.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    path = d / f"snapshot-{stamp}.txt"
    sec = [
        ("reason", reason),
        ("date", _run(["date"])[1]),
        ("uptime / load", _run(["uptime"])[1]),
        ("kernel", _run(["uname", "-a"])[1]),
        ("memory", _run(["free", "-h"])[1]),
        ("disk", _run(["df", "-h"])[1]),
        ("top by MEM", _run(["bash", "-c", "ps -eo pid,ppid,rss,pcpu,comm --sort=-rss | head -16"])[1]),
        ("top by CPU", _run(["bash", "-c", "ps -eo pid,ppid,rss,pcpu,comm --sort=-pcpu | head -16"])[1]),
        ("D-state (uninterruptible) procs", _run(["bash", "-c", "ps -eo pid,stat,wchan,comm | awk '$2 ~ /D/'"])[1]),
        ("temps", _run(["bash", "-c", "sensors 2>/dev/null || cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null"])[1]),
        ("failed units", _run(["systemctl", "--failed", "--no-legend"])[1]),
        ("recent kernel log", _run(["journalctl", "-k", "-n", "80", "--no-pager", "-o", "short-iso"])[1]),
    ]
    body = f"# secwatch forensic snapshot — {reason}\n\n" + "\n\n".join(
        f"===== {name} =====\n{val}" for name, val in sec)
    try:
        path.write_text(body)
    except OSError as exc:
        log.warning("snapshot write failed: %s", exc)
        return None
    # keep the last ~30
    try:
        snaps = sorted(d.glob("snapshot-*.txt"))
        for old in snaps[:-30]:
            old.unlink()
    except OSError:
        pass
    return str(path)


# ---- safe remediations (opt-in) ------------------------------------------

def _throttled(action, min_gap=900):
    now = time.time()
    if now - _last_action.get(action, 0) < min_gap:
        return True
    _last_action[action] = now
    return False


def remediate_disk_cleanup():
    """Reclaim space (best-effort; each step degrades gracefully w/o privilege)."""
    before = shutil.disk_usage("/")
    steps = []
    for label, cmd in [
        ("journal vacuum", ["journalctl", "--vacuum-size=500M"]),
        ("user journal vacuum", ["journalctl", "--user", "--vacuum-size=200M"]),
        ("apt clean", ["apt-get", "clean"]),
        ("docker prune", ["docker", "system", "prune", "-f"]),
    ]:
        rc, _, err = _run(cmd, timeout=120)
        steps.append(f"{label}: {'ok' if rc == 0 else 'skip(' + (err[:40] or 'no perm') + ')'}")
    after = shutil.disk_usage("/")
    freed = (after.free - before.free) / 1e9
    pct = round(after.used / after.total * 100)
    resolved = pct < config.KERNWATCH_DISK_PCT
    return (True, f"freed {freed:.1f} GB → {pct}% used [{'; '.join(steps)}]", resolved)


def remediate_restart_failed():
    """Restart systemd units currently in a failed state (capped)."""
    rc, out, _ = _run(["systemctl", "--failed", "--no-legend", "--plain"])
    units = [ln.split()[0] for ln in out.splitlines() if ln.strip()][:5]
    if not units:
        rc2, out2, _ = _run(["systemctl", "--user", "--failed", "--no-legend", "--plain"])
        units = [("--user", ln.split()[0]) for ln in out2.splitlines() if ln.strip()][:5]
    done = []
    for u in units:
        scope, name = (u if isinstance(u, tuple) else ("", u))
        cmd = ["systemctl"] + ([scope] if scope else []) + ["restart", name]
        rc, _, err = _run(cmd, timeout=30)
        done.append(f"{name}: {'restarted' if rc == 0 else 'failed(' + err[:30] + ')'}")
    if not done:
        return (True, "no failed units", True)
    # recheck
    rc, out, _ = _run(["systemctl", "--failed", "--no-legend"])
    resolved = not out.strip()
    return (True, "; ".join(done), resolved)


_REMEDIATIONS = {"disk_cleanup": remediate_disk_cleanup, "restart_failed": remediate_restart_failed}


# ---- orchestration -------------------------------------------------------

def record(conn, engine, f, action, result, detail, snapshot=None, now=None):
    now = now or time.time()
    conn.execute("INSERT INTO remediations(ts,category,severity,trigger,action,result,detail,snapshot)"
                 " VALUES(?,?,?,?,?,?,?,?)",
                 (now, f["category"], f["severity"], f.get("trigger", ""), action, result,
                  detail, snapshot))
    conn.commit()
    if engine is not None:
        act = f"[self-heal: {action} → {result}] " if action not in ("none", "advisory") else ""
        engine.emit("", f"kern_{f['category']}", f["severity"],
                    f"{act}{f.get('trigger', '')} — {detail}", host="kernel", now=now)


def handle(conn, engine, f, now=None):
    """Decide + apply the action for one finding, and audit it."""
    now = now or time.time()
    global _last_snapshot
    snap = None
    # 1) snapshot on any high-severity precursor (always-safe; the whole point)
    if config.KERNWATCH_SNAPSHOT and f["severity"] == "high" and (now - _last_snapshot) > 120:
        snap = capture_snapshot(f"{f['category']}: {f.get('trigger', '')[:80]}")
        _last_snapshot = now
    # 2) an active fix if we have a safe one AND autofix is enabled
    fix = f.get("fix")
    if fix and config.KERNWATCH_AUTOFIX and fix in config.KERNWATCH_AUTOFIX_ACTIONS \
            and fix in _REMEDIATIONS and not _throttled(fix):
        ok, detail, resolved = _REMEDIATIONS[fix]()
        record(conn, engine, f, fix, ("resolved" if resolved else "unresolved" if ok else "failed"),
               detail, snap, now)
        return
    # 3) otherwise: advisory (record the recommended fix) — esp. hardware faults
    record(conn, engine, f, ("snapshot" if snap else "advisory"),
           "advisory", f["rec"], snap, now)


def poll(conn, engine, now=None):
    """One kernwatch cycle. Returns the number of findings handled."""
    _seen_kernel.clear()
    findings = scan_kernel() + check_resources()
    for f in findings:
        try:
            handle(conn, engine, f, now)
        except Exception as exc:   # never let self-heal crash the host monitor
            log.error("kernwatch handle(%s) failed: %s", f.get("category"), exc)
    return len(findings)


class KernWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn

    async def run(self):
        import asyncio
        if not config.KERNWATCH_ENABLED:
            return
        log.info("kernwatch on (snapshot=%s autofix=%s)", config.KERNWATCH_SNAPSHOT,
                 config.KERNWATCH_AUTOFIX)
        scan_kernel()   # seed the cursor so we don't replay history on first poll
        while True:
            await asyncio.sleep(config.KERNWATCH_INTERVAL)
            try:
                n = await asyncio.to_thread(poll, self.conn, self.engine)
                if n:
                    log.warning("kernwatch: %d hang-precursor finding(s) handled", n)
            except Exception as exc:
                log.error("kernwatch poll: %s", exc)
