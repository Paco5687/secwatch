"""kernwatch: broad fault-signature matching, resource-precursor thresholds, and
the handle() decision tree (snapshot always-safe; active remediation only when
autofix is enabled; hardware faults → advisory) with a full audit trail."""
import pytest


@pytest.mark.parametrize("line,cat", [
    ("AMD-Vi: Completion-Wait loop timed out", "iommu"),
    ("mce: [Hardware Error]: corrected error", "mce"),
    ("watchdog: BUG: soft lockup - CPU#1 stuck", "lockup"),
    ("rcu: INFO: rcu_sched self-detected stall on CPU", "lockup"),
    ("Out of memory: Killed process 999 (node)", "oom"),
    ("nvme nvme0: I/O timeout, reset controller", "storage"),
    ("EXT4-fs error (device nvme0n1p2): ext4_journal", "storage"),
    ("pcieport 0000:00:01.1: AER: Uncorrected error", "pcie"),
    ("thermal thermal_zone0: critical temperature reached", "thermal"),
    ("e1000e: Detected Hardware Unit Hang", "network"),
])
def test_signatures_match(line, cat):
    from secwatch import kernwatch
    hit = next((c for rx, c, s, r in kernwatch.SIGNATURES if rx.search(line)), None)
    assert hit == cat


def test_no_false_positive():
    from secwatch import kernwatch
    for benign in ["systemd[1]: Started foo.service", "audit: type=1400 apparmor",
                   "usb 1-1: new high-speed USB device"]:
        assert not any(rx.search(benign) for rx, *_ in kernwatch.SIGNATURES)


def test_resource_disk_full(monkeypatch):
    from secwatch import config, kernwatch
    monkeypatch.setattr(config, "KERNWATCH_DISK_PCT", 90)
    monkeypatch.setattr(kernwatch.shutil, "disk_usage",
                        lambda p: type("U", (), {"used": 95, "total": 100, "free": 5})())
    monkeypatch.setattr(kernwatch, "_meminfo", lambda: {"MemTotal": 100, "MemAvailable": 50})
    cats = [f["category"] for f in kernwatch.check_resources()]
    assert "disk_full" in cats
    df = next(f for f in kernwatch.check_resources() if f["category"] == "disk_full")
    assert df.get("fix") == "disk_cleanup" and df["severity"] == "high"


def test_resource_healthy_is_quiet(monkeypatch):
    from secwatch import kernwatch
    monkeypatch.setattr(kernwatch.shutil, "disk_usage",
                        lambda p: type("U", (), {"used": 40, "total": 100, "free": 60})())
    monkeypatch.setattr(kernwatch, "_meminfo", lambda: {"MemTotal": 100, "MemAvailable": 80})
    monkeypatch.setattr(kernwatch, "_dstate_count", lambda: 0)
    monkeypatch.setattr(kernwatch, "_max_temp", lambda: 45.0)
    assert kernwatch.check_resources() == []


def _conn(config, db, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    return db.connect()


class FakeEngine:
    def __init__(self):
        self.events = []

    def emit(self, ip, rule, sev, detail, host="", now=None):
        self.events.append({"rule": rule, "sev": sev, "detail": detail})


def test_hardware_fault_is_advisory_not_fixed(tmp_path, monkeypatch):
    from secwatch import config, db, kernwatch
    conn = _conn(config, db, tmp_path, monkeypatch)
    monkeypatch.setattr(config, "KERNWATCH_AUTOFIX", True)   # even with autofix on...
    monkeypatch.setattr(kernwatch, "capture_snapshot", lambda r: "/snap/x.txt")
    eng = FakeEngine()
    f = {"category": "iommu", "severity": "high", "trigger": "AMD-Vi timeout", "rec": "update kernel"}
    kernwatch.handle(conn, eng, f, now=1000)
    row = conn.execute("SELECT category,action,result,snapshot FROM remediations").fetchone()
    assert row["category"] == "iommu"
    assert row["result"] == "advisory"          # nothing to auto-fix on hardware
    assert row["snapshot"] == "/snap/x.txt"     # but we DID snapshot (high sev)
    assert eng.events and eng.events[0]["rule"] == "kern_iommu"


def test_disk_autofix_gated_off_by_default(tmp_path, monkeypatch):
    from secwatch import config, db, kernwatch
    conn = _conn(config, db, tmp_path, monkeypatch)
    monkeypatch.setattr(config, "KERNWATCH_AUTOFIX", False)   # default
    monkeypatch.setattr(kernwatch, "capture_snapshot", lambda r: None)
    called = []
    monkeypatch.setattr(kernwatch, "remediate_disk_cleanup",
                        lambda: called.append(1) or (True, "x", True))
    kernwatch._REMEDIATIONS["disk_cleanup"] = kernwatch.remediate_disk_cleanup
    f = {"category": "disk_full", "severity": "high", "trigger": "95%", "rec": "clean", "fix": "disk_cleanup"}
    kernwatch.handle(conn, FakeEngine(), f, now=1000)
    assert called == []                          # autofix off → NOT run
    assert conn.execute("SELECT result FROM remediations").fetchone()["result"] == "advisory"


def test_disk_autofix_runs_and_audits_when_enabled(tmp_path, monkeypatch):
    from secwatch import config, db, kernwatch
    conn = _conn(config, db, tmp_path, monkeypatch)
    monkeypatch.setattr(config, "KERNWATCH_AUTOFIX", True)
    monkeypatch.setattr(config, "KERNWATCH_AUTOFIX_ACTIONS", ["disk_cleanup"])
    monkeypatch.setattr(kernwatch, "capture_snapshot", lambda r: "/snap/y.txt")
    kernwatch._last_action.clear()
    monkeypatch.setattr(kernwatch, "remediate_disk_cleanup", lambda: (True, "freed 3.0 GB → 80% used", True))
    kernwatch._REMEDIATIONS["disk_cleanup"] = kernwatch.remediate_disk_cleanup
    f = {"category": "disk_full", "severity": "high", "trigger": "95%", "rec": "clean", "fix": "disk_cleanup"}
    kernwatch.handle(conn, FakeEngine(), f, now=2000)
    row = conn.execute("SELECT action,result,detail FROM remediations").fetchone()
    assert row["action"] == "disk_cleanup"
    assert row["result"] == "resolved"           # recheck said it dropped below threshold
    assert "freed" in row["detail"]
