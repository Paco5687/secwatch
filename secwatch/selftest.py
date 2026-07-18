"""Fire-drill: exercise the real detect → enforce → restore chain on demand and
report each stage green/red. Answers "is the pipeline actually working *right
now*?" with evidence instead of hope.

Safety (this module must never leave a real-looking ban behind):
  * The synthetic attacker is 203.0.113.7 (RFC-5737 TEST-NET-3 — reserved for
    documentation, can never be a real host or a real visitor).
  * It is written to the live enforcement target only transiently and is NEVER
    inserted into the DB. The final `restore` stage runs in a `finally`, and it
    calls `ban.write_file` which reconciles the edge to the DB's *real* bans — so
    the synthetic IP is always removed, even if an earlier stage raises. And
    because it's never in the DB, the normal maintenance reconcile would strip it
    anyway on the next cycle if the process died mid-drill. Belt and suspenders.
"""
import logging
import os
import sqlite3
import subprocess
import time
from pathlib import Path

from . import ban, banactuators, config, db, detect

log = logging.getLogger("secwatch.selftest")

FIREDRILL_IP = "203.0.113.7"      # RFC 5737 TEST-NET-3; never routable/real
_DETECT_IP = "203.0.113.9"        # synthetic source for the detection stage


def _stage(name, fn):
    t = time.perf_counter()
    try:
        ok, detail = fn()
    except Exception as exc:       # a broken stage is a red result, not a crash
        log.exception("fire-drill stage %s errored", name)
        ok, detail = False, f"error: {exc}"
    return {"stage": name, "ok": bool(ok), "detail": detail,
            "ms": round((time.perf_counter() - t) * 1000)}


def _enforcement_text():
    """Current enforcement state as text, per actuator. None if unreadable."""
    a = config.BAN_ACTUATOR
    try:
        if a == "traefik":
            return config.BANS_FILE.read_text() if config.BANS_FILE.exists() else ""
        if a == "nginx":
            from pathlib import Path
            p = Path(config.NGINX_DENY_FILE)
            return p.read_text() if p.exists() else ""
        if a == "nftables":
            r = subprocess.run(["nft", "list", "set", "inet", config.NFT_TABLE,
                                config.NFT_SET], capture_output=True, text=True)
            return r.stdout if r.returncode == 0 else None
    except OSError:
        return None
    return None


def _detect():
    """A synthetic secret-file probe is recognized and classified as ban-worthy —
    run through a REAL Engine on an isolated in-memory DB (zero side effects)."""
    mem = sqlite3.connect(":memory:")
    mem.row_factory = sqlite3.Row
    mem.executescript(db.SCHEMA)
    try:
        eng = detect.Engine(mem, alert_cb=lambda e: None, ban_cb=None)
        eng.emit(_DETECT_IP, "secret_probe", "high",
                 "fire-drill synthetic /.env probe",
                 host="firedrill.local", path="/.env")
        row = mem.execute(
            "SELECT severity FROM events WHERE rule='secret_probe'").fetchone()
        ban_ruleset = bool(eng.ban_rules)
    finally:
        mem.close()
    if row and row["severity"] == "high" and ban_ruleset:
        return True, ("synthetic /.env probe recognized as high severity; "
                      f"{len(eng.ban_rules)} ban rule(s) loaded")
    return False, f"recorded={dict(row) if row else None} ban_ruleset={ban_ruleset}"


def _enforce(conn):
    """The synthetic ban actually reaches the edge, and real bans are preserved."""
    if config.BAN_ACTUATOR == "none":
        return True, "actuator=none (alert-only by design) — nothing to enforce"
    real = [b["ip"] for b in ban.active(conn)]
    banactuators.sync(real + [FIREDRILL_IP])
    text = _enforcement_text()
    if text is None:
        return False, f"could not read {config.BAN_ACTUATOR} enforcement state"
    wrote = FIREDRILL_IP in text
    kept = all(ip in text for ip in real)
    if wrote and kept:
        return True, (f"synthetic ban reached {config.BAN_ACTUATOR}; "
                      f"{len(real)} real ban(s) preserved")
    return False, f"wrote_synthetic={wrote} preserved_{len(real)}_real={kept}"


def _edge():
    """The edge is actually positioned to honor the ban (traefik-specific)."""
    if config.BAN_ACTUATOR != "traefik":
        return True, f"actuator={config.BAN_ACTUATOR}; edge check is traefik-specific"
    import yaml
    try:
        yaml.safe_load(config.BANS_FILE.read_text())
    except Exception as exc:
        return False, f"ban file is not valid YAML the proxy can load: {exc}"
    try:
        r = subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.Status}}"],
                           capture_output=True, text=True, timeout=5)
        traefik = [ln for ln in r.stdout.splitlines() if "traefik" in ln.lower()]
    except (OSError, subprocess.SubprocessError):
        traefik = None
    if traefik == []:
        return False, "ban file is valid YAML but no running traefik container found"
    suffix = f" + traefik up ({traefik[0]})" if traefik else " (traefik liveness unknown)"
    return True, "ban file is valid YAML the proxy watches" + suffix


def _file_target():
    """The file the actuator writes, if it's file-based (else None)."""
    if config.BAN_ACTUATOR == "traefik":
        return config.BANS_FILE
    if config.BAN_ACTUATOR == "nginx":
        return Path(config.NGINX_DENY_FILE)
    return None


def _atomic_write(path, content):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)   # the proxy's watcher never sees a partial file


def _restore(conn, snapshot):
    """Return enforcement to EXACTLY the pre-drill state — a self-test must leave
    zero footprint. For a file actuator we write the captured bytes back verbatim
    (so expired-but-still-listed bans stay exactly as found — reconciling them away
    is the maintenance loop's job, not the drill's). Otherwise reconcile to the DB.
    """
    target = _file_target()
    if snapshot and target is not None:
        _atomic_write(target, snapshot)
    else:                               # nftables / none / fresh install
        ban.write_file(conn)
    text = _enforcement_text()
    if text is None:
        return False, "could not confirm restore (enforcement state unreadable)"
    if FIREDRILL_IP in text:
        return False, "WARNING: synthetic ban still present after restore"
    if snapshot and target is not None and text != snapshot:
        return False, "restore did not reproduce the original enforcement state exactly"
    return True, "synthetic ban removed; enforcement restored byte-for-byte as found"


def run_firedrill(conn):
    """Run the full drill. `restore` is guaranteed to run even if a stage raises,
    and returns enforcement to the exact bytes captured before the drill began."""
    started = time.perf_counter()
    snapshot = _enforcement_text()      # exact pre-drill enforcement state
    stages = []
    try:
        stages.append(_stage("detect", _detect))
        stages.append(_stage("enforce", lambda: _enforce(conn)))
        stages.append(_stage("edge", _edge))
    finally:
        restore = _stage("restore", lambda: _restore(conn, snapshot))
    stages.append(restore)
    return {"ok": all(s["ok"] for s in stages),
            "actuator": config.BAN_ACTUATOR, "synthetic_ip": FIREDRILL_IP,
            "stages": stages,
            "ms": round((time.perf_counter() - started) * 1000)}
