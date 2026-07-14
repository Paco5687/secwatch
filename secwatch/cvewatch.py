"""CVE / vulnerability awareness.

Scans the running container images with Trivy (run as a container — no host
install, no root), cross-references the CISA KEV catalog (actively-exploited
CVEs), and stores findings. New KEV-listed vulns alert loudly; other HIGH/CRITICAL
findings are recorded for the dashboard without alert-spam.

Blocking (docker + network) — driven from a worker thread by web.py.
"""
import json
import logging
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

from . import config

log = logging.getLogger("secwatch.cve")

_TRIVY_BIN = None


def _have_docker():
    return shutil.which("docker") is not None


def running_images():
    if not _have_docker():
        return []
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Image}}"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return sorted({ln.strip() for ln in out.stdout.splitlines() if ln.strip()})


def trivy_bin():
    """Path to a trivy binary — needed for host (rootfs) scanning without Docker.
    Uses one on PATH, else installs a self-contained copy under the cache dir on
    first use. Returns None if it can't be obtained (offline, etc.)."""
    global _TRIVY_BIN
    if _TRIVY_BIN and Path(_TRIVY_BIN).exists():
        return _TRIVY_BIN
    onpath = shutil.which("trivy")
    if onpath:
        _TRIVY_BIN = onpath
        return onpath
    bindir = Path(config.TRIVY_CACHE).parent / "trivy-bin"
    binp = bindir / "trivy"
    if not binp.exists():
        bindir.mkdir(parents=True, exist_ok=True)
        log.info("installing trivy binary to %s (one-time)", bindir)
        try:
            subprocess.run(
                "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/"
                f"main/contrib/install.sh | sh -s -- -b {bindir}",
                shell=True, capture_output=True, text=True, timeout=180, check=True)
        except Exception as exc:  # noqa: BLE001 — best-effort
            log.warning("trivy binary install failed: %s", exc)
            return None
    _TRIVY_BIN = str(binp) if binp.exists() else None
    return _TRIVY_BIN


def _parse_trivy(stdout):
    """Extract HIGH/CRITICAL vuln dicts from Trivy JSON (image or rootfs)."""
    try:
        doc = json.loads(stdout or "{}")
    except ValueError:
        return []
    vulns = []
    for res in doc.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            vulns.append({
                "cve": v.get("VulnerabilityID", ""),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", ""),
                "severity": v.get("Severity", ""),
                "title": (v.get("Title") or v.get("Description", ""))[:200],
            })
    return vulns


def scan_rootfs():
    """Scan the HOST's installed OS packages for CVEs — no Docker needed. Returns
    (label, vulns) where label identifies the host in the findings table."""
    trivy = trivy_bin()
    if not trivy:
        return None, []
    label = "host: " + _host_os()
    cmd = [trivy, "rootfs", "--quiet", "--scanners", "vuln", "--pkg-types", "os",
           "--severity", config.CVE_SEVERITIES, "--format", "json",
           "--cache-dir", config.TRIVY_CACHE]
    if config.CVE_IGNORE_UNFIXED:
        cmd.append("--ignore-unfixed")
    cmd.append("/")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=config.CVE_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning("trivy rootfs scan timed out")
        return label, []
    if proc.returncode != 0:
        log.warning("trivy rootfs scan failed: %s", (proc.stderr or "")[-300:])
        return label, []
    return label, _parse_trivy(proc.stdout)


def _host_os():
    try:
        for ln in Path("/etc/os-release").read_text().splitlines():
            if ln.startswith("PRETTY_NAME="):
                return ln.split("=", 1)[1].strip().strip('"')[:40]
    except OSError:
        pass
    return "this host"


def fetch_kev():
    """Return set of CVE IDs in the CISA Known Exploited Vulnerabilities catalog,
    cached daily to disk (falls back to cache on network failure)."""
    fresh = (config.KEV_CACHE.exists()
             and time.time() - config.KEV_CACHE.stat().st_mtime < config.KEV_MAX_AGE)
    if not fresh:
        try:
            req = urllib.request.Request(config.KEV_URL,
                                         headers={"User-Agent": "secwatch/0.1"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            config.KEV_CACHE.write_bytes(data)
            log.info("refreshed CISA KEV catalog (%d bytes)", len(data))
        except Exception as exc:
            log.warning("KEV fetch failed (%s); using cache if present", exc)
    try:
        doc = json.loads(config.KEV_CACHE.read_text())
        return {v["cveID"] for v in doc.get("vulnerabilities", [])}
    except (OSError, ValueError):
        return set()


def scan_image(image):
    """Run Trivy on one image; return list of vuln dicts (HIGH/CRITICAL).

    Exports the image with `docker save` and scans the tarball, so locally-built
    images (not in any registry) work and nothing is re-pulled — Trivy in its
    container can't see the host's local image store otherwise.
    """
    tar = os.path.join(config.TRIVY_CACHE, "scan.tar")
    try:
        save = subprocess.run(["docker", "save", "-o", tar, image],
                              capture_output=True, text=True,
                              timeout=config.CVE_SCAN_TIMEOUT)
        if save.returncode != 0:
            log.warning("docker save %s failed: %s", image, save.stderr[-200:])
            return []
        icmd = ["docker", "run", "--rm", "-v", f"{config.TRIVY_CACHE}:/root/.cache/",
                config.TRIVY_IMAGE, "image", "--quiet",
                "--severity", config.CVE_SEVERITIES, "--format", "json",
                "--scanners", "vuln", "--input", "/root/.cache/scan.tar"]
        if config.CVE_IGNORE_UNFIXED:
            icmd.append("--ignore-unfixed")
        proc = subprocess.run(icmd, capture_output=True, text=True,
                              timeout=config.CVE_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning("trivy scan of %s timed out", image)
        return []
    finally:
        try:
            os.remove(tar)
        except OSError:
            pass
    if proc.returncode != 0:
        log.warning("trivy scan of %s failed: %s", image, proc.stderr[-300:])
        return []
    return _parse_trivy(proc.stdout)


def run_scan(conn, engine=None, now=None):
    """Scan all running images, reconcile the vulnerabilities table, emit events
    for newly-seen KEV-listed CVEs. Returns a summary dict."""
    now = now or time.time()
    kev = fetch_kev()
    existing = {(r["cve"], r["image"], r["pkg"])
                for r in conn.execute("SELECT cve,image,pkg FROM vulnerabilities")}
    total = kev_hits = new_kev = 0

    # host OS packages (no Docker needed) + running container images (if Docker)
    targets = []   # (label, [vulns])
    host_label = None
    if config.CVE_SCAN_HOST:
        host_label, host_vulns = scan_rootfs()
        if host_label:
            targets.append((host_label, host_vulns))
    images = running_images()
    for image in images:
        targets.append((image, scan_image(image)))

    for image, vulns in targets:
        for v in vulns:
            if not v["cve"]:
                continue
            total += 1
            in_kev = 1 if v["cve"] in kev else 0
            kev_hits += in_kev
            key = (v["cve"], image, v["pkg"])
            is_new = key not in existing
            conn.execute(
                "INSERT INTO vulnerabilities(cve,image,pkg,installed,fixed,severity,"
                "in_kev,title,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(cve,image,pkg) DO UPDATE SET last_seen=?, in_kev=?, "
                "fixed=excluded.fixed, severity=excluded.severity",
                (v["cve"], image, v["pkg"], v["installed"], v["fixed"], v["severity"],
                 in_kev, v["title"], now, now, now, in_kev))
            if is_new and in_kev and engine is not None:
                new_kev += 1
                fix = f"; fix: upgrade {v['pkg']} to {v['fixed']}" if v["fixed"] else \
                    "; no fix published yet"
                engine.emit("", "cve_kev", "high",
                            f"{v['cve']} ({v['severity']}) in {image} [{v['pkg']} "
                            f"{v['installed']}] is on the CISA KEV list — ACTIVELY "
                            f"EXPLOITED in the wild{fix}", host="cve", now=now)
    conn.commit()
    log.info("cve scan: host=%s, %d images, %d HIGH/CRIT findings, %d KEV (%d new)",
             bool(host_label), len(images), total, kev_hits, new_kev)
    return {"images": len(images), "host_scanned": bool(host_label),
            "findings": total, "kev": kev_hits, "new_kev": new_kev, "scanned_at": now}
