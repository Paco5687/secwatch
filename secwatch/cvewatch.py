"""CVE / vulnerability awareness.

Scans the running container images with Trivy (run as a container — no host
install, no root), cross-references the CISA KEV catalog (actively-exploited
CVEs), and stores findings. New KEV-listed vulns alert loudly; other HIGH/CRITICAL
findings are recorded for the dashboard without alert-spam.

Blocking (docker + network) — driven from a worker thread by web.py.
"""
import json
import logging
import subprocess
import time
import urllib.request

from . import config, db

log = logging.getLogger("secwatch.cve")


def running_images():
    out = subprocess.run(["docker", "ps", "--format", "{{.Image}}"],
                         capture_output=True, text=True, timeout=30)
    return sorted({ln.strip() for ln in out.stdout.splitlines() if ln.strip()})


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
    import os
    tar = os.path.join(config.TRIVY_CACHE, "scan.tar")
    try:
        save = subprocess.run(["docker", "save", "-o", tar, image],
                              capture_output=True, text=True,
                              timeout=config.CVE_SCAN_TIMEOUT)
        if save.returncode != 0:
            log.warning("docker save %s failed: %s", image, save.stderr[-200:])
            return []
        proc = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{config.TRIVY_CACHE}:/root/.cache/",
             config.TRIVY_IMAGE, "image", "--quiet",
             "--severity", config.CVE_SEVERITIES, "--format", "json",
             "--scanners", "vuln", "--input", "/root/.cache/scan.tar"],
            capture_output=True, text=True, timeout=config.CVE_SCAN_TIMEOUT)
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
    try:
        doc = json.loads(proc.stdout or "{}")
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


def run_scan(conn, engine=None, now=None):
    """Scan all running images, reconcile the vulnerabilities table, emit events
    for newly-seen KEV-listed CVEs. Returns a summary dict."""
    now = now or time.time()
    kev = fetch_kev()
    images = running_images()
    existing = {(r["cve"], r["image"], r["pkg"])
                for r in conn.execute("SELECT cve,image,pkg FROM vulnerabilities")}
    total = kev_hits = new_kev = 0

    for image in images:
        for v in scan_image(image):
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
    log.info("cve scan: %d images, %d HIGH/CRIT findings, %d KEV (%d new)",
             len(images), total, kev_hits, new_kev)
    return {"images": len(images), "findings": total, "kev": kev_hits,
            "new_kev": new_kev, "scanned_at": now}
