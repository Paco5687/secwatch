"""Self-update — a node is a git checkout of the install repo, so updating is
`git pull` (+ reinstall deps if they changed) + restart the service.

Two ways it runs:
  • locally — the operator clicks "Update this node" (or UPDATE_AUTO checks the
    origin on a schedule and updates if behind);
  • fleet-wide — a peer triggers an update campaign (see cluster.py). Reachable
    peers get it pushed; a leaf (not reachable) PULLs it on its next cycle. Either
    way the node ends up calling self_update() here.

Everything is best-effort and guarded: no git checkout / no systemd → it reports
why it can't, rather than half-updating. The restart is detached (a short-lived
child) so the HTTP response returns before systemd kills this process.
"""
import logging
import os
import re
import shutil
import subprocess
import sys
import threading

from . import __version__, config
from .config import BASE_DIR

log = logging.getLogger("secwatch.update")

_lock = threading.Lock()
_VERSION_RE = re.compile(r'__version__\s*=\s*["\']([^"\']+)["\']')


def _git(*args, timeout=120):
    """Run git in the repo dir; return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(["git", "-C", str(BASE_DIR), *args],
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def is_git_checkout():
    return shutil.which("git") is not None and (BASE_DIR / ".git").exists()


def _upstream_ref():
    """The tracking ref to compare/pull against (e.g. origin/main)."""
    rc, out, _ = _git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if rc == 0 and out:
        return out
    return "origin/main"


def _remote_version(ref):
    """Parse __version__ from the fetched upstream copy of __init__.py."""
    rc, out, _ = _git("show", f"{ref}:secwatch/__init__.py")
    if rc == 0:
        m = _VERSION_RE.search(out)
        if m:
            return m.group(1)
    return None


def status(fetch=True):
    """Report current vs available version. `fetch=True` contacts the origin."""
    if not is_git_checkout():
        return {"current": __version__, "supported": False,
                "reason": "not a git checkout — update via your package manager or reinstall",
                "behind": False, "auto": config.UPDATE_AUTO,
                "allow_remote": config.UPDATE_ALLOW_REMOTE}
    ref = _upstream_ref()
    fetch_err = None
    if fetch:
        rc, _, err = _git("fetch", "--quiet", timeout=60)
        if rc != 0:
            fetch_err = err or "git fetch failed"
    rc, local, _ = _git("rev-parse", "HEAD")
    rc2, remote, _ = _git("rev-parse", ref)
    # count how many commits we're behind the upstream tip
    behind_n = 0
    rcc, cnt, _ = _git("rev-list", "--count", f"HEAD..{ref}")
    if rcc == 0 and cnt.isdigit():
        behind_n = int(cnt)
    behind = bool(local and remote and local != remote and behind_n > 0)
    return {"current": __version__, "supported": True, "behind": behind,
            "behind_commits": behind_n, "latest": _remote_version(ref) or "(unknown)",
            "upstream": ref, "local_sha": local[:9], "remote_sha": remote[:9],
            "fetch_error": fetch_err, "auto": config.UPDATE_AUTO,
            "allow_remote": config.UPDATE_ALLOW_REMOTE, "updating": _lock.locked()}


def _reinstall_deps():
    """Reinstall pinned deps into the running interpreter's environment. Only
    called when requirements.txt actually changed. Prefers uv if this looks like
    a uv venv; falls back to pip. Best-effort — logs and continues on failure."""
    req = BASE_DIR / "requirements.txt"
    if not req.exists():
        return
    uv = shutil.which("uv") or str(BASE_DIR / ".uv" / "bin" / "uv")
    env = dict(os.environ, VIRTUAL_ENV=os.path.dirname(os.path.dirname(sys.executable)))
    cmds = []
    if os.path.exists(uv):
        cmds.append([uv, "pip", "install", "-r", str(req)])
    cmds.append([sys.executable, "-m", "pip", "install", "-r", str(req)])
    for cmd in cmds:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
            if p.returncode == 0:
                log.info("deps reinstalled via %s", os.path.basename(cmd[0]))
                return
            log.warning("deps reinstall (%s) failed: %s", cmd[0], (p.stderr or "")[-200:])
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("deps reinstall (%s) errored: %s", cmd[0], exc)
    log.warning("could not reinstall deps automatically — re-run install.sh if the "
                "service fails to start")


def _restart_cmd():
    """How to restart THIS node's service, matching how install.sh set it up:
    a root/system unit restarts directly; otherwise the per-user unit."""
    def active(args):
        try:
            p = subprocess.run(["systemctl", *args, "is-active", "secwatch"],
                               capture_output=True, text=True, timeout=10)
            return p.stdout.strip() == "active"
        except (OSError, subprocess.TimeoutExpired):
            return False
    if not shutil.which("systemctl"):
        return None
    if active([]):            # system unit (service runs as root → no sudo needed)
        return "systemctl restart secwatch"
    if active(["--user"]):    # per-user unit
        return "systemctl --user restart secwatch"
    return None


def _schedule_restart():
    """Restart after a short delay in a detached child, so the caller's HTTP
    response is sent and flushed before systemd SIGTERMs us."""
    cmd = _restart_cmd()
    if not cmd:
        log.warning("update: couldn't determine how to restart the service — "
                    "restart secwatch manually to run the new code")
        return False
    try:
        subprocess.Popen(["sh", "-c", f"sleep 3; {cmd}"], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info("update: restart scheduled (%s)", cmd)
        return True
    except OSError as exc:
        log.warning("update: failed to schedule restart: %s", exc)
        return False


def self_update(reason="manual"):
    """git pull the upstream tip, reinstall deps if they changed, and schedule a
    restart. Returns (ok, message). Non-blocking on the restart itself."""
    if not is_git_checkout():
        return False, "not a git checkout — can't self-update; reinstall to upgrade"
    if not _lock.acquire(blocking=False):
        return False, "an update is already in progress"
    try:
        ref = _upstream_ref()
        _git("fetch", "--quiet", timeout=60)
        rc, before, _ = _git("rev-parse", "HEAD")
        rc2, remote, _ = _git("rev-parse", ref)
        if rc == 0 and rc2 == 0 and before == remote:
            return True, f"already up to date ({__version__})"
        # snapshot requirements to see if we must reinstall
        rcq, req_before, _ = _git("show", "HEAD:requirements.txt")
        rc, out, err = _git("merge", "--ff-only", ref, timeout=120)
        if rc != 0:
            # local commits/dirty tree block a fast-forward — don't clobber, report
            return False, (f"git update failed (local changes block a fast-forward "
                           f"update): {err or out}")[:300]
        rcq2, req_after, _ = _git("show", "HEAD:requirements.txt")
        if req_before != req_after:
            log.info("update (%s): requirements.txt changed — reinstalling deps", reason)
            _reinstall_deps()
        new_ver = _remote_version("HEAD") or __version__
        log.info("update (%s): %s → %s, restarting", reason, __version__, new_ver)
        restarting = _schedule_restart()
        msg = f"updated to {new_ver}" + (" — restarting now" if restarting else
              " — restart the service to run it")
        return True, msg
    finally:
        _lock.release()
