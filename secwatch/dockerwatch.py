"""Docker container + systemd unit watch: new/changed containers, restart
loops, and newly failing systemd units. Baseline persists in host_baseline
(keys docker:* / unit:*) so a secwatch restart doesn't re-announce the world.
"""
import asyncio
import logging
import time

from . import config

log = logging.getLogger("secwatch.docker")


async def _run(*argv):
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    out, _ = await proc.communicate()
    return out.decode(errors="replace") if proc.returncode == 0 else ""


class DockerWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn
        self.restart_counts = {}

    async def run(self):
        while True:
            try:
                await self.check()
            except Exception:
                log.exception("docker/systemd poll failed")
            await asyncio.sleep(config.DOCKER_POLL_INTERVAL)

    async def check(self, now=None):
        now = now or time.time()
        baseline = {r["key"]: r["value"] for r in self.conn.execute(
            "SELECT key, value FROM host_baseline WHERE key LIKE 'docker:%' "
            "OR key LIKE 'unit:%'")}
        first_run = not baseline
        seen = {}

        out = await _run("docker", "ps", "-a", "--format",
                         "{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}")
        for ln in out.splitlines():
            try:
                name, image, state, status = ln.split("\t", 3)
            except ValueError:
                continue
            key = f"docker:{name}"
            seen[key] = f"{image}|{state}"
            old = baseline.get(key)
            if old is None:
                if not first_run:
                    self.engine.emit("", "docker_new", "medium",
                                     f"new container {name!r} (image {image})",
                                     host="docker", now=now)
            else:
                old_image, old_state = (old.split("|", 1) + [""])[:2]
                if old_image != image:
                    self.engine.emit(
                        "", "docker_image", "medium",
                        f"container {name!r} image changed: "
                        f"{old_image} → {image}", host="docker", now=now)
                if old_state == "running" and state in ("exited", "dead"):
                    self.engine.emit("", "docker_down", "low",
                                     f"container {name!r} is {state} ({status})",
                                     host="docker", now=now)
            if state == "restarting":
                self.engine.emit("", "docker_restart_loop", "medium",
                                 f"container {name!r} is restart-looping",
                                 host="docker", now=now)

        for scope, argv in (
            ("system", ("systemctl", "--failed", "--no-legend", "--plain")),
            ("user", ("systemctl", "--user", "--failed", "--no-legend", "--plain")),
        ):
            out = await _run(*argv)
            for ln in out.splitlines():
                unit = ln.split()[0] if ln.split() else ""
                if not unit.endswith(".service") and not unit.endswith(".timer"):
                    continue
                key = f"unit:{scope}:{unit}"
                seen[key] = "failed"
                if key not in baseline and not first_run:
                    self.engine.emit("", "unit_failed", "medium",
                                     f"systemd {scope} unit failed: {unit}",
                                     host="systemd", now=now)

        # persist: add/update seen, drop entries that no longer exist
        for key, value in seen.items():
            if baseline.get(key) != value:
                self.conn.execute(
                    "INSERT INTO host_baseline(key,value,updated) VALUES(?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "updated=excluded.updated", (key, value, now))
        for key in set(baseline) - set(seen):
            self.conn.execute("DELETE FROM host_baseline WHERE key=?", (key,))
        self.conn.commit()
        if first_run:
            log.info("docker/systemd baseline initialized (%d entries)", len(seen))
