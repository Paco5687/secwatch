"""SSH / auth.log monitoring: brute force, first-seen logins, new users, sudo."""
import logging
import re
import time
from collections import defaultdict, deque

from . import config, db, tailer

log = logging.getLogger("secwatch.auth")

FAILED_RE = re.compile(
    r"sshd(?:-session)?\[\d+\]: Failed \S+ for (?:invalid user )?(\S+) from (\S+)")
INVALID_RE = re.compile(r"sshd(?:-session)?\[\d+\]: Invalid user (\S*) from (\S+)")
ACCEPTED_RE = re.compile(
    r"sshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+)")
SUDO_RE = re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.+)$")
NEWUSER_RE = re.compile(r"useradd\[\d+\]: new user: name=([^,]+)")
NEWGROUP_SUDO_RE = re.compile(r"usermod\[\d+\]:.*'(sudo|admin|docker)'")


class AuthWatcher:
    def __init__(self, engine, conn):
        self.engine = engine
        self.conn = conn
        self.fails = defaultdict(deque)  # ip -> timestamps
        self._last_state = None

    async def run(self):
        state = db.meta_get(self.conn, "authtail")
        initial = None
        if state and ":" in state:
            ino, off = state.split(":")
            initial = (int(ino), int(off))
        async for line, ino, off in tailer.follow(
                config.AUTH_LOG_FILE, initial, start_at_end=True):
            if line and "CRON" not in line:
                try:
                    self.handle(line)
                except Exception:
                    log.exception("failed on line: %r", line[:200])
            state = f"{ino}:{off}"
            if state != self._last_state:
                # only write when the offset moved — idle heartbeats must not
                # open write transactions (they'd hold the WAL lock ~forever)
                db.meta_set(self.conn, "authtail", state)
                self._last_state = state
            # commit rides along with the engine's periodic flush

    def handle(self, line, now=None):
        now = now or time.time()

        m = FAILED_RE.search(line) or INVALID_RE.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            dq = self.fails[ip]
            dq.append(now)
            while dq and dq[0] < now - config.SSH_BRUTE_WINDOW:
                dq.popleft()
            if len(dq) >= config.SSH_BRUTE_LIMIT:
                self.engine.emit(
                    ip, "ssh_brute", ("high", "medium"),
                    f"{len(dq)} failed SSH logins in "
                    f"{config.SSH_BRUTE_WINDOW // 60} min (last user: {user!r})",
                    host="ssh", count=len(dq), now=now)
            return

        m = ACCEPTED_RE.search(line)
        if m:
            method, user, ip = m.groups()
            known = self.conn.execute(
                "SELECT 1 FROM ssh_known WHERE user=? AND ip=?", (user, ip)
            ).fetchone()
            self.conn.execute(
                "INSERT OR IGNORE INTO ssh_known(user,ip,first_seen) VALUES(?,?,?)",
                (user, ip, now))
            if not known:
                self.engine.emit(
                    ip, "ssh_login", ("high", "info"),
                    f"SSH login for {user!r} via {method} from never-before-seen IP",
                    host="ssh", now=now)
            self.fails.pop(ip, None)
            return

        m = NEWUSER_RE.search(line)
        if m:
            self.engine.emit("", "new_user", "high",
                             f"system user created: {m.group(1)!r}",
                             host="host", now=now)
            return

        m = NEWGROUP_SUDO_RE.search(line)
        if m:
            self.engine.emit("", "priv_group", "high",
                             f"account added to privileged group: {line.strip()[-160:]}",
                             host="host", now=now)
            return

        m = SUDO_RE.search(line)
        if m:
            user, cmd = m.groups()
            self.engine.emit("", "sudo", "info",
                             f"sudo by {user}: {cmd[:160]}", host="host", now=now)
