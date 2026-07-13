"""Detection engine: sliding-window rules over parsed access-log records.

Rules:
  probe       — request path matches a known vuln-scan / recon pattern
  scan        — burst of 4xx responses from one IP (path enumeration)
  flood       — raw request-rate anomaly from one IP
  scripted    — raw HTTP client (python-requests, curl, ...) at volume
  crawler     — self-declared bot UA at volume
  cred_stuff  — burst of POSTs against the configured login-flow host from one IP
"""
import ipaddress
import logging
import re
import time
from collections import defaultdict, deque

from . import config

log = logging.getLogger("secwatch.detect")

PROBE_RE = re.compile(
    r"(?i)("
    r"\.env(\.|$|\b)|\.git(/|$)|wp-login|wp-admin|wp-includes|xmlrpc\.php|"
    r"phpmyadmin|/vendor/phpunit|eval-stdin|/actuator(/|$)|/\.aws/|/etc/passwd|"
    r"\.\./\.\.|/cgi-bin/|/boaform|/hnap1|/solr/|/owa/|/autodiscover|/\.ds_store|"
    r"/server-status|id_rsa|\.sql($|\?)|/telescope(/|$)|/_profiler|/sftp\.json|"
    r"/login\.action|/manager/html|/jmx-console|/\.vscode/|/\.ssh/|/config\.php|"
    r"/wlwmanifest|\\x[0-9a-f]{2}"
    r")"
)

# Unambiguous secret/credential-file probes — zero legitimate use. Deliberately
# does NOT match /.well-known/ (legit: ACME, security.txt).
SECRET_PROBE_RE = re.compile(
    r"(?i)("
    # Match the dangerous token anywhere it appears as a path segment — do NOT
    # require a specific terminator, or variants slip through: /.env.sample.php,
    # /.env~, /.env.production.local, /.git-credentials, etc. Nothing legitimate
    # on these apps contains /.env, /.git, /.aws, or /.ssh.
    r"/\.env|/\.git|/\.aws|/\.ssh|"
    r"/id_rsa|/id_dsa|/id_ecdsa|/id_ed25519|"
    r"/\.htpasswd|/\.htaccess|"
    r"/\.npmrc|/\.dockercfg|/\.docker/config|"
    r"/wp-config\.php|/config\.php\.(bak|old|save|txt|orig)|"
    r"/\.DS_Store|/\.svn(/|$)|/\.hg(/|$)|/\.bzr(/|$)|"
    r"/\.vscode(/|$)|/\.idea(/|$)|"
    r"/\.pem($|[?])|/\.key($|[?])|/privkey\.pem|/server\.key|"
    r"\.sql($|[?])|\.sql\.(gz|zip|bz2)|/dump\.(sql|rdb)|"
    r"/backup\.(sql|zip|tar|tar\.gz|tgz|rar)|/db\.(sql|sqlite)|"
    r"/\.travis\.ya?ml|/\.circleci(/|$)|/\.gitlab-ci\.yml|"
    r"/phpinfo\.php|/\.bash_history|/\.mysql_history"
    r")")

SCRIPTED_UA_RE = re.compile(
    r"(?i)^(python-requests|python-httpx|python-urllib|aiohttp|go-http-client|"
    r"curl|wget|libwww|okhttp|java|scrapy|node-fetch|axios|ruby|perl|winhttp)"
)
CRAWLER_UA_RE = re.compile(r"(?i)(bot|spider|crawl|scan(?:ner)?)\b")

TRUSTED = [ipaddress.ip_network(n.strip()) for n in config.TRUSTED_NETS if n.strip()]


def _compile_endpoint_rules():
    compiled = []
    for r in config.ENDPOINT_RULES:
        rr = dict(r)
        rr["_re"] = re.compile(r["path_re"])
        hosts = r.get("hosts", ["*"])
        rr["_any_host"] = "*" in hosts
        rr["_hosts"] = set(hosts)
        rr["_statuses"] = set(r.get("statuses", []))
        compiled.append(rr)
    return compiled

# How long one triggered rule keeps an IP "hot" before its windows are relevant again
IDLE_PRUNE_SECS = 3600
MAX_TRACKED_IPS = 20000


def is_trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in TRUSTED)


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class _IpState:
    __slots__ = ("req", "e4xx", "auth", "last_seen")

    def __init__(self):
        self.req = deque()
        self.e4xx = deque()
        self.auth = deque()
        self.last_seen = 0.0


class Engine:
    """Feeds records, writes events + traffic rollups to sqlite, queues alerts."""

    def __init__(self, conn, alert_cb, ban_cb=None, forward_cb=None):
        self.conn = conn
        self.alert_cb = alert_cb
        self.ban_cb = ban_cb
        # agent mode: emit() forwards events to a core instead of local processing
        self.forward_cb = forward_cb
        self.ips = defaultdict(_IpState)
        self.suppress = {}       # (ip, rule) -> until_ts (event dedup)
        self.alert_gate = {}     # (ip, rule) -> until_ts (alert cooldown)
        self.traffic_buf = defaultdict(lambda: [0, 0, 0])   # minute -> [req,4xx,5xx]
        self.ip_buf = defaultdict(lambda: [0, 0])           # (minute,ip) -> [req,4xx]
        self.last_flush = 0.0
        # per log-source tail offsets {source_key: (inode, offset)}, persisted on flush
        self.tail_states = {}
        self._flushed_tail_states = {}
        # per log-source liveness for the dashboard {path: {records, last_ts}}
        self.source_status = {}
        self.last_log_line_ts = 0.0   # updated on every parsed access-log line
        # host -> True (catch-all SPA: 200s any path) / False (real backend).
        # A probe path returning 200 only means "hit" on a real backend; a SPA
        # serves its app shell for everything, so a 200 there is noise.
        self.catchall = {}
        self.catchall_pending = set()
        # custom endpoint detection
        self._endpoint_rules = _compile_endpoint_rules()
        self.ep_win = defaultdict(deque)   # (rule, ip) -> timestamps
        self.ep_enum = defaultdict(dict)   # (rule, ip) -> {id: last_ts}
        self.ban_rules = set(config.BAN_RULES)
        if config.SECRET_PROBE_BAN:
            self.ban_rules.add("secret_probe")
        self.ban_rules |= {r["name"] for r in config.ENDPOINT_RULES if r.get("ban")}

    # ---- ingestion -------------------------------------------------------

    def feed(self, rec, now=None):
        now = now or time.time()
        self.last_log_line_ts = now
        ip, status, path, ua = rec["ip"], rec["status"], rec["path"], rec["ua"]
        minute = int(now // 60)

        t = self.traffic_buf[minute]
        t[0] += 1
        if 400 <= status < 500:
            t[1] += 1
        elif status >= 500:
            t[2] += 1
        b = self.ip_buf[(minute, ip)]
        b[0] += 1
        if 400 <= status < 500:
            b[1] += 1

        st = self.ips[ip]
        st.last_seen = now
        st.req.append(now)
        if 400 <= status < 500:
            st.e4xx.append(now)
        self._trim(st.req, now - max(config.RATE_WINDOW, config.BOT_WINDOW))
        self._trim(st.e4xx, now - config.SCAN_WINDOW)

        trusted = is_trusted(ip)

        if SECRET_PROBE_RE.search(path):
            if trusted:
                self._event(now, ip, "secret_probe", "info", rec,
                            f"secret-file path {path[:120]} from trusted source")
            else:
                self._event(now, ip, "secret_probe", "high", rec,
                            f"secret/credential-file probe: {path[:120]} "
                            f"— banned on sight (no legitimate use)")
        elif PROBE_RE.search(path):
            hit = 200 <= status < 300
            if trusted:
                sev = "info"
                detail = f"vuln-probe path{' RETURNED ' + str(status) if hit else ''}"
            elif not hit:
                sev, detail = "medium", "vuln-probe path (no successful response)"
            else:
                verdict = self.catchall.get(rec["host"])
                if verdict is True:
                    sev = "low"
                    detail = (f"probe path returned {status}, but {rec['host']} is a "
                              f"catch-all SPA that serves its app shell for any path "
                              f"— not a real endpoint")
                elif verdict is False:
                    sev = "high"
                    detail = f"vuln-probe path RETURNED {status} from a real backend"
                else:
                    # unknown host: stay below alert/ban threshold and queue a
                    # classification so future hits are judged correctly
                    sev = "medium"
                    detail = (f"vuln-probe path returned {status}; {rec['host']} "
                              f"not yet classified as SPA vs real backend")
                    self.catchall_pending.add(rec["host"])
            self._event(now, ip, "probe", sev, rec, detail)

        if trusted:
            return

        if len(st.e4xx) >= config.SCAN_4XX_LIMIT:
            self._event(now, ip, "scan", "high", rec,
                        f"{len(st.e4xx)} 4xx responses in {config.SCAN_WINDOW}s",
                        count=len(st.e4xx))

        recent = sum(1 for ts in st.req if ts >= now - config.RATE_WINDOW)
        if recent >= config.RATE_LIMIT:
            self._event(now, ip, "flood", "high", rec,
                        f"{recent} requests in {config.RATE_WINDOW}s", count=recent)

        if len(st.req) >= config.BOT_MIN_REQS:
            if not ua:
                self._event(now, ip, "scripted", "medium", rec,
                            f"empty User-Agent, {len(st.req)} reqs in {config.BOT_WINDOW}s",
                            count=len(st.req))
            elif SCRIPTED_UA_RE.search(ua):
                self._event(now, ip, "scripted", "medium", rec,
                            f"raw HTTP client at volume ({len(st.req)} reqs "
                            f"in {config.BOT_WINDOW}s)", count=len(st.req))
            elif CRAWLER_UA_RE.search(ua):
                self._event(now, ip, "crawler", "low", rec,
                            f"declared bot at volume ({len(st.req)} reqs "
                            f"in {config.BOT_WINDOW}s)", count=len(st.req))

        if (rec["method"] == "POST" and rec["host"] == config.AUTH_HOST
                and any(m in path for m in config.AUTH_PATH_MARKERS)):
            st.auth.append(now)
            self._trim(st.auth, now - config.STUFF_WINDOW)
            if len(st.auth) >= config.STUFF_LIMIT:
                self._event(now, ip, "cred_stuff", "high", rec,
                            f"{len(st.auth)} login-flow POSTs in "
                            f"{config.STUFF_WINDOW}s", count=len(st.auth))

        self._check_endpoints(now, ip, rec)

    def _check_endpoints(self, now, ip, rec):
        """Custom per-app-endpoint rules (untrusted IPs only — caller-gated)."""
        path, status, host = rec["path"], rec["status"], rec["host"]
        for r in self._endpoint_rules:
            if not (r["_any_host"] or host in r["_hosts"]):
                continue
            m = r["_re"].search(path)
            if not m:
                continue
            typ = r["type"]
            if typ == "privileged":
                if status in r["_statuses"]:
                    self._event(now, ip, r["name"], r["severity"], rec,
                                f"unauthorized ({status}) hit on privileged "
                                f"endpoint {r['label']}: {path[:100]}")
            elif typ == "auth_abuse":
                if status in r["_statuses"]:
                    dq = self.ep_win[(r["name"], ip)]
                    dq.append(now)
                    self._trim(dq, now - r["window"])
                    if len(dq) >= r["limit"]:
                        self._event(now, ip, r["name"], r["severity"], rec,
                                    f"{len(dq)} failed {r['label']} attempts in "
                                    f"{r['window'] // 60} min", count=len(dq))
            elif typ == "rate":
                dq = self.ep_win[(r["name"], ip)]
                dq.append(now)
                self._trim(dq, now - r["window"])
                if len(dq) >= r["limit"]:
                    self._event(now, ip, r["name"], r["severity"], rec,
                                f"{len(dq)} requests to {r['label']} in "
                                f"{r['window'] // 60} min (possible scraping)",
                                count=len(dq))
            elif typ == "enumeration":
                token = m.group(m.lastindex) if m.lastindex else path
                d = self.ep_enum[(r["name"], ip)]
                d[token] = now
                if len(d) > 8:
                    cutoff = now - r["window"]
                    for k in [k for k, t in d.items() if t < cutoff]:
                        del d[k]
                if len(d) >= r["limit"]:
                    self._event(now, ip, r["name"], r["severity"], rec,
                                f"{len(d)} distinct IDs on {r['label']} in "
                                f"{r['window'] // 60} min (enumeration / IDOR)",
                                count=len(d))

    def emit(self, ip, rule, severity, detail, host="", path="", ua="",
             count=1, now=None):
        """Entry point for non-HTTP collectors (ssh, host, docker watchers).

        Severity may be passed as (untrusted_sev, trusted_sev) to downgrade
        events originating from trusted networks.
        """
        now = now or time.time()
        if isinstance(severity, tuple):
            severity = severity[1] if (ip and is_trusted(ip)) else severity[0]
        if self.forward_cb:   # agent mode → ship to the core, don't process locally
            self.forward_cb({"ts": now, "ip": ip or "-", "rule": rule,
                             "severity": severity, "detail": detail, "host": host,
                             "path": path, "ua": ua, "count": count})
            return
        rec = {"host": host, "path": path, "ua": ua}
        self._event(now, ip or "-", rule, severity, rec, detail, count=count)

    # ---- internals -------------------------------------------------------

    @staticmethod
    def _trim(dq, cutoff):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _event(self, now, ip, rule, severity, rec, detail, count=1):
        key = (ip, rule)
        if self.suppress.get(key, 0) > now:
            return
        self.suppress[key] = now + config.EVENT_SUPPRESS

        alert = (
            config.SEVERITY_RANK[severity]
            >= config.SEVERITY_RANK[config.ALERT_MIN_SEVERITY]
            and self.alert_gate.get(key, 0) <= now
        )
        if alert:
            self.alert_gate[key] = now + config.ALERT_COOLDOWN

        self.conn.execute(
            "INSERT INTO events(ts,ip,rule,severity,host,path,ua,detail,count,alerted)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (now, ip, rule, severity, rec["host"], rec["path"][:500],
             rec["ua"][:300], detail, count, int(alert)),
        )
        if alert and self.alert_cb:
            self.alert_cb({
                "ts": now, "ip": ip, "rule": rule, "severity": severity,
                "host": rec["host"], "path": rec["path"][:500],
                "ua": rec["ua"][:300], "detail": detail, "count": count,
            })
        if (self.ban_cb and config.AUTOBAN and severity == "high"
                and rule in self.ban_rules and ip and not is_trusted(ip)
                and (config.AUTOBAN_PRIVATE or not is_private(ip))):
            self.ban_cb(ip, rule, detail)

    def maybe_flush(self, now=None, force=False):
        now = now or time.time()
        if not force and now - self.last_flush < 5:
            return
        self.last_flush = now
        for minute, (r, e4, e5) in self.traffic_buf.items():
            self.conn.execute(
                "INSERT INTO traffic(minute,requests,s4xx,s5xx) VALUES(?,?,?,?) "
                "ON CONFLICT(minute) DO UPDATE SET requests=requests+excluded.requests,"
                " s4xx=s4xx+excluded.s4xx, s5xx=s5xx+excluded.s5xx",
                (minute, r, e4, e5),
            )
        for (minute, ip), (r, e4) in self.ip_buf.items():
            self.conn.execute(
                "INSERT INTO ip_minute(minute,ip,requests,s4xx) VALUES(?,?,?,?) "
                "ON CONFLICT(minute,ip) DO UPDATE SET requests=requests+excluded.requests,"
                " s4xx=s4xx+excluded.s4xx",
                (minute, ip, r, e4),
            )
        self.traffic_buf.clear()
        self.ip_buf.clear()
        for key, st in list(self.tail_states.items()):
            if st and st != self._flushed_tail_states.get(key):
                self.conn.execute(
                    "INSERT INTO meta(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (f"tail:{key}", "%d:%d" % st),
                )
                self._flushed_tail_states[key] = st
        if self.conn.in_transaction:
            self.conn.commit()
        self._prune_idle(now)

    def _prune_idle(self, now):
        if len(self.ips) <= MAX_TRACKED_IPS:
            cutoff = now - IDLE_PRUNE_SECS
        else:
            cutoff = now - 300
        for ip in [ip for ip, st in self.ips.items() if st.last_seen < cutoff]:
            del self.ips[ip]
        for d in (self.suppress, self.alert_gate):
            for k in [k for k, until in d.items() if until < now]:
                del d[k]
        stale = now - 3600
        for k in [k for k, dq in self.ep_win.items() if not dq or dq[-1] < stale]:
            del self.ep_win[k]
        for k in [k for k, d in self.ep_enum.items()
                  if not d or max(d.values()) < stale]:
            del self.ep_enum[k]
