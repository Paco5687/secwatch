"""secwatch configuration.

Resolution order for every value: environment variable (SECWATCH_*) wins, then
the site config file (`secwatch.yaml`, or $SECWATCH_CONFIG), then a generic
built-in default. Host/site-specifics (endpoint rules, trusted nets, app hosts,
FIM dirs, proxy paths, integrations) live in `secwatch.yaml` — NOT in this file —
so the code is portable and shareable. See `secwatch.example.yaml`.
"""
import json
import os
import socket
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parents[1]


def _load_site_config():
    path = Path(os.environ.get("SECWATCH_CONFIG", BASE_DIR / "secwatch.yaml"))
    if path.exists():
        try:
            with open(path) as f:
                return yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as exc:  # never crash on a bad config
            import logging
            logging.getLogger("secwatch.config").error(
                "failed to load %s: %s — using defaults", path, exc)
    return {}


_cfg = _load_site_config()

# In-app editable overrides (Settings page). Layer BETWEEN env and yaml so a UI
# edit wins over the declarative secwatch.yaml but an explicit env var still wins
# over the UI (containers/ops). settings.py imports nothing from secwatch.
from . import settings as _settings  # noqa: E402
_overrides = _settings.load_overrides()


def _y(dotted, default=None):
    """Read a dotted key from the site config, else default."""
    node = _cfg
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return default
    return node


def _s(env_name, dotted, default):
    """Scalar: env var wins, then in-app override, then site config, then default."""
    v = os.environ.get(env_name) if env_name else None
    if v is not None:
        return v
    if dotted in _overrides:
        return _overrides[dotted]
    y = _y(dotted)
    return y if y is not None else default


def _bool(env_name, dotted, default):
    v = os.environ.get(env_name) if env_name else None
    if v is not None:
        return v == "1"
    if dotted in _overrides:
        return bool(_overrides[dotted])
    y = _y(dotted)
    return bool(y) if y is not None else default


def _list(env_name, dotted, default):
    """List: comma-string env var wins, then in-app override, then site config."""
    v = os.environ.get(env_name) if env_name else None
    if v is not None:
        return [x.strip() for x in v.split(",") if x.strip()]
    if dotted in _overrides:
        ov = _overrides[dotted]
        return list(ov) if isinstance(ov, list) else \
            [x.strip() for x in str(ov).split(",") if x.strip()]
    y = _y(dotted)
    return list(y) if y is not None else list(default)


# ---- core paths / server ------------------------------------------------
DB_PATH = Path(os.environ.get("SECWATCH_DB", BASE_DIR / "data" / "secwatch.db"))
ACCESS_LOG = Path(_s("SECWATCH_ACCESS_LOG", "paths.access_log",
                     str(BASE_DIR / "logs" / "traefik" / "access.json.log")))
AUTH_LOG_FILE = Path(_s("SECWATCH_AUTH_LOG", "paths.auth_log", "/var/log/auth.log"))
DASHBOARD_URL = _s("SECWATCH_DASHBOARD_URL", "paths.dashboard_url",
                   "http://localhost:8931/")
# Optional header added to the dashboard's mutating (POST) requests — only needed
# when secwatch is fronted by a proxy that enforces a CSRF header. Empty = none.
PROXY_MUTATION_HEADER = _s(None, "dashboard.proxy_mutation_header", "")

# ---- log-source adapter(s) ----------------------------------------------
# traefik (JSON) | nginx (combined) | caddy (JSON) | regex (custom, needs regex)
LOG_SOURCE_TYPE = _s("SECWATCH_LOG_SOURCE", "log_source.type", "traefik")
LOG_SOURCE_REGEX = _s(None, "log_source.regex", "")


# Extra sources added at runtime via the dashboard (not the hand-edited YAML)
# are persisted here as a JSON list and merged in below. logsources.py manages it.
MANAGED_SOURCES_FILE = DB_PATH.parent / "log_sources.json"


def _read_managed_sources():
    try:
        with open(MANAGED_SOURCES_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _build_log_sources():
    """Watch several access logs at once (e.g. your reverse proxy AND a
    directly-exposed internal app). Site config `log_sources: [{path,type,regex}]`;
    otherwise wrap the single paths.access_log + log_source.* (back-compat).
    Dashboard-added sources (MANAGED_SOURCES_FILE) are appended on top."""
    srcs = _y("log_sources")
    out = []
    if isinstance(srcs, list) and srcs:
        for s in srcs:
            path = s.get("path")
            if not path:
                continue
            out.append({"path": path, "type": s.get("type", "traefik"),
                        "regex": s.get("regex", ""),
                        "name": s.get("name") or path})
    if not out:
        out = [{"path": str(ACCESS_LOG), "type": LOG_SOURCE_TYPE,
                "regex": LOG_SOURCE_REGEX, "name": "primary"}]
    out[0]["primary"] = True   # primary resumes the legacy 'tail' offset key
    seen = {s["path"] for s in out}
    for s in _read_managed_sources():
        path = s.get("path")
        if not path or path in seen:
            continue
        seen.add(path)
        out.append({"path": path, "type": s.get("type", "traefik"),
                    "regex": s.get("regex", ""), "name": s.get("name") or path,
                    "managed": True})
    return out


LOG_SOURCES = _build_log_sources()
LISTEN_HOST = os.environ.get("SECWATCH_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("SECWATCH_PORT", "8931"))

# Deployment mode:
#   all   — everything in one process (default; the classic single-host setup)
#   core  — detection/dashboard/CVE/LLM/alerting + ban; host collectors come
#           from a separate agent (containerized core without host access)
#   agent — ONLY host collectors (auth/host/persistence/process/docker); forwards
#           events to a core over HTTP (runs on the host, feeds a container core)
MODE = _s("SECWATCH_MODE", "mode", "all")
# Fleet identity: the label this instance stamps on the events it reports (its own,
# or — in agent mode — the ones it forwards to a core). Defaults to the hostname so
# a central hub can tell boxes apart. Keep it stable + unique across the fleet.
DEVICE = _s("SECWATCH_DEVICE", "device.name", socket.gethostname() or "secwatch")
CORE_URL = os.environ.get("SECWATCH_CORE_URL", "http://127.0.0.1:8931")
# Shared token for agent→core event ingestion (POST /api/ingest). Empty disables.
INGEST_TOKEN = _s("SECWATCH_INGEST_TOKEN", "hub.ingest_token", "")

# ---- cluster (P2P fleet, no central hub) --------------------------------
# Every node stays fully autonomous (detects + bans ITSELF); nodes gossip bans so
# a hit on one hardens the rest, and any peer can view the whole cluster. Explicit
# join (a shared secret), never auto-discovery. Roles are configurable — NOTHING
# host-specific is baked in:
#   standalone — not clustered (default)
#   peer       — full member: shares bans, serves + reads cluster telemetry (trusted)
#   leaf       — push-only member for exposed/less-trusted boxes: pushes its bans +
#                events to peers and pulls the cluster blocklist, but is NOT
#                queryable and does NOT read peers (contains a compromised edge box)
CLUSTER_ROLE = _s("SECWATCH_CLUSTER_ROLE", "cluster.role", "standalone")
CLUSTER_ENABLED = CLUSTER_ROLE in ("peer", "leaf")
CLUSTER_NAME = DEVICE  # a node's cluster identity is its device name
# The URL peers use to reach THIS node (e.g. http://10.20.0.5:8931). Required for
# a 'peer' (it gets queried); a 'leaf' can leave it blank (it's push-only).
CLUSTER_URL = _s("SECWATCH_CLUSTER_URL", "cluster.url", "")
CLUSTER_STORE = DB_PATH.parent / "cluster.json"     # peer roster (managed by CLI)
CLUSTER_SECRET_FILE = DB_PATH.parent / "cluster.secret"   # shared secret, chmod 600
CLUSTER_MAX_CLOCK_SKEW = int(_s(None, "cluster.max_clock_skew", 120))  # HMAC replay window
CLUSTER_GOSSIP_SECS = int(_s("SECWATCH_CLUSTER_GOSSIP", "cluster.gossip_secs", 60))
# Device enrollment ("Add device" one-liner → /install.sh). Tokens are single-use.
CLUSTER_ENROLL_TTL = int(_s(None, "cluster.enroll_ttl", 3600))       # token lifetime (s)
CLUSTER_INSTALL_REPO = _s(None, "cluster.install_repo",
                          "https://github.com/Paco5687/secwatch.git")
CLUSTER_INSTALL_DIR = _s(None, "cluster.install_dir", "/opt/secwatch")

# ---- crowd-sourced threat intel (OPT-IN, off by default) ----------------
# Optionally share confirmed bans (attacker IP + rule + timestamp ONLY — never
# your traffic or data) with a self-hostable aggregator, and pull its consensus
# community blocklist to pre-emptively block IPs many installs have flagged.
CROWD_ENABLED = _bool("SECWATCH_CROWD", "crowd.enabled", False)
CROWD_URL = _s("SECWATCH_CROWD_URL", "crowd.url", "")
CROWD_TOKEN = _s("SECWATCH_CROWD_TOKEN", "crowd.token", "")
CROWD_SHARE = _bool(None, "crowd.share", True)      # report my bans upstream
CROWD_CONSUME = _bool(None, "crowd.consume", True)  # pull + block the community list
CROWD_PULL_INTERVAL = int(_s(None, "crowd.pull_interval", 3600))
CROWD_BAN_TTL_HOURS = float(_s(None, "crowd.ban_ttl_hours", 72))
# --- aggregator side (only used when running `python -m secwatch.aggregator`) ---
AGG_DB = str(BASE_DIR / "data" / "aggregator.db")
AGG_TOKEN = os.environ.get("SECWATCH_AGG_TOKEN", "")        # required to run
AGG_PORT = int(os.environ.get("SECWATCH_AGG_PORT", "8950"))
AGG_CONSENSUS = int(os.environ.get("SECWATCH_AGG_CONSENSUS", "3"))  # distinct reporters
AGG_WINDOW_DAYS = int(os.environ.get("SECWATCH_AGG_WINDOW_DAYS", "7"))
AGG_MAX_REPORTS_PER_MIN = int(os.environ.get("SECWATCH_AGG_RATE", "120"))

# ---- network trust (site-specific) --------------------------------------
# Trusted = exempt from detection/ban. Keep this NARROW (server subnet + admin
# hosts), not the whole LAN, so a compromised device elsewhere is still watched.
# Generic default trusts only loopback + docker; real values come from the site
# config. See secwatch.example.yaml.
TRUSTED_NETS = _list("SECWATCH_TRUSTED_NETS", "network.trusted_nets",
                     ["127.0.0.0/8", "172.16.0.0/12"])
# Internal/RFC1918 anomalies alert but are not auto-banned by default (avoids
# blocking a legit device on a false positive); flip on to auto-ban them too.
AUTOBAN_PRIVATE = _bool("SECWATCH_AUTOBAN_PRIVATE", "network.autoban_private", False)
# External destinations that are known-good egress (won't alert). Cloudflare
# ranges are a sensible generic default (apps often sit behind CF).
EGRESS_ALLOWLIST_NETS = _list("SECWATCH_EGRESS_ALLOWLIST", "network.egress_allowlist", [
    "173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13", "104.24.0.0/14",
    "172.64.0.0/13", "131.0.72.0/22", "162.158.0.0/15", "198.41.128.0/17",
])

# ---- reverse proxy / ban actuator (site-specific) -----------------------
TRAEFIK_CONTAINER = _s("SECWATCH_TRAEFIK_CONTAINER", "proxy.traefik_container", "traefik")
TRAEFIK_DYNAMIC_DIR = Path(_s("SECWATCH_TRAEFIK_DYNAMIC", "proxy.traefik_dynamic_dir",
                              "/etc/traefik/dynamic"))
BANS_FILE = Path(_s("SECWATCH_BANS_FILE", "proxy.bans_file",
                    str(TRAEFIK_DYNAMIC_DIR / "secwatch-bans.yml")))
# secwatch rewrites this on every ban — don't alert on it.
TRAEFIK_CONFIG_SELF_MANAGED = {"secwatch-bans.yml"}

# ---- credential-stuffing target (site-specific) -------------------------
AUTH_HOST = _s("SECWATCH_AUTH_HOST", "credential_stuffing.host", "")
AUTH_PATH_MARKERS = tuple(_y("credential_stuffing.path_markers",
                             ("/api/v3/flows", "/if/flow")))

# ---- detection thresholds (generic — tune via site config if needed) ----
RATE_WINDOW, RATE_LIMIT = 60, int(_s(None, "thresholds.rate_limit", 300))
SCAN_WINDOW, SCAN_4XX_LIMIT = 60, int(_s(None, "thresholds.scan_4xx_limit", 20))
BOT_WINDOW, BOT_MIN_REQS = 300, int(_s(None, "thresholds.bot_min_reqs", 30))
STUFF_WINDOW, STUFF_LIMIT = 300, int(_s(None, "thresholds.stuff_limit", 12))
SECRET_PROBE_BAN = _bool("SECWATCH_SECRET_PROBE_BAN", "thresholds.secret_probe_ban", True)

# ---- custom per-endpoint detection (site-specific) ----------------------
# Declarative rules matched against the app's real edge paths. Types:
#   auth_abuse / privileged / rate / enumeration. See secwatch.example.yaml.
APP_HOSTS = _list(None, "app_hosts", [])
ENDPOINT_RULES = _y("endpoint_rules", []) or []

# ---- event/alert bookkeeping (generic) ----------------------------------
EVENT_SUPPRESS = 600
ALERT_COOLDOWN = 1800
ALERT_MIN_SEVERITY = _s("SECWATCH_ALERT_MIN_SEVERITY", "alerting.min_severity", "high")
# Anti-noise: these rules still BAN + record to the dashboard, but do NOT push a
# Discord alert on their own. They're the constant background of blocked internet
# scanning (secret-file probes, path scans, floods, hits on privileged endpoints
# that got 403'd) that every public host sees — alerting on each one is just
# fatigue and buries real signals (host/EDR events, successful probes, cred
# stuffing). An event from a PRIVATE/internal source still alerts (possible
# lateral movement). Tune in secwatch.yaml: alerting.quiet_rules: [...].
ALERT_QUIET_RULES = set(_list("SECWATCH_ALERT_QUIET_RULES", "alerting.quiet_rules",
    ["secret_probe", "scan", "flood", "privileged_access"]))
# When True, a quiet rule still alerts if the source IP is private/internal.
ALERT_QUIET_EXCEPT_PRIVATE = _bool(None, "alerting.quiet_except_private", True)
EVENT_RETENTION_DAYS = 14
IP_MINUTE_RETENTION_HOURS = 48
LOG_ROTATE_BYTES = 200 * 1024 * 1024

# ---- auto-ban (generic + CF exemption) ----------------------------------
AUTOBAN = _bool("SECWATCH_AUTOBAN", "ban.enabled", True)
# ban actuator (how a ban is enforced): traefik | nftables | nginx | none
BAN_ACTUATOR = _s("SECWATCH_BAN_ACTUATOR", "ban.actuator", "traefik")
NFT_TABLE = _s(None, "ban.nftables.table", "secwatch")
NFT_SET = _s(None, "ban.nftables.set", "banned")
NGINX_DENY_FILE = _s(None, "ban.nginx.deny_file", "/etc/nginx/secwatch-bans.conf")
NGINX_RELOAD_CMD = _s(None, "ban.nginx.reload_cmd", "nginx -s reload")
BAN_RULES = set(_list(None, "ban.rules", ["probe", "scan", "flood", "cred_stuff"]))
BAN_TTL_HOURS = float(os.environ.get("SECWATCH_BAN_TTL_HOURS", "24"))
BAN_MAX_ACTIVE = 500
# Never ban these: shared proxy edges (Cloudflare) — a ban would hit every
# visitor of any CF-proxied domain. Generic default; override in site config.
BAN_EXEMPT_NETS = _list(None, "ban.exempt_nets", [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
])

# ---- SSH / auth.log (generic) -------------------------------------------
SSH_BRUTE_WINDOW, SSH_BRUTE_LIMIT = 600, 8

# ---- host baseline / docker (generic) -----------------------------------
HOST_SNAPSHOT_INTERVAL = 300
DOCKER_POLL_INTERVAL = 60
EPHEMERAL_PORT_MIN = 32768

# ---- CVE / vulnerability awareness (generic) ----------------------------
CVE_SCAN = _bool("SECWATCH_CVE_SCAN", "cve.enabled", True)
TRIVY_IMAGE = _s("SECWATCH_TRIVY_IMAGE", "cve.trivy_image", "aquasec/trivy:0.58.0")
TRIVY_CACHE = str(BASE_DIR / "data" / "trivy")
CVE_SCAN_INTERVAL = int(os.environ.get("SECWATCH_CVE_INTERVAL", str(24 * 3600)))
CVE_SEVERITIES = _s("SECWATCH_CVE_SEVERITIES", "cve.severities", "HIGH,CRITICAL")
CVE_SCAN_TIMEOUT = int(os.environ.get("SECWATCH_CVE_TIMEOUT", "600"))
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_CACHE = BASE_DIR / "data" / "cisa-kev.json"
KEV_MAX_AGE = 24 * 3600

# ---- process + egress / C2 detection (generic) --------------------------
PROC_INTERVAL = int(os.environ.get("SECWATCH_PROC_INTERVAL", "30"))
# Real-time exec monitoring via the Linux audit subsystem catches short-lived
# processes the poll misses. Needs auditd + a readable audit log (root); falls
# back to the /proc poll when unavailable. set_rule adds the execve rule if root.
AUDIT_ENABLED = _bool("SECWATCH_AUDIT", "audit.enabled", True)
AUDIT_LOG = _s(None, "audit.log", "/var/log/audit/audit.log")
AUDIT_KEY = "secwatch_exec"
AUDIT_SET_RULE = _bool(None, "audit.set_rule", True)

# ---- file-integrity monitoring (site-specific dirs) ---------------------
FIM_INTERVAL = int(os.environ.get("SECWATCH_FIM_INTERVAL", "120"))
FIM_WATCH_DIRS = _list("SECWATCH_FIM_WATCH_DIRS", "fim.watch_dirs", [])
FIM_CANARY_DIRS = _list("SECWATCH_FIM_CANARY_DIRS", "fim.canary_dirs", [str(BASE_DIR)])
FIM_MAX_SCAN_FILES = int(os.environ.get("SECWATCH_FIM_MAX_FILES", "20000"))
FIM_SCRIPT_EXTS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".sh", ".bash",
    ".py", ".rb", ".exe", ".elf", ".dll", ".so", ".jar", ".war",
}
FIM_WEBSHELL_MARKERS = (
    b"eval(", b"base64_decode(", b"system(", b"passthru(", b"shell_exec(",
    b"exec(", b"$_POST[", b"$_GET[", b"$_REQUEST[", b"proc_open(", b"popen(",
)

# ---- standalone dashboard auth (for IP:port deployments) ----------------
# OFF by default (deployments behind an authenticating reverse proxy don't need
# it). `secwatch install` turns it ON for standalone hosts. Requests from
# trust_proxy_from bypass auth (a fronting proxy already authenticated them);
# localhost is trusted by default so a co-located proxy keeps working.
AUTH_ENABLED = _bool("SECWATCH_AUTH_ENABLED", "auth.enabled", False)
AUTH_USERNAME = _s("SECWATCH_AUTH_USERNAME", "auth.username", "admin")
AUTH_PASSWORD_HASH = _s("SECWATCH_AUTH_PASSWORD_HASH", "auth.password_hash", "")
AUTH_SESSION_TTL = int(_s(None, "auth.session_ttl", 86400))
AUTH_TRUST_PROXY_FROM = _list("SECWATCH_AUTH_TRUST_PROXY_FROM",
                              "auth.trust_proxy_from", ["127.0.0.1/32", "::1/128"])
AUTH_MAX_FAILS = int(_s(None, "auth.max_fails", 8))
AUTH_LOCKOUT_SECS = int(_s(None, "auth.lockout_secs", 300))

# ---- self-maintenance (health + update awareness) -----------------------
HEALTH_INTERVAL = int(os.environ.get("SECWATCH_HEALTH_INTERVAL", "300"))
HEALTH_DISK_MIN_PCT = int(_s(None, "maintenance.disk_min_free_pct", 5))
# Notify (not auto-apply) when a newer secwatch version is published. Best-effort.
UPDATE_CHECK = _bool("SECWATCH_UPDATE_CHECK", "maintenance.update_check", True)
UPDATE_VERSION_URL = _s(None, "maintenance.version_url",
    "https://raw.githubusercontent.com/Paco5687/secwatch/main/secwatch/__init__.py")

# ---- Traefik-integrity failsafes (generic) ------------------------------
LOG_SILENCE_ALERT_SECS = int(os.environ.get("SECWATCH_LOG_SILENCE_SECS", "900"))

# ---- LLM log analysis (OPTIONAL, off by default) ------------------------
# Enable via site config (llm.enabled) or SECWATCH_LLM_ANALYSIS=1, pointing at
# ANY OpenAI-compatible endpoint (local vLLM/Ollama, or a remote API + api_key).
LLM_ANALYSIS = _bool("SECWATCH_LLM_ANALYSIS", "llm.enabled", False)
# Works with ANY OpenAI-compatible /chat/completions endpoint: a local runner
# (Ollama http://127.0.0.1:11434/v1, vLLM, LM Studio, llama.cpp) OR a hosted API
# (OpenAI https://api.openai.com/v1, OpenRouter, Together, Groq, Azure, …). For a
# hosted API set base_url + model + an api_key (sent as a Bearer token).
LLM_BASE_URL = _s("SECWATCH_LLM_BASE_URL", "llm.base_url", "http://127.0.0.1:11434/v1")
LLM_MODEL = _s("SECWATCH_LLM_MODEL", "llm.model", "your-model")
LLM_API_KEY = _s("SECWATCH_LLM_API_KEY", "llm.api_key", "")
# Keep the API key out of the config file: point at a file whose contents are the
# key (raw, or an env-style SECWATCH_LLM_API_KEY=... line; # comments ignored).
LLM_API_KEY_FILE = _s(None, "llm.api_key_file", "")
# response_format: json_object — supported by OpenAI/vLLM/Ollama, but some
# providers reject it. Turn off if your endpoint 400s on it (the prompt still
# asks for JSON either way).
LLM_JSON_MODE = _bool("SECWATCH_LLM_JSON_MODE", "llm.json_mode", True)
LLM_TEMPERATURE = float(_s(None, "llm.temperature", "0.2"))
LLM_MAX_TOKENS = int(_s(None, "llm.max_tokens", "2000"))
LLM_TIMEOUT = int(os.environ.get("SECWATCH_LLM_TIMEOUT", "150"))


def llm_api_key() -> str:
    """Resolve the API key: env/inline (LLM_API_KEY) first, else llm.api_key_file."""
    if LLM_API_KEY:
        return LLM_API_KEY
    if LLM_API_KEY_FILE:
        try:
            for line in Path(LLM_API_KEY_FILE).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("SECWATCH_LLM_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"')
                return line   # first non-comment line = the raw key
        except OSError:
            pass
    return ""
LLM_ANALYSIS_INTERVAL = int(os.environ.get("SECWATCH_LLM_INTERVAL", str(6 * 3600)))
LLM_ANALYSIS_HOURS = 24
LLM_EVIDENCE_TAIL_BYTES = 8 * 1024 * 1024
LLM_MAX_TALKERS = 25
LLM_MAX_PATHS = 20
LLM_MAX_UAS = 15
LLM_RDNS_TIMEOUT = 1.5
LLM_ALERT_THREAT = _s("SECWATCH_LLM_ALERT_THREAT", "llm.alert_threat", "elevated")
THREAT_RANK = {"low": 0, "guarded": 1, "elevated": 2, "high": 3, "critical": 4}

# ---- LLM steering (site-specific) ---------------------------------------
# Endpoints legitimate-by-design (never flag) and defenses already in place
# (don't re-recommend). Surfaced to the LLM analysis pass.
KNOWN_LEGIT_ENDPOINTS = _y("known_legitimate_endpoints", []) or []
ACTIVE_MITIGATIONS = _y("active_mitigations", []) or []

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def discord_webhook_url() -> str:
    url = os.environ.get("SECWATCH_DISCORD_WEBHOOK_URL", "").strip()
    if url:
        return url
    ov = str(_overrides.get("alerting.discord_webhook_url", "")).strip()  # Settings page
    if ov:
        return ov
    cfg_url = (_y("alerting.discord_webhook_url") or "").strip()
    if cfg_url:
        return cfg_url
    # optional: read from files (path configurable; keeps secrets out of config)
    candidates = [(BASE_DIR / ".secrets" / "discord-webhook.env",
                   "SECWATCH_DISCORD_WEBHOOK_URL")]
    wf = _y("alerting.discord_webhook_file")
    if wf:
        candidates.insert(0, (Path(wf), _y("alerting.discord_webhook_file_key",
                                            "SECWATCH_DISCORD_WEBHOOK_URL")))
    for envfile, key in candidates:
        try:
            for line in Path(envfile).read_text(encoding="utf-8").splitlines():
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            continue
    return ""


# ---- in-app Settings: live reload ---------------------------------------
# Dotted keys the Settings page can hot-swap WITHOUT a restart (read fresh on
# each use — per-event detection, per-call LLM/alerting). Anything editable but
# NOT here (feature loops, listen port) needs a restart to take effect.
SETTING_LIVE_KEYS = {
    "alerting.quiet_rules", "alerting.quiet_except_private", "alerting.min_severity",
    "alerting.discord_webhook_url", "ban.enabled",
    "thresholds.rate_limit", "thresholds.scan_4xx_limit", "thresholds.bot_min_reqs",
    "thresholds.stuff_limit", "thresholds.secret_probe_ban",
    "llm.base_url", "llm.model", "llm.api_key", "llm.json_mode",
    "llm.temperature", "llm.max_tokens", "llm.alert_threat", "cve.severities",
}


def reload_live():
    """Re-read in-app overrides and hot-swap the live-safe settings into module
    globals. Called after a Settings save. Keys not in SETTING_LIVE_KEYS still
    persist but need a restart — the API tells the UI which."""
    global _overrides, ALERT_QUIET_RULES, ALERT_QUIET_EXCEPT_PRIVATE, \
        ALERT_MIN_SEVERITY, AUTOBAN, RATE_LIMIT, SCAN_4XX_LIMIT, BOT_MIN_REQS, \
        STUFF_LIMIT, SECRET_PROBE_BAN, LLM_BASE_URL, LLM_MODEL, LLM_API_KEY, \
        LLM_JSON_MODE, LLM_TEMPERATURE, LLM_MAX_TOKENS, LLM_ALERT_THREAT, \
        CVE_SEVERITIES, CLUSTER_ROLE, CLUSTER_ENABLED, CLUSTER_URL
    _overrides = _settings.load_overrides()
    CLUSTER_ROLE = _s("SECWATCH_CLUSTER_ROLE", "cluster.role", "standalone")
    CLUSTER_ENABLED = CLUSTER_ROLE in ("peer", "leaf")
    CLUSTER_URL = _s("SECWATCH_CLUSTER_URL", "cluster.url", "")
    ALERT_QUIET_RULES = set(_list("SECWATCH_ALERT_QUIET_RULES", "alerting.quiet_rules",
        ["secret_probe", "scan", "flood", "privileged_access"]))
    ALERT_QUIET_EXCEPT_PRIVATE = _bool(None, "alerting.quiet_except_private", True)
    ALERT_MIN_SEVERITY = _s("SECWATCH_ALERT_MIN_SEVERITY", "alerting.min_severity", "high")
    AUTOBAN = _bool("SECWATCH_AUTOBAN", "ban.enabled", True)
    RATE_LIMIT = int(_s(None, "thresholds.rate_limit", 300))
    SCAN_4XX_LIMIT = int(_s(None, "thresholds.scan_4xx_limit", 20))
    BOT_MIN_REQS = int(_s(None, "thresholds.bot_min_reqs", 30))
    STUFF_LIMIT = int(_s(None, "thresholds.stuff_limit", 12))
    SECRET_PROBE_BAN = _bool("SECWATCH_SECRET_PROBE_BAN", "thresholds.secret_probe_ban", True)
    LLM_BASE_URL = _s("SECWATCH_LLM_BASE_URL", "llm.base_url", "http://127.0.0.1:11434/v1")
    LLM_MODEL = _s("SECWATCH_LLM_MODEL", "llm.model", "your-model")
    LLM_API_KEY = _s("SECWATCH_LLM_API_KEY", "llm.api_key", "")
    LLM_JSON_MODE = _bool("SECWATCH_LLM_JSON_MODE", "llm.json_mode", True)
    LLM_TEMPERATURE = float(_s(None, "llm.temperature", "0.2"))
    LLM_MAX_TOKENS = int(_s(None, "llm.max_tokens", "2000"))
    LLM_ALERT_THREAT = _s("SECWATCH_LLM_ALERT_THREAT", "llm.alert_threat", "elevated")
    CVE_SEVERITIES = _s("SECWATCH_CVE_SEVERITIES", "cve.severities", "HIGH,CRITICAL")
