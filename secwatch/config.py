"""secwatch configuration.

Resolution order for every value: environment variable (SECWATCH_*) wins, then
the site config file (`secwatch.yaml`, or $SECWATCH_CONFIG), then a generic
built-in default. Host/site-specifics (endpoint rules, trusted nets, app hosts,
FIM dirs, proxy paths, integrations) live in `secwatch.yaml` — NOT in this file —
so the code is portable and shareable. See `secwatch.example.yaml`.
"""
import os
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
    """Scalar: env var (string) wins, then site config, then default."""
    v = os.environ.get(env_name) if env_name else None
    if v is not None:
        return v
    y = _y(dotted)
    return y if y is not None else default


def _bool(env_name, dotted, default):
    v = os.environ.get(env_name) if env_name else None
    if v is not None:
        return v == "1"
    y = _y(dotted)
    return bool(y) if y is not None else default


def _list(env_name, dotted, default):
    """List: comma-string env var wins, then site-config list, then default."""
    v = os.environ.get(env_name) if env_name else None
    if v is not None:
        return [x.strip() for x in v.split(",") if x.strip()]
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

# ---- log-source adapter (which proxy's access log) ----------------------
# traefik (JSON) | nginx (combined) | caddy (JSON) | regex (custom, needs regex)
LOG_SOURCE_TYPE = _s("SECWATCH_LOG_SOURCE", "log_source.type", "traefik")
LOG_SOURCE_REGEX = _s(None, "log_source.regex", "")
LISTEN_HOST = os.environ.get("SECWATCH_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("SECWATCH_PORT", "8931"))

# Deployment mode:
#   all   — everything in one process (default; the classic single-host setup)
#   core  — detection/dashboard/CVE/LLM/alerting + ban; host collectors come
#           from a separate agent (containerized core without host access)
#   agent — ONLY host collectors (auth/host/persistence/process/docker); forwards
#           events to a core over HTTP (runs on the host, feeds a container core)
MODE = _s("SECWATCH_MODE", "mode", "all")
CORE_URL = os.environ.get("SECWATCH_CORE_URL", "http://127.0.0.1:8931")
# Shared token for agent→core event ingestion (POST /api/ingest). Empty disables.
INGEST_TOKEN = os.environ.get("SECWATCH_INGEST_TOKEN", "")

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
ALERT_MIN_SEVERITY = os.environ.get("SECWATCH_ALERT_MIN_SEVERITY", "high")
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
LLM_BASE_URL = _s("SECWATCH_LLM_BASE_URL", "llm.base_url", "http://127.0.0.1:11434/v1")
LLM_MODEL = _s("SECWATCH_LLM_MODEL", "llm.model", "your-model")
LLM_API_KEY = _s("SECWATCH_LLM_API_KEY", "llm.api_key", "")
LLM_TIMEOUT = int(os.environ.get("SECWATCH_LLM_TIMEOUT", "150"))
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
