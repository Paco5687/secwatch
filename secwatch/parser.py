"""Access-log parsing — pluggable per reverse proxy (log-source adapter).

Every parser returns the same normalized record, or None if the line can't be
parsed:  {ip, host, method, path, status, ua, router}

Select the source with `log_source.type` in secwatch.yaml (or SECWATCH_LOG_SOURCE):
traefik (JSON) | nginx (combined) | caddy (JSON) | regex (custom).
"""
import json
import re

from . import config


def _rec(ip, host, method, path, status, ua, router=""):
    if not ip:
        return None
    try:
        status = int(status or 0)
    except (TypeError, ValueError):
        status = 0
    return {"ip": ip, "host": (host or "").lower(), "method": method or "",
            "path": path or "", "status": status, "ua": ua or "", "router": router}


def parse_traefik(line):
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        r = json.loads(line)
    except ValueError:
        return None
    return _rec(r.get("ClientHost") or r.get("ClientAddr", "").rsplit(":", 1)[0],
                r.get("RequestHost"), r.get("RequestMethod"), r.get("RequestPath"),
                r.get("DownstreamStatus"), r.get("request_User-Agent"),
                r.get("RouterName") or "")


# nginx "combined" (default). Host is absent unless you add $host to log_format;
# for host-aware detection use log_source.type: regex with a (?P<host>...) group.
_NGINX_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"')


def parse_nginx(line):
    m = _NGINX_RE.search(line)
    if not m:
        return None
    g = m.groupdict()
    return _rec(g["ip"], g.get("host", ""), g["method"], g["path"],
                g["status"], g["ua"])


def parse_caddy(line):
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        r = json.loads(line)
    except ValueError:
        return None
    req = r.get("request", {}) or {}
    ua = ""
    hdrs = req.get("headers", {}) or {}
    if isinstance(hdrs.get("User-Agent"), list) and hdrs["User-Agent"]:
        ua = hdrs["User-Agent"][0]
    return _rec(req.get("remote_ip") or req.get("client_ip"),
                req.get("host"), req.get("method"), req.get("uri"),
                r.get("status"), ua)


_regex_cache = None


def parse_regex(line):
    """User-supplied regex (log_source.regex) with named groups:
    ip (required), host, method, path, status, ua."""
    global _regex_cache
    if _regex_cache is None:
        pat = config.LOG_SOURCE_REGEX
        _regex_cache = re.compile(pat) if pat else False
    if not _regex_cache:
        return None
    m = _regex_cache.search(line)
    if not m:
        return None
    g = m.groupdict()
    return _rec(g.get("ip"), g.get("host", ""), g.get("method", ""),
                g.get("path", ""), g.get("status", 0), g.get("ua", ""))


_PARSERS = {"traefik": parse_traefik, "nginx": parse_nginx,
            "caddy": parse_caddy, "regex": parse_regex}


def parser_for(source_type, regex=""):
    """Return a line→record callable for one source (its own compiled regex if
    type is 'regex'). Used by multi-source tailing."""
    if source_type == "regex":
        pat = re.compile(regex) if regex else None

        def _p(line):
            if not pat:
                return None
            m = pat.search(line)
            if not m:
                return None
            g = m.groupdict()
            return _rec(g.get("ip"), g.get("host", ""), g.get("method", ""),
                        g.get("path", ""), g.get("status", 0), g.get("ua", ""))
        return _p
    return _PARSERS.get(source_type, parse_traefik)


def parse_line(line, source=None):
    return _PARSERS.get(source or config.LOG_SOURCE_TYPE, parse_traefik)(line)
