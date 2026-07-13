"""Dashboard-managed log sources — add/remove local app logs without editing YAML.

Runtime-added sources are persisted to `data/log_sources.json` (so they survive a
restart; the config loader merges them with the YAML `log_sources`) and tailed
live via asyncio tasks tracked here — so adding or removing one takes effect
immediately, no restart. YAML/primary sources are read-only from the UI's point
of view (edit the YAML for those).
"""
import glob
import json
import logging
import os
import re
from pathlib import Path

from . import config, parser

log = logging.getLogger("secwatch.logsources")

STORE = config.MANAGED_SOURCES_FILE
VALID_TYPES = {"traefik", "nginx", "caddy", "regex"}
MAX_MANAGED = 32
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,40}$")

# --- auto-discovery of watchable access logs -----------------------------
# Common locations for reverse-proxy + app access logs on a homelab host.
SCAN_GLOBS = [
    "/var/log/nginx/*.log",
    "/var/log/caddy/*.log", "/var/log/caddy/*.json",
    "/var/log/apache2/*.log", "/var/log/httpd/*.log",
    "/var/log/traefik/*.log", "/var/log/traefik/*.json*",
    "/var/log/*/access*.log",
    "/srv/*/logs/*.log", "/srv/*/logs/*/*.log", "/srv/*/logs/*/*/*.log",
    "/opt/*/logs/*.log", "/home/*/*/logs/*.log",
]
# rotated/compressed copies we should not tail (name ends .gz/.1/.2025-01-02/…)
_ROTATED_RE = re.compile(r"\.(gz|bz2|xz|zip|old|\d+|\d{4}-\d\d-\d\d)$", re.I)
SCAN_MAX_FILES = 400          # cap files opened per scan
SCAN_TAIL_BYTES = 64 * 1024   # only sniff the tail of each file
SCAN_SAMPLE_LINES = 40
SCAN_MAX_CANDIDATES = 60
_SNIFF_TYPES = ("traefik", "caddy", "nginx")   # structured formats we can detect


def load():
    """Return the persisted list of dashboard-managed sources."""
    try:
        with open(STORE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save(items):
    STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(items, f, indent=2)
    os.replace(tmp, STORE)   # atomic


def validate(name, path, stype, regex):
    """Normalize + sanity-check a source. Returns (source_dict, "ok") or
    (None, human-readable-reason). The path must be an existing readable file."""
    name = (name or "").strip()
    path = (path or "").strip()
    stype = (stype or "traefik").strip().lower()
    regex = (regex or "").strip()
    if not _NAME_RE.match(name):
        return None, "Name: 1–41 chars, letters/digits/space/._- only."
    if stype not in VALID_TYPES:
        return None, f"Type must be one of: {', '.join(sorted(VALID_TYPES))}."
    if not path.startswith("/"):
        return None, "Path must be absolute (start with /)."
    try:
        rp = Path(path).resolve()
    except OSError as exc:
        return None, f"Bad path: {exc}"
    if not rp.is_file():
        return None, "No readable file at that path (does it exist yet?)."
    if not os.access(rp, os.R_OK):
        return None, "That file exists but secwatch can't read it (permissions)."
    if stype == "regex":
        if not regex:
            return None, "The 'regex' type needs a pattern with a (?P<ip>…) group."
        try:
            rx = re.compile(regex)
        except re.error as exc:
            return None, f"Invalid regex: {exc}"
        if "ip" not in rx.groupindex:
            return None, "Regex must contain a named (?P<ip>…) group."
    return {"name": name, "path": str(rp), "type": stype, "regex": regex}, "ok"


def _tail_lines(path, nbytes=SCAN_TAIL_BYTES, maxlines=SCAN_SAMPLE_LINES):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > nbytes:
                f.seek(-nbytes, os.SEEK_END)
                f.readline()   # drop the partial first line after the seek
            data = f.read()
    except OSError:
        return []
    lines = [ln for ln in data.decode("utf-8", "replace").splitlines() if ln.strip()]
    return lines[-maxlines:]


def _sniff(path):
    """Guess the access-log format by parsing a tail sample. Returns
    (type, sample_line) if ≥half the sampled lines parse as one known format,
    else (None, last_line)."""
    lines = _tail_lines(path)
    if not lines:
        return None, ""
    best, best_ratio, best_sample = None, 0.0, ""
    for t in _SNIFF_TYPES:
        parse = parser.parser_for(t)
        hits, sample = 0, ""
        for ln in lines:
            rec = parse(ln)
            if rec and rec.get("ip"):
                hits += 1
                sample = sample or ln
        ratio = hits / len(lines)
        if ratio > best_ratio:
            best, best_ratio, best_sample = t, ratio, sample
    if best_ratio >= 0.5:
        return best, best_sample[:300]
    return None, lines[-1][:300]


def _suggest_name(path):
    stem = re.sub(r"\.?(access|json|log)$", "", Path(path).stem, flags=re.I).strip("._-")
    if not stem or stem.lower() in ("access", "log", "json"):
        stem = Path(path).parent.name
    name = re.sub(r"[^A-Za-z0-9 _.\-]", "-", stem)[:41]
    return name if _NAME_RE.match(name) else "app"


def scan():
    """Walk common log locations, sniff format, and return watchable candidates
    not already being watched. Read-only — nothing is added. For the review queue."""
    watched = {s["path"] for s in config.LOG_SOURCES} | {s["path"] for s in load()}
    files = []
    for pat in SCAN_GLOBS:
        files += glob.glob(pat)
        if len(files) > SCAN_MAX_FILES * 3:
            break
    seen, cands = set(), []
    for path in files[:SCAN_MAX_FILES * 3]:
        try:
            rp = str(Path(path).resolve())
        except OSError:
            continue
        if rp in seen or rp in watched:
            continue
        seen.add(rp)
        p = Path(rp)
        if _ROTATED_RE.search(p.name) or not p.is_file() or not os.access(rp, os.R_OK):
            continue
        try:
            if p.stat().st_size == 0:
                continue
        except OSError:
            continue
        stype, sample = _sniff(rp)
        if not stype:
            continue
        cands.append({"name": _suggest_name(rp), "path": rp,
                      "type": stype, "sample": sample})
        if len(cands) >= SCAN_MAX_CANDIDATES:
            break
    cands.sort(key=lambda c: c["path"])
    return cands


class Manager:
    """Owns the live tail tasks and the persisted list. Constructed in the web
    lifespan with the shared engine and a `spawn(source)->task` callback."""

    def __init__(self, engine, spawn):
        self.engine = engine
        self._spawn = spawn        # callable(source_dict) -> asyncio.Task
        self.tasks = {}            # path -> asyncio.Task (every tailed source)

    def register(self, path, task):
        """Record a tail task started elsewhere (e.g. YAML sources at boot)."""
        self.tasks[path] = task

    def add(self, name, path, stype, regex):
        src, msg = validate(name, path, stype, regex)
        if not src:
            return False, msg
        items = load()
        watched = {s["path"] for s in config.LOG_SOURCES} | {s["path"] for s in items}
        if src["path"] in watched:
            return False, "That path is already being watched."
        if len(items) >= MAX_MANAGED:
            return False, f"Reached the limit of {MAX_MANAGED} managed sources."
        # start tailing first; only persist once the task is actually running
        live = dict(src, managed=True)
        self.tasks[src["path"]] = self._spawn(live)
        config.LOG_SOURCES.append(live)          # so /status reflects it at once
        items.append(src)
        _save(items)
        log.info("added log source %r (%s) -> %s", src["name"], src["type"], src["path"])
        return True, "Added — now tailing."

    def remove(self, path):
        path = (path or "").strip()
        items = load()
        kept = [s for s in items if s["path"] != path]
        if len(kept) == len(items):
            return False, "Not a dashboard-managed source (YAML/primary sources " \
                          "are edited in secwatch.yaml)."
        _save(kept)
        config.LOG_SOURCES[:] = [s for s in config.LOG_SOURCES if s["path"] != path]
        task = self.tasks.pop(path, None)
        if task:
            task.cancel()
        self.engine.source_status.pop(path, None)
        log.info("removed log source %s", path)
        return True, "Removed."

    def status(self):
        """One row per active source for the dashboard."""
        managed_paths = {s["path"] for s in load()}
        rows = []
        for s in config.LOG_SOURCES:
            info = self.engine.source_status.get(s["path"], {})
            rows.append({
                "name": s.get("name") or s["path"],
                "path": s["path"],
                "type": s.get("type", "traefik"),
                "primary": bool(s.get("primary")),
                "managed": s["path"] in managed_paths,
                "records": info.get("records", 0),
                "last_ts": info.get("last_ts", 0),
                "live": s["path"] in self.tasks,
            })
        return rows
