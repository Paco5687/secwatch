import sqlite3

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  ip TEXT NOT NULL,
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,
  host TEXT,
  path TEXT,
  ua TEXT,
  detail TEXT,
  count INTEGER DEFAULT 1,
  alerted INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);

CREATE TABLE IF NOT EXISTS traffic(
  minute INTEGER PRIMARY KEY,
  requests INTEGER DEFAULT 0,
  s4xx INTEGER DEFAULT 0,
  s5xx INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ip_minute(
  minute INTEGER NOT NULL,
  ip TEXT NOT NULL,
  requests INTEGER DEFAULT 0,
  s4xx INTEGER DEFAULT 0,
  PRIMARY KEY (minute, ip)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS bans(
  ip TEXT PRIMARY KEY,
  rule TEXT,
  reason TEXT,
  created REAL NOT NULL,
  expires REAL NOT NULL,
  banned_by TEXT DEFAULT 'auto'
);

CREATE TABLE IF NOT EXISTS ssh_known(
  user TEXT NOT NULL,
  ip TEXT NOT NULL,
  first_seen REAL NOT NULL,
  PRIMARY KEY (user, ip)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS host_baseline(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities(
  cve TEXT NOT NULL,
  image TEXT NOT NULL,
  pkg TEXT,
  installed TEXT,
  fixed TEXT,
  severity TEXT,
  in_kev INTEGER DEFAULT 0,
  title TEXT,
  first_seen REAL,
  last_seen REAL,
  PRIMARY KEY (cve, image, pkg)
);
CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(in_kev);

CREATE TABLE IF NOT EXISTS fim_baseline(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses(
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  hours INTEGER,
  ok INTEGER DEFAULT 1,
  threat_level TEXT,
  headline TEXT,
  json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_ts ON analyses(ts);
"""


def connect(readonly: bool = False) -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if readonly:
        conn = sqlite3.connect(f"file:{config.DB_PATH}?mode=ro", uri=True, timeout=5)
    else:
        conn = sqlite3.connect(config.DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
    conn.row_factory = sqlite3.Row
    return conn


def meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def meta_set(conn, key, value):
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
