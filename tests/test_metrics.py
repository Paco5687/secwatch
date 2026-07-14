"""Prometheus /metrics: render produces valid exposition text with the expected
series, and the endpoint gate lets loopback/token through but blocks unauth."""
import time


def _seed(config, db, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "CLUSTER_ENABLED", False)
    conn = db.connect()
    now = time.time()
    conn.execute("INSERT INTO events(ts,ip,rule,severity) VALUES(?,?,?,?)",
                 (now, "1.2.3.4", "scan", "high"))
    conn.execute("INSERT INTO events(ts,ip,rule,severity) VALUES(?,?,?,?)",
                 (now, "1.2.3.5", "probe", "info"))
    conn.execute("INSERT INTO bans(ip,rule,reason,created,expires,banned_by) VALUES(?,?,?,?,?,?)",
                 ("1.2.3.4", "scan", "x", now, now + 3600, "auto"))
    conn.execute("INSERT INTO vulnerabilities(cve,image,pkg,severity,in_kev,first_seen,last_seen) "
                 "VALUES(?,?,?,?,?,?,?)", ("CVE-1", "host", "p", "HIGH", 1, now, now))
    conn.commit()
    return conn


def test_render_has_expected_series(tmp_path, monkeypatch):
    from secwatch import config, db, metrics
    conn = _seed(config, db, monkeypatch, tmp_path)
    out = metrics.render(conn)
    assert "secwatch_up 1" in out
    assert "secwatch_build_info{" in out
    assert 'secwatch_events_recent{severity="high"} 1' in out
    assert "secwatch_high_events_24h 1" in out
    assert "secwatch_bans_active 1" in out
    assert 'secwatch_bans_by_source{source="local"} 1' in out
    assert 'secwatch_vulnerabilities{severity="HIGH",kev="true"} 1' in out


def test_render_is_valid_exposition(tmp_path, monkeypatch):
    from secwatch import config, db, metrics
    conn = _seed(config, db, monkeypatch, tmp_path)
    for ln in metrics.render(conn).splitlines():
        if not ln or ln.startswith("#"):
            continue
        # every sample line must be "<name>[{labels}] <value>"
        assert " " in ln
        name, val = ln.rsplit(" ", 1)
        assert name and val
        float(val)   # value parses as a number


def test_endpoint_gate(monkeypatch):
    from secwatch import config, web

    class Req:
        def __init__(self, host, auth_hdr=""):
            self.client = type("C", (), {"host": host})()
            self.headers = {"authorization": auth_hdr} if auth_hdr else {}

    monkeypatch.setattr(config, "METRICS_TOKEN", "")
    monkeypatch.setattr(config, "AUTH_ENABLED", True)
    assert web._metrics_authorized(Req("127.0.0.1"))          # loopback always ok
    assert not web._metrics_authorized(Req("10.0.0.9"))       # remote + auth-on + no token -> blocked

    monkeypatch.setattr(config, "METRICS_TOKEN", "sekret")
    assert web._metrics_authorized(Req("10.0.0.9", "Bearer sekret"))
    assert not web._metrics_authorized(Req("10.0.0.9", "Bearer wrong"))

    monkeypatch.setattr(config, "METRICS_TOKEN", "")
    monkeypatch.setattr(config, "AUTH_ENABLED", False)        # open LAN dashboard
    assert web._metrics_authorized(Req("10.0.0.9"))
