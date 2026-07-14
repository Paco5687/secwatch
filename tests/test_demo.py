"""Demo seeder: populates events, bans (varied sources), vulnerabilities (incl a
KEV), devices, and traffic — enough to make the dashboard look real, offline."""


def test_seed_populates(tmp_path, monkeypatch):
    from secwatch import config, db, demo
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "demo.db")
    conn = db.connect()
    counts = demo.seed(conn, now=1_700_000_000)
    assert counts["events"] > 5 and counts["bans"] >= 3 and counts["vulns"] >= 3

    assert conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"] == counts["events"]
    assert conn.execute("SELECT COUNT(*) c FROM bans").fetchone()["c"] == counts["bans"]
    # a KEV finding exists (drives the 'actively exploited' UI)
    assert conn.execute("SELECT COUNT(*) c FROM vulnerabilities WHERE in_kev=1").fetchone()["c"] >= 1
    # bans span more than one source (local + cluster + community)
    sources = {r["banned_by"] for r in conn.execute("SELECT banned_by FROM bans")}
    assert any(s.startswith("cluster:") for s in sources)
    assert "community" in sources
    # traffic minutes exist for sparklines
    assert conn.execute("SELECT COUNT(*) c FROM traffic").fetchone()["c"] > 0
