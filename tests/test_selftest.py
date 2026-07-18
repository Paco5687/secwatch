"""Fire-drill self-test — the load-bearing guarantee is that the synthetic ban
NEVER survives the drill and real bans are untouched (no repeat of the demo.py
ban-file clobber)."""
import time

from secwatch import ban, config, db, selftest


def _setup(tmp_path, monkeypatch, real_ips=()):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "BANS_FILE", tmp_path / "secwatch-bans.yml")
    monkeypatch.setattr(config, "BAN_ACTUATOR", "traefik")
    conn = db.connect()
    now = time.time()
    for ip in real_ips:  # insert straight to DB to skip crowd/cluster propagation
        conn.execute("INSERT INTO bans(ip,rule,reason,created,expires,banned_by)"
                     " VALUES(?,?,?,?,?,?)", (ip, "test", "", now, now + 3600, "manual"))
    conn.commit()
    ban.write_file(conn)                 # establish the real ban file
    return conn, config.BANS_FILE


def test_detect_stage_recognizes_a_probe():
    ok, detail = selftest._detect()
    assert ok is True, detail


def test_firedrill_leaves_no_synthetic_ban_and_preserves_real(tmp_path, monkeypatch):
    conn, bans = _setup(tmp_path, monkeypatch, real_ips=("45.9.148.10", "185.220.101.5"))
    monkeypatch.setattr(selftest, "_edge", lambda: (True, "edge stubbed for test"))
    before = bans.read_text()

    result = selftest.run_firedrill(conn)

    assert result["ok"] is True
    assert {s["stage"] for s in result["stages"]} == {"detect", "enforce", "edge", "restore"}
    after = bans.read_text()
    # THE safety invariants
    assert selftest.FIREDRILL_IP not in after            # synthetic ban gone
    assert "45.9.148.10" in after and "185.220.101.5" in after   # real bans intact
    assert after == before                                # file fully restored


def test_enforce_stage_actually_wrote_then_restore_removed(tmp_path, monkeypatch):
    conn, bans = _setup(tmp_path, monkeypatch, real_ips=("45.9.148.10",))
    monkeypatch.setattr(selftest, "_edge", lambda: (True, "stub"))
    result = selftest.run_firedrill(conn)
    enforce = next(s for s in result["stages"] if s["stage"] == "enforce")
    assert enforce["ok"] is True                            # the write reached the edge
    assert "1 real ban(s) preserved" in enforce["detail"]   # ...without dropping the real one
    assert selftest.FIREDRILL_IP not in bans.read_text()    # restore cleaned the synthetic IP


def test_cleanup_runs_even_when_a_stage_errors(tmp_path, monkeypatch):
    conn, bans = _setup(tmp_path, monkeypatch, real_ips=())

    def boom():
        raise RuntimeError("edge exploded mid-drill")
    monkeypatch.setattr(selftest, "_edge", boom)

    result = selftest.run_firedrill(conn)

    assert result["ok"] is False                           # the drill reports the failure
    edge = next(s for s in result["stages"] if s["stage"] == "edge")
    assert edge["ok"] is False and "error" in edge["detail"]
    restore = next(s for s in result["stages"] if s["stage"] == "restore")
    assert restore["ok"] is True                           # ...but cleanup still ran
    assert selftest.FIREDRILL_IP not in bans.read_text()   # and the synthetic ban is gone


def test_none_actuator_is_honest_about_no_enforcement(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "BAN_ACTUATOR", "none")
    conn = db.connect()
    ok, detail = selftest._enforce(conn)
    assert ok is True and "alert-only" in detail
