"""Never-ban allowlist: add/remove/match (IP + CIDR), normalization, and that
ban.add actually refuses an allowlisted address (from any source)."""


def _iso(config, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ALLOWLIST_FILE", tmp_path / "allow.json")


def test_add_match_remove_ip(tmp_path, monkeypatch):
    from secwatch import allowlist, config
    _iso(config, tmp_path, monkeypatch)
    ok, _ = allowlist.add("203.0.113.9")
    assert ok and allowlist.matches("203.0.113.9")
    assert not allowlist.matches("203.0.113.10")
    allowlist.remove("203.0.113.9")
    assert not allowlist.matches("203.0.113.9")


def test_cidr_match(tmp_path, monkeypatch):
    from secwatch import allowlist, config
    _iso(config, tmp_path, monkeypatch)
    allowlist.add("198.51.100.0/24")
    assert allowlist.matches("198.51.100.42")
    assert not allowlist.matches("198.51.101.1")


def test_invalid_rejected(tmp_path, monkeypatch):
    from secwatch import allowlist, config
    _iso(config, tmp_path, monkeypatch)
    ok, msg = allowlist.add("not-an-ip")
    assert not ok and "valid" in msg
    assert allowlist.load() == []


def test_ban_add_refuses_allowlisted(tmp_path, monkeypatch):
    from secwatch import allowlist, ban, config, db
    _iso(config, tmp_path, monkeypatch)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    allowlist.add("45.45.45.45")
    conn = db.connect()
    ok, msg = ban.add(conn, "45.45.45.45", rule="scan", banned_by="auto")
    assert not ok and "allowlist" in msg
    # and it isn't in the bans table
    assert conn.execute("SELECT COUNT(*) c FROM bans WHERE ip='45.45.45.45'").fetchone()["c"] == 0
