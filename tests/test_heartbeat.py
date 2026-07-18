"""Dead-man's-switch heartbeat: right URL, right status, best-effort."""
from secwatch import config, healthwatch, heartbeat


def _capture(monkeypatch):
    calls = []
    monkeypatch.setattr(heartbeat, "_get", lambda url, timeout=10: calls.append(url) or True)
    return calls


def test_healthy_pings_up_url(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(config, "HEARTBEAT_URL", "http://kuma/api/push/abc")
    monkeypatch.setattr(config, "HEARTBEAT_FAIL_URL", "")
    healthwatch.STATE.update(status="ok", checks={})
    assert heartbeat.send_once() is True
    assert len(calls) == 1
    assert "status=up" in calls[0] and calls[0].startswith("http://kuma/api/push/abc?")


def test_kuma_url_with_existing_query_appends_with_amp(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(config, "HEARTBEAT_URL", "http://kuma/api/push/abc?status=up")
    healthwatch.STATE.update(status="ok", checks={})
    heartbeat.send_once()
    # our status is merged via '&' when the base already carries a query
    assert calls[0].count("?") == 1 and "&status=up" in calls[0]


def test_degraded_pings_down_and_names_failing_check(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(config, "HEARTBEAT_URL", "http://kuma/up")
    monkeypatch.setattr(config, "HEARTBEAT_FAIL_URL", "")
    healthwatch.STATE.update(status="degraded",
                             checks={"ban_actuator": {"ok": False, "detail": "x"},
                                     "db": {"ok": True}})
    heartbeat.send_once()
    assert "status=down" in calls[0]
    assert "ban_actuator" in calls[0]  # tells the monitor *what* broke


def test_degraded_prefers_dedicated_fail_url(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(config, "HEARTBEAT_URL", "http://kuma/up")
    monkeypatch.setattr(config, "HEARTBEAT_FAIL_URL", "http://hc-ping.com/uuid/fail")
    healthwatch.STATE.update(status="degraded", checks={"db": {"ok": False}})
    heartbeat.send_once()
    assert calls[0].startswith("http://hc-ping.com/uuid/fail")


def test_no_url_is_a_noop(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(config, "HEARTBEAT_URL", "")
    monkeypatch.setattr(config, "HEARTBEAT_FAIL_URL", "")
    healthwatch.STATE.update(status="ok", checks={})
    assert heartbeat.send_once() is False
    assert calls == []


def test_ping_failure_never_raises(monkeypatch):
    def boom(url, timeout=10):
        raise OSError("monitor unreachable")
    monkeypatch.setattr(heartbeat, "_get", boom)
    monkeypatch.setattr(config, "HEARTBEAT_URL", "http://kuma/up")
    healthwatch.STATE.update(status="ok", checks={})
    assert heartbeat.send_once() is False  # swallowed, not raised
