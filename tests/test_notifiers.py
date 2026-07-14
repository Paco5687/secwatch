"""Multi-target alert delivery: correct per-type requests, unknown types are safe,
a failing target never breaks the others, and Discord stays back-compatible."""
import json


def _capture(monkeypatch):
    calls = []

    def fake_post(url, data, headers=None, timeout=10):
        calls.append({"url": url, "data": data, "headers": headers or {}})
        return True
    from secwatch import notifiers
    monkeypatch.setattr(notifiers, "_post", fake_post)
    monkeypatch.setattr(notifiers.config, "discord_webhook_url", lambda: "")   # no implicit discord
    return notifiers, calls


EVENT = {"rule": "secret_probe", "severity": "high", "ip": "9.9.9.9",
         "detail": "hit /.env", "host": "app", "path": "/.env", "count": 3, "ts": 0}


def test_ntfy_and_webhook_dispatch(monkeypatch):
    notifiers, calls = _capture(monkeypatch)
    monkeypatch.setattr(notifiers.config, "ALERT_TARGETS", [
        {"type": "ntfy", "url": "https://ntfy.sh", "topic": "sec", "token": "tok"},
        {"type": "webhook", "url": "https://hook.example/x"},
    ])
    sent = notifiers.dispatch(EVENT)
    assert sent == 2
    ntfy = next(c for c in calls if "ntfy" in c["url"])
    assert ntfy["url"] == "https://ntfy.sh/sec"
    assert ntfy["headers"]["Authorization"] == "Bearer tok"
    assert ntfy["headers"]["Priority"] == "5"          # high severity
    hook = next(c for c in calls if "hook.example" in c["url"])
    assert json.loads(hook["data"])["rule"] == "secret_probe"   # webhook gets the raw event


def test_gotify_and_telegram_urls(monkeypatch):
    notifiers, calls = _capture(monkeypatch)
    monkeypatch.setattr(notifiers.config, "ALERT_TARGETS", [
        {"type": "gotify", "url": "https://gotify.lan", "token": "G"},
        {"type": "telegram", "bot_token": "BOT", "chat_id": "123"},
    ])
    notifiers.dispatch(EVENT)
    assert any(c["url"] == "https://gotify.lan/message?token=G" for c in calls)
    assert any(c["url"] == "https://api.telegram.org/botBOT/sendMessage" for c in calls)


def test_unknown_type_is_safe(monkeypatch):
    notifiers, calls = _capture(monkeypatch)
    monkeypatch.setattr(notifiers.config, "ALERT_TARGETS", [{"type": "smoke-signals"}])
    assert notifiers.dispatch(EVENT) == 0        # nothing sent, no exception


def test_one_target_failing_does_not_block_others(monkeypatch):
    from secwatch import notifiers

    def flaky_post(url, data, headers=None, timeout=10):
        if "bad" in url:
            raise OSError("boom")
        return True
    monkeypatch.setattr(notifiers, "_post", flaky_post)
    monkeypatch.setattr(notifiers.config, "discord_webhook_url", lambda: "")
    monkeypatch.setattr(notifiers.config, "ALERT_TARGETS", [
        {"type": "webhook", "url": "https://bad/x"},
        {"type": "webhook", "url": "https://good/x"},
    ])
    assert notifiers.dispatch(EVENT) == 1        # the good one still went


def test_discord_backcompat_implicit_target(monkeypatch):
    from secwatch import notifiers
    monkeypatch.setattr(notifiers.config, "ALERT_TARGETS", [])
    monkeypatch.setattr(notifiers.config, "discord_webhook_url",
                        lambda: "https://hook.invalid/discord")
    sent = {}
    monkeypatch.setattr(notifiers.alert, "send_discord", lambda e: sent.setdefault("hit", True) or True)
    assert notifiers.dispatch(EVENT) == 1 and sent.get("hit")


def test_test_target_reports_result(monkeypatch):
    notifiers, calls = _capture(monkeypatch)
    ok, msg = notifiers.test_target({"type": "ntfy", "url": "https://ntfy.sh", "topic": "t"})
    assert ok and msg == "delivered"
