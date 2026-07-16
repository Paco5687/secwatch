"""Self-update against a throwaway git repo: it fast-forwards to the upstream tip,
reinstalls deps only when requirements.txt changed, schedules a restart, and is a
no-op once already current. A non-git tree can't self-update."""
import subprocess

import pytest


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """An 'origin' repo one commit ahead of a local clone, wired into update.BASE_DIR."""
    from secwatch import update
    origin, clone = tmp_path / "origin", tmp_path / "clone"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "t@t")
    _git(origin, "config", "user.name", "t")
    (origin / "secwatch").mkdir()
    (origin / "secwatch" / "__init__.py").write_text('__version__ = "1.0.0"\n')
    (origin / "requirements.txt").write_text("fastapi==1\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "v1")
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True,
                   capture_output=True, text=True)
    # advance origin: version bump + requirements change
    (origin / "secwatch" / "__init__.py").write_text('__version__ = "1.1.0"\n')
    (origin / "requirements.txt").write_text("fastapi==1\nnewdep==2\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "v2")

    reinstalled, restarted = [], []
    monkeypatch.setattr(update, "BASE_DIR", clone)
    monkeypatch.setattr(update, "_reinstall_deps", lambda: reinstalled.append(True))
    monkeypatch.setattr(update, "_schedule_restart", lambda: restarted.append(True) or True)
    return update, clone, reinstalled, restarted


def test_is_git_checkout(sandbox):
    update, clone, _, _ = sandbox
    assert update.is_git_checkout()


def test_status_reports_behind(sandbox):
    update, clone, _, _ = sandbox
    st = update.status(fetch=True)
    assert st["supported"] and st["behind"] and st["behind_commits"] == 1
    assert st["latest"] == "1.1.0"


def test_self_update_fast_forwards_and_reinstalls(sandbox):
    update, clone, reinstalled, restarted = sandbox
    ok, msg = update.self_update("test")
    assert ok
    assert reinstalled == [True]          # requirements.txt changed
    assert restarted == [True]
    assert '1.1.0' in (clone / "secwatch" / "__init__.py").read_text()


def test_self_update_idempotent(sandbox):
    update, clone, reinstalled, restarted = sandbox
    update.self_update("test")
    reinstalled.clear(); restarted.clear()
    ok, msg = update.self_update("test")
    assert ok and "up to date" in msg
    assert restarted == []                # nothing to do the second time


def test_non_git_tree_cannot_self_update(tmp_path, monkeypatch):
    from secwatch import update
    monkeypatch.setattr(update, "BASE_DIR", tmp_path)   # no .git
    assert not update.is_git_checkout()
    ok, msg = update.self_update("test")
    assert not ok and "not a git checkout" in msg


def _tagged_origin_and_clone(tmp_path, sign=False):
    """origin at v1.1.0 (tagged) one commit ahead of a clone still at v1.0.0."""
    origin, clone = tmp_path / "o", tmp_path / "c"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "t@t")
    _git(origin, "config", "user.name", "t")
    (origin / "secwatch").mkdir()
    (origin / "secwatch" / "__init__.py").write_text('__version__ = "1.0.0"\n')
    (origin / "requirements.txt").write_text("x\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "v1")
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True,
                   capture_output=True, text=True)
    (origin / "secwatch" / "__init__.py").write_text('__version__ = "1.1.0"\n')
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "v2")
    # --no-sign keeps this hermetic: the test must produce an *unsigned* tag even
    # when the host's global git config sets tag.gpgsign=true (and in CI, where
    # there's no signing key at all).
    _git(origin, "tag", "--no-sign", "-a", "v1.1.0", "-m", "release")
    return origin, clone


def test_stable_channel_follows_latest_tag(tmp_path, monkeypatch):
    from secwatch import config, update
    _, clone = _tagged_origin_and_clone(tmp_path)
    monkeypatch.setattr(update, "BASE_DIR", clone)
    monkeypatch.setattr(update, "_reinstall_deps", lambda: None)
    monkeypatch.setattr(update, "_schedule_restart", lambda: True)
    monkeypatch.setattr(config, "UPDATE_CHANNEL", "stable")
    monkeypatch.setattr(config, "UPDATE_VERIFY", False)
    st = update.status(fetch=True)
    assert st["channel"] == "stable"
    assert st["upstream"] == "v1.1.0"        # targeting the tag, not origin/main
    assert st["behind"]
    ok, _ = update.self_update("test")
    assert ok and '1.1.0' in (clone / "secwatch" / "__init__.py").read_text()


def test_main_channel_follows_branch_tip(tmp_path, monkeypatch):
    from secwatch import config, update
    _, clone = _tagged_origin_and_clone(tmp_path)
    monkeypatch.setattr(update, "BASE_DIR", clone)
    monkeypatch.setattr(config, "UPDATE_CHANNEL", "main")
    st = update.status(fetch=True)
    assert st["channel"] == "main"
    assert st["upstream"].startswith("origin/")   # branch tip, not the v1.1.0 tag
    assert st["upstream"] != "v1.1.0"


def test_verify_signature_refuses_unsigned_tag(tmp_path, monkeypatch):
    from secwatch import config, update
    _, clone = _tagged_origin_and_clone(tmp_path)   # tag is NOT signed
    monkeypatch.setattr(update, "BASE_DIR", clone)
    monkeypatch.setattr(update, "_schedule_restart", lambda: True)
    monkeypatch.setattr(config, "UPDATE_CHANNEL", "stable")
    monkeypatch.setattr(config, "UPDATE_VERIFY", True)
    ok, msg = update.self_update("test")
    assert not ok and "signature check failed" in msg
    assert '1.0.0' in (clone / "secwatch" / "__init__.py").read_text()   # not updated
