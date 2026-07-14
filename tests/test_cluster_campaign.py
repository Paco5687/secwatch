"""Fleet self-update campaign: the initiator doesn't update itself, a received
campaign re-broadcasts + applies once, an already-applied campaign is a no-op (no
loop), allow_remote gates it, and a leaf poll takes the newest campaign."""
import pytest


@pytest.fixture
def campaign(cfg, monkeypatch):
    from secwatch import cluster, update
    applied, pushed = [], []
    monkeypatch.setattr(update, "self_update", lambda reason="x": (applied.append(reason), (True, "ok"))[1])
    monkeypatch.setattr(cluster, "queryable_peers",
                        lambda: [{"name": "b", "url": "http://b"}, {"name": "c", "url": "http://c"}])
    monkeypatch.setattr(cluster, "peer_request",
                        lambda url, path, payload, timeout=8: pushed.append((url, payload)) or {"ts": 0})
    return cluster, applied, pushed


def test_initiator_does_not_self_update(campaign):
    cluster, applied, pushed = campaign
    reached = cluster.request_fleet_update("nodeA", "0.9.0", ts=1000)
    st = cluster._load_update_state()
    assert reached == ["b", "c"]
    assert st["applied_ts"] == 1000        # marked applied so a later pull won't bounce it
    assert applied == []                   # ...but it did NOT run self_update on itself


def test_receive_rebroadcasts_and_applies_once(campaign):
    cluster, applied, pushed = campaign
    cluster.receive_update_campaign(2000, "seed", "1.0.0")
    assert applied == ["fleet:seed"]
    assert len(pushed) == 2                # flooded to both peers
    assert cluster._load_update_state()["applied_ts"] == 2000
    # same campaign again -> no re-apply, no re-flood
    applied.clear(); pushed.clear()
    cluster.receive_update_campaign(2000, "seed", "1.0.0")
    assert applied == [] and pushed == []


def test_allow_remote_false_records_but_skips(campaign, cfg):
    cluster, applied, pushed = campaign
    cfg.UPDATE_ALLOW_REMOTE = False
    cluster.receive_update_campaign(3000, "seed", "1.1.0")
    st = cluster._load_update_state()
    assert applied == []                   # did not update
    assert st["campaign_ts"] == 3000       # but recorded that it exists
    assert st.get("applied_ts", 0) == 0


def test_leaf_poll_takes_newest(campaign, monkeypatch):
    cluster, applied, pushed = campaign
    monkeypatch.setattr(cluster, "peer_request",
                        lambda url, path, payload, timeout=8:
                        {"ts": 5000, "by": "seed", "to_version": "1.1"} if "b" in url else {"ts": 4000})
    cluster.poll_update_campaign()
    assert applied == ["fleet:seed"]
    assert cluster._load_update_state()["applied_ts"] == 5000
