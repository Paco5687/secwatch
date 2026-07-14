"""Leaf ban reshare: a leaf re-pushes only its LOCALLY-ORIGINATED bans (never ones
relayed from the cluster), on boot and every Nth tick; a peer never reshares."""


def test_reshare_only_local_origin(cfg, monkeypatch):
    from secwatch import cluster
    cfg.CLUSTER_ROLE = "leaf"
    sent = []
    monkeypatch.setattr(cluster, "queryable_peers", lambda: [{"name": "t", "url": "http://t"}])
    monkeypatch.setattr(cluster, "peer_request",
                        lambda url, path, payload, timeout=8: sent.append([b["ip"] for b in payload["bans"]]))
    monkeypatch.setattr(cluster, "local_blocklist", lambda conn: [
        {"ip": "1.1.1.1", "rule": "scan", "reason": "", "expires": 9e9, "origin": cfg.CLUSTER_NAME},
        {"ip": "2.2.2.2", "rule": "probe", "reason": "", "expires": 9e9, "origin": cfg.CLUSTER_NAME},
        {"ip": "3.3.3.3", "rule": "cluster", "reason": "", "expires": 9e9, "origin": "peerX"},  # relayed
    ])
    cluster._reshare_local_bans(conn=None)
    assert sent == [["1.1.1.1", "2.2.2.2"]]   # relayed 3.3.3.3 excluded


def test_reshare_noop_when_no_local_bans(cfg, monkeypatch):
    from secwatch import cluster
    sent = []
    monkeypatch.setattr(cluster, "queryable_peers", lambda: [{"name": "t", "url": "http://t"}])
    monkeypatch.setattr(cluster, "peer_request", lambda *a, **k: sent.append(1))
    monkeypatch.setattr(cluster, "local_blocklist", lambda conn: [
        {"ip": "3.3.3.3", "rule": "cluster", "reason": "", "expires": 9e9, "origin": "peerX"},
    ])
    cluster._reshare_local_bans(conn=None)
    assert sent == []


def test_tick_cadence_leaf_vs_peer(cfg, monkeypatch):
    from secwatch import cluster, db
    fired = []
    monkeypatch.setattr(cluster, "_push_outbox", lambda: None)
    monkeypatch.setattr(cluster, "_gossip_roster", lambda: None)
    monkeypatch.setattr(cluster, "_pull_blocklists", lambda c: None)
    monkeypatch.setattr(cluster, "poll_update_campaign", lambda: None)
    monkeypatch.setattr(cluster, "_reshare_local_bans", lambda conn: fired.append(cluster._tick_count))

    class FakeConn:
        def close(self):
            pass
    monkeypatch.setattr(db, "connect", lambda *a, **k: FakeConn())

    cfg.CLUSTER_ROLE = "leaf"
    cluster._tick_count = 0
    for _ in range(23):
        cluster.tick()
    assert fired == [0, 10, 20]            # boot + every Nth cycle

    cfg.CLUSTER_ROLE = "peer"
    cluster._tick_count = 0
    fired.clear()
    for _ in range(23):
        cluster.tick()
    assert fired == []                     # peers never reshare (mutual pull covers them)
