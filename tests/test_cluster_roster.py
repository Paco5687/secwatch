"""Roster: add/remove peers, self is never added, version is stored and preserved
across churn, leaves are excluded from the queryable set."""


def test_add_and_list_peer(cfg):
    from secwatch import cluster
    cluster.add_peer("alpha", "http://alpha:8931/", "peer", "0.9.0")
    peers = cluster.load_peers()
    assert [p["name"] for p in peers] == ["alpha"]
    assert peers[0]["url"] == "http://alpha:8931"       # trailing slash stripped
    assert peers[0]["version"] == "0.9.0"


def test_self_never_added(cfg):
    from secwatch import cluster
    cluster.add_peer(cfg.CLUSTER_NAME, "http://self:8931", "peer")
    assert cluster.load_peers() == []


def test_version_preserved_when_reoffered_without_one(cfg):
    from secwatch import cluster
    cluster.add_peer("alpha", "http://alpha:8931", "peer", "0.9.0")
    cluster.add_peer("alpha", "http://alpha:8931", "peer")          # no version this time
    assert cluster.load_peers()[0]["version"] == "0.9.0"
    cluster.add_peer("alpha", "http://alpha:8931", "peer", "0.9.5")  # bump
    assert cluster.load_peers()[0]["version"] == "0.9.5"


def test_queryable_excludes_leaves_and_urlless(cfg):
    from secwatch import cluster
    cluster.add_peer("peerA", "http://a:8931", "peer")
    cluster.add_peer("leafB", "http://b:8931", "leaf")
    cluster.add_peer("peerC", "", "peer")                # no url -> not queryable
    names = {p["name"] for p in cluster.queryable_peers()}
    assert names == {"peerA"}


def test_remove_peer(cfg):
    from secwatch import cluster
    cluster.add_peer("alpha", "http://a:8931", "peer")
    cluster.add_peer("beta", "http://b:8931", "peer")
    cluster.remove_peer("alpha")
    assert {p["name"] for p in cluster.load_peers()} == {"beta"}


def test_node_identity_carries_version(cfg):
    from secwatch import __version__, cluster
    ident = cluster.node_identity()
    assert ident["name"] == cfg.CLUSTER_NAME
    assert ident["version"] == __version__
