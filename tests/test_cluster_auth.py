"""Inter-node HMAC: a good signature over the exact body verifies; a tampered
body, wrong signature, missing secret, or stale timestamp (replay) all fail."""
import time


def test_sign_verify_roundtrip(cfg):
    from secwatch import cluster
    cfg.CLUSTER_SECRET_FILE.write_bytes(b"shared-secret")
    body = b'{"node":"a"}'
    ts, sig = cluster.sign(body)
    assert cluster.verify(ts, sig, body)


def test_tampered_body_fails(cfg):
    from secwatch import cluster
    cfg.CLUSTER_SECRET_FILE.write_bytes(b"shared-secret")
    ts, sig = cluster.sign(b'{"amount":1}')
    assert not cluster.verify(ts, sig, b'{"amount":1000000}')


def test_wrong_signature_fails(cfg):
    from secwatch import cluster
    cfg.CLUSTER_SECRET_FILE.write_bytes(b"shared-secret")
    ts, _ = cluster.sign(b"{}")
    assert not cluster.verify(ts, "deadbeef", b"{}")


def test_no_secret_never_verifies(cfg):
    from secwatch import cluster
    # no secret file written
    assert not cluster.verify(str(int(time.time())), "anything", b"{}")


def test_stale_timestamp_rejected_replay_window(cfg):
    from secwatch import cluster
    cfg.CLUSTER_SECRET_FILE.write_bytes(b"shared-secret")
    body = b"{}"
    old = int(time.time()) - (cfg.CLUSTER_MAX_CLOCK_SKEW + 60)
    ts, sig = cluster.sign(body, ts=old)
    assert not cluster.verify(ts, sig, body)   # outside the replay window


def test_wrong_secret_fails(cfg):
    from secwatch import cluster
    cfg.CLUSTER_SECRET_FILE.write_bytes(b"secret-A")
    ts, sig = cluster.sign(b"{}")
    cfg.CLUSTER_SECRET_FILE.write_bytes(b"secret-B")   # peer has a different secret
    assert not cluster.verify(ts, sig, b"{}")
