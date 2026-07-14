"""The fail-closed exposure guard — the thing that once crash-looped the fleet.
Public interface with no auth -> protected (loopback); private LAN -> warn+allow;
loopback / password / opt-out -> run as configured. It must NEVER hard-fail."""
import pytest


def _set(config, host, auth_on, pw, optout, primary):
    config.LISTEN_HOST = host
    config.AUTH_ENABLED = auth_on
    config.AUTH_PASSWORD_HASH = pw
    config.AUTH_INSECURE_OK = optout
    config._primary_ip = lambda: primary


@pytest.mark.parametrize("host,auth,pw,optout,primary,reason_expected,public_expected", [
    # the fleet case: 0.0.0.0 + no auth + private IP -> concern, but NOT public
    ("0.0.0.0", False, "", False, "10.10.0.229", True, False),
    ("0.0.0.0", False, "", False, "192.168.1.5", True, False),
    ("0.0.0.0", False, "", False, "172.16.0.9", True, False),
    # public interface -> concern AND public (guard will force loopback)
    ("0.0.0.0", False, "", False, "8.8.8.8", True, True),
    ("0.0.0.0", False, "", False, "", True, True),        # unknown route -> assume public
    ("8.8.4.4", False, "", False, "8.8.4.4", True, True),   # bind a specific PUBLIC IP
    # safe configs -> no concern at all
    ("127.0.0.1", False, "", False, "10.0.0.1", False, False),   # loopback
    ("localhost", False, "", False, "10.0.0.1", False, False),
    ("0.0.0.0", True, "hash", False, "8.8.8.8", False, True),    # has a password
    ("0.0.0.0", False, "", True, "8.8.8.8", False, True),        # explicit opt-out
    # auth enabled but NO password set is still a concern (broken config)
    ("0.0.0.0", True, "", False, "10.0.0.1", True, False),
])
def test_guard_matrix(cfg, host, auth, pw, optout, primary, reason_expected, public_expected):
    _set(cfg, host, auth, pw, optout, primary)
    assert (cfg.insecure_exposure_reason() is not None) == reason_expected
    if reason_expected:
        assert cfg.bind_is_public() == public_expected


def test_guard_message_is_actionable(cfg):
    _set(cfg, "0.0.0.0", False, "", False, "10.0.0.5")
    msg = cfg.insecure_exposure_reason()
    assert msg and "SECWATCH_NO_AUTH" in msg and "127.0.0.1" in msg


def test_public_ip_classification(cfg):
    # sanity on the RFC1918 boundary the guard leans on
    _set(cfg, "0.0.0.0", False, "", False, "8.8.8.8")
    assert cfg.bind_is_public() is True
    cfg._primary_ip = lambda: "10.1.2.3"
    assert cfg.bind_is_public() is False
