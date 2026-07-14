"""Shared fixtures. Isolate all on-disk cluster/update state into a tmp dir so
tests never touch a real deployment, and give the node a known identity."""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    """secwatch.config with cluster/update paths redirected to tmp + a known node."""
    from secwatch import config
    monkeypatch.setattr(config, "CLUSTER_STORE", tmp_path / "cluster.json")
    monkeypatch.setattr(config, "CLUSTER_SECRET_FILE", tmp_path / "cluster.secret")
    monkeypatch.setattr(config, "UPDATE_STATE", tmp_path / "update.json")
    monkeypatch.setattr(config, "CLUSTER_NAME", "testnode")
    monkeypatch.setattr(config, "CLUSTER_ROLE", "peer")
    monkeypatch.setattr(config, "CLUSTER_ENABLED", True)
    monkeypatch.setattr(config, "CLUSTER_URL", "http://testnode:8931")
    monkeypatch.setattr(config, "CLUSTER_MAX_CLOCK_SKEW", 120)
    monkeypatch.setattr(config, "CLUSTER_LEAF_RESHARE_EVERY", 10)
    monkeypatch.setattr(config, "UPDATE_ALLOW_REMOTE", True)
    return config
