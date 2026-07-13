"""P2P cluster — explicit-join gossip mesh, no central hub.

Every node stays fully autonomous (it detects + bans ITSELF). Nodes additionally
gossip bans so a hit on one hardens the rest, and any 'peer' can view the whole
cluster (federated read). Membership is by EXPLICIT JOIN with a shared secret —
never auto-discovery, so a random box on the LAN can't join or read.

Roles (config `cluster.role`, nothing host-specific):
  peer — full member: shares bans, serves + reads cluster telemetry (trusted).
  leaf — push-only member for exposed/less-trusted boxes: pushes its bans + events
         to peers and pulls the cluster blocklist, but is NOT queryable and does
         NOT read peers, so a compromised edge box can't recon/poison the cluster.

Wire security: inter-node requests are HMAC-signed with the shared secret (the
secret never crosses the wire) + timestamped to bound replay. Use TLS / a WG
tunnel if the inter-node path isn't trusted.

Stores (in the data dir): cluster.secret (chmod 600), cluster.json (peer roster).
CLI: python -m secwatch.cluster {init|join|list|leave|ping}
"""
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request

from . import config

log = logging.getLogger("secwatch.cluster")

VALID_ROLES = ("standalone", "peer", "leaf")


# ---- shared secret -------------------------------------------------------

def secret() -> bytes:
    try:
        return config.CLUSTER_SECRET_FILE.read_bytes().strip()
    except OSError:
        return b""


def _set_secret(value: bytes):
    config.CLUSTER_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(config.CLUSTER_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(value)


def _generate_secret() -> bytes:
    return hashlib.sha256(os.urandom(32)).hexdigest().encode()


# ---- peer roster ---------------------------------------------------------

def load_peers() -> list:
    try:
        d = json.loads(config.CLUSTER_STORE.read_text())
        return d.get("peers", []) if isinstance(d, dict) else []
    except (OSError, ValueError):
        return []


def _save_peers(peers):
    config.CLUSTER_STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = config.CLUSTER_STORE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"peers": peers}, indent=2))
    os.replace(tmp, config.CLUSTER_STORE)


def add_peer(name, url, role="peer"):
    if not name or name == config.CLUSTER_NAME:
        return load_peers()
    peers = [p for p in load_peers() if p.get("name") != name]
    peers.append({"name": name, "url": (url or "").rstrip("/"), "role": role,
                  "added": time.time()})
    _save_peers(peers)
    return peers


def remove_peer(name):
    _save_peers([p for p in load_peers() if p.get("name") != name])


def queryable_peers():
    """Peers we can read from / push to (leaves aren't queryable)."""
    return [p for p in load_peers() if p.get("role") != "leaf" and p.get("url")]


# ---- HMAC request signing ------------------------------------------------

def sign(body: bytes, ts=None):
    ts = str(int(ts or time.time()))
    sig = hmac.new(secret(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return ts, sig


def verify(ts, sig, body: bytes) -> bool:
    s = secret()
    if not s or not ts or not sig:
        return False
    try:
        if abs(time.time() - int(ts)) > config.CLUSTER_MAX_CLOCK_SKEW:
            return False
    except (ValueError, TypeError):
        return False
    expected = hmac.new(s, str(ts).encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def peer_request(base_url, path, payload, timeout=8):
    """Signed POST to a peer. Returns the decoded JSON, or raises."""
    body = json.dumps(payload).encode()
    ts, sig = sign(body)
    req = urllib.request.Request(
        base_url.rstrip("/") + path, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "secwatch-cluster",
                 "x-secwatch-node": config.CLUSTER_NAME,
                 "x-secwatch-cluster-ts": ts, "x-secwatch-cluster-sig": sig})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def node_identity():
    return {"name": config.CLUSTER_NAME, "role": config.CLUSTER_ROLE,
            "url": config.CLUSTER_URL}


# ---- in-app setup (called by the dashboard, no CLI needed) ---------------

def init_cluster():
    """Create this node's cluster secret if absent. Returns the secret string
    (the operator copies it to the nodes that will join)."""
    if not secret():
        _set_secret(_generate_secret())
    return secret().decode()


def join(peer_url, secret_str):
    """Programmatic join (in-app). Stores the secret, announces to the peer, and
    learns the roster. Returns (ok, message)."""
    peer_url = (peer_url or "").strip().rstrip("/")
    if secret_str:
        _set_secret(secret_str.strip().encode())
    if not secret():
        return False, "no cluster secret provided"
    if not peer_url:
        return False, "a peer URL is required to join"
    try:
        resp = peer_request(peer_url, "/api/cluster/join", {"node": node_identity()})
    except Exception as exc:
        return False, (f"couldn't reach {peer_url}: {exc}. Check the URL, that the "
                       f"peer uses the SAME secret, and that this node can reach it.")
    peer = resp.get("node", {})
    add_peer(peer.get("name"), peer_url, peer.get("role", "peer"))
    for p in resp.get("peers", []):
        add_peer(p.get("name"), p.get("url"), p.get("role", "peer"))
    log.info("joined cluster via %s", peer_url)
    return True, "Joined — %d peer(s) known." % len(load_peers())


def leave_cluster():
    """Drop the secret + roster; this node goes standalone (set role separately)."""
    for f in (config.CLUSTER_STORE, config.CLUSTER_SECRET_FILE):
        try:
            f.unlink()
        except OSError:
            pass


# ---- device enrollment ("Add device" → one-liner) ------------------------
# Single-use, short-TTL tokens gate the /install.sh endpoint. The generated
# script embeds the cluster secret so the new box can auto-join — so a token is a
# credential: mint it just before you run the one-liner, and it's burned on use.
_enroll_tokens = {}   # token -> {expires, role, used}


def mint_enroll_token(role="peer"):
    now = time.time()
    for k in [k for k, v in _enroll_tokens.items() if v["expires"] < now]:
        _enroll_tokens.pop(k, None)   # prune expired
    tok = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    _enroll_tokens[tok] = {"expires": now + config.CLUSTER_ENROLL_TTL,
                           "role": role if role in ("peer", "leaf") else "peer",
                           "used": False}
    return tok, _enroll_tokens[tok]["expires"]


def consume_enroll_token(tok):
    v = _enroll_tokens.get(tok or "")
    if not v or v["used"] or v["expires"] < time.time():
        return None
    v["used"] = True
    return v


def install_script(role):
    """The shell installer served by /install.sh — clones the repo, then hands off
    to install.sh (single source of truth for prereqs/venv/deps/service) in
    cluster-join mode. Runs as root."""
    return f"""#!/bin/sh
# secwatch cluster enrollment — installs secwatch on this host and joins the
# cluster. Runs as root. Review before running.
set -e
REPO="{config.CLUSTER_INSTALL_REPO}"
DIR="{config.CLUSTER_INSTALL_DIR}"

echo "[secwatch] enrolling this host as a {role} ..."
# git is needed to fetch the code; install.sh handles python3/venv/deps.
command -v git >/dev/null 2>&1 || {{ command -v apt-get >/dev/null 2>&1 && apt-get update -qq && apt-get install -y -qq git; }}
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull -q; else git clone -q "$REPO" "$DIR"; fi
cd "$DIR"
SECWATCH_JOIN_URL="{config.CLUSTER_URL}" \\
SECWATCH_JOIN_SECRET="{secret().decode()}" \\
SECWATCH_CLUSTER_ROLE="{role}" \\
  sh ./install.sh
"""


# ---- ban gossip ----------------------------------------------------------
# Bans converge two ways so a firewalled/leaf box (outbound-only) still works:
#   push — the origin immediately POSTs new bans to reachable peers (low latency)
#   pull — every node periodically pulls each reachable peer's blocklist and
#          applies anything new (catches missed pushes + lets a leaf, which can't
#          be pushed to, harden itself by pulling)
_outbox = []   # [{ip, rule, reason, expires}] pending push


def queue_ban(ip, rule, reason, expires):
    """Called from ban.add for LOCAL bans (never cluster/community ones). No-op
    unless this node is clustered."""
    if config.CLUSTER_ENABLED:
        _outbox.append({"ip": ip, "rule": rule, "reason": reason,
                        "expires": expires, "origin": config.CLUSTER_NAME})


def _apply_remote_bans(conn, bans, source):
    from . import ban
    now = time.time()
    applied = 0
    have = {b["ip"] for b in ban.active(conn)}
    for b in bans:
        ip = b.get("ip")
        exp = b.get("expires", 0)
        if not ip or ip in have or exp <= now:
            continue
        ok, _ = ban.add(conn, ip, rule=b.get("rule", "cluster"),
                        reason=(b.get("reason") or "")[:280],
                        ttl_hours=max(0.02, (exp - now) / 3600),
                        banned_by="cluster:" + (b.get("origin") or source))
        applied += 1 if ok else 0
    return applied


def _push_outbox():
    if not _outbox:
        return
    batch, _outbox[:] = list(_outbox), []
    for p in queryable_peers():
        try:
            peer_request(p["url"], "/api/cluster/ban", {"bans": batch})
        except Exception as exc:
            log.debug("cluster push to %s failed: %s", p["name"], exc)


def _pull_blocklists(conn):
    for p in queryable_peers():
        try:
            resp = peer_request(p["url"], "/api/cluster/blocklist", {})
            n = _apply_remote_bans(conn, resp.get("bans", []), p["name"])
            if n:
                log.info("cluster: applied %d ban(s) pulled from %s", n, p["name"])
        except Exception as exc:
            log.debug("cluster pull from %s failed: %s", p["name"], exc)


def _gossip_roster():
    """Converge membership: share my roster with peers, learn theirs."""
    mine = [{"name": p["name"], "url": p.get("url", ""), "role": p.get("role", "peer")}
            for p in load_peers()]
    mine.append(node_identity())
    for p in queryable_peers():
        try:
            resp = peer_request(p["url"], "/api/cluster/roster", {"peers": mine})
            for q in resp.get("peers", []):
                add_peer(q.get("name"), q.get("url"), q.get("role", "peer"))
        except Exception as exc:
            log.debug("cluster roster gossip to %s failed: %s", p["name"], exc)


def merge_roster(peers):
    for q in peers or []:
        add_peer(q.get("name"), q.get("url"), q.get("role", "peer"))


def local_blocklist(conn):
    """Active bans this node holds, for peers to pull."""
    from . import ban
    out = []
    for b in ban.active(conn):
        bb = b.get("banned_by", "") or ""
        # a relayed cluster ban keeps its original origin; a local ban is ours
        origin = bb[len("cluster:"):] if bb.startswith("cluster:") else config.CLUSTER_NAME
        out.append({"ip": b["ip"], "rule": b["rule"], "reason": b.get("reason", ""),
                    "expires": b["expires"], "origin": origin})
    return out


def tick():
    """One gossip cycle (runs in a worker thread, own DB connection)."""
    from . import db
    conn = db.connect()
    try:
        _push_outbox()
        _gossip_roster()
        _pull_blocklists(conn)
        poll_update_campaign()   # catch a fleet-update we weren't pushed (or a leaf)
    finally:
        conn.close()


# ---- leaf event push (leaf isn't queryable, so it pushes its events up) ---

def current_max_event_id():
    from . import db
    conn = db.connect(readonly=True)
    try:
        r = conn.execute("SELECT MAX(id) m FROM events").fetchone()
        return (r["m"] or 0) if r else 0
    finally:
        conn.close()


def push_events_since(last_id):
    """Push this leaf's new events to one reachable peer for the cluster view.
    Returns the new high-water id."""
    from . import db
    peer = next(iter(queryable_peers()), None)
    if not peer:
        return last_id
    conn = db.connect(readonly=True)
    try:
        rows = conn.execute(
            "SELECT id,ts,ip,rule,severity,host,path,ua,detail,count FROM events "
            "WHERE id > ? ORDER BY id LIMIT 300", (last_id,)).fetchall()
    finally:
        conn.close()
    if not rows:
        return last_id
    evs = [dict(r, device=config.CLUSTER_NAME) for r in rows]
    try:
        peer_request(peer["url"], "/api/cluster/event", {"events": evs})
        return rows[-1]["id"]
    except Exception as exc:
        log.debug("leaf event push failed: %s", exc)
        return last_id


# ---- fleet self-update campaign ------------------------------------------
# A peer triggers "update the fleet": it stamps a campaign (ts + target version)
# and pushes it to reachable peers, who apply it (git pull + restart) and re-push
# — so it floods the mesh. A leaf isn't reachable, so it PULLs the campaign on its
# own cycle. Each node records the last campaign it applied, so a campaign fires
# once per node and can't loop (the restart wipes memory; the record is on disk).


def _load_update_state():
    try:
        return json.loads(config.UPDATE_STATE.read_text())
    except (OSError, ValueError):
        return {"campaign_ts": 0, "applied_ts": 0, "by": "", "to_version": ""}


def _save_update_state(st):
    config.UPDATE_STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = config.UPDATE_STATE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(st))
    os.replace(tmp, config.UPDATE_STATE)


def _maybe_apply_campaign(ts, by, to_version):
    """Record a campaign and, if it's newer than what we've applied and this node
    accepts remote updates, self-update. Returns True if an update was started."""
    st = _load_update_state()
    if ts <= st.get("campaign_ts", 0) and ts <= st.get("applied_ts", 0):
        return False
    st["campaign_ts"] = max(ts, st.get("campaign_ts", 0))
    st["by"], st["to_version"] = by, to_version
    if ts <= st.get("applied_ts", 0):
        _save_update_state(st)
        return False
    if not config.UPDATE_ALLOW_REMOTE:
        _save_update_state(st)
        log.info("cluster: ignoring fleet-update from %s (update.allow_remote=false)", by)
        return False
    from . import update
    ok, msg = update.self_update(reason=f"fleet:{by}")
    if ok:
        st["applied_ts"] = ts    # mark applied so we don't loop after the restart
    _save_update_state(st)
    log.info("cluster: fleet-update from %s → %s: %s", by, to_version or "latest", msg)
    return ok


def request_fleet_update(by=None, to_version=None, ts=None):
    """Initiate a fleet update: stamp a campaign and push it to reachable peers.
    Returns the list of peer names reached."""
    ts = int(ts or time.time())
    by = by or config.CLUSTER_NAME
    st = _load_update_state()
    st["campaign_ts"] = ts
    # the initiator doesn't self-update from its own campaign (it's the one already
    # on the new version) — mark it applied so a later pull doesn't bounce it.
    st["applied_ts"] = max(ts, st.get("applied_ts", 0))
    st["by"], st["to_version"] = by, to_version or ""
    _save_update_state(st)
    return _push_update_campaign(ts, by, to_version or "")


def _push_update_campaign(ts, by, to_version):
    reached = []
    for p in queryable_peers():
        try:
            peer_request(p["url"], "/api/cluster/update",
                         {"ts": ts, "by": by, "to_version": to_version})
            reached.append(p["name"])
        except Exception as exc:
            log.debug("cluster update push to %s failed: %s", p["name"], exc)
    return reached


def receive_update_campaign(ts, by, to_version):
    """Handle a campaign pushed by a peer: re-broadcast to our own peers (flood the
    mesh), then apply locally. Re-broadcast happens first so it propagates before
    our own restart. The applied-record guard stops the flood from looping."""
    ts = int(ts or 0)
    if not ts:
        return
    st = _load_update_state()
    if ts > st.get("campaign_ts", 0):
        _push_update_campaign(ts, by, to_version)   # fan out to peers-of-peers
    _maybe_apply_campaign(ts, by, to_version)


def poll_update_campaign():
    """Ask reachable peers for the current campaign and apply it if newer. This is
    how a leaf (never reachable) receives fleet updates, and how a peer catches a
    push it missed. No-op for the initiator (its applied_ts already covers it)."""
    best_ts, best_by, best_ver = 0, "", ""
    for p in queryable_peers():
        try:
            resp = peer_request(p["url"], "/api/cluster/update-poll", {})
            if int(resp.get("ts", 0)) > best_ts:
                best_ts = int(resp["ts"])
                best_by, best_ver = resp.get("by", ""), resp.get("to_version", "")
        except Exception as exc:
            log.debug("cluster update poll from %s failed: %s", p["name"], exc)
    if best_ts:
        _maybe_apply_campaign(best_ts, best_by, best_ver)


def current_campaign():
    st = _load_update_state()
    return {"ts": st.get("campaign_ts", 0), "by": st.get("by", ""),
            "to_version": st.get("to_version", "")}


# ---- CLI -----------------------------------------------------------------

def _cmd_init():
    if secret():
        print("Cluster already initialized (secret exists at %s)." % config.CLUSTER_SECRET_FILE)
    else:
        _set_secret(_generate_secret())
        print("✓ Cluster initialized. Shared secret written (chmod 600) to")
        print("   ", config.CLUSTER_SECRET_FILE)
    print("\nThis node: %s   role: %s   url: %s"
          % (config.CLUSTER_NAME, config.CLUSTER_ROLE, config.CLUSTER_URL or "(unset)"))
    if config.CLUSTER_ROLE == "standalone":
        print("\n⚠ cluster.role is 'standalone' — set it to 'peer' (or 'leaf') in "
              "secwatch.yaml and restart for this node to participate.")
    print("\nOn another node, join this cluster with:")
    print("   python -m secwatch.cluster join %s '%s'"
          % (config.CLUSTER_URL or "http://THIS-NODE:8931", secret().decode() or "<secret>"))


def _cmd_join(peer_url, secret_str):
    if not config.CLUSTER_URL and config.CLUSTER_ROLE == "peer":
        print("⚠ set cluster.url (how peers reach this node) in secwatch.yaml first "
              "— a 'peer' must be reachable. (A 'leaf' can skip it.)")
    _set_secret(secret_str.strip().encode())
    try:
        resp = peer_request(peer_url, "/api/cluster/join",
                            {"node": node_identity()})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print("✗ join failed talking to %s: %s" % (peer_url, exc))
        print("  (check the URL, that the peer is initialized with the SAME secret, "
              "and that this node can reach it across the network/VLAN.)")
        return 1
    peer = resp.get("node", {})
    add_peer(peer.get("name"), peer_url, peer.get("role", "peer"))
    for p in resp.get("peers", []):
        add_peer(p.get("name"), p.get("url"), p.get("role", "peer"))
    print("✓ Joined cluster via %s. Known peers: %s"
          % (peer_url, ", ".join(p["name"] for p in load_peers()) or "(none)"))
    return 0


def _cmd_list():
    print("This node: %s (role=%s, url=%s)"
          % (config.CLUSTER_NAME, config.CLUSTER_ROLE, config.CLUSTER_URL or "-"))
    print("Secret:", "set" if secret() else "NOT SET (run `init` or `join`)")
    peers = load_peers()
    if not peers:
        print("Peers: none")
        return
    print("Peers:")
    for p in peers:
        print("  - %-20s role=%-5s %s" % (p["name"], p.get("role", "?"), p.get("url", "")))


def _cmd_ping(peer_url):
    try:
        resp = peer_request(peer_url, "/api/cluster/ping", {"node": node_identity()})
        print("✓ %s → %s" % (peer_url, resp))
    except Exception as exc:
        print("✗ ping failed: %s" % exc)
        return 1
    return 0


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    cmd = argv[0] if argv else "list"
    if cmd == "init":
        _cmd_init()
    elif cmd == "join":
        if len(argv) < 3:
            print("usage: python -m secwatch.cluster join <peer-url> <shared-secret>")
            return 2
        return _cmd_join(argv[1], argv[2])
    elif cmd == "list":
        _cmd_list()
    elif cmd == "leave":
        if len(argv) < 2:
            print("usage: python -m secwatch.cluster leave <peer-name>")
            return 2
        remove_peer(argv[1])
        print("Removed peer:", argv[1])
    elif cmd == "ping":
        if len(argv) < 2:
            print("usage: python -m secwatch.cluster ping <peer-url>")
            return 2
        return _cmd_ping(argv[1])
    else:
        print("commands: init | join <url> <secret> | list | leave <name> | ping <url>")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
