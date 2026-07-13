"""Ban actuators — how a ban is enforced at the edge (pluggable).

`sync(ips)` makes the edge reflect exactly the given set of banned IPs
(idempotent). Select with `ban.actuator` in secwatch.yaml:
  traefik  — write a high-priority ClientIP deny router file (default)
  nftables — maintain an nft set dropped in the input chain (needs root)
  nginx    — write a `deny <ip>;` include + reload nginx (needs root)
  none     — alert-only; don't actuate anything
"""
import logging
import os
import subprocess

from . import config

log = logging.getLogger("secwatch.ban.actuator")

_HEADER = "# Managed by secwatch — do not edit by hand.\n"

_TRAEFIK_EMPTY = _HEADER + """\
http:
  middlewares:
    secwatch-deny-all:
      ipWhiteList:
        sourceRange:
          - "255.255.255.255/32"
"""

# A Traefik router is either TLS or non-TLS, so a single router can't cover both
# HTTP and HTTPS — we emit one per entrypoint (websecure needs tls:{} or it never
# matches HTTPS). Without this, banned IPs are only blocked on :80, not :443.
_TRAEFIK_TEMPLATE = _HEADER + """\
http:
  routers:
    secwatch-ban-web:
      rule: "{rule}"
      priority: 2000000
      entryPoints: [ "web" ]
      middlewares: [ "secwatch-deny-all" ]
      service: noop@internal
    secwatch-ban-websecure:
      rule: "{rule}"
      priority: 2000000
      entryPoints: [ "websecure" ]
      middlewares: [ "secwatch-deny-all" ]
      service: noop@internal
      tls: {{}}
  middlewares:
    secwatch-deny-all:
      ipWhiteList:
        sourceRange:
          - "255.255.255.255/32"
"""


def _traefik(ips):
    content = (_TRAEFIK_TEMPLATE.format(
        rule=" || ".join(f"ClientIP(`{ip}`)" for ip in ips)) if ips
        else _TRAEFIK_EMPTY)
    path = config.BANS_FILE
    try:
        if path.exists() and path.read_text() == content:
            return
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content)
        os.replace(tmp, path)  # atomic — the proxy's watcher never sees a partial file
        log.info("traefik actuator: wrote %s (%d ban(s))", path, len(ips))
    except OSError as exc:
        log.error("traefik actuator: %s", exc)


def _none(ips):
    log.debug("none actuator: %d ban(s) recorded but not enforced", len(ips))


def nft_commands(ips):
    """The nft commands to reconcile the banned set (also used by tests)."""
    t, s = config.NFT_TABLE, config.NFT_SET
    cmds = [
        ["nft", "add", "table", "inet", t],
        ["nft", "add", "set", "inet", t, s, "{ type ipv4_addr; }"],
        ["nft", "add", "chain", "inet", t, "input",
         "{ type filter hook input priority -5; }"],
        ["nft", "add", "rule", "inet", t, "input", f"ip saddr @{s} drop"],
        ["nft", "flush", "set", "inet", t, s],
    ]
    if ips:
        cmds.append(["nft", "add", "element", "inet", t, s,
                     "{ " + ", ".join(ips) + " }"])
    return cmds


def _nftables(ips):
    ok = True
    for cmd in nft_commands([ip for ip in ips if ":" not in ip]):  # IPv4 set
        r = subprocess.run(cmd, capture_output=True, text=True)
        # the add-table/set/chain/rule calls are idempotent; ignore "exists"
        if r.returncode != 0 and "exists" not in r.stderr.lower() \
                and cmd[1] in ("flush", "add") and cmd[2] == "element":
            ok = False
            log.error("nftables actuator: %s → %s", " ".join(cmd), r.stderr.strip())
    if ok:
        log.info("nftables actuator: synced %d ban(s) into %s/%s",
                 len(ips), config.NFT_TABLE, config.NFT_SET)


def _nginx(ips):
    content = _HEADER + "".join(f"deny {ip};\n" for ip in ips)
    path = config.NGINX_DENY_FILE
    try:
        with open(path, "w") as f:
            f.write(content)
    except OSError as exc:
        log.error("nginx actuator: write %s: %s", path, exc)
        return
    r = subprocess.run(config.NGINX_RELOAD_CMD.split(), capture_output=True, text=True)
    if r.returncode != 0:
        log.error("nginx actuator: reload failed: %s", r.stderr.strip())
    else:
        log.info("nginx actuator: wrote %s (%d ban(s)) + reloaded", path, len(ips))


_ACTUATORS = {"traefik": _traefik, "nftables": _nftables,
              "nginx": _nginx, "none": _none}


def sync(ips):
    ips = list(ips)[: config.BAN_MAX_ACTIVE]
    fn = _ACTUATORS.get(config.BAN_ACTUATOR)
    if fn is None:
        log.error("unknown ban.actuator %r — using 'none'", config.BAN_ACTUATOR)
        fn = _none
    fn(ips)
