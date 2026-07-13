# secwatch

A lightweight, self-hosted **edge + host security monitor** for homelab and
small-fleet servers. It tails your reverse proxy's access log and the host's
auth log, watches host/process/container state, auto-bans hostile IPs at the
edge, and serves a self-contained dashboard — with an optional local-LLM traffic
analysis pass. One config file, no external services required.

> Config-driven and proxy-agnostic. Works with Traefik, nginx, or Caddy; bans via
> Traefik, nftables, or nginx. Runs as a systemd service or a container.

## Features

- **Edge detection** — vulnerability probes, path scanning, request floods,
  credential stuffing, secret-file probes (`.env`/`.git`/…), and declarative
  per-endpoint rules (login brute force, admin-route abuse, API scraping, IDOR
  enumeration). Hostile IPs are **auto-banned** at the proxy.
- **Host & EDR-lite** — SSH/auth monitoring, a persistence/foothold baseline
  (systemd units, SUID binaries, `ld.so.preload`, cron, shell rc, UID-0
  accounts), process signatures (reverse shells, miners, temp-dir execs), and
  new-egress/C2 awareness.
- **File integrity** — webshell/dropped-script detection in web roots, plus
  ransomware canaries.
- **CVE awareness** — scans running container images with Trivy and flags CVEs on
  the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  list (actively exploited in the wild).
- **Watchdogs** — alerts if the access log goes silent (proxy down / logging
  disabled) and on unexpected changes to the proxy's route config.
- **Optional LLM analysis** — an OpenAI-compatible endpoint (local Ollama/vLLM or
  a remote API) can produce a plain-language traffic assessment. Off by default.
- **Self-contained dashboard** — stat tiles, traffic chart, events, bans, and
  (optionally) CVE + AI-analysis cards. Built-in login for direct IP:port use.
- **Alerting** — high-severity events to a Discord webhook.

## Quick start

```bash
git clone https://github.com/Paco5687/secwatch && cd secwatch
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

python -m secwatch.install     # pick a port, create an admin login, auto-detect config
# follow the printed steps → open http://SERVER-IP:PORT/ and sign in
```

`secwatch install` auto-detects your reverse proxy + access log, app hosts,
network topology (→ trusted nets), running images, web dirs, and any local LLM
endpoint, writes a reviewable `secwatch.yaml`, and can generate a systemd unit.

Prefer to configure by hand? `cp secwatch.example.yaml secwatch.yaml`, edit it
(or run `python -m secwatch.init` to draft one), then `python -m secwatch.main`.

## Configuration

All host/site-specifics live in `secwatch.yaml` (see the fully-commented
`secwatch.example.yaml`); every value can also be overridden with a `SECWATCH_*`
environment variable. Highlights:

- `log_source.type` — `traefik` | `nginx` | `caddy` | `regex`
- `ban.actuator` — `traefik` | `nftables` | `nginx` | `none`
- `network.trusted_nets` — keep this **narrow** (server subnet + admin hosts),
  not the whole LAN, so a compromised device elsewhere is still monitored
- `endpoint_rules` — declarative app-specific detection
- `auth.*` — built-in dashboard login (for direct IP:port exposure)
- `llm.*` — optional AI analysis (off by default)

## Deployment modes

A security monitor's need for host visibility is in tension with container
isolation, so `SECWATCH_MODE` offers three shapes:

| Mode | Runs | Host access |
|---|---|---|
| `all` | everything, one process | high (pid, /proc, /var/log, docker socket) |
| `core` | detection / dashboard / CVE / LLM / alerting / ban | minimal — pairs with an agent |
| `agent` | host collectors only, forwards events to a core | high, but a small host process |

The **core + agent** split keeps the internet-facing web core in a low-privilege
container while the deep-host-access part stays a minimal host process (`python
-m secwatch.agent`), forwarding events to the core's token-gated `/api/ingest`.

```bash
docker compose up -d      # see docker-compose.yml for mounts and the mode options
```

## Dashboard auth

When reached directly on `IP:PORT` (no authenticating proxy), enable the built-in
login (`auth.enabled`, set up by `secwatch install`): password-hashed, signed
session cookie, failed-login lockout. Deployments already behind an
authenticating proxy can leave it off; `auth.trust_proxy_from` (localhost by
default) bypasses it so the proxy path keeps working.

## Requirements

Python 3.11+. Optional: Docker (CVE scan + container watch), an OpenAI-compatible
LLM endpoint (AI analysis), `nft`/`nginx` for those ban actuators.

## Security & scope

secwatch is a monitoring and mitigation aid, not a replacement for a firewall,
patching, or least-privilege configuration. Detection is heuristic; review
before automating destructive actions. Contributions and issues welcome.

## License

MIT
