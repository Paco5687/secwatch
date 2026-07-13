<h1 align="center">secwatch</h1>

<p align="center">
  <b>The easy, all-in-one security monitor for your self-hosted server.</b><br>
  Edge detection, auto-ban, host/EDR-lite, CVE awareness, and optional local-LLM
  traffic analysis — one lightweight tool, one config file, one command to install.
</p>

---

secwatch watches your reverse proxy's access log **and your internal apps' logs**,
keeps an eye on host/process/container state, auto-bans hostile IPs at the edge, and
serves a self-contained dashboard — so you can actually *see* what's hitting your
box and what it's doing. No agents-and-managers stack, no external SaaS, no
account required.

> **Who it's for:** homelabbers and small-fleet admins who expose a few apps
> behind Traefik / nginx / Caddy — and often run internal-only apps too — and want
> real security visibility **without** standing up and wiring together
> CrowdSec + Wazuh + Trivy + fail2ban separately.

## Why secwatch (and how it compares)

secwatch doesn't try to replace the heavyweights — it **rolls the pieces most
homelabbers actually want into one readable, low-dependency tool**:

| You might otherwise run… | …for | secwatch does it |
|---|---|---|
| **fail2ban** | ban brute-forcers from logs | ✅ edge + auth, app-aware |
| **CrowdSec** | edge detection + auto-ban (+ crowd intel) | ✅ edge detection + auto-ban¹ |
| **Wazuh** | host FIM / persistence / EDR | ✅ FIM, persistence, process/egress (lite) |
| **Trivy / Grype** | image CVE scanning | ✅ + CISA-KEV "actively exploited" flag |
| *(nothing common)* | plain-English traffic analysis | ✅ optional local-LLM analyst |

¹ secwatch now has an OPTIONAL, self-hostable crowd-intel layer too (see CROWD.md) — off by default, attacker-IPs-only. **If you already run and love CrowdSec or Wazuh,
keep them** — secwatch is for people who find that stack too much and want one
small thing they can read the source of. Honest scope: it's a monitoring and
mitigation *aid*, not a firewall or a patch manager.

## Features

- **Edge detection + auto-ban** — vuln probes, path scanning, floods, credential
  stuffing, secret-file probes (`.env`/`.git`/…), and declarative per-endpoint
  rules (login brute force, admin abuse, API scraping, IDOR enumeration). Hostile
  IPs are banned at the proxy (Traefik / nftables / nginx).
- **Watches every app, not just the edge** — point it at multiple access logs at
  once (your reverse proxy *and* internal apps that don't sit behind it). One
  detection engine, so bans and rules apply across all of them. Add or
  **auto-discover** ("Scan for logs") sources right from the dashboard — no restart,
  no YAML editing.
- **Host & EDR-lite** — SSH/auth monitoring; a persistence baseline (systemd
  units, SUID, `ld.so.preload`, cron, shell rc, UID-0 accounts); process
  signatures (reverse shells, miners, temp-dir execs); new-egress/C2 awareness.
- **File integrity** — webshell/dropped-script detection in web roots + ransomware
  canaries.
- **CVE awareness** — Trivy-scans running images and flags CVEs on the CISA KEV
  list (actively exploited in the wild).
- **Watchdogs** — alerts if the access log goes silent or the proxy's route config
  changes unexpectedly.
- **Optional LLM analysis** — point it at any OpenAI-compatible endpoint (local
  Ollama/vLLM or a remote API) for a plain-language traffic assessment. Off by
  default.
- **Self-contained dashboard** with a built-in login for direct `IP:PORT` use, and
  Discord alerting.

## Quick start

**One command** — installs everything and starts secwatch as a background service:

```bash
curl -fsSL https://raw.githubusercontent.com/Paco5687/secwatch/main/install.sh | sudo sh
```

It installs prerequisites (git/python3/venv), sets up a virtualenv, writes config
(port `8931` + an auto-generated admin password it prints), and **installs +
starts the systemd service** — no prompts. It ends with
`✅ secwatch is ACTIVE — open http://IP:8931/` and the login it generated.

Customize with env vars: `SECWATCH_PORT`, `SECWATCH_ADMIN_PASSWORD`,
`SECWATCH_NO_AUTH=1` (open dashboard on a trusted LAN), `SECWATCH_NO_START=1`.

Prefer to review the code first? Clone and run the same installer:

```bash
git clone https://github.com/Paco5687/secwatch && cd secwatch
./install.sh        # one sudo prompt to install the service; otherwise identical
```

`secwatch install` auto-detects your reverse proxy + access log, app hosts,
network topology (→ trusted nets), running images, web dirs, and any local LLM
endpoint, writes a reviewable `secwatch.yaml`, and can generate a systemd unit.

Configuring by hand? `cp secwatch.example.yaml secwatch.yaml`, edit it (or run
`python -m secwatch.init` to draft one from your host), then `python -m secwatch.main`.

## Configuration

Everything host-specific lives in `secwatch.yaml` (see the fully-commented
`secwatch.example.yaml`); any value can also be set via a `SECWATCH_*` env var.
Highlights: `log_source.type` (traefik/nginx/caddy/regex), `log_sources` (watch
several at once), `ban.actuator` (traefik/nftables/nginx/none),
`network.trusted_nets` (keep it **narrow**), `endpoint_rules`, `auth.*`
(dashboard login), `llm.*` (optional). You can also add or scan for extra log
sources live from the dashboard's **Log sources** card.

Prefer clicking to editing YAML? The dashboard's **Settings** page edits the
commonly-tuned settings in-app (alerting, LLM, detection thresholds, feature
toggles) — most apply live, secrets are stored encrypted at rest, and it layers
over `secwatch.yaml` (env vars still win). Security-critical settings (trusted
networks, ban actuator, dashboard auth) stay YAML-only by design.

## Alerting

Point secwatch at a **Discord webhook** to get pushed high-severity alerts. Keep
the URL in a gitignored secrets file (see `discord-webhook.env.example`), inline
as `alerting.discord_webhook_url`, or via `SECWATCH_DISCORD_WEBHOOK_URL`:

```yaml
alerting:
  discord_webhook_file: /path/to/.secrets/discord-webhook.env
```

secwatch **bans and records everything** it detects, but by default it does *not*
alert on the constant background of blocked internet scanning (`.env`/`.git`
probes, path scans, floods, 403'd `/admin` hits) — that noise buries the events
that matter. Those still ban + show on the dashboard; tune what's quiet with
`alerting.quiet_rules` (a probe from an internal IP still alerts). Full details in
the [Wiki](https://github.com/Paco5687/secwatch/wiki/Alerting).

## Cluster (fleet)

Run secwatch on several boxes and join them into a **peer-to-peer cluster** — no
central hub. Every node stays fully autonomous (it detects + bans *itself*), and
nodes gossip bans so **a hit on one hardens all**, while any peer can view the
whole fleet. Membership is by explicit join with a shared secret (never
auto-discovery), and inter-node requests are HMAC-signed.

**Easiest: the dashboard's Cluster tab** — pick a role, click **Create cluster**
(copy the secret) or **Join cluster** (paste a peer's URL + secret). No CLI, no
restart. To add more boxes, **Add a device** hands you a one-liner
(`curl -fsSL "http://SEEDER:8931/install.sh?token=…" | sudo sh`) that installs
secwatch and auto-joins — RMM-style. The token is single-use; the script carries
the cluster secret, so run it only over your trusted network. Or from the shell:

```bash
# on the first node:
python -m secwatch.cluster init          # prints the shared secret
# on each other node (set cluster.role in secwatch.yaml first, then):
python -m secwatch.cluster join http://FIRST-NODE:8931 '<secret>'
```

Roles (config `cluster.role`): **peer** — full member (shares bans, viewable,
reads peers); **leaf** — push-only for exposed/less-trusted boxes (contributes
its bans + events and pulls the blocklist, but isn't queryable and can't read
peers, so a compromised edge box can't recon or poison the cluster). A leaf only
makes *outbound* connections, so its port can stay firewalled. See the
[Cluster wiki page](https://github.com/Paco5687/secwatch/wiki/Cluster).

## Deploying with Docker

```bash
docker compose up -d      # see docker-compose.yml for mounts + the mode options
```

`SECWATCH_MODE` = `all` (one privileged container), `core` (isolated web core), or
`agent` (host collectors only, forwarding to a core). The **core + agent** split
keeps the internet-facing core low-privilege while the deep-host-access part stays
a minimal host process.

## Documentation

Full how-to guides live in the **[Wiki](https://github.com/Paco5687/secwatch/wiki)** —
installation, configuration reference, log sources (multi-source + dashboard),
detection & bans, dashboard auth, CVE/LLM/crowd-intel, Docker & deployment modes,
and troubleshooting.

## Requirements

Python 3.11+. Optional: Docker (CVE scan + container watch), an OpenAI-compatible
LLM endpoint (AI analysis), `nft`/`nginx` for those ban actuators.

## Contributing

Issues and PRs welcome — new log-source/ban adapters, detection rules, and distro
testing especially. secwatch is young; real-world reports make it better. Please
don't file exploit details for third-party software here.

## License

[MIT](LICENSE)
