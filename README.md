<h1 align="center">secwatch</h1>

<p align="center">
  <b>The easy, all-in-one security monitor for your self-hosted server.</b><br>
  Edge detection, auto-ban, host/EDR-lite, CVE awareness, and optional local-LLM
  traffic analysis — one lightweight tool, one config file, one command to install.
</p>

---

secwatch watches your reverse proxy's access log and your host's auth log, keeps
an eye on host/process/container state, auto-bans hostile IPs at the edge, and
serves a self-contained dashboard — so you can actually *see* what's hitting your
box and what it's doing. No agents-and-managers stack, no external SaaS, no
account required.

> **Who it's for:** homelabbers and small-fleet admins who expose a few apps
> behind Traefik / nginx / Caddy and want real security visibility **without**
> standing up and wiring together CrowdSec + Wazuh + Trivy + fail2ban separately.

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

```bash
git clone https://github.com/Paco5687/secwatch && cd secwatch
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

python -m secwatch.install     # pick a port, create an admin login, auto-detect config
# follow the printed steps → open http://SERVER-IP:PORT/ and sign in
```

`secwatch install` auto-detects your reverse proxy + access log, app hosts,
network topology (→ trusted nets), running images, web dirs, and any local LLM
endpoint, writes a reviewable `secwatch.yaml`, and can generate a systemd unit.

Configuring by hand? `cp secwatch.example.yaml secwatch.yaml`, edit it (or run
`python -m secwatch.init` to draft one from your host), then `python -m secwatch.main`.

## Configuration

Everything host-specific lives in `secwatch.yaml` (see the fully-commented
`secwatch.example.yaml`); any value can also be set via a `SECWATCH_*` env var.
Highlights: `log_source.type` (traefik/nginx/caddy/regex), `ban.actuator`
(traefik/nftables/nginx/none), `network.trusted_nets` (keep it **narrow**),
`endpoint_rules`, `auth.*` (dashboard login), `llm.*` (optional).

## Deploying with Docker

```bash
docker compose up -d      # see docker-compose.yml for mounts + the mode options
```

`SECWATCH_MODE` = `all` (one privileged container), `core` (isolated web core), or
`agent` (host collectors only, forwarding to a core). The **core + agent** split
keeps the internet-facing core low-privilege while the deep-host-access part stays
a minimal host process.

## Requirements

Python 3.11+. Optional: Docker (CVE scan + container watch), an OpenAI-compatible
LLM endpoint (AI analysis), `nft`/`nginx` for those ban actuators.

## Contributing

Issues and PRs welcome — new log-source/ban adapters, detection rules, and distro
testing especially. secwatch is young; real-world reports make it better. Please
don't file exploit details for third-party software here.

## License

[MIT](LICENSE)
