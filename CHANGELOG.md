# Changelog

Notable changes per release. secwatch is pre-1.0; only the latest release gets
security fixes. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.11.4]

### Added
- **A logo.** A shield-with-monitoring-pulse mark + the `secwatch_` terminal wordmark
  (cyan accent, matching the dashboard). Ships as `docs/brand/` SVGs (light + dark
  lockups, square mark), in the README header (theme-aware via `<picture>`), and as
  the dashboard's favicon.

## [0.11.3]

### Added
- **Dashboard screenshots in the README** — hero overview + a "look inside" gallery
  (ban explainability, CVE/KEV, in-app settings) and the three themes (Ops / Terminal
  / Light). Captured from `--demo`, so entirely synthetic.

### Fixed
- **Demo mode is fully isolated from the live host.** `python -m secwatch.demo` started
  the full app, so it (a) ran the host collectors against the real box — writing real
  events (operator IP, hostnames, process cmdlines) into the demo DB — and (b) drove
  the real ban actuator, overwriting the live Traefik ban file with its seeded synthetic
  bans. Demo now forces `MODE=core` (no host collectors), `BAN_ACTUATOR=none` +
  `AUTOBAN=false` (never touches a real ban file), and starts from a fresh DB — strictly
  the seeded synthetic dataset.

## [0.11.1]

### Security
- **Signed releases.** Release tags are now GPG-signed by the maintainer. The public
  key ships in [`KEYS`](KEYS) (fingerprint in SECURITY.md); verify any release with
  `gpg --import KEYS && git verify-tag vX.Y.Z`. `update.verify_signature: true` makes a
  node refuse an unsigned/untrusted tag. `release.sh` signs the tag when a signing key
  is configured (it now is).

## [0.11.0]

### Added
- **Host hang/crash early-warning + self-heal (kernwatch).** Watches the kernel log
  for *any* fault class that precedes an unresponsive hang — IOMMU/DMA (`AMD-Vi`),
  MCE/EDAC, soft/hard lockups, rcu stalls, OOM, storage/nvme/ata errors, PCIe AER,
  thermal, NIC hangs, oops — plus resource precursors (root fs near-full, RAM
  exhaustion, runaway load with stuck-I/O procs, dangerous temps). Because a hard
  freeze can't be repaired live, the key action is a **forensic snapshot** captured
  the instant a high-severity precursor appears (top procs, D-state list, dmesg,
  temps, failed units) — so the next hang leaves a file instead of a black hole.
  Safe **auto-remediations** (disk cleanup, restart failed units) are **opt-in**
  (`kernwatch.autofix`, off by default); hardware faults get an **advisory** with the
  recommended fix. Everything — trigger, action, and a *did-it-resolve* re-check — is
  written to a `remediations` audit table and shown in a new **Self-heal** dashboard
  view (`/api/remediations`, `POST /api/remediations/snapshot`). Detection + snapshots
  on by default. Directly motivated by the real `AMD-Vi` freeze this platform hit.

## [0.10.1]

### Added
- **Inline ban / allowlist / mute in the Events rows.** Every event row now has
  one-click actions: **ban** or **allowlist** its IP, and **mute** — a *targeted*
  false-positive suppressor. A mute is scoped from the event: by IP, by host (e.g.
  silence `edge_silent` on a node that isn't really your edge proxy), or by an
  editable **detail substring** (e.g. your own `curl | bash` installer URL, so a
  `dropper` alert for your own tooling stops firing) — never the blunt whole-rule
  silence unless you choose it. Muted events are still recorded; they just don't
  alert. A **Suppression** card in Settings lists the allowlist + mutes and removes
  them. Endpoints: `GET /api/mutes`, `POST /api/mute`; check lives in
  `detect.Engine._event`.

## [0.10.0]

### Added
- **Demo mode (`python -m secwatch.demo`).** Seeds a throwaway DB with realistic
  synthetic activity (probes, brute force, a webshell, bans from several sources, a
  KEV CVE) and serves the dashboard — no config, no real logs — so anyone can see a
  populated secwatch in one command. Loopback + auth-off + a separate `demo.db`, and
  it never tails a real log. README "See it first" section; `docs/screenshots/` teed
  up for a hero shot + GIF.
- **Packaging.** A CI workflow builds + pushes a **multi-arch image** (amd64 + arm64)
  to **GHCR** (`ghcr.io/paco5687/secwatch`) on every release tag, and a
  **Proxmox LXC helper** (`deploy/proxmox-lxc.sh`) creates a Debian container and
  installs secwatch in it with one command on the PVE host. README documents both.
- **Ban transparency + a never-ban allowlist.** The IP drill-down now shows *why* an
  IP was banned (the rule/reason) and its **source** (this node / a named cluster peer
  / the community list), alongside the existing evidence trail (triggering events +
  traffic). New actions: **Unban + allowlist** (reverse a ban and never re-ban that
  IP) and a plain **Allowlist/Remove**. The allowlist is a runtime, dashboard-editable
  never-ban list (IP or CIDR) enforced in `ban.add`, so *any* source — local, cluster,
  or community — is refused for an allowlisted address. Kills the "will it lock me out
  of my own thing?" fear.
- **Alerts beyond Discord.** A notifier layer delivers alerts to **ntfy, Gotify,
  Telegram, and a generic webhook** as well as Discord — any number of targets via
  `alerting.targets`. Discord stays fully back-compatible (rich embeds; a bare
  webhook is an implicit target). Settings → Alerts has a **"Send test alert"** button
  that fires a test to every configured target and shows per-target results. A failing
  target never blocks the others.
- **Prometheus metrics + Grafana dashboard.** `GET /metrics` exposes a scrape
  snapshot — events (total + 24h by severity), high-severity count, active bans (and
  by source), CVE findings (by severity + KEV), log-source lag, and cluster peers —
  in native Prometheus text format (no new dependency). Gated by loopback / a bearer
  token (`metrics.token`) / an open-LAN dashboard, never unauthenticated on a public
  interface. Ships `deploy/grafana-dashboard.json` and a scrape example.
- **Supply-chain hardening for install + self-update.** Update now follows a
  **channel**: `stable` (default) tracks the latest signed release **tag** — a
  deliberate, verifiable version — instead of the bleeding-edge branch tip (`main`);
  it falls back to `main` until the repo has tags. `update.verify_signature` makes a
  node run `git verify-tag` and **refuse** an unsigned/untrusted release. `release.sh`
  now cuts a signed (or annotated) tag and publishes a GitHub Release with a source
  tarball + `SHA256SUMS`. SECURITY.md documents the full update trust model. The
  dashboard shows the active channel.
- **Automated test suite + CI.** A `pytest` suite in `tests/` covers the
  regression-prone core we'd been checking by hand: the fail-closed exposure guard
  (public→loopback, private→warn, safe configs), cluster HMAC auth (+ replay window),
  the roster (version storage/preservation, leaf exclusion), the fleet-update campaign
  state machine, leaf ban reshare, and `self_update` git fast-forward. A GitHub
  Actions workflow runs ruff + pytest on Python 3.11–3.13 plus a boot/`/healthz`
  smoke test on every push and PR. CI badge in the README.

## [0.9.6]

### Added
- **Change a node's role from the dashboard.** The Cluster → *Manage cluster* card now
  has a peer/leaf selector, so you can flip a node between peer and leaf without SSHing
  in to edit config. It persists to the node's config (visible to the CLI and dashboard
  alike — no env-vs-config split) and applies live; restart to fully settle a
  peer↔leaf switch. (Enrollment already persisted the role chosen at "Add device"
  time; this covers changing it afterward.)

## [0.9.5]

### Fixed
- **A leaf's bans now reliably reach the cluster.** Peers converge bans two ways
  (push *and* being pulled from); a **leaf** can't be pulled from, so its bans went
  out by one-shot push only — and that push was fire-and-forget, so a transient
  failure silently dropped the ban (worst on an internet-facing edge box, whose bans
  matter most). A leaf now also **re-pushes its full locally-originated blocklist**
  on boot and every Nth gossip cycle (`cluster.leaf_reshare_every`, default 10) —
  idempotent, so peers skip what they already hold. Also propagates bans that predate
  a restart (the in-memory outbox starts empty).

## [0.9.4]

### Fixed
- **The fail-closed guard no longer crash-loops a homelab node.** In 0.9.1–0.9.3 a
  node bound to `0.0.0.0` with no dashboard password (a legitimate trusted-LAN setup)
  would *refuse to start* after updating — turning a running monitor into a boot
  loop. The guard is now network-aware: it force-protects only a **public** interface
  (falls back to `127.0.0.1`, stays up, not exposed) and merely **warns** on a
  private LAN (`10.x`/`192.168.x`/`172.16.x`). It never exits. Set a password or
  `SECWATCH_NO_AUTH=1` to silence the warning. If your cluster nodes were stuck
  restarting, updating to this release brings them back automatically.

## [0.9.3]

### Added
- **Unreachable-peer detection.** When a cluster peer is in the roster but this node
  can't reach its `:8931`, the Cluster view now shows a **warning banner** (and marks
  the node card "unreachable — connection refused / timed out") with step-by-step fix
  instructions: check the service is listening on a LAN address, and open the port to
  the cluster subnet with a ready-to-paste `ufw` rule. Previously such peers silently
  showed "offline" with no explanation. The overview also reports *why* (the
  connection error) per node.

### Docs
- README + Cluster wiki: a **Networking** section — peers must reach each other on
  `:8931`, open it to the cluster subnet only (not the internet), leaves need no
  inbound rule — plus an "unreachable peer" troubleshooting walkthrough.

## [0.9.2]

### Added
- **Updates work on standalone nodes too** — the *Software updates* card now also
  lives on the **Settings** page, so a node that isn't in a cluster has a place to
  check for and apply updates (previously it was only on the Cluster page).
- **Version badges in the cluster view** — each node shows its running version, with
  an "update available ⬆" marker when it's behind the newest node in the fleet.
  Versions propagate via node identity / roster gossip (leaves included, refreshed on
  their event push).

## [0.9.1]

### Security
- **Fail closed on unauthenticated exposure.** secwatch now refuses to start if it
  would serve the dashboard on a non-loopback interface (e.g. `0.0.0.0`) with no
  password set. Opt out for a trusted-LAN/behind-a-proxy deployment with
  `SECWATCH_NO_AUTH=1` or `auth.allow_insecure: true`; binding
  `SECWATCH_HOST=127.0.0.1` is exempt. This closes a footgun on the
  clone-and-run-by-hand path (the installer already set a password).

### Added
- `SECURITY.md` (private disclosure policy), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  and this changelog.

## [0.9.0]

### Added
- **In-app self-update + one-click fleet updates.** Cluster → *Software updates*
  shows running vs. latest version and updates a node in place (`git pull` +
  restart). From a peer, *Update entire fleet* pushes the update to every peer and
  leaf (leaves pull it on their next sync). `update.auto` for scheduled updates;
  `update.allow_remote` to pin a node.

## [0.8.0]

### Added
- **Host OS CVE scanning (no Docker required).** Trivy binary scans the host's
  installed OS packages, in addition to running container images. Reports only
  fixable HIGH/CRITICAL by default (`cve.ignore_unfixed`), cross-referenced with the
  CISA KEV list. `cve.scan_host` toggle.

## [0.7.0] – [0.7.11]

### Added
- **Peer-to-peer cluster (no hub):** explicit join with a shared secret, HMAC-signed
  inter-node requests, ban gossip (a hit on one hardens all), federated read, and a
  push-only *leaf* role for exposed boxes.
- **In-app cluster setup** and **RMM-style device enrollment** — an *Add device*
  one-liner (`curl … install.sh?token=… | sudo sh`) that installs and auto-joins.

### Changed
- **Onboarding hardened for public use:** a true one-liner installer that installs
  dependencies and auto-starts the systemd service with zero prompts; portable
  pinned Python via `uv` (host Python version no longer matters); pinned dependency
  set for reproducible installs.

### Fixed
- Numerous installer/venv edge cases (missing `ensurepip`, broken venv recovery,
  sudo password prompt handling, cluster-URL auto-detection on enrollment).

## [0.6.0]

### Added
- **In-app Settings page** — edit commonly-tuned config from the dashboard; secrets
  encrypted at rest; most settings apply live.

## [0.5.0]

### Added
- **First-class hosted LLM support** — point the optional analyst at any
  OpenAI-compatible endpoint (local Ollama/vLLM or a remote API).

## [0.4.x] and earlier

Foundational releases: edge detection + auto-ban, multi-log-source support, host &
EDR-lite (persistence, process/egress), file-integrity (webshell/canary), CVE
awareness (container images), the themeable dashboard, Discord alerting with
noise-quieting, standalone dashboard auth, and the first-run installer.
