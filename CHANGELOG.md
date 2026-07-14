# Changelog

Notable changes per release. secwatch is pre-1.0; only the latest release gets
security fixes. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

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
