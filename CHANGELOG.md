# Changelog

Notable changes per release. secwatch is pre-1.0; only the latest release gets
security fixes. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

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
