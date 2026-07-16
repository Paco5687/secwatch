# Security Policy

secwatch is a security tool, so it holds itself to the standard it asks of others:
report privately, fix quickly, disclose honestly.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's private advisory form — **[Report a vulnerability](https://github.com/Paco5687/secwatch/security/advisories/new)**
(Security → Advisories → *Report a vulnerability*). If you can't use that, open a
normal issue titled "security contact needed" with **no details** and we'll open a
private channel.

Please include, as far as you can:

- the version / commit (`git rev-parse HEAD`, or the version in the dashboard footer),
- how secwatch was deployed (installer, Docker, cluster role, ban actuator),
- a description of the issue and its impact,
- steps or a proof-of-concept to reproduce it.

## What to expect

- **Acknowledgement:** within **3 business days**.
- **Assessment + severity:** within about a week, shared back with you.
- **Fix:** targeted as fast as severity warrants — critical issues first, with a
  patched release and an advisory. We'll credit you unless you'd rather stay anonymous.

This is a small, volunteer-maintained project, not a company with a 24/7 SoC — but
security reports jump the queue.

## Scope

In scope (secwatch's own code and defaults):

- authentication / session handling for the dashboard,
- the inter-node cluster protocol (HMAC auth, ban gossip, enrollment tokens, the
  `/install.sh` endpoint),
- the self-update mechanism,
- ban-actuator adapters (Traefik / nftables / nginx),
- secret handling (encrypted settings store, gitignored secrets, the release scrubber),
- unsafe-by-default behaviour (e.g. anything that would expose the dashboard without a login).

Out of scope:

- vulnerabilities in **third-party software** secwatch monitors or integrates with
  (report those to their maintainers — including CVEs Trivy surfaces),
- findings that require an already-root/already-compromised host,
- missing hardening that is documented and opt-in (e.g. deliberately running
  `SECWATCH_NO_AUTH=1` on an untrusted network),
- reports from automated scanners with no demonstrated impact.

## Deploying secwatch safely

A short version of the hardening secwatch already tries to enforce:

- **Keep a dashboard password** (the installer sets one). secwatch refuses to serve
  an unauthenticated dashboard on a network interface unless you explicitly opt in.
- **Keep secrets out of git** — the cluster secret, webhooks, and API keys live in
  gitignored files / the encrypted settings store, never in the repo.
- **Treat enrollment one-liners like passwords** — they carry the cluster secret and
  are single-use; run them only over a trusted network.
- **Front it with TLS** (a reverse proxy or WireGuard) if nodes talk across an
  untrusted network — the HMAC layer authenticates peers but doesn't encrypt.

## Update & supply-chain trust model

secwatch installs and self-updates from its git repo, so **the repository is part of
your trust boundary**: whoever can push to it (or tamper with the network path of a
fetch on a node that trusts plain HTTP) can ship code that runs as root on every node
that updates. Be clear-eyed about that, and reduce it:

- **Follow signed release tags, not the branch tip.** `update.channel: stable`
  (default) updates to the latest `vX.Y.Z` **release tag** rather than `main`, so a
  node only moves to a version the maintainer deliberately cut and tagged. Releases
  are published as GitHub Releases with a source tarball and `SHA256SUMS`.
- **Verify signatures.** Release tags are **GPG-signed**. The maintainer's public key
  is in [`KEYS`](KEYS) in this repo; its fingerprint is:

  ```
  F09F AE2D F0EA 30DC DA34  AB93 BE63 96E3 59FE 03B5
  ```

  Verify a release before trusting it:

  ```bash
  gpg --import KEYS
  git verify-tag v0.11.1          # "Good signature" from the fingerprint above
  ```

  Set `update.verify_signature: true` on a node (after `gpg --import KEYS` into the
  service user's keyring) to make self-update run `git verify-tag` and **refuse** any
  unsigned or untrusted tag. (Commits are unsigned by policy; release *tags* are the
  trust anchor.)
- **Pin if you want zero surprise.** Leave `update.auto: false` (the default) and
  update on your schedule; or pin a node to a specific tag and update it by hand.
- **Fetch over a trusted path.** Clone/fetch over HTTPS or SSH; on untrusted segments,
  tunnel it. The cluster's HMAC authenticates peers but doesn't encrypt the git path.
- **A leaf never accepts inbound update commands it can't verify** — fleet updates are
  gated by `update.allow_remote`, and each node still fetches + (optionally) verifies
  the code itself; a peer only tells it *when*, not *what bytes to run*.

If you find a way to make a node run code that bypasses these controls, that's exactly
the kind of report we want — see above.

## Supported versions

secwatch is pre-1.0 and moves fast; only the **latest release** receives security
fixes. Update before reporting if you're behind (`git pull` + restart, or the
dashboard's Software updates card).
