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

## Supported versions

secwatch is pre-1.0 and moves fast; only the **latest release** receives security
fixes. Update before reporting if you're behind (`git pull` + restart, or the
dashboard's Software updates card).
