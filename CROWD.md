# Crowd-sourced threat intel

secwatch can **optionally** pool threat data across installs: each install shares
the IPs it confirms as hostile, a self-hostable aggregator builds a *consensus*
blocklist (an IP many independent installs flagged), and every install pulls that
list to block known-bad IPs before they even probe it. Each install makes the
rest stronger.

**It is off by default and opt-in.** A security tool phoning home has to earn
that trust, so:

## Privacy

Only three things ever leave your install, and only when you enable sharing:

- the **attacker's IP**
- the **rule** that flagged it (e.g. `scan`, `secret_probe`)
- a **timestamp**

Plus an opaque per-install `reporter` id (a random UUID, not tied to your
hostname, network, or any identity). **Never shared:** your traffic, request
contents, hostnames, users, config, or anything about *you* — only about the
attacker. It's the same principle as a shared fail2ban blocklist.

## How consensus works (and why it resists poisoning)

The aggregator only lists an IP once **N distinct reporters** (`AGG_CONSENSUS`,
default 3) have independently flagged it within a window (`AGG_WINDOW_DAYS`,
default 7). So one malicious or misconfigured install can't push an IP onto the
community list. Reports are token-gated, rate-limited per reporter, and only
public IPs are accepted (private/reserved ranges are rejected).

> **Threat model (v1):** run the aggregator among installs you trust, gated by a
> shared token you distribute. Strong Sybil resistance (per-install identity /
> vouching so one actor can't fake many reporters) is future work.

## Running an aggregator (self-hosted)

```bash
SECWATCH_AGG_TOKEN=<a-long-shared-secret> python -m secwatch.aggregator
# listens on :8950 — put it behind your reverse proxy with TLS
```

It stores only `reporter, ip, rule, ts` in its own SQLite DB. Endpoints:
`POST /report`, `GET /blocklist`, `GET /healthz` (all token-gated except health).

## Enabling it on an install

In `secwatch.yaml`:

```yaml
crowd:
  enabled: true
  url: https://your-aggregator.example        # your self-hosted aggregator
  token: <the-shared-secret>
  share: true       # report my confirmed bans (attacker IPs only)
  consume: true     # pull + pre-emptively block the consensus list
  ban_ttl_hours: 72 # community bans expire (self-heal if an IP goes good)
```

Set `share: false` to consume only (leech), or `consume: false` to contribute
only. Community-sourced bans are tagged `community` in the ban list and are
**never re-reported** upstream (no feedback loops).
