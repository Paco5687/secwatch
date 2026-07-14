# Contributing to secwatch

Thanks for looking! secwatch is young, and real-world reports make it better.
Bug reports, distro/proxy testing, detection rules, and new adapters are all
especially welcome.

## Ground rules

- **Security issues do not go here.** See [SECURITY.md](SECURITY.md) and report
  privately.
- **Don't file exploit details for third-party software.** secwatch monitors other
  software; vulnerabilities in *that* software belong to its maintainers.
- Be kind. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Good first contributions

- **Log-source adapters** — a new reverse proxy / app log format (`parser.py`,
  `logsources.py`).
- **Ban actuators** — a new way to enforce a ban (`ban.py` adapters: Traefik,
  nftables, nginx today).
- **Detection rules** — new `endpoint_rules`, or tuning the built-in thresholds with
  evidence from real logs.
- **Distro / deployment testing** — run the installer on a distro we haven't tried
  and tell us what broke.

## Development setup

secwatch is plain Python (3.11+) with a small pinned dependency set and no build step.

```bash
git clone https://github.com/Paco5687/secwatch && cd secwatch
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp secwatch.example.yaml secwatch.yaml     # then edit for your host
python -m secwatch.main                    # dashboard on http://127.0.0.1:8931/
```

For a throwaway run against sample data, point `log_sources` at a copy of a log
file rather than a live one.

## Making a change

1. **Open an issue first** for anything non-trivial, so we can agree on the approach
   before you write code.
2. Branch, make the change, and **keep it focused** — one logical change per PR.
3. **Match the surrounding style.** secwatch favours small, readable modules with
   explanatory docstrings over cleverness. No formatter is enforced; read like the
   neighbours.
4. **Test what you touch.** There's no heavy framework — a short `python -` snippet
   or script that exercises the new path (and proves the failure mode) is enough.
   Describe how you verified it in the PR.
5. **Don't commit secrets or host-specifics.** No real IPs, hostnames, tokens,
   webhooks, or password hashes — the public repo is scrubbed on release, but keep
   your commits clean too.
6. **Update docs** — the README, `secwatch.example.yaml`, and the wiki page for the
   feature you changed.

## Reporting a bug

Include the version (dashboard footer / `git rev-parse HEAD`), how you deployed it,
what you expected, what happened, and any relevant log lines
(`journalctl --user -u secwatch -b`) — with IPs/hostnames redacted.

## License

By contributing, you agree your contributions are licensed under the project's
[MIT License](LICENSE).
