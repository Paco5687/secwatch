# Screenshots

Drop dashboard screenshots here and reference them from the top of the main README
(a hero shot + a short GIF sells a security dashboard better than any paragraph).

## How to capture a clean, real-looking set

Run demo mode — it populates the UI with synthetic-but-realistic data, offline:

```bash
python -m secwatch.demo        # http://127.0.0.1:8931/
```

Then capture (light theme reads best in a README; grab dark too if you like):

| File | View | What it shows |
|------|------|---------------|
| `overview.png` | Overview | threat banner, stat tiles, traffic sparkline, recent events |
| `events.png` | Events | the event stream + an IP drill-down (why an IP was banned) |
| `cluster.png` | Cluster | the fleet with per-node version badges + roles |
| `vulnerabilities.png` | Vulnerabilities | CVE findings with the KEV (actively-exploited) flag |
| `settings.png` | Settings | in-app config, Software updates, Alerts test |
| `demo.gif` | — | a ~15s screen recording clicking through the above |

Keep images ≲ 1600px wide and optimized (`oxipng`/`pngquant`). Reference them like:

```markdown
<p align="center"><img src="docs/screenshots/overview.png" alt="secwatch dashboard" width="900"></p>
```
