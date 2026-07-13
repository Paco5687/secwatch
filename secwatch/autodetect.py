"""Host auto-detection for `secwatch init` — probes the environment and builds a
draft site config. Everything is best-effort and non-root: a failed probe just
leaves that section for the operator to fill in. Nothing risky is enabled
silently (LLM stays off; the operator reviews before running).
"""
import glob
import ipaddress
import json
import os
import re
import subprocess
import urllib.request


def _run(*argv, timeout=15):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


# --------------------------------------------------------------------------
# network topology → trusted_nets + admin IPs
# --------------------------------------------------------------------------

def detect_topology():
    notes = []
    server_subnets = []
    for ln in _run("ip", "-4", "-o", "addr", "show").splitlines():
        m = re.search(r"\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", ln)
        if not m:
            continue
        iface, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if iface == "lo" or iface.startswith(("docker", "br-", "veth", "cni")):
            continue
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            continue
        server_subnets.append(str(net))
    # admin IPs = private hosts seen authenticating over SSH
    admin = {}
    for logf in ("/var/log/auth.log", "/var/log/secure"):
        try:
            data = open(logf, errors="replace").read()
        except OSError:
            continue
        for m in re.finditer(r"sshd.*(?:Accepted|Failed).*from ([\d.]+)", data):
            ip = m.group(1)
            try:
                if ipaddress.ip_address(ip).is_private:
                    admin[ip] = admin.get(ip, 0) + 1
            except ValueError:
                pass
    admin_ips = sorted(admin, key=admin.get, reverse=True)[:4]
    trusted = list(dict.fromkeys(
        server_subnets + [f"{a}/32" for a in admin_ips]
        + ["127.0.0.0/8", "172.16.0.0/12"]))
    if server_subnets:
        notes.append(f"server subnet(s): {', '.join(server_subnets)}")
    if admin_ips:
        notes.append(f"admin SSH sources → trusted: {', '.join(admin_ips)} "
                     f"(REVIEW — only keep hosts you administer from)")
    return {"trusted_nets": trusted}, notes


# --------------------------------------------------------------------------
# reverse proxy + access log
# --------------------------------------------------------------------------

def detect_proxy():
    notes = []
    ps = _run("docker", "ps", "--format", "{{.Names}}\t{{.Image}}")
    traefik = next((l.split("\t")[0] for l in ps.splitlines()
                    if "traefik" in l.lower()), None)
    if traefik:
        # access log: a mount destined at /var/log/traefik + a *.log inside it
        access = ""
        for cand in glob.glob("/srv/*/logs/traefik/*.log") + \
                glob.glob("/var/log/traefik/*.log"):
            access = cand
            break
        dyn = ""
        insp = _run("docker", "inspect", traefik)
        try:
            mounts = json.loads(insp)[0].get("Mounts", []) if insp else []
            for mt in mounts:
                if mt.get("Destination", "").endswith("/dynamic"):
                    dyn = mt.get("Source", "")
        except (ValueError, IndexError, KeyError):
            pass
        notes.append(f"reverse proxy: Traefik (container '{traefik}')")
        return {"kind": "traefik", "container": traefik,
                "access_log": access, "dynamic_dir": dyn}, notes
    # nginx / caddy
    if os.path.isdir("/etc/nginx") or _run("pgrep", "-x", "nginx"):
        notes.append("reverse proxy: nginx (log-source adapter is Phase 3)")
        return {"kind": "nginx",
                "access_log": "/var/log/nginx/access.log"}, notes
    if os.path.isdir("/etc/caddy") or _run("pgrep", "-x", "caddy"):
        notes.append("reverse proxy: Caddy (log-source adapter is Phase 3)")
        return {"kind": "caddy", "access_log": ""}, notes
    notes.append("no reverse proxy detected — set paths.access_log manually")
    return {"kind": "unknown", "access_log": ""}, notes


# --------------------------------------------------------------------------
# app hosts (from Traefik rules / container labels)
# --------------------------------------------------------------------------

def detect_app_hosts(proxy):
    hosts = set()
    if proxy.get("dynamic_dir"):
        for f in glob.glob(os.path.join(proxy["dynamic_dir"], "*.yml")):
            if ".bak" in f:
                continue
            try:
                for m in re.finditer(r"Host\(`([^`]+)`\)", open(f).read()):
                    hosts.add(m.group(1))
            except OSError:
                pass
    labels = _run("docker", "ps", "--format", "{{.Names}}")
    for name in labels.splitlines():
        insp = _run("docker", "inspect", "--format",
                    "{{range .Config.Labels}}{{println .}}{{end}}", name)
        for m in re.finditer(r"Host\(`([^`]+)`\)", insp):
            hosts.add(m.group(1))
    # drop internal/admin-ish hosts from the app list (heuristic)
    apps = sorted(h for h in hosts
                  if not h.endswith(".local") and "traefik" not in h)
    notes = [f"discovered {len(apps)} app host(s): {', '.join(apps[:8])}"
             + (" …" if len(apps) > 8 else "")] if apps else \
            ["no app hosts discovered — add endpoint_rules manually"]
    return apps, notes


# --------------------------------------------------------------------------
# containers / images (informational)
# --------------------------------------------------------------------------

def detect_containers():
    imgs = sorted({l.strip() for l in
                   _run("docker", "ps", "--format", "{{.Image}}").splitlines()
                   if l.strip()})
    return imgs, ([f"{len(imgs)} running image(s) → CVE scan target"] if imgs
                  else ["no docker detected — CVE scan + docker watch will idle"])


# --------------------------------------------------------------------------
# local LLM endpoint (opt-in)
# --------------------------------------------------------------------------

def detect_llm():
    for port in (8891, 11434, 8000, 1234, 5000, 8080):
        url = f"http://127.0.0.1:{port}/v1/models"
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                doc = json.loads(r.read())
            model = (doc.get("data") or [{}])[0].get("id", "")
            return ({"base_url": f"http://127.0.0.1:{port}/v1", "model": model},
                    [f"found an OpenAI-compatible LLM on :{port} (model '{model}') "
                     f"— left DISABLED; set llm.enabled: true to use it"])
        except Exception:
            continue
    return None, ["no local LLM endpoint found — LLM analysis stays off (optional)"]


# --------------------------------------------------------------------------
# web-root / upload dirs for FIM
# --------------------------------------------------------------------------

def detect_fim_dirs():
    found = []
    for pat in ("/srv/*/dist", "/srv/*/*/dist", "/srv/*/api/ui/dist",
                "/var/www/*", "/srv/*/public", "/srv/*/*/media",
                "/srv/*/data/*media*"):
        found += [d for d in glob.glob(pat) if os.path.isdir(d)]
    found = sorted(set(found))[:12]
    return found, ([f"{len(found)} candidate web/upload dir(s) for FIM"] if found
                   else ["no obvious web-root dirs — set fim.watch_dirs manually"])


def detect_webhook():
    for f in glob.glob("/srv/*/.secrets/*discord*") + \
            glob.glob("/srv/*/.secrets/*webhook*"):
        return f, [f"found a possible Discord webhook file: {f}"]
    return None, []


# --------------------------------------------------------------------------
# assemble the draft
# --------------------------------------------------------------------------

def build_draft():
    all_notes = []
    topo, n = detect_topology(); all_notes += n
    proxy, n = detect_proxy(); all_notes += n
    apps, n = detect_app_hosts(proxy); all_notes += n
    imgs, n = detect_containers(); all_notes += n
    llm, n = detect_llm(); all_notes += n
    fim, n = detect_fim_dirs(); all_notes += n
    webhook, n = detect_webhook(); all_notes += n

    draft = {
        "paths": {
            "access_log": proxy.get("access_log") or "/var/log/traefik/access.json.log",
            "auth_log": "/var/log/auth.log",
            "dashboard_url": "http://CHANGE-ME:8931/",
        },
        "network": {
            "trusted_nets": topo["trusted_nets"],
            "autoban_private": False,
        },
    }
    if proxy.get("kind") == "traefik":
        draft["proxy"] = {
            "traefik_container": proxy.get("container", "traefik"),
            "traefik_dynamic_dir": proxy.get("dynamic_dir")
            or "/etc/traefik/dynamic",
        }
    if apps:
        draft["app_hosts"] = apps
        draft["endpoint_rules"] = [{
            "name": "login_bruteforce", "label": "app login",
            "hosts": list(apps),   # copy so YAML doesn't emit an anchor/alias
            "path_re": r"^/(login|auth|signin|admin/login)($|[/?])",
            "type": "auth_abuse", "statuses": [400, 401, 403, 422, 429],
            "window": 300, "limit": 12, "severity": "high", "ban": True,
        }]
    if fim:
        draft["fim"] = {"watch_dirs": fim, "canary_dirs": ["/srv", os.path.expanduser("~")]}
    draft["llm"] = {"enabled": False,
                    "base_url": (llm or {}).get("base_url", "http://127.0.0.1:11434/v1"),
                    "model": (llm or {}).get("model", "your-model"), "api_key": ""}
    draft["cve"] = {"enabled": bool(imgs)}
    if webhook:
        draft["alerting"] = {"discord_webhook_file": webhook,
                             "discord_webhook_file_key": "SECWATCH_DISCORD_WEBHOOK_URL"}
    return draft, all_notes, {"images": imgs, "proxy": proxy.get("kind")}
