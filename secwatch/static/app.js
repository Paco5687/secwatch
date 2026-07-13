/* secwatch UI — hash-routed SPA, no build step, no dependencies.
   All URLs are relative so the app works at / or under a proxy subpath. */
"use strict";

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const fmtN = n => n >= 1e6 ? (n/1e6).toFixed(1)+"M" : n >= 1e4 ? Math.round(n/1e3)+"k" : n >= 1000 ? (n/1e3).toFixed(1)+"k" : String(n ?? 0);
const fmtT = ts => new Date(ts*1000).toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"});
const fmtAgo = ts => {
  if (!ts) return "never";
  const s = Math.max(0, Date.now()/1000 - ts);
  if (s < 90) return Math.round(s) + "s ago";
  if (s < 5400) return Math.round(s/60) + "m ago";
  if (s < 172800) return Math.round(s/3600) + "h ago";
  return Math.round(s/86400) + "d ago";
};
const chip = sev => `<span class="chip sev-${esc(sev)}"><i></i>${esc(sev)}</span>`;
const ipLink = ip => ip && ip !== "-" ? `<a class="iplink" data-ip="${esc(ip)}">${esc(ip)}</a>` : `<span class="mono">${esc(ip)}</span>`;

let CFG = {mut: {}, auth: false, llm: false, version: ""};
let hoursSel = () => +($("hours").value || 24);

async function jget(url) { const r = await fetch(url); if (!r.ok) throw new Error(r.status); return r.json(); }
async function jpost(url, body) {
  return fetch(url, {method: "POST",
    headers: body !== undefined ? {"Content-Type": "application/json", ...CFG.mut} : {...CFG.mut},
    body: body !== undefined ? JSON.stringify(body) : undefined})
    .then(r => r.json()).catch(() => ({ok: false, message: "request failed"}));
}

/* ---------- theme ---------- */
const THEME_KEY = "secwatch-theme";
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("theme").value = t;
  try { localStorage.setItem(THEME_KEY, t); } catch (e) {}
}
$("theme").addEventListener("change", () => applyTheme($("theme").value));

/* ---------- router ---------- */
const VIEWS = {};   // name -> {title, render()}
let current = null, refreshTimer = null;

function parseHash() {
  const h = location.hash.replace(/^#\/?/, "");
  const [name, qs] = h.split("?");
  const params = new URLSearchParams(qs || "");
  return {name: name || "overview", params};
}
function nav(name, params) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  location.hash = "#/" + name + qs;
}
async function route() {
  const {name, params} = parseHash();
  const view = VIEWS[name] || VIEWS.overview;
  current = {name: VIEWS[name] ? name : "overview", params};
  document.querySelectorAll(".navitem").forEach(el =>
    el.classList.toggle("active", el.dataset.view === current.name));
  $("viewTitle").textContent = view.title;
  $("view").innerHTML = `<div class="empty">Loading…</div>`;
  try { await view.render(params); }
  catch (e) { $("view").innerHTML = `<div class="card"><div class="empty">Failed to load: ${esc(e.message || e)}</div></div>`; }
  $("foot").textContent = `updated ${new Date().toLocaleTimeString()} · auto-refresh 30s`;
}
window.addEventListener("hashchange", route);
document.querySelectorAll(".navitem").forEach(el =>
  el.addEventListener("click", () => nav(el.dataset.view)));
$("hours").addEventListener("change", () => route());

function scheduleRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    const el = document.activeElement;
    const typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA");
    if (!document.hidden && !typing && !$("dossier").classList.contains("open")) route();
  }, 30000);
}

/* ---------- shared chart ---------- */
function drawBars(svg, series, hours) {
  const W = svg.clientWidth || 700, H = +svg.getAttribute("height") || 180;
  const padL = 36, padR = 6, padT = 8, padB = 20;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  if (!series.length) { svg.innerHTML = `<text x="${W/2}" y="${H/2}" text-anchor="middle">no traffic data yet</text>`; return; }
  const max = Math.max(...series.map(d => d.r), 1);
  const iw = W - padL - padR, ih = H - padT - padB;
  const n = series.length, bw = Math.max(2, iw/n - 2);
  let g = "";
  for (let i = 1; i <= 3; i++) {
    const v = max * i / 3, y = padT + ih - ih * i / 3;
    g += `<line x1="${padL}" y1="${y}" x2="${W-padR}" y2="${y}" stroke="var(--grid)" stroke-width="1"/>`;
    g += `<text x="${padL-6}" y="${y+4}" text-anchor="end">${fmtN(Math.round(v))}</text>`;
  }
  const t0 = series[0].t, t1 = series[n-1].t, span = Math.max(t1 - t0, 1);
  series.forEach(d => {
    const x = padL + (n === 1 ? 0 : (d.t - t0) / span * (iw - bw));
    const h = Math.max(d.r > 0 ? 2 : 0, d.r / max * ih);
    g += `<rect class="bar" x="${x}" y="${padT+ih-h}" width="${bw}" height="${h}" rx="2"
           data-t="${d.t}" data-r="${d.r}" data-e="${d.e ?? ""}"/>`;
  });
  g += `<line x1="${padL}" y1="${padT+ih}" x2="${W-padR}" y2="${padT+ih}" stroke="var(--baseline)" stroke-width="1"/>`;
  const labelEvery = Math.ceil(n / 6);
  series.forEach((d, i) => {
    if (i % labelEvery) return;
    const x = padL + (n === 1 ? 0 : (d.t - t0) / span * (iw - bw));
    const opts = hours > 48 ? {month:"short", day:"numeric"} : {hour:"2-digit", minute:"2-digit"};
    g += `<text x="${x}" y="${H-4}">${new Date(d.t*1000).toLocaleString([], opts)}</text>`;
  });
  svg.innerHTML = g;
  const tip = $("tooltip");
  svg.querySelectorAll(".bar").forEach(b => {
    b.addEventListener("mousemove", e => {
      tip.style.display = "block";
      tip.style.left = Math.min(e.clientX + 12, window.innerWidth - 190) + "px";
      tip.style.top = (e.clientY - 44) + "px";
      tip.innerHTML = `<div class="t">${fmtT(+b.dataset.t)}</div>` +
        `<b>${(+b.dataset.r).toLocaleString()}</b> requests` +
        (b.dataset.e !== "" && +b.dataset.e ? ` · ${(+b.dataset.e).toLocaleString()} errors` : "");
    });
    b.addEventListener("mouseleave", () => tip.style.display = "none");
  });
}

/* ---------- dossier drawer (IP drill-down) ---------- */
async function openDossier(ip) {
  const d = $("dossier"), ov = $("overlay");
  d.innerHTML = `<div class="dhead"><span class="dip">${esc(ip)}</span></div><div class="empty">Loading…</div>`;
  d.classList.add("open"); ov.classList.add("open");
  let info;
  try { info = await jget(`api/ipinfo?ip=${encodeURIComponent(ip)}`); }
  catch (e) { d.innerHTML += `<div class="empty">lookup failed</div>`; return; }
  const b = info.ban;
  const banBtn = b
    ? `<button class="danger" data-act="unban">Unban</button>`
    : `<button class="danger" data-act="ban">Ban 24h</button>`;
  const evs = (info.events || []).map(e =>
    `<div class="devent sev-${esc(e.severity)}">
       <div class="when">${fmtT(e.ts)} · ${esc(e.rule)}${e.count > 1 ? " ×" + e.count : ""}</div>
       <div class="what">${esc(e.path || e.detail || "")}</div>
     </div>`).join("");
  d.innerHTML =
    `<div class="dhead"><span class="dip">${esc(ip)}</span>` +
    (info.trusted ? `<span class="tag">trusted</span>` : "") +
    (b ? `<span class="tag" style="background:var(--crit);color:var(--chip-ink)">banned</span>` : "") +
    `<div class="spacer" style="flex:1"></div>${info.trusted ? "" : banBtn}` +
    `<button data-act="close">✕</button></div>` +
    `<div class="drdns">${esc(info.rdns || "no reverse DNS")}</div>` +
    (b ? `<div class="drdns">ban: ${esc(b.rule)} · by ${esc(b.banned_by)} · until ${fmtT(b.expires)}</div>` : "") +
    `<div class="dstats">
       <span><b>${fmtN(info.requests)}</b>requests ${info.hours}h</span>
       <span><b>${fmtN(info.s4xx)}</b>4xx</span>
       <span><b>${(info.events || []).length}</b>events</span>
       <span><b>${info.last_seen ? fmtAgo(info.last_seen) : "–"}</b>last seen</span>
     </div>` +
    `<div class="dsec">Traffic (24h)</div><svg id="dChart" width="100%" height="70"></svg>` +
    `<div class="dsec">Events</div>` + (evs || `<div class="empty">No events recorded.</div>`);
  drawBars($("dChart"), info.series || [], 24);
  d.querySelectorAll("[data-act]").forEach(btn => btn.addEventListener("click", async () => {
    const act = btn.dataset.act;
    if (act === "close") return closeDossier();
    if (act === "ban") { await jpost("api/ban", {ip}); openDossier(ip); }
    if (act === "unban") { await jpost("api/unban", {ip}); openDossier(ip); }
  }));
}
function closeDossier() { $("dossier").classList.remove("open"); $("overlay").classList.remove("open"); }
$("overlay").addEventListener("click", closeDossier);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDossier(); });
// any .iplink anywhere opens the dossier
document.addEventListener("click", e => {
  const t = e.target.closest && e.target.closest(".iplink");
  if (t && t.dataset.ip) { e.preventDefault(); openDossier(t.dataset.ip); }
});

/* ================= views ================= */

/* ---------- overview ---------- */
const CAT_META = {
  edge:   {label: "EDGE",   sub: "proxy & app traffic", go: () => nav("events", {cat: "edge"})},
  host:   {label: "HOST",   sub: "ssh · processes · docker", go: () => nav("host")},
  files:  {label: "FILES",  sub: "webshells · canaries", go: () => nav("host", {cat: "files"})},
  cve:    {label: "CVE",    sub: "image vulnerabilities", go: () => nav("vulns")},
  system: {label: "SYSTEM", sub: "self-checks", go: () => nav("system")},
};
function catState(c) {
  if (c.state) return c.state;                       // server-decided (cve/system)
  if (c.high) return ["CRITICAL", "st-critical", "on-crit"];
  if (c.medium) return ["ALERT", "st-alert", "on-serious"];
  if (c.low) return ["WATCH", "st-watch", "on-warn"];
  return ["NOMINAL", "st-secure", "on-good"];
}
VIEWS.overview = {
  title: "Overview",
  async render() {
    const hours = hoursSel();
    const [ov, sum] = await Promise.all([
      jget(`api/overview?hours=${hours}`), jget(`api/summary?hours=${hours}`)]);
    if (sum.auth) $("logoutForm").style.display = "block";
    const high = (sum.severities || {}).high || 0;
    const badge = $("navHigh");
    badge.style.display = high ? "" : "none"; badge.textContent = high;

    const t = ov.threat || {};
    const lamp = `<span class="statuslamp lamp-${esc(t.level || "low")}"><i></i>${esc((t.level || "low").toUpperCase())}</span>`;
    const cats = Object.entries(CAT_META).map(([key, meta]) => {
      const c = Object.assign({}, (ov.categories || {})[key]);
      // server sends facts; presentation overrides for the two special cards
      if (key === "cve" && ov.kev) {
        c.state = ["KEV RISK", "st-critical", "on-crit"];
        c.sub = `${ov.kev} actively exploited — patch first`;
      }
      if (key === "system" && ov.health_ok === false) {
        c.state = ["DEGRADED", "st-alert", "on-serious"];
        c.sub = "self-check failing — see System";
      }
      const [word, cls, seg] = catState(c);
      const total = c.count || 0;
      const lit = c.state ? 8
        : total ? Math.min(8, Math.ceil(Math.log2(total + 1)) + (c.high ? 4 : c.medium ? 2 : 0))
        : 1;   // healthy heartbeat: one lit segment
      const segClass = total || c.state ? seg : "on-good";
      const segs = Array.from({length: 8}, (_, i) =>
        `<i class="${i < lit ? segClass : ""}"></i>`).join("");
      const sub = c.sub || (total ? `${total} event${total > 1 ? "s" : ""}${c.top ? " · " + c.top : ""}` : meta.sub);
      return `<div class="card catcard" data-cat="${key}">
        <div class="catname">${meta.label}</div>
        <div class="catstate ${cls}">${word}</div>
        <div class="catsub">${esc(sub)}</div>
        <div class="catbar">${segs}</div></div>`;
    }).join("");

    const recent = (ov.recent || []).map(e =>
      `<div class="row"><span>${chip(e.severity)} <span class="mono">${esc(e.rule)}</span> ${ipLink(e.ip)}</span>` +
      `<span class="n">${fmtAgo(e.ts)}</span></div>`).join("");

    $("view").innerHTML =
      `<div class="card" id="threatBanner">${lamp}
         <div class="headline">${esc(t.headline || "No anomalies requiring attention.")}</div>
         <div class="quick">
           <span><b>${fmtN(sum.requests)}</b>requests</span>
           <span><b>${fmtN(sum.unique_ips)}</b>unique IPs</span>
           <span><b>${fmtN(Object.values(sum.severities || {}).reduce((a, b) => a + b, 0))}</b>events</span>
           <span><b>${ov.bans ?? 0}</b>bans active</span>
         </div></div>` +
      `<div class="catgrid">${cats}</div>` +
      `<div class="grid2">
         <div class="card"><h2>Traffic · ${sum.bucket_minutes}-min buckets</h2>
           <svg id="ovChart" width="100%" height="190"></svg></div>
         <div class="card"><h2>Recent activity</h2>
           <div class="list">${recent || `<div class="empty">Quiet out there.</div>`}</div></div>
       </div>`;
    drawBars($("ovChart"), sum.series || [], hours);
    document.querySelectorAll(".catcard").forEach(el =>
      el.addEventListener("click", () => CAT_META[el.dataset.cat].go()));
  },
};

/* ---------- events (shared by Events + Host views) ---------- */
async function renderEventTable(params, opts) {
  const hours = hoursSel();
  const q = new URLSearchParams({hours, limit: 400});
  ["severity", "rule", "ip", "q", "cat", "device"].forEach(k => { const v = params.get(k); if (v) q.set(k, v); });
  if (opts.forceCat) q.set("cat", opts.forceCat);
  const [data, fleet] = await Promise.all([jget(`api/events?${q}`), jget("api/devices").catch(() => ({devices: [], count: 0}))]);
  const rules = [...new Set(data.events.map(e => e.rule))].sort();
  const multi = (fleet.count || 0) > 1;   // only surface device UI on a real fleet
  const rows = data.events.map(e =>
    `<tr><td class="mono" style="white-space:nowrap">${fmtT(e.ts)}</td><td>${chip(e.severity)}</td>` +
    `<td><span class="rulechip" data-rule="${esc(e.rule)}">${esc(e.rule)}</span></td>` +
    (multi ? `<td><span class="rulechip" data-dev="${esc(e.device || "")}">${esc(e.device || "—")}</span></td>` : "") +
    `<td>${ipLink(e.ip)}</td><td>${esc(e.host)}</td>` +
    `<td class="path" title="${esc(e.path)}">${esc(e.path)}</td>` +
    `<td style="font-size:12.5px;color:var(--ink2)">${esc(e.detail)}${e.alerted ? " 🔔" : ""}</td>` +
    `<td class="mono">${e.count}</td></tr>`).join("");
  const ncol = multi ? 9 : 8;

  $("view").innerHTML =
    `<div class="card">
      <div class="filters">
        <select id="fSev">
          <option value="">All severities</option>
          ${["high","medium","low","info"].map(s => `<option ${params.get("severity") === s ? "selected" : ""}>${s}</option>`).join("")}
        </select>
        <select id="fRule">
          <option value="">All rules</option>
          ${rules.map(r => `<option ${params.get("rule") === r ? "selected" : ""}>${esc(r)}</option>`).join("")}
        </select>
        ${multi ? `<select id="fDev"><option value="">All devices</option>${
          fleet.devices.map(d => `<option ${params.get("device") === d.device ? "selected" : ""}>${esc(d.device)}</option>`).join("")}</select>` : ""}
        <input type="text" id="fQ" placeholder="search path / detail / host…" value="${esc(params.get("q") || "")}">
        ${params.get("cat") && !opts.forceCat ? `<span class="tag">category: ${esc(params.get("cat"))}</span><button id="fClearCat">✕</button>` : ""}
        <span class="rules" style="margin-left:auto">${data.events.length} shown</span>
      </div>
      <div class="tablewrap"><table>
        <thead><tr><th>Time</th><th>Sev</th><th>Rule</th>${multi ? "<th>Device</th>" : ""}<th>IP</th><th>Host</th><th>Path</th><th>Detail</th><th>N</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="${ncol}" class="empty">No events match.</td></tr>`}</tbody>
      </table></div>
    </div>`;

  const upd = patch => {
    const p = Object.fromEntries(params);
    Object.assign(p, patch);
    Object.keys(p).forEach(k => { if (!p[k]) delete p[k]; });
    nav(opts.viewName, p);
  };
  $("fSev").addEventListener("change", () => upd({severity: $("fSev").value}));
  $("fRule").addEventListener("change", () => upd({rule: $("fRule").value}));
  const fd = $("fDev"); if (fd) fd.addEventListener("change", () => upd({device: fd.value}));
  let deb;
  $("fQ").addEventListener("input", () => { clearTimeout(deb); deb = setTimeout(() => upd({q: $("fQ").value}), 450); });
  const cc = $("fClearCat"); if (cc) cc.addEventListener("click", () => upd({cat: ""}));
  document.querySelectorAll(".rulechip").forEach(el =>
    el.addEventListener("click", () => upd(el.dataset.dev !== undefined ? {device: el.dataset.dev} : {rule: el.dataset.rule})));
}
VIEWS.events = { title: "Events", render: p => renderEventTable(p, {viewName: "events"}) };
VIEWS.host = { title: "Host / EDR", render: p => renderEventTable(p, {viewName: "host", forceCat: p.get("cat") || "host,files"}) };

/* ---------- bans ---------- */
VIEWS.bans = {
  title: "Bans",
  async render() {
    const d = await jget("api/bans");
    const rows = d.bans.map(b =>
      `<tr><td>${ipLink(b.ip)}</td><td class="mono">${esc(b.rule)}</td>` +
      `<td style="font-size:12.5px;color:var(--ink2)">${esc(b.reason || "")}</td>` +
      `<td class="mono">${esc(b.banned_by)}</td><td class="mono" style="white-space:nowrap">${fmtT(b.expires)}</td>` +
      `<td><button class="danger" data-unban="${esc(b.ip)}">unban</button></td></tr>`).join("");
    $("view").innerHTML =
      `<div class="card">
        <div class="cardhead"><h2>Active bans</h2>
          <span class="tag">${d.autoban ? "auto-ban ON" : "auto-ban OFF"}</span>
          <div class="spacer"></div>
          <input type="text" id="banIp" placeholder="IP to ban" spellcheck="false" style="width:170px">
          <button id="banBtn" class="danger">Ban 24h</button>
        </div>
        <div class="tablewrap"><table>
          <thead><tr><th>IP</th><th>Rule</th><th>Reason</th><th>By</th><th>Expires</th><th></th></tr></thead>
          <tbody>${rows || `<tr><td colspan="6" class="empty">No active bans.</td></tr>`}</tbody>
        </table></div>
      </div>`;
    document.querySelectorAll("[data-unban]").forEach(el =>
      el.addEventListener("click", async () => { await jpost("api/unban", {ip: el.dataset.unban}); route(); }));
    $("banBtn").addEventListener("click", async () => {
      const ip = $("banIp").value.trim(); if (!ip) return;
      const res = await jpost("api/ban", {ip});
      if (!res.ok) alert(res.message);
      route();
    });
  },
};

/* ---------- log sources ---------- */
VIEWS.sources = {
  title: "Log sources",
  async render() {
    const d = await jget("api/logsources");
    const rows = (d.sources || []).map(s => {
      const tags = (s.primary ? `<span class="tag">primary</span>` : "") +
                   (s.managed || s.primary ? "" : `<span class="tag">yaml</span>`);
      const rm = s.managed ? `<button class="danger" data-rmsrc="${esc(s.path)}">remove</button>`
                           : `<span class="rules" title="edit secwatch.yaml to change this">—</span>`;
      return `<tr><td><span class="dot ${s.live ? "on" : "off"}"></span><b>${esc(s.name)}</b>${tags}</td>` +
        `<td class="path" title="${esc(s.path)}">${esc(s.path)}</td><td class="mono">${esc(s.type)}</td>` +
        `<td class="mono">${(s.records || 0).toLocaleString()}</td>` +
        `<td class="mono" style="white-space:nowrap">${fmtAgo(s.last_ts)}</td><td>${rm}</td></tr>`;
    }).join("");
    $("view").innerHTML =
      `<div class="card">
        <div class="cardhead"><h2>Watched sources</h2><span class="rules">${(d.sources || []).length} watched</span>
          <div class="spacer"></div>
          <button id="scanBtn">Scan for logs</button>
          <button id="addSourceBtn">+ Add local app</button></div>
        <div class="tablewrap"><table>
          <thead><tr><th>Name</th><th>Path</th><th>Format</th><th>Lines</th><th>Last activity</th><th></th></tr></thead>
          <tbody>${rows || `<tr><td colspan="6" class="empty">No sources.</td></tr>`}</tbody>
        </table></div>
        <div id="scanResults" style="display:none;margin-top:12px;border-top:1px solid var(--grid);padding-top:10px"></div>
        <form id="addSourceForm" style="display:none;margin-top:12px;border-top:1px solid var(--grid);padding-top:12px">
          <div class="formgrid">
            <label>Name<input id="srcName" placeholder="gitea" spellcheck="false"></label>
            <label>Log file path<input id="srcPath" placeholder="/var/log/nginx/gitea.access.log" spellcheck="false"></label>
            <label>Format
              <select id="srcType">
                <option value="traefik">traefik (JSON)</option><option value="nginx">nginx (combined)</option>
                <option value="caddy">caddy (JSON)</option><option value="regex">regex (custom)</option>
              </select></label>
          </div>
          <label id="srcRegexWrap" class="formcol" style="display:none;margin-top:8px">Regex (named groups; needs (?P&lt;ip&gt;…))
            <input id="srcRegex" spellcheck="false"></label>
          <div class="formrow">
            <button type="submit" id="srcSave">Add source</button>
            <button type="button" id="srcCancel">Cancel</button>
            <span id="srcMsg"></span></div>
        </form>
      </div>`;
    document.querySelectorAll("[data-rmsrc]").forEach(el =>
      el.addEventListener("click", async () => {
        if (!confirm("Stop watching this log source?")) return;
        await jpost("api/logsources/remove", {path: el.dataset.rmsrc}); route();
      }));
    $("addSourceBtn").addEventListener("click", () => {
      const f = $("addSourceForm");
      f.style.display = f.style.display === "none" ? "block" : "none";
    });
    $("srcCancel").addEventListener("click", () => $("addSourceForm").style.display = "none");
    $("srcType").addEventListener("change", () =>
      $("srcRegexWrap").style.display = $("srcType").value === "regex" ? "flex" : "none");
    $("addSourceForm").addEventListener("submit", async e => {
      e.preventDefault();
      $("srcSave").disabled = true;
      const res = await jpost("api/logsources", {name: $("srcName").value, path: $("srcPath").value,
        type: $("srcType").value, regex: $("srcRegex").value});
      $("srcSave").disabled = false;
      $("srcMsg").textContent = res.message || (res.ok ? "Added." : "Failed.");
      $("srcMsg").className = res.ok ? "msg-ok" : "msg-err";
      if (res.ok) setTimeout(route, 600);
    });
    $("scanBtn").addEventListener("click", async () => {
      $("scanBtn").disabled = true; $("scanBtn").textContent = "Scanning…";
      const r = await jpost("api/logsources/scan");
      $("scanBtn").disabled = false; $("scanBtn").textContent = "Scan for logs";
      const cands = r.candidates || [], box = $("scanResults");
      box.style.display = "block";
      if (!cands.length) { box.innerHTML = `<div class="empty">No new log files found — already watching everything auto-detectable.</div>`; return; }
      box.innerHTML =
        `<div class="cardhead"><h2>Found ${cands.length} candidate(s) — review and add</h2>
          <div class="spacer"></div><button id="addAllScan">Add all</button></div>` +
        cands.map((c, i) => `<div class="scanrow">
          <div class="meta"><span class="tag">${esc(c.type)}</span> <b>${esc(c.name)}</b>
            <div class="rules">${esc(c.path)}</div>
            <div class="samp" title="${esc(c.sample || "")}">${esc(c.sample || "")}</div></div>
          <button data-addscan="${i}">Add</button></div>`).join("");
      $("addAllScan").addEventListener("click", async e2 => {
        e2.target.disabled = true;
        for (const c of cands) await jpost("api/logsources", {name: c.name, path: c.path, type: c.type, regex: ""});
        route();
      });
      box.querySelectorAll("[data-addscan]").forEach(btn => btn.addEventListener("click", async () => {
        const c = cands[+btn.dataset.addscan];
        btn.disabled = true;
        const res = await jpost("api/logsources", {name: c.name, path: c.path, type: c.type, regex: ""});
        btn.textContent = res.ok ? "Added ✓" : "Add";
        if (!res.ok) { btn.disabled = false; alert(res.message || "failed"); }
      }));
    });
  },
};

/* ---------- vulnerabilities ---------- */
VIEWS.vulns = {
  title: "Vulnerabilities",
  async render() {
    const v = await jget("api/vulnerabilities");
    if (!v.total) { $("view").innerHTML = `<div class="card"><div class="empty">No findings yet — the scan (host OS packages + any container images) runs on a schedule; give it a few minutes on first boot while it fetches the vuln database.</div></div>`; return; }
    const byImg = {};
    for (const r of v.vulnerabilities) {
      byImg[r.image] = byImg[r.image] || {n: 0, crit: 0, kev: 0};
      byImg[r.image].n++;
      if (r.severity === "CRITICAL") byImg[r.image].crit++;
      if (r.in_kev) byImg[r.image].kev++;
    }
    const kevRows = v.vulnerabilities.filter(r => r.in_kev).slice(0, 12).map(r =>
      `<div class="finding sev-high"><div class="ft">${esc(r.cve)} — ${esc(r.image)}</div>
       <div class="fa">${esc(r.pkg)} ${esc(r.installed)} · ${r.fixed ? "fix: " + esc(r.fixed) : "no fix yet"}</div></div>`).join("");
    const imgRows = Object.entries(byImg).sort((a, b) => b[1].kev - a[1].kev || b[1].crit - a[1].crit)
      .map(([img, s]) => `<div class="row"><span class="mono">${esc(img)}</span>
        <span class="n">${s.n} findings${s.crit ? " · " + s.crit + " critical" : ""}${s.kev ? " · " + s.kev + " KEV" : ""}</span></div>`).join("");
    $("view").innerHTML =
      `<div class="card" style="margin-bottom:12px">
        <div class="cardhead">
          <span class="statuslamp ${v.kev ? "lamp-high" : "lamp-low"}"><i></i>${v.kev ? v.kev + " ACTIVELY EXPLOITED" : "NONE EXPLOITED"}</span>
          <span class="rules">${v.total} high/critical findings across running images</span></div>
        ${kevRows ? `<div class="dsec" style="margin-top:8px;font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-family:var(--mono)">Actively exploited — patch first</div>${kevRows}` : ""}
      </div>
      <div class="card"><h2>By image</h2><div class="list">${imgRows}</div>
        <div class="ai-note">Trivy scan cross-referenced with CISA KEV. KEV findings alert; the rest are informational.</div></div>`;
  },
};

/* ---------- AI analysis ---------- */
const THREAT_LABEL = {low: "Low", guarded: "Guarded", elevated: "Elevated", high: "High", critical: "Critical"};
VIEWS.analysis = {
  title: "AI analysis",
  async render() {
    const a = await jget("api/analysis/latest");
    if (a.enabled === false) {
      $("view").innerHTML = `<div class="card"><div class="empty">LLM analysis is disabled. Enable it with <span class="mono">llm.enabled: true</span> in secwatch.yaml — any OpenAI-compatible endpoint works (local Ollama/vLLM or a remote API).</div></div>`;
      return;
    }
    const lvl = a.threat_level || "guarded";
    let body;
    if (!a.result) {
      body = a.last_error ? `<div class="empty">Last run failed: ${esc(a.last_error)}</div>`
                          : `<div class="empty">No analysis yet — click "Analyze now".</div>`;
    } else {
      const r = a.result, m = r._meta || {};
      const findings = (r.findings || []).map(f =>
        `<div class="finding sev-${esc(f.severity || "info")}">
           <div class="ft">${esc(f.title || "")}</div>
           <div class="fa">${esc(f.assessment || "")}</div>
           <div class="fe">${esc(f.evidence || "")}</div></div>`).join("");
      const recs = (r.hardening_recommendations || []).map(x =>
        `<li><span class="pri pri-${esc(x.priority || "consider")}">${esc(x.priority || "")}</span>
           <span><b>${esc(x.action || "")}</b>${x.rationale ? " — " + esc(x.rationale) : ""}</span></li>`).join("");
      const watch = (r.watch_items || []).map(w => `<li><span></span><span>${esc(w)}</span></li>`).join("");
      body =
        `<div style="font-size:15px;font-weight:600;margin:4px 0 6px">${esc(r.headline || a.headline || "")}</div>` +
        `<div style="color:var(--ink2);margin-bottom:12px">${esc(r.traffic_summary || "")}</div>` +
        (findings ? `<h2>Findings</h2>${findings}` : "") +
        (recs ? `<h2 style="margin-top:12px">Hardening recommendations</h2><ul class="recs">${recs}</ul>` : "") +
        (watch ? `<h2 style="margin-top:12px">Watch items</h2><ul class="recs">${watch}</ul>` : "") +
        `<div class="ai-note">Model: ${esc(m.model || "local")} · ${m.requests_analyzed || "?"} requests · ${m.window_hours || "?"}h window. LLM-generated; verify before acting.</div>`;
    }
    $("view").innerHTML =
      `<div class="card">
        <div class="cardhead">
          <span class="statuslamp lamp-${esc(lvl)}"><i></i>${esc((THREAT_LABEL[lvl] || lvl).toUpperCase())}</span>
          <span class="rules">${a.running ? "analyzing…" : a.ts ? "as of " + fmtT(a.ts) : ""}</span>
          <div class="spacer"></div>
          <button id="analyzeBtn" ${a.running ? "disabled" : ""}>${a.running ? "Analyzing…" : "Analyze now"}</button>
        </div>${body}</div>`;
    $("analyzeBtn").addEventListener("click", async () => {
      $("analyzeBtn").disabled = true;
      await jpost("api/analysis/run");
      const started = Date.now();
      const poll = setInterval(async () => {
        const s = await jget("api/analysis/latest").catch(() => null);
        if ((s && !s.running) || Date.now() - started > 240000) {
          clearInterval(poll);
          if (current.name === "analysis") route();
        }
      }, 4000);
    });
  },
};

/* ---------- system ---------- */
VIEWS.system = {
  title: "System",
  async render() {
    const [h, u] = await Promise.all([jget("api/health"), jget("api/uiconfig")]);
    const checks = Object.entries(h.checks || {}).map(([name, c]) =>
      `<div class="checkrow"><span class="dot ${c.ok ? "on" : "off"}" style="${c.ok ? "" : "background:var(--crit)"}"></span>
        <span class="cname">${esc(name)}</span><span class="cmsg">${esc(c.detail || "")}</span></div>`).join("");
    const feat = (name, on, note) =>
      `<div class="checkrow"><span class="dot ${on ? "on" : "off"}"></span>
        <span class="cname">${esc(name)}</span><span class="cmsg">${on ? "enabled" : "off"}${note ? " · " + esc(note) : ""}</span></div>`;
    $("view").innerHTML =
      `<div class="gridrow" style="grid-template-columns:1fr 1fr">
        <div class="card">
          <div class="cardhead"><h2>Self-checks</h2>
            <span class="statuslamp ${h.status === "ok" ? "lamp-low" : "lamp-elevated"}"><i></i>${esc((h.status || "?").toUpperCase())}</span>
            <div class="spacer"></div><span class="rules">${h.checked ? "checked " + fmtAgo(h.checked) : ""}</span></div>
          ${checks || `<div class="empty">First check pending.</div>`}
          ${h.update_available ? `<div class="ai-note" style="color:var(--warn)">Update available: v${esc(h.latest_version)} (running v${esc(h.version)}). secwatch never auto-updates — pull when ready.</div>` : ""}
        </div>
        <div class="card"><h2>Configuration</h2>
          <dl class="kv">
            <dt>version</dt><dd>v${esc(u.version)}</dd>
            <dt>mode</dt><dd>${esc(u.mode)}</dd>
            <dt>ban actuator</dt><dd>${esc(u.ban_actuator)}${u.autoban ? " (auto-ban on)" : " (auto-ban OFF)"}</dd>
            <dt>log sources</dt><dd>${u.sources} watched</dd>
            <dt>dashboard auth</dt><dd>${u.auth ? "built-in login" : "off / proxy-managed"}</dd>
          </dl>
          <h2 style="margin-top:14px">Features</h2>
          ${feat("CVE scanning", u.cve)}${feat("LLM analysis", u.llm)}${feat("Crowd intel", u.crowd)}${feat("Audit (real-time exec)", u.audit)}
          <div class="ai-note">Config lives in secwatch.yaml — edit + restart to change. Log sources can be managed live from this UI.</div>
        </div>
      </div>`;
  },
};

/* ---------- cluster ---------- */
function nodeCards(nodes) {
  const dot = n => n.online === false ? `<span class="dot off"></span>`
    : n.online === null ? `<span class="dot" style="background:var(--muted)"></span>`
    : `<span class="dot on"></span>`;
  return nodes.map(n => {
    const node = n.node || {};
    const status = n.online === false ? "offline" : n.online === null ? "leaf" : "online";
    return `<div class="card catcard" style="cursor:default">
      <div class="catname">${dot(n)}${esc(node.name || "?")} ${n.self ? `<span class="tag">this node</span>` : ""}${node.role === "leaf" ? `<span class="tag">leaf</span>` : ""}</div>
      <div class="catstate ${n.high_24h ? "st-alert" : "st-secure"}">${status.toUpperCase()}</div>
      <div class="catsub">${n.events_24h || 0} events · ${n.high_24h || 0} high · ${n.bans || 0} bans (24h)</div>
    </div>`;
  }).join("");
}
function secretBox(secret) {
  return `<div class="formrow"><input type="text" readonly value="${esc(secret)}" id="secretVal" style="width:340px" onclick="this.select()">
    <button id="copySecret">Copy</button>
    <span class="rules">share this with nodes that will join — treat it like a password</span></div>`;
}
function wireCopy() {
  const c = $("copySecret"); if (!c) return;
  c.addEventListener("click", () => { const i = $("secretVal"); i.select();
    try { navigator.clipboard.writeText(i.value); c.textContent = "Copied ✓"; } catch (e) { document.execCommand("copy"); } });
}
function renderClusterSetup(cfg) {
  $("view").innerHTML =
    `<div class="card" style="margin-bottom:12px"><div class="sethelp">
       Join this box to a <b>peer-to-peer cluster</b> — nodes share bans (a hit on one hardens all)
       and you can view the whole fleet from any peer. No central hub. Every node keeps defending itself.
     </div></div>
     <div class="card" style="margin-bottom:12px"><h2>This node</h2>
       <div class="setrow"><div class="setlabel"><b>Role</b><div class="sethelp">
         <b>peer</b> = full member (internal/trusted). <b>leaf</b> = push-only for an exposed box
         (contributes + pulls bans, but isn't readable by peers).</div></div>
         <div class="setctl"><select id="cRole">
           <option value="peer">peer</option><option value="leaf">leaf</option></select></div></div>
       <div class="setrow" id="cUrlRow"><div class="setlabel"><b>This node's URL</b>
         <div class="sethelp">How peers reach it, e.g. http://THIS-IP:8931 (a leaf can leave blank).</div></div>
         <div class="setctl"><input type="text" id="cUrl" placeholder="http://THIS-IP:8931" value="${esc(cfg.url || "")}" style="width:220px"></div></div>
     </div>
     <div class="gridrow" style="grid-template-columns:1fr 1fr">
       <div class="card"><h2>Create a new cluster</h2>
         <div class="sethelp">Start a cluster with this node as the first member. You'll get a secret to add others.</div>
         <div class="formrow"><button id="cCreate">Create cluster</button><span id="cCreateMsg"></span></div>
         <div id="cCreatedSecret"></div></div>
       <div class="card"><h2>Join an existing cluster</h2>
         <div class="formcol"><label>A peer's URL<input type="text" id="cJoinUrl" placeholder="http://PEER-IP:8931"></label>
           <label style="margin-top:8px">Shared secret<input type="password" id="cJoinSecret" placeholder="paste the secret"></label></div>
         <div class="formrow"><button id="cJoin">Join cluster</button><span id="cJoinMsg"></span></div></div>
     </div>`;
  const roleSel = $("cRole"); roleSel.value = (cfg.role === "leaf") ? "leaf" : "peer";
  const syncUrl = () => $("cUrlRow").style.display = roleSel.value === "leaf" ? "none" : "flex";
  roleSel.addEventListener("change", syncUrl); syncUrl();
  $("cCreate").addEventListener("click", async () => {
    $("cCreate").disabled = true; $("cCreateMsg").textContent = "Creating…";
    const res = await jpost("api/cluster/setup", {action: "create", role: roleSel.value, url: $("cUrl").value});
    $("cCreate").disabled = false; $("cCreateMsg").textContent = res.message || "";
    $("cCreateMsg").className = res.ok ? "msg-ok" : "msg-err";
    if (res.ok && res.secret) { $("cCreatedSecret").innerHTML = secretBox(res.secret); wireCopy();
      $("navCluster").style.display = ""; }
  });
  $("cJoin").addEventListener("click", async () => {
    $("cJoin").disabled = true; $("cJoinMsg").textContent = "Joining…";
    const res = await jpost("api/cluster/setup", {action: "join", role: roleSel.value, url: $("cUrl").value,
      peer_url: $("cJoinUrl").value, secret: $("cJoinSecret").value});
    $("cJoin").disabled = false; $("cJoinMsg").textContent = res.message || "";
    $("cJoinMsg").className = res.ok ? "msg-ok" : "msg-err";
    if (res.ok) setTimeout(() => route(), 1200);
  });
}
VIEWS.cluster = {
  title: "Cluster",
  async render() {
    const cfg = await jget("api/cluster/config");
    if (!cfg.enabled) { renderClusterSetup(cfg); return; }
    const d = await jget("api/cluster/overview").catch(() => ({nodes: [], self: cfg.name}));
    const nodes = d.nodes || [];
    const totBans = nodes.reduce((a, n) => a + (n.bans || 0), 0);
    const totHigh = nodes.reduce((a, n) => a + (n.high_24h || 0), 0);
    const peerRows = (cfg.peers || []).map(p =>
      `<div class="checkrow"><span class="cname">${esc(p.name)}</span>
        <span class="cmsg">${esc(p.role)} · ${esc(p.url || "—")}</span>
        <div class="spacer" style="flex:1"></div>
        <button class="danger" data-rmpeer="${esc(p.name)}">remove</button></div>`).join("");
    $("view").innerHTML =
      `<div class="card" id="threatBanner">
         <span class="statuslamp ${totHigh ? "lamp-elevated" : "lamp-low"}"><i></i>${nodes.length} NODE${nodes.length > 1 ? "S" : ""}</span>
         <div class="headline">P2P cluster · every node defends itself and shares bans. Viewing from <b>${esc(cfg.name)}</b> (${esc(cfg.role)}).</div>
         <div class="quick"><span><b>${nodes.filter(n => n.online !== false).length}</b>reachable</span>
           <span><b>${totHigh}</b>high (24h)</span><span><b>${totBans}</b>bans</span></div>
       </div>
       <div class="catgrid">${nodeCards(nodes)}</div>
       <div class="card" style="margin-top:12px"><div class="cardhead"><h2>Add a device</h2>
         <div class="spacer"></div>
         <select id="cEnrollRole"><option value="peer">peer</option><option value="leaf">leaf</option></select>
         <button id="cEnroll">Generate install command</button></div>
         <div class="sethelp">Run the generated one-liner on a new Linux box (as root) — it installs secwatch and auto-joins this cluster. Single-use, expires shortly. The command carries the cluster secret, so treat it like a password and only run it over your trusted network.</div>
         <div id="cEnrollOut" style="margin-top:8px"></div>
       </div>
       <div class="card" style="margin-top:12px" id="updCard"><div class="cardhead"><h2>Software updates</h2>
         <div class="spacer"></div><button id="uCheck">Check for updates</button></div>
         <div id="updBody"><div class="sethelp">Checking this node's version…</div></div>
       </div>
       <div class="card" style="margin-top:12px"><div class="cardhead"><h2>Manage cluster</h2>
         <div class="spacer"></div><button id="cReveal">Show secret</button>
         <button id="cLeave" class="danger">Leave cluster</button></div>
         <div id="cSecretReveal"></div>
         ${peerRows ? `<div style="margin-top:10px">${peerRows}</div>` : `<div class="empty">No peers yet — add a device above, or share the secret to join another node.</div>`}
       </div>`;
    wireUpdatePanel();
    $("cEnroll").addEventListener("click", async () => {
      $("cEnroll").disabled = true;
      const r = await jpost("api/cluster/enroll", {role: $("cEnrollRole").value});
      $("cEnroll").disabled = false;
      if (!r.ok) { $("cEnrollOut").innerHTML = `<span class="msg-err">${esc(r.message)}</span>`; return; }
      $("cEnrollOut").innerHTML =
        `<div class="formrow"><input type="text" readonly value="${esc(r.command)}" id="enrollCmd" style="width:100%;font-family:var(--mono);font-size:12px" onclick="this.select()">
          <button id="copyEnroll">Copy</button></div>
         <div class="sethelp">Role: <b>${esc(r.role)}</b> · expires in ~${r.ttl_min} min · single-use.</div>`;
      const c = $("copyEnroll");
      c.addEventListener("click", () => { const i = $("enrollCmd"); i.select();
        try { navigator.clipboard.writeText(i.value); c.textContent = "Copied ✓"; } catch (e) { document.execCommand("copy"); } });
    });
    $("cReveal").addEventListener("click", async () => {
      const r = await jpost("api/cluster/reveal");
      $("cSecretReveal").innerHTML = secretBox(r.secret || ""); wireCopy();
    });
    $("cLeave").addEventListener("click", async () => {
      if (!confirm("Leave the cluster? This node keeps defending itself but stops sharing bans.")) return;
      await jpost("api/cluster/setup", {action: "leave"});
      $("navCluster").style.display = "none"; nav("overview");
    });
    document.querySelectorAll("[data-rmpeer]").forEach(el => el.addEventListener("click", async () => {
      await jpost("api/cluster/peer/remove", {name: el.dataset.rmpeer}); route();
    }));
  },
};

async function wireUpdatePanel() {
  const body = $("updBody"), btn = $("uCheck");
  async function load() {
    btn.disabled = true; btn.textContent = "Checking…";
    let s;
    try { s = await jget("api/update/status"); }
    catch (e) { body.innerHTML = `<span class="msg-err">Update check failed.</span>`; btn.disabled = false; btn.textContent = "Check for updates"; return; }
    btn.disabled = false; btn.textContent = "Check for updates";
    if (!s.supported) {
      body.innerHTML = `<div class="sethelp">Version <b>${esc(s.current)}</b>. ${esc(s.reason || "Self-update unavailable on this node.")}</div>`;
      return;
    }
    const behind = s.behind;
    const lamp = behind ? "lamp-elevated" : "lamp-low";
    const state = behind
      ? `<b>${esc(s.latest)}</b> available — this node is <b>${s.behind_commits}</b> commit${s.behind_commits === 1 ? "" : "s"} behind.`
      : `Up to date.`;
    const fetchWarn = s.fetch_error ? `<div class="sethelp msg-err">Couldn't reach the origin: ${esc(s.fetch_error)}</div>` : "";
    let fleetBtn = "";
    if (s.cluster_role === "peer") {
      const dis = s.peer_count ? "" : "disabled";
      fleetBtn = `<button id="uFleet" ${dis} title="${s.peer_count ? "" : "no peers to push to"}">Update entire fleet</button>`;
    }
    body.innerHTML =
      `<div class="checkrow"><span class="statuslamp ${lamp}"><i></i>${esc(s.current)}</span>
         <span class="cmsg" style="margin-left:8px">${state}</span></div>
       ${fetchWarn}
       <div class="formrow" style="margin-top:10px">
         <button id="uSelf" ${behind ? "" : "disabled"}>${behind ? "Update this node" : "This node is current"}</button>
         ${fleetBtn}
         <span id="uMsg" class="cmsg"></span>
       </div>
       <div class="sethelp">Nodes are git checkouts — “update” pulls the latest release and restarts the service. ${s.cluster_role === "peer" ? "“Update entire fleet” pushes the update to every peer and leaf; leaves apply it on their next sync." : ""}</div>`;
    const self = $("uSelf");
    if (self && behind) self.addEventListener("click", async () => {
      if (!confirm("Update this node now? secwatch will pull the latest release and restart — the dashboard will blip for a few seconds.")) return;
      self.disabled = true; $("uMsg").textContent = "Updating…";
      const r = await jpost("api/update/self", {});
      $("uMsg").innerHTML = r.ok ? `<span class="msg-ok">${esc(r.message)}</span>` : `<span class="msg-err">${esc(r.message)}</span>`;
    });
    const fleet = $("uFleet");
    if (fleet) fleet.addEventListener("click", async () => {
      if (!confirm("Push this update to every other node in the cluster? Each will pull the latest release and restart.")) return;
      fleet.disabled = true; $("uMsg").textContent = "Sending…";
      const r = await jpost("api/update/fleet", {});
      fleet.disabled = false;
      $("uMsg").innerHTML = r.ok ? `<span class="msg-ok">${esc(r.message)}</span>` : `<span class="msg-err">${esc(r.message)}</span>`;
    });
  }
  btn.addEventListener("click", load);
  load();
}

/* ---------- settings ---------- */
function setControl(f) {
  const ro = f.readonly ? "disabled" : "";
  const dk = `data-key="${esc(f.key)}" data-type="${esc(f.type)}"`;
  if (f.type === "bool")
    return `<label class="switch"><input type="checkbox" ${dk} ${f.value ? "checked" : ""} ${ro}><span></span></label>`;
  if (f.type === "select")
    return `<select ${dk} ${ro}>${(f.options || []).map(o =>
      `<option ${o === f.value ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
  if (f.type === "secret")
    return `<div class="secretctl"><input type="password" ${dk} autocomplete="new-password"
       placeholder="${f.is_set ? "•••••• set — blank keeps it" : "not set"}" ${ro}>` +
       (f.is_set && !f.readonly ? `<button type="button" data-clearkey="${esc(f.key)}">clear</button>` : "") + `</div>`;
  if (f.type === "list") {
    const v = Array.isArray(f.value) ? f.value.join(", ") : (f.value || "");
    return `<input type="text" ${dk} value="${esc(v)}" ${ro}>`;
  }
  const it = (f.type === "int" || f.type === "float") ? "number" : "text";
  const step = f.type === "float" ? 'step="0.1"' : "";
  return `<input type="${it}" ${step} ${dk} value="${esc(f.value ?? "")}" ${ro}>`;
}
function fieldRow(f) {
  const badge = f.readonly ? `<span class="tag">yaml</span>`
    : (f.live === false ? `<span class="tag" title="needs a restart to take effect">restart</span>` : "");
  return `<div class="setrow"><div class="setlabel"><b>${esc(f.label)}</b> ${badge}` +
    (f.help ? `<div class="sethelp">${esc(f.help)}</div>` : "") +
    `</div><div class="setctl">${setControl(f)}</div></div>`;
}
VIEWS.settings = {
  title: "Settings",
  async render() {
    const d = await jget("api/settings");
    let html = "";
    if (!d.crypto_available)
      html += `<div class="card" style="margin-bottom:12px"><div class="msg-err">⚠ <b>cryptography</b> isn't installed — secret settings can't be stored encrypted. Run <span class="mono">pip install cryptography</span> and restart, or keep secrets in files.</div></div>`;
    html += `<div class="card" style="margin-bottom:12px"><div class="sethelp">
      Edits here layer over <span class="mono">secwatch.yaml</span> (env vars still win). Most apply
      immediately; a <span class="tag">restart</span> tag means the change is saved but needs a restart.
      Secrets are stored encrypted on the box.</div></div>`;
    for (const sec of d.sections) {
      html += `<div class="card" style="margin-bottom:12px"><h2>${esc(sec.title)}</h2>`;
      for (const f of sec.fields) html += fieldRow(f);
      html += `</div>`;
    }
    html += `<div class="card" id="saveBar" style="display:none">
      <div class="cardhead"><span id="saveMsg" class="rules"></span><div class="spacer"></div>
        <button id="revertBtn">Revert</button><button id="saveBtn">Save changes</button></div></div>`;
    $("view").innerHTML = html;

    const dirty = new Set();
    const show = () => { $("saveBar").style.display = "block"; };
    const onEdit = e => { if (e.target.dataset && e.target.dataset.key) { dirty.add(e.target.dataset.key); show(); } };
    $("view").addEventListener("input", onEdit);
    $("view").addEventListener("change", onEdit);
    $("view").addEventListener("click", e => {
      const k = e.target.dataset && e.target.dataset.clearkey;
      if (!k) return;
      const inp = $("view").querySelector(`input[data-key="${k}"]`);
      inp.dataset.clear = "1"; inp.value = ""; inp.placeholder = "(will clear on save)";
      dirty.add(k); show();
    });
    $("revertBtn").addEventListener("click", () => route());
    $("saveBtn").addEventListener("click", async () => {
      const updates = {};
      dirty.forEach(key => {
        const el = $("view").querySelector(`[data-key="${key}"]`);
        if (!el) return;
        const t = el.dataset.type;
        if (t === "bool") updates[key] = el.checked;
        else if (t === "secret") {
          if (el.dataset.clear === "1") updates[key] = "";
          else if (el.value) updates[key] = el.value;   // only send if typed
        } else updates[key] = el.value;                 // server coerces
      });
      if (!Object.keys(updates).length) { $("saveBar").style.display = "none"; return; }
      $("saveBtn").disabled = true;
      const res = await jpost("api/settings", {updates});
      $("saveBtn").disabled = false;
      $("saveMsg").textContent = res.message || (res.ok ? "Saved." : "Failed.");
      $("saveMsg").className = res.ok ? "msg-ok" : "msg-err";
      if (res.ok) { dirty.clear(); setTimeout(() => { if (current.name === "settings") route(); }, 1400); }
    });
  },
};

/* ---------- boot ---------- */
(async function boot() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch (e) {}
  applyTheme(saved || "ops");
  try {
    CFG = await jget("api/uiconfig");
    CFG.mut = CFG.mut_header ? {[CFG.mut_header]: "1"} : {};
    if (!CFG.llm) $("navAnalysis").style.display = "none";
    if (CFG.cluster) $("navCluster").style.display = "";
    if (CFG.update_available) $("updNote").textContent = "· update available";
  } catch (e) { CFG.mut = {}; }
  await route();
  scheduleRefresh();
})();
