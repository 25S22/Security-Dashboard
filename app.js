"use strict";
/* Secdash front end. Three pages: Overview (graph + news), Repos & Exploits, Search. Graph = d3-force with one zone per node type. */
(() => {
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const safe = u => (/^https?:\/\//i.test(u || "") ? u : "");
const ago = t => { const s = Math.max(0, Date.now() / 1e3 - t); return s < 90 ? "now" : s < 5400 ? Math.round(s / 60) + "m" : s < 172800 ? Math.round(s / 3600) + "h" : Math.round(s / 86400) + "d"; };
const fmt = n => (n >= 1e3 ? (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + "k" : String(n));
const pill = (c, t) => `<span class="pill ${c}">${esc(t)}</span>`;
const tagH = (c, t) => `<span class="tag ${esc(c)}">${esc(t)}</span>`;

/* ───────── types: colour + label per node kind (palette matches app.css; no blues) ───────── */
const TYPES = {
  itw: ["Exploited in the wild", "#f0605d"], public: ["Public exploit", "#e9895a"], poc: ["GitHub PoC", "#f0cf78"], adv: ["Advisory", "#e68ab8"],
  nvd: ["NVD record", "#d9803f"], news: ["News", "#d6cfc0"], repo: ["GitHub repo", "#9ccc84"], dep: ["My dependency", "#ffb38a"], rf: ["Recorded Future", "#7fd3b5"],
  ioc: ["IOC", "#f0605d"], ransom: ["Ransomware", "#f0605d"], breach: ["Breach", "#a9a092"],
  cve: ["CVE", "#fff3df"], tech: ["Technology", "#cddc6a"], actor: ["Threat actor", "#b48ee0"],
};
const ORDER = ["itw", "public", "poc", "adv", "nvd", "cve", "tech", "actor", "news", "repo", "dep", "rf", "ioc", "ransom", "breach"];
const ENTITY = new Set(["cve", "tech", "actor"]);
const KL = { itw: "EXPLOITED", public: "EXPLOIT", poc: "PoC", adv: "ADVISORY", cve: "NVD" };
const FL = { KEV: "KEV", MSF: "METASPLOIT", EDB: "EXPLOIT-DB", NUC: "NUCLEI", SIG: "SIGMA" };
function typeOf(i) {
  if (i.sec === "news") return "news";
  if (i.sec === "exploit") return i.kind === "cve" ? "nvd" : (["itw", "public", "poc", "adv"].includes(i.kind) ? i.kind : "adv");
  return ["repo", "dep", "rf", "ioc", "ransom", "breach"].includes(i.sec) ? i.sec : "news";
}

/* ───────── state ───────── */
const PAGES = ["overview", "intel", "rf", "search"];
const S = {
  data: null, ver: 0, page: "overview", q: "", mine: false, sort: "new", src: "all", maxNews: 60, maxRes: 80,
  tab: { ex: "itw", repo: "trending", th: "ioc" }, open: new Set(), hidden: { ov: new Set(), se: new Set() },
  search: null, rf: null, last: 0, t0: Date.now(), graphAt: 0,
};
let mounted = null, ovGraph = null, seGraph = null, toastT = 0, graphTimer = 0;

/* ───────── graph data: items -> nodes (one zone per type) + shared CVE / technology / actor entities ───────── */
function buildGraphData(items, o) {
  const rank = [...items].sort((a, b) => (b.p || 0) - (a.p || 0) || b.ts - a.ts);
  const per = {}, picked = [];
  for (const it of rank) {
    const t = typeOf(it);
    if (o.hidden.has(t)) continue;
    per[t] = (per[t] || 0) + 1;
    if (per[t] <= (o.caps[t] || o.caps.default)) picked.push(it);
  }
  const ent = new Map();
  const add = (type, label, it) => {
    if (o.hidden.has(type)) return;
    const k = type + ":" + label;
    let e = ent.get(k);
    if (!e) ent.set(k, e = { id: k, type, label, items: [] });
    e.items.push(it);
  };
  for (const it of picked) {
    it.cves.slice(0, 4).forEach(c => add("cve", c, it));
    (it.techs || []).forEach(t => add("tech", t, it));
    (it.actors || []).forEach(a => add("actor", a, it));
  }
  const kept = [], pe = {};
  for (const e of [...ent.values()].sort((a, b) => b.items.length - a.items.length)) {
    if (e.items.length < o.minShare) continue;
    pe[e.type] = (pe[e.type] || 0) + 1;
    if (pe[e.type] <= (o.caps[e.type] || 12)) kept.push(e);
  }
  const linked = new Set(kept.flatMap(e => e.items.map(i => i.id)));
  let iso = 0;
  const nodes = [], links = [];
  for (const it of picked) {
    if (!linked.has(it.id)) { if (iso >= o.maxIso) continue; iso++; }
    nodes.push({ id: "i:" + it.id, type: typeOf(it), label: it.title, item: it, r: 5 + Math.min(5, (it.p || 0) / 20) });
  }
  const have = new Set(nodes.map(n => n.id));
  for (const e of kept) {
    const n = { id: e.id, type: e.type, label: e.label, items: e.items, r: 8 + Math.min(12, e.items.length * 1.1) };
    nodes.push(n);
    for (const it of e.items) if (have.has("i:" + it.id)) links.push({ key: "i:" + it.id + "|" + e.id, source: "i:" + it.id, target: e.id });
  }
  return { nodes, links };
}

/* ───────── graph widget ───────── */
function Graph(host, cb) {
  host.innerHTML = '<svg class="gsvg" role="img" aria-label="Threat knowledge graph"></svg><div class="gtip"></div><div class="gempty" hidden></div><div class="ghint">drag nodes · scroll to zoom · click to inspect · double-click a CVE / technology / actor to search it</div>';
  const svgEl = host.querySelector("svg"), tip = host.querySelector(".gtip"), emptyEl = host.querySelector(".gempty");
  const svg = d3.select(svgEl), root = svg.append("g");
  const gZ = root.append("g"), gL = root.append("g"), gN = root.append("g"), gT = root.append("g");
  let W = 900, H = 560, nodes = [], links = [], A = {}, sim = null, touched = false, sel = null, hov = null, fitT = 0, ro = null;
  const pos = new Map(), nb = new Map(), zoom = d3.zoom().scaleExtent([0.3, 4]).on("zoom", e => { root.attr("transform", e.transform); if (e.sourceEvent) touched = true; });
  svg.call(zoom).on("dblclick.zoom", null);

  const size = () => { W = host.clientWidth || 900; H = host.clientHeight || 560; svg.attr("viewBox", `0 0 ${W} ${H}`); };
  const zr = n => 30 + Math.sqrt(n) * 13;

  function anchors(counts) {   // zones sit on an ellipse around the centre: the middle stays empty, nothing piles up there
    const types = ORDER.filter(t => counts[t]), n = types.length, maxR = Math.max(40, ...types.map(t => zr(counts[t])));
    const rx = Math.max(60, W / 2 - maxR - 24), ry = Math.max(50, H / 2 - maxR - 24), a0 = -Math.PI / 2 + Math.PI / Math.max(n, 2), out = {};
    types.forEach((t, i) => { const a = a0 + 2 * Math.PI * i / n; out[t] = { x: W / 2 + (n === 1 ? 0 : rx * Math.cos(a)), y: H / 2 + (n === 1 ? 0 : ry * Math.sin(a)), n: counts[t] }; });
    return out;
  }
  function focus() {
    const f = sel || hov, set = f ? nb.get(f.id) : null;
    gN.selectAll("circle").attr("opacity", d => (!set || set.has(d.id) ? 1 : 0.14)).classed("sel", d => d === sel);
    gL.selectAll("line").attr("stroke-opacity", d => (!f ? 0.2 : d.source === f || d.target === f ? 0.9 : 0.04)).attr("stroke", d => (f && (d.source === f || d.target === f) ? "#e9895a" : "#8d8579"));
    gT.selectAll("text").attr("opacity", d => (!set || set.has(d.id) ? 1 : 0.14));
  }
  function ticked() {
    gL.selectAll("line").attr("x1", d => d.source.x).attr("y1", d => d.source.y).attr("x2", d => d.target.x).attr("y2", d => d.target.y);
    gN.selectAll("circle").attr("cx", d => d.x).attr("cy", d => d.y);
    gT.selectAll("text").attr("x", d => d.x + d.r + 4).attr("y", d => d.y + 4);
    gZ.selectAll("g.zone").each(function (z) {
      const ns = nodes.filter(n => n.type === z.type);
      if (!ns.length) return;
      const cx = d3.mean(ns, n => n.x), cy = d3.mean(ns, n => n.y), r = Math.max(26, d3.max(ns, n => Math.hypot(n.x - cx, n.y - cy) + n.r) + 16);
      const g = d3.select(this);
      g.select("circle").attr("cx", cx).attr("cy", cy).attr("r", r);
      g.select("text").attr("x", cx).attr("y", cy - r - 7);
    });
  }
  function fit(now) {
    if (!nodes.length) return;
    let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9;
    for (const n of nodes) { x0 = Math.min(x0, n.x - n.r - 18); x1 = Math.max(x1, n.x + n.r + 18); y0 = Math.min(y0, n.y - n.r - 34); y1 = Math.max(y1, n.y + n.r + 18); }
    const k = Math.max(0.35, Math.min(1.5, (W - 40) / Math.max(80, x1 - x0), (H - 30) / Math.max(80, y1 - y0)));
    const t = d3.zoomIdentity.translate(W / 2 - (x0 + x1) / 2 * k, H / 2 - (y0 + y1) / 2 * k).scale(k);
    (now ? svg : svg.transition().duration(450)).call(zoom.transform, t);
  }
  function showTip(e, d) {
    tip.textContent = (TYPES[d.type] ? TYPES[d.type][0] : d.type) + " · " + d.label.slice(0, 120);
    const r = host.getBoundingClientRect();
    tip.style.cssText = `display:block;left:${Math.min(e.clientX - r.left + 14, W - 330)}px;top:${e.clientY - r.top + 14}px`;
  }

  function setData(data, hiddenSet) {
    size();
    const old = new Map(nodes.map(n => [n.id, n]));
    for (const n of nodes) pos.set(n.id, { x: n.x, y: n.y });
    nodes = data.nodes; links = data.links;
    const counts = {}; nodes.forEach(n => { counts[n.type] = (counts[n.type] || 0) + 1; });
    A = anchors(counts);
    nodes.forEach(n => { const p = pos.get(n.id), a = A[n.type]; n.x = p ? p.x : a.x + (Math.random() - 0.5) * 50; n.y = p ? p.y : a.y + (Math.random() - 0.5) * 50; });
    const byId = new Map(nodes.map(n => [n.id, n]));
    sel = sel && byId.get(sel.id) || null;
    emptyEl.hidden = nodes.length > 0;
    nb.clear(); nodes.forEach(n => nb.set(n.id, new Set([n.id])));
    links.forEach(l => { nb.get(l.source).add(l.target); nb.get(l.target).add(l.source); });

    gZ.selectAll("g.zone").data(Object.keys(A).map(t => ({ type: t, n: A[t].n })), d => d.type).join(en => {
      const g = en.append("g").attr("class", "zone"); g.append("circle").attr("class", "zone-c"); g.append("text").attr("class", "zlabel"); return g;
    }).each(function (d) { d3.select(this).select("text").attr("fill", TYPES[d.type][1]).text(`${TYPES[d.type][0].toUpperCase()} · ${d.n}`); });

    gL.selectAll("line").data(links, d => d.key).join("line").attr("class", "edge");
    gN.selectAll("circle").data(nodes, d => d.id).join("circle").attr("class", "node").attr("r", d => d.r).attr("fill", d => TYPES[d.type][1])
      .on("mouseenter", (e, d) => { hov = d; focus(); showTip(e, d); }).on("mousemove", (e, d) => showTip(e, d))
      .on("mouseleave", () => { hov = null; tip.style.display = "none"; focus(); })
      .on("click", (e, d) => { sel = sel === d ? null : d; focus(); cb.select && cb.select(sel); })
      .on("dblclick", (e, d) => { if (ENTITY.has(d.type) && cb.search) cb.search(d.label); })
      .call(d3.drag().on("start", (e, d) => { if (!e.active) sim.alphaTarget(0.2).restart(); d.fx = d.x; d.fy = d.y; touched = true; })
        .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; }).on("end", (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = d.fy = null; }));
    gT.selectAll("text").data(nodes.filter(n => ENTITY.has(n.type)), d => d.id).join("text").attr("class", "nlabel").text(d => d.label.slice(0, 28));

    if (sim) sim.stop();
    sim = d3.forceSimulation(nodes)
      .force("x", d3.forceX(d => A[d.type].x).strength(0.14)).force("y", d3.forceY(d => A[d.type].y).strength(0.14))
      .force("charge", d3.forceManyBody().strength(-16).distanceMax(120))
      .force("collide", d3.forceCollide(d => d.r + (ENTITY.has(d.type) ? 22 : 2.5)).iterations(2))
      .force("link", d3.forceLink(links).id(d => d.id).distance(100).strength(0.008))
      .alphaDecay(0.035).on("tick", ticked).on("end", () => { if (!touched) fit(); });
    sim.alpha(old.size ? 0.35 : 1).restart();
    clearTimeout(fitT); fitT = setTimeout(() => { if (!touched) fit(); }, 1400);
    focus();
    if (sel && cb.select) cb.select(sel);
    return counts;
  }
  if (typeof ResizeObserver !== "undefined") {
    ro = new ResizeObserver(() => { const w = host.clientWidth, h = host.clientHeight; if (w && h && (Math.abs(w - W) > 40 || Math.abs(h - H) > 40) && nodes.length) { size(); const c = {}; nodes.forEach(n => { c[n.type] = (c[n.type] || 0) + 1; }); A = anchors(c); sim.force("x").x(d => A[d.type].x); sim.force("y").y(d => A[d.type].y); sim.alpha(0.3).restart(); if (!touched) fit(true); } });
    ro.observe(host);
  }
  return {
    setData,
    fit: () => { touched = false; fit(); },
    relayout: () => { pos.clear(); touched = false; setData({ nodes: nodes.map(n => ({ ...n })), links: links.map(l => ({ key: l.key, source: l.source.id || l.source, target: l.target.id || l.target })) }); },
    select: id => { sel = nodes.find(n => n.id === id) || null; focus(); cb.select && cb.select(sel); },
    destroy: () => { clearTimeout(fitT); if (sim) sim.stop(); if (ro) ro.disconnect(); host.innerHTML = ""; },
    stats: () => ({ nodes: nodes.length, links: links.length }),
  };
}

/* ───────── shared renderers ───────── */
const triage = i => (S.data && S.data.triage[i.tk]) || {};
const hl = p => (p >= 75 ? 4 : p >= 50 ? 3 : 0);
const chipsOf = i => [
  ...i.cves.slice(0, 4).map(c => `<button class="chip" data-search="${esc(c)}" title="Search ${esc(c)}">${esc(c)}</button>`),
  ...(i.techs || []).map(t => `<button class="chip t" data-search="${esc(t)}" title="Search ${esc(t)}">${esc(t)}</button>`),
  ...(i.actors || []).map(a => `<button class="chip a" data-search="${esc(a)}" title="Search ${esc(a)}">${esc(a)}</button>`),
].join("");
function badges(i) {
  let h = "";
  if (i.new) h += pill("new", "NEW");
  if (i.mine) h += pill("mine", "MY STACK");
  if (i.m.ransom) h += pill("hot", "RANSOMWARE");
  if (i.flags.includes("KEV") && i.kind !== "itw") h += pill("hot", "EXPLOITED");
  h += i.flags.filter(f => !(i.kind === "itw" && f === "KEV")).map(f => pill("arm", FL[f] || f)).join("");
  if (i.m.epss != null) h += `<span class="mut">EPSS ${esc(i.m.epss)}%</span>`;
  if (i.m.cvss != null) h += pill("pri", "CVSS " + i.m.cvss);
  if (i.p) h += pill("pri", "P" + i.p);
  return h;
}
function detailH(i) {
  const t = triage(i), st = t.status || "New";
  const sel = `<select data-tri="${esc(i.tk)}" class="st-${esc(st)}" aria-label="Triage status">${S.data.statuses.map(x => `<option${x === st ? " selected" : ""}>${esc(x)}</option>`).join("")}</select>`;
  const meta = [`<span>${esc(i.src)} · ${ago(i.ts)} ago</span>`, i.m.due ? `<span>patch by ${esc(i.m.due)}</span>` : "", i.m.verified ? "<span>verified</span>" : "", i.m.module ? `<span class="mono">${esc(i.m.module)}</span>` : ""].join("");
  return `<div class="detail"><p>${esc(i.desc) || '<span class="mut">No description.</span>'}</p><div class="dmeta">${meta}${chipsOf(i)}</div>
    <div class="tri">${sel}<button data-pin="${esc(i.tk)}">${t.pinned ? "📌 Pinned" : "📌 Pin"}</button><button data-note="${esc(i.tk)}">✎ Note</button>${t.owner ? `<span class="mut">${esc(t.owner)} · ${ago(t.ts)} ago</span>` : ""}</div>${t.note ? `<div class="tn">${esc(t.note)}</div>` : ""}</div>`;
}
function itemH(i, c) {   // c = { time, tag, title (html), badges }
  const t = triage(i), open = S.open.has(i.id);
  const cls = ["item", open && "open", t.pinned && "pin", ["Ignored", "Mitigated"].includes(t.status) && "dim"].filter(Boolean).join(" ");
  return `<div class="${cls}"><div class="row h${hl(i.p || 0)}" data-toggle="${esc(i.id)}"><span class="c-time">${c.time}</span><span class="c-tag">${c.tag}</span>${c.title}<span class="c-badges">${c.badges}</span><button class="chev" aria-label="Details" aria-expanded="${open}">▾</button></div>${open ? detailH(i) : ""}</div>`;
}
const titleH = (i, extra = "") => {
  const u = safe(i.url), inner = esc(i.title) + (extra ? `<span class="sub"> — ${esc(extra)}</span>` : "");
  return u ? `<a class="c-title" href="${esc(u)}" target="_blank" rel="noopener noreferrer" title="${esc(i.title)}">${inner}</a>` : `<span class="c-title" title="${esc(i.title)}">${inner}</span>`;
};
const newsRow = i => itemH(i, { time: ago(i.ts), tag: tagH("news", i.src.length > 14 ? i.src.slice(0, 13) + "…" : i.src), title: titleH(i), badges: badges(i) });
const exploitRow = i => itemH(i, { time: ago(i.ts), tag: tagH(i.kind, KL[i.kind] || i.kind.toUpperCase()), title: titleH(i), badges: badges(i) + `<span class="mut">${esc(i.src)}</span>` });
const repoRow = i => {
  const m = i.m;
  return itemH(i, { time: "★ " + fmt(m.stars || 0), tag: m.lang ? tagH("lang", m.lang) : "", title: titleH(i, i.desc),
    badges: (i.new ? pill("new", "NEW") : "") + (i.mine ? pill("mine", "MY STACK") : "") + (m.today ? pill("up", "+" + fmt(m.today) + " " + m.window) : "") + (m.gained > 0 ? pill("up", "▲ +" + fmt(m.gained)) : "") + (m.per_day ? `<span class="mut">${esc(m.per_day)}/day</span>` : "") + (m.kinds || [i.kind]).map(k => tagH(k, k)).join("") });
};
const iocRow = i => itemH(i, { time: ago(i.ts), tag: tagH(i.kind, i.kind.toUpperCase()), title: `<span class="c-title mono" title="${esc(i.title)}">${esc(i.title)}<span class="sub"> — ${esc(i.desc)}</span></span>`, badges: `<span class="mut">${esc(i.src)}</span>` });
const rfRow = i => itemH(i, { time: ago(i.ts), tag: tagH(i.kind === "vuln" ? "vuln" : "alert", i.kind === "vuln" ? (i.m.label || "VULN").toUpperCase() : "ALERT"), title: titleH(i, i.kind === "vuln" ? (i.m.rules || [])[0] : i.desc), badges: i.kind === "vuln" ? pill("hot", "RISK " + i.m.score) : "" });
const rows = (l, fn, e) => (l.length ? l.map(fn).join("") : `<div class="empty sm">${e}</div>`);
const rowFor = i => (i.sec === "news" ? newsRow : i.sec === "repo" ? repoRow : i.sec === "rf" ? rfRow : ["ioc", "ransom", "breach"].includes(i.sec) ? iocRow : exploitRow)(i);
const srt = l => [...l].sort((a, b) => ((triage(b).pinned ? 1 : 0) - (triage(a).pinned ? 1 : 0)) || (S.sort === "pri" ? (b.p || 0) - (a.p || 0) : 0) || b.ts - a.ts);
const okItem = i => (!S.q || i.q.includes(S.q)) && (!S.mine || i.mine);
const dayLbl = t => { const d = new Date(t * 1e3), n = new Date(), s = x => x.toDateString(); return s(d) === s(n) ? "Today" : s(d) === s(new Date(n - 864e5)) ? "Yesterday" : d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" }); };
const keepScroll = (el, fn) => { const y = el ? el.scrollTop : 0; fn(); if (el) el.scrollTop = y; };

function legendH(counts, hidden, ns) {
  return ORDER.filter(t => counts[t] || hidden.has(t)).map(t => `<button class="lg ${hidden.has(t) ? "off" : ""}" data-leg="${ns}:${t}" title="Show / hide"><span class="dot" style="background:${TYPES[t][1]}"></span>${esc(TYPES[t][0])} <b>${counts[t] || 0}</b></button>`).join("");
}
function inspectH(n) {
  if (!n) return `<h3>Nothing selected</h3><p class="mut">Click any node to see what it is and what it is linked to. Each zone groups one kind of thing; lines connect items that share a CVE, technology or threat actor.</p>`;
  const li = i => `<div class="gi">${tagH(typeOf(i), (TYPES[typeOf(i)] || [i.kind])[0].toUpperCase())} ${safe(i.url) ? `<a href="${esc(safe(i.url))}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a>` : esc(i.title)}<div class="dmeta">${esc(i.src)} · ${ago(i.ts)} ago ${badges(i)}</div></div>`;
  if (n.item) {
    const i = n.item;
    return `<h3>${safe(i.url) ? `<a href="${esc(safe(i.url))}" target="_blank" rel="noopener noreferrer">${esc(i.title)} ↗</a>` : esc(i.title)}</h3><div class="dmeta">${tagH(typeOf(i), TYPES[typeOf(i)][0])} ${esc(i.src)} · ${ago(i.ts)} ago ${badges(i)}</div><p>${esc(i.desc)}</p>${chipsOf(i) ? `<h4>Search related</h4><div class="dmeta">${chipsOf(i)}</div>` : ""}`;
  }
  const extra = n.type === "actor" && S.data ? (S.data.actors.find(a => a.name === n.label) || {}).url : n.type === "cve" ? "https://nvd.nist.gov/vuln/detail/" + n.label : "";
  return `<h3>${esc(n.label)}</h3><div class="dmeta">${tagH(n.type, TYPES[n.type][0])} ${n.items.length} linked items ${n.type === "cve" ? [...new Set(n.items.flatMap(i => i.flags))].map(f => pill("arm", FL[f] || f)).join("") : ""}</div>
    <div class="tri"><button class="btn primary sm" data-search="${esc(n.label)}">Search “${esc(n.label.slice(0, 24))}”</button>${safe(extra) ? `<a class="btn sm" href="${esc(safe(extra))}" target="_blank" rel="noopener noreferrer">Reference ↗</a>` : ""}</div><h4>Linked items</h4>${n.items.slice(0, 40).map(li).join("")}`;
}
const refreshHot = () => {
  const el = $("#hot");
  if (el) el.innerHTML = S.data.hot.length ? `<h3>HOT CVEs</h3>${S.data.hot.map(h => `<button class="chip" data-search="${esc(h.cve)}" title="${esc(h.t)}">${esc(h.cve)} · ${h.n}${h.kev ? " · KEV" : ""}${h.msf ? " · MSF" : ""}${h.nuc ? " · NUC" : ""}${h.sig ? " · SIG" : ""}</button>`).join("")}` : "";
};

/* ───────── page: Overview (graph first, then news line by line) ───────── */
const OV_CAPS = { default: 12, itw: 14, public: 10, poc: 8, adv: 8, news: 28, repo: 14, dep: 10, cve: 22, tech: 14, actor: 10 };
const Overview = {
  html: () => `<div class="panel"><div class="ph"><h2>Latest news</h2><span class="sub" id="nc"></span><span class="grow"></span>
    <input type="search" id="flt" placeholder="Filter news and graph  ( / )" aria-label="Filter"><button class="btn sm" id="sort">Sort: Newest</button><button class="btn sm" data-act="to-graph">Graph ↓</button></div>
    <div class="chips" id="nchips"></div><div class="scroll nscroll" id="news"></div></div>
    <div class="panel" id="ov-graph"><div class="ph"><h2>Threat graph</h2><span class="sub">news, exploits, PoCs and repos, linked by CVE, technology and threat actor</span><span class="grow"></span>
    <button class="btn sm" data-act="ov-fit">Fit</button><button class="btn sm" data-act="ov-layout">Re-layout</button></div>
    <div class="hotbar" id="hot"></div><div class="legend" id="ov-leg"></div><div class="gwrap"><div class="gbox" id="ov-g"></div><aside class="inspector" id="ov-i"></aside></div></div>`,
  mount() {
    ovGraph = Graph($("#ov-g"), { select: n => { $("#ov-i").innerHTML = inspectH(n); }, search: goSearch });
    $("#ov-i").innerHTML = inspectH(null);
    S.graphAt = 0;   // a fresh mount draws at once; the 8 s throttle only applies to live refreshes
    $("#flt").value = S.q;
    $("#sort").textContent = "Sort: " + (S.sort === "new" ? "Newest" : "Priority");
  },
  unmount() { if (ovGraph) ovGraph.destroy(); ovGraph = null; },
  graph() {
    if (!ovGraph || !S.data) return;
    const s = S.data, repos = s.repos.filter(i => (i.m.kinds || []).some(k => k === "trending" || k === "rising")).sort((a, b) => (b.m.today || 0) + (b.m.per_day || 0) - (a.m.today || 0) - (a.m.per_day || 0));
    const pool = [...s.exploits, ...s.news, ...repos, ...s.deps].filter(okItem);
    const d = buildGraphData(pool, { caps: OV_CAPS, minShare: 2, maxIso: 24, hidden: S.hidden.ov });
    const full = buildGraphData(pool, { caps: OV_CAPS, minShare: 2, maxIso: 24, hidden: new Set() }), counts = {};
    full.nodes.forEach(n => { counts[n.type] = (counts[n.type] || 0) + 1; });
    ovGraph.setData(d);
    $("#ov-leg").innerHTML = legendH(counts, S.hidden.ov, "ov") + `<span class="mut">lines = shared CVE / technology / actor</span>`;
    S.graphAt = Date.now();
  },
  update() { this.lists(); this.graphSoon(); refreshHot(); },
  graphSoon(force) {
    clearTimeout(graphTimer);
    const wait = force ? 0 : Math.max(0, 8000 - (Date.now() - S.graphAt));   // live data refreshes the graph at most every 8 s
    graphTimer = setTimeout(() => mounted === "overview" && this.graph(), wait);
  },
  lists() {
    const s = S.data, cn = {};
    s.news.forEach(i => { cn[i.src] = (cn[i.src] || 0) + 1; });
    const nr = srt(s.news.filter(i => okItem(i) && (S.src === "all" || i.src === S.src)));
    $("#nc").textContent = nr.length + " articles";
    $("#nchips").innerHTML = [["all", "All"], ...Object.entries(cn).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => [k, `${k} <i>${v}</i>`])].map(([k, n]) => `<button data-src="${esc(k)}" class="${S.src === k ? "on" : ""}">${k === "all" ? "All" : n.replace(/^(.*?) <i>/, (m, a) => esc(a) + " <i>")}</button>`).join("");
    let last = "", out = "";
    nr.slice(0, S.maxNews).forEach(i => { const d = S.sort === "new" ? dayLbl(i.ts) : ""; if (d && d !== last) { last = d; out += `<div class="day">${esc(d)}</div>`; } out += newsRow(i); });
    if (nr.length > S.maxNews) out += `<button class="btn more" data-more="1">Show more (${nr.length - S.maxNews})</button>`;
    keepScroll($("#news"), () => { $("#news").innerHTML = out || '<div class="empty">No matching articles yet.</div>'; });
  },
};

/* ───────── page: Repos & Exploits ───────── */
const EX_TABS = [["itw", "In the wild"], ["public", "Public exploits"], ["poc", "GitHub PoCs"], ["adv", "Advisories"]];
const RP_TABS = [["trending", "Trending"], ["rising", "Rising"], ["active", "Active"]];
const TH_TABS = [["ioc", "IOCs & C2"], ["ransom", "Ransomware"], ["breach", "Breaches"], ["deps", "My packages"]];
const TH_EMPTY = { ioc: "Feodo needs no key. ThreatFox and URLhaus need a free abuse.ch key (config.py).", ransom: "Needs a free ransomware.live key (config.py).", breach: "Waiting for Have I Been Pwned.", deps: "Add your packages to PACKAGES in config.py, or none of them has a known vulnerability." };
const tabsH = (g, list, count) => list.map(([k, n]) => `<button data-tab="${g}:${k}" class="${S.tab[g] === k ? "on" : ""}">${n} <i>${count(k)}</i></button>`).join("");
const Intel = {
  html: () => `<div class="hotbar" id="hot"></div><div class="ph" style="border:0;padding:0 0 14px"><input type="search" id="flt" placeholder="Filter exploits and repos  ( / )" aria-label="Filter"><span class="grow"></span><button class="btn sm" id="sort">Sort: Newest</button></div>
    <div class="cols"><section class="panel"><div class="ph"><h2>Exploits &amp; advisories</h2><span class="tabs" id="ex-t"></span></div><div id="ex-w"></div><div class="scroll" id="ex-l"></div></section>
    <section class="panel"><div class="ph"><h2>GitHub security repos</h2><span class="tabs" id="rp-t"></span></div><div class="scroll" id="rp-l"></div></section></div>
    <section class="panel"><div class="ph"><h2>Active threats</h2><span class="tabs" id="th-t"></span></div><div class="scroll" id="th-l"></div></section>`,
  mount() { $("#flt").value = S.q; $("#sort").textContent = "Sort: " + (S.sort === "new" ? "Newest" : "Priority"); },
  update() {
    const s = S.data, exTabs = EX_TABS;
    const exList = k => s.exploits.filter(i => i.kind === k).filter(okItem);
    const rpList = k => s.repos.filter(i => (i.m.kinds || []).includes(k) && okItem(i));
    const thList = k => (k === "deps" ? s.deps : s[k]).filter(okItem);
    if (!exTabs.some(t => t[0] === S.tab.ex)) S.tab.ex = "itw";
    $("#ex-t").innerHTML = tabsH("ex", exTabs, k => exList(k).length);
    $("#rp-t").innerHTML = tabsH("repo", RP_TABS, k => rpList(k).length);
    $("#th-t").innerHTML = tabsH("th", TH_TABS, k => thList(k).length);
    $("#ex-w").innerHTML = S.tab.ex === "poc" ? '<div class="warn">⚠ Unvetted code. Fake PoCs on GitHub often carry malware: read first, run only in an isolated lab.</div>' : "";
    const rk = { rising: i => i.m.per_day || 0, trending: i => i.m.today || 0, active: i => (i.m.gained || 0) * 1e6 + (i.m.stars || 0) }[S.tab.repo];
    keepScroll($("#ex-l"), () => { $("#ex-l").innerHTML = rows(srt(exList(S.tab.ex)), rowFor, "Nothing yet for this view."); });
    keepScroll($("#rp-l"), () => { $("#rp-l").innerHTML = rows(rpList(S.tab.repo).sort((a, b) => rk(b) - rk(a)), repoRow, "Nothing yet for this view."); });
    keepScroll($("#th-l"), () => { $("#th-l").innerHTML = rows(thList(S.tab.th), rowFor, TH_EMPTY[S.tab.th]); });
    refreshHot();
  },
};

/* ───────── page: Recorded Future (API feed + IOC lookup) ───────── */
const RK = n => (n == null ? ["na", "NO SCORE"] : n >= 90 ? ["hi", "VERY MALICIOUS"] : n >= 65 ? ["hi", "MALICIOUS"] : n >= 25 ? ["md", "SUSPICIOUS"] : n >= 5 ? ["lo", "UNUSUAL"] : ["no", "NO MALICIOUS CONTENT"]);
const RT = { ip: "IP", domain: "DOMAIN", url: "URL", hash: "HASH", vulnerability: "CVE" };
const critPill = c => (c >= 4 ? "hot" : c === 3 ? "arm" : c === 2 ? "pri" : "src");
const getRfHist = () => { try { return JSON.parse(localStorage.getItem("sd_rfhist") || "[]"); } catch (e) { return []; } };
const pushRfHist = q => { try { localStorage.setItem("sd_rfhist", JSON.stringify([q, ...getRfHist().filter(x => x !== q)].slice(0, 8))); } catch (e) { /* storage blocked */ } };
function rfCard(r) {
  const rk = r.risk || {}, [cls, lab] = RK(rk.score);
  const badge = r.ok === 1 ? `<span class="rk rk-${cls}"><b>${rk.score == null ? "–" : esc(rk.score)}</b> ${esc(rk.label ? String(rk.label).toUpperCase() : lab)}</span>` : r.ok === 2 ? '<span class="rk rk-na">NOT IN RECORDED FUTURE</span>' : '<span class="rk rk-err">LOOKUP FAILED</span>';
  let body;
  if (r.ok !== 1) body = `<div class="empty sm">${esc(r.msg)}</div>`;
  else {
    const meta = [r.first ? `first seen ${ago(r.first)} ago` : "", r.last ? `last seen ${ago(r.last)} ago` : "",
      rk.hit != null ? `${rk.hit}${rk.max ? " of " + rk.max : ""} risk rules triggered` : "", ...Object.entries(r.location || {}).map(([k, v]) => `${k}: ${v}`)].filter(Boolean);
    const ev = (rk.evidence || []).map(e => `<div class="evr"><span class="pill ${critPill(e.crit)}">${esc(e.label || (e.crit != null ? "L" + e.crit : "RULE"))}</span><div><b>${esc(e.rule)}</b>${e.ts ? `<span class="mut"> · ${ago(e.ts)} ago</span>` : ""}<div class="mut">${esc(e.text)}</div></div></div>`).join("");
    body = (rk.score != null ? `<div class="meter rk-${cls}"><i style="width:${Math.max(2, Math.min(100, rk.score))}%"></i></div>` : "")
      + (meta.length ? `<div class="dmeta pad">${meta.map(m => `<span>${esc(m)}</span>`).join("")}</div>` : "")
      + (r.insight ? `<p class="pad">${esc(r.insight)}</p>` : "")
      + (ev ? `<div class="ev">${ev}</div>` : '<div class="empty sm">No risk rules triggered.</div>')
      + `<details class="raw pad"><summary>Raw API response</summary><pre>${esc(r.raw || "")}</pre></details>`;
  }
  const acts = (safe(r.url) ? `<a class="btn sm" href="${esc(safe(r.url))}" target="_blank" rel="noopener noreferrer">Open in Recorded Future ↗</a>` : "") + (r.type !== "url" ? `<button class="btn sm" data-search="${esc(r.ioc)}">Search all sources</button>` : "");
  return `<div class="rfc"><div class="rfh"><span class="tag">${esc(RT[r.type] || r.type)}</span><span class="mono ioc" title="${esc(r.ioc)}">${esc(r.ioc)}</span>${badge}<span class="grow"></span>${acts}</div>${body}</div>`;
}
const RFPage = {
  html: () => `<div class="panel"><div class="ph"><h2>IOC lookup</h2><span class="sub">Recorded Future risk score and evidence for IPs, domains, URLs, file hashes and CVEs</span></div>
    <form class="sbar pad" id="rfform"><input type="search" id="rfq" placeholder="Paste IOCs, space or comma separated:  185.220.101.4  evil[.]example  44d88612fea8a8f36de82e1278abb02f  CVE-2024-3400" autocomplete="off" aria-label="IOCs to look up"><button class="btn primary">Look up</button></form>
    <div class="sugg pad" id="rfh"></div><div id="rfwarn"></div><div id="rfres"></div></div>
    <div class="cols"><section class="panel"><div class="ph"><h2>RF vulnerabilities</h2><span class="sub" id="rfvn"></span></div><div class="scroll" id="rfv"></div></section>
    <section class="panel"><div class="ph"><h2>RF alerts</h2><span class="sub" id="rfan"></span></div><div class="scroll" id="rfa"></div></section></div>`,
  mount() {
    $("#rfq").value = (S.rf && S.rf.q) || "";
    const h = getRfHist();
    $("#rfh").innerHTML = (h.length ? `<span>Recent:</span>${h.map(x => `<button data-rf="${esc(x)}" title="${esc(x)}">${esc(x.length > 28 ? x.slice(0, 27) + "…" : x)}</button>`).join("")}` : "<span>Defanged input such as hxxp://bad[.]example is cleaned up automatically. Private addresses are never sent out.</span>");
    this.draw();
  },
  update() {
    const s = S.data, on = s.rf_on;
    $("#rfwarn").innerHTML = on ? "" : '<div class="warn">Recorded Future is not connected. Set <b>RF_TOKEN</b> (a Connect API token) in your environment or in <code>config.py</code> and restart. The feed and lookups below come alive on their own.</div>';
    $("#rfq").disabled = !on; $("#rfform button").disabled = !on;
    const v = s.rf.vulns.filter(okItem).sort((a, b) => (b.m.score || 0) - (a.m.score || 0)), a = s.rf.alerts.filter(okItem);
    $("#rfvn").textContent = on ? `${v.length} by risk` : ""; $("#rfan").textContent = on ? `${a.length} recent` : "";
    keepScroll($("#rfv"), () => { $("#rfv").innerHTML = rows(v, rfRow, on ? "No vulnerabilities returned yet. Check the status line below." : "Needs RF_TOKEN."); });
    keepScroll($("#rfa"), () => { $("#rfa").innerHTML = rows(a, rfRow, on ? "No alerts in the last few days." : "Needs RF_TOKEN."); });
  },
  draw() {
    const el = $("#rfres"), st = S.rf;
    if (!el) return;
    if (!st) { el.innerHTML = ""; return; }
    let h = "";
    if (st.loading) h += '<div class="empty">Asking Recorded Future…</div>';
    if (st.error) h += `<div class="warn err">${esc(st.error)}</div>`;
    if (st.invalid && st.invalid.length) h += `<div class="warn">Skipped: ${st.invalid.map(x => `<span class="mono">${esc(x.input)}</span> (${esc(x.reason)})`).join("; ")}</div>`;
    if (st.truncated) h += '<div class="warn">Only the first 10 IOCs were looked up.</div>';
    el.innerHTML = h + (st.results || []).map(rfCard).join("");
  },
  async run(q) {
    q = q.trim();
    if (!q) return;
    const st = S.rf = { q, loading: true, results: [], invalid: [], error: "", truncated: false };
    if (mounted === "rf") { $("#rfq").value = q; this.draw(); }
    try {
      const r = await fetch("/api/rf/lookup?q=" + encodeURIComponent(q), { cache: "no-store" });
      if (r.status === 401) return location.reload();
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
      st.results = j.results || []; st.invalid = j.invalid || []; st.truncated = !!j.truncated;
      if (st.results.length) pushRfHist(q);
    } catch (e) { st.error = String(e.message || e); }
    st.loading = false;
    if (S.rf === st && mounted === "rf") this.draw();
  },
};

/* ───────── page: Search (GitHub, NVD, Exploit-DB, Metasploit, KEV, advisories, HN, Recorded Future... streamed in) ───────── */
const SE_CAPS = { default: 14, news: 24, nvd: 26, repo: 18, public: 14, itw: 14, cve: 30, tech: 12, actor: 10 };
const getHist = () => { try { return JSON.parse(localStorage.getItem("sd_hist") || "[]"); } catch (e) { return []; } };
const pushHist = q => { try { localStorage.setItem("sd_hist", JSON.stringify([q, ...getHist().filter(x => x.toLowerCase() !== q.toLowerCase())].slice(0, 10))); } catch (e) { /* storage blocked */ } };
const Search = {
  html: () => `<form class="sbar" id="sform"><input type="search" id="sq" placeholder="Search a technology, vendor, CVE, threat actor or IP:  fortinet · CVE-2024-3400 · LockBit · 8.8.8.8" autocomplete="off" aria-label="Search"><button class="btn primary">Search</button></form>
    <div class="sugg" id="sugg"></div><div id="sres"></div>`,
  mount() {
    $("#sq").value = (S.search && S.search.q) || "";
    const h = getHist(), kw = (S.data ? S.data.keywords : []).slice(0, 8);
    $("#sugg").innerHTML = (h.length ? `<span>Recent:</span>${h.slice(0, 6).map(x => `<button data-search="${esc(x)}">${esc(x)}</button>`).join("")}` : "") + (kw.length ? `<span>Your stack:</span>${kw.map(x => `<button data-search="${esc(x)}">${esc(x)}</button>`).join("")}` : "");
    this.draw(true);
  },
  unmount() { if (seGraph) seGraph.destroy(); seGraph = null; },
  update() { /* search results do not follow the live feed */ },
  start(q) {
    if (S.search && S.search.ctl) S.search.ctl.abort();
    const st = S.search = { q, items: new Map(), sources: new Map(), plan: [], loading: true, ctl: new AbortController(), type: "all", lookup: null, error: "" };
    pushHist(q);
    if (mounted === "search") { $("#sq").value = q; this.draw(true); }
    (async () => {
      try {
        const r = await fetch("/api/search?q=" + encodeURIComponent(q), { signal: st.ctl.signal, cache: "no-store" });
        if (r.status === 401) return location.reload();
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "HTTP " + r.status);
        const rd = r.body.getReader(), dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await rd.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let k;
          while ((k = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, k).trim(); buf = buf.slice(k + 1); if (line) this.part(st, JSON.parse(line)); }
        }
      } catch (e) { if (e.name !== "AbortError") st.error = String(e.message || e); }
      if (S.search === st) { st.loading = false; this.paint(); }
    })();
  },
  part(st, p) {
    if (S.search !== st) return;
    if (p.plan) st.plan = p.plan;
    if (p.error) st.error = p.error;
    if (p.source) {
      st.sources.set(p.source, p);
      if (p.lookup) st.lookup = p.lookup;
      for (const it of p.items) {
        it.q = (it.title + " " + it.desc + " " + it.cves.join(" ") + " " + it.src).toLowerCase();
        const o = st.items.get(it.id);
        if (o) { o.m.kinds = [...new Set([...(o.m.kinds || []), ...(it.m.kinds || [it.kind])])]; } else st.items.set(it.id, it);
      }
    }
    clearTimeout(st.paintT); st.paintT = setTimeout(() => this.paint(), 220);   // batch bursts of parts
  },
  draw(full) {
    const el = $("#sres"), st = S.search;
    if (!el) return;
    if (!st) { el.innerHTML = `<div class="panel"><div class="empty">Search any keyword. One query asks GitHub, NVD, Exploit-DB, Metasploit, CISA KEV, GitHub advisories, OSV, Hacker News and Recorded Future (if configured) at the same time, then links everything it finds into a graph you can navigate: double-click a CVE, technology or actor to search it next.</div></div>`; return; }
    if (full) {
      if (seGraph) seGraph.destroy();
      el.innerHTML = `<div class="srcs" id="ssrc"></div><div id="sip"></div>
        <div class="panel"><div class="ph"><h2>Result graph</h2><span class="sub" id="sgs"></span><span class="grow"></span><button class="btn sm" data-act="se-fit">Fit</button><button class="btn sm" data-act="se-layout">Re-layout</button></div>
        <div class="legend" id="se-leg"></div><div class="gwrap"><div class="gbox" id="se-g"></div><aside class="inspector" id="se-i"></aside></div></div>
        <div class="panel"><div class="ph"><h2>Results</h2><span class="sub" id="src"></span></div><div class="chips" id="sch"></div><div id="sl"></div></div>`;
      seGraph = Graph($("#se-g"), { select: n => { $("#se-i").innerHTML = inspectH(n); }, search: goSearch });
      $("#se-i").innerHTML = inspectH(null);
    }
    this.paint();
  },
  paint() {
    const st = S.search;
    if (!st || mounted !== "search" || !$("#ssrc")) return;
    const names = st.plan.length ? st.plan : [...st.sources.keys()];
    $("#ssrc").innerHTML = names.map(n => { const p = st.sources.get(n); return p ? `<span class="${["fail", "ok", "skip"][p.ok]}" title="${esc(p.msg)}">${esc(n)}${p.ok === 1 ? ` <b>${p.items.length || p.lookup ? p.items.length : 0}</b>` : ` <b>${esc(String(p.msg).slice(0, 46))}</b>`}</span>` : `<span class="wait">${esc(n)}</span>`; }).join("")
      + (st.error ? `<span class="fail">${esc(st.error)}</span>` : "");
    $("#sip").innerHTML = st.lookup ? ipCard(st.lookup) : "";
    const all = [...st.items.values()], counts = {};
    all.forEach(i => { const t = typeOf(i); counts[t] = (counts[t] || 0) + 1; });
    const d = buildGraphData(all.filter(i => !S.mine || i.mine), { caps: SE_CAPS, minShare: 2, maxIso: 30, hidden: S.hidden.se });
    const full = buildGraphData(all, { caps: SE_CAPS, minShare: 2, maxIso: 30, hidden: new Set() }), gc = {};
    full.nodes.forEach(n => { gc[n.type] = (gc[n.type] || 0) + 1; });
    if (seGraph) seGraph.setData(d);
    $("#se-leg").innerHTML = legendH(gc, S.hidden.se, "se");
    $("#sgs").textContent = st.loading ? "searching…" : `${d.nodes.length} nodes · ${d.links.length} links`;
    $(".gempty", $("#se-g")).textContent = st.loading ? "Searching every source…" : "Nothing found. Try a broader keyword, a vendor or product name, or a CVE id.";
    const types = ORDER.filter(t => counts[t] && !ENTITY.has(t));
    $("#sch").innerHTML = [["all", "All", all.length], ...types.map(t => [t, TYPES[t][0], counts[t]])].map(([k, n, c]) => `<button data-stype="${k}" class="${st.type === k ? "on" : ""}">${esc(n)} <i>${c}</i></button>`).join("");
    const list = srt(all.filter(i => (st.type === "all" || typeOf(i) === st.type) && (!S.mine || i.mine))).sort((a, b) => (b.p || 0) - (a.p || 0) || b.ts - a.ts);
    $("#src").textContent = `${list.length} items for “${st.q}”`;
    keepScroll(null, () => { $("#sl").innerHTML = rows(list.slice(0, S.maxRes), rowFor, st.loading ? "Searching…" : "No results.") + (list.length > S.maxRes ? `<button class="btn more" data-more="res">Show more (${list.length - S.maxRes})</button>` : ""); });
  },
};
function ipCard(L) {
  const sh = L.shodan_internetdb || {}, gn = L.greynoise_community || {};
  const kv = o => Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : v)}</dd>`).join("");
  return `<div class="panel ipgrid"><div><div class="ph"><h2>Shodan InternetDB · ${esc(L.ip)}</h2></div><dl class="kv">${kv({ ports: sh.ports, hostnames: sh.hostnames, tags: sh.tags, cpes: sh.cpes, vulns: sh.vulns, error: sh.error, detail: sh.detail }) || "<dt>result</dt><dd>no data</dd>"}</dl></div>
    <div><div class="ph"><h2>GreyNoise community</h2></div><dl class="kv">${kv({ classification: gn.classification, name: gn.name, noise: gn.noise, riot: gn.riot, last_seen: gn.last_seen, message: gn.message, error: gn.error }) || "<dt>result</dt><dd>no data</dd>"}${(L.seen_in_local_feeds || []).length ? `<dt>local IOC feeds</dt><dd>${esc(L.seen_in_local_feeds.join("; "))}</dd>` : ""}</dl></div></div>`;
}
const goSearch = q => { location.hash = "search/" + encodeURIComponent(q); };

/* ───────── routing, polling, events ───────── */
const Pg = { overview: Overview, intel: Intel, rf: RFPage, search: Search };
function route() {
  const [p, ...rest] = location.hash.replace(/^#\/?/, "").split("/");
  S.page = PAGES.includes(p) ? p : "overview";
  if (S.page === "rf") {
    let q = ""; try { q = decodeURIComponent(rest.join("/")); } catch (e) { q = rest.join("/"); }
    q = q.trim();
    if (q && (!S.rf || S.rf.q !== q)) S.pendingRf = q;
  }
  if (S.page === "search") {
    let q = ""; try { q = decodeURIComponent(rest.join("/")); } catch (e) { q = rest.join("/"); }
    q = q.trim();
    if (q.length >= 2 && (!S.search || S.search.q !== q)) { S.pendingSearch = q; }
  }
}
function show() {
  if (!S.data) return;
  if (mounted !== S.page) {
    if (mounted && Pg[mounted].unmount) Pg[mounted].unmount();
    clearTimeout(graphTimer);
    $("#main").innerHTML = Pg[S.page].html();
    mounted = S.page;
    if (Pg[S.page].mount) Pg[S.page].mount();
    window.scrollTo(0, 0);
  }
  if (S.page === "rf" && S.pendingRf) { const q = S.pendingRf; S.pendingRf = ""; RFPage.run(q); }
  if (S.page === "search" && S.pendingSearch) { const q = S.pendingSearch; S.pendingSearch = ""; Search.start(q); }
  Pg[S.page].update();
  $$("#nav button").forEach(b => b.classList.toggle("on", b.dataset.page === S.page));
  foot();
}
function foot() {
  const s = S.data, g = s.gh, q = $("#ghq");
  q.textContent = g && g.limit ? `GitHub API ${g.remaining}/${g.limit}` : "";
  q.className = "quota" + (g && g.limit && g.remaining <= 2 ? " low" : "");
  $("#foot").innerHTML = Object.entries(s.status).map(([k, v]) => `<span class="${["r", "g", "sk"][v.ok]}" title="${esc(v.msg)}">${["✕", "●", "○"][v.ok]} ${esc(k)}: ${esc(v.msg)}</span>`).join("");
  const nw = [...s.news, ...s.exploits, ...s.repos].filter(i => i.new).length;
  document.title = (nw ? `(${nw}) ` : "") + "Secdash";
}
function prep() { for (const l of [S.data.news, S.data.exploits, S.data.repos, S.data.rf.vulns, S.data.rf.alerts, S.data.ioc, S.data.ransom, S.data.breach, S.data.deps]) for (const i of l) i.q = (i.title + " " + i.desc + " " + i.cves.join(" ") + " " + i.src + " " + (i.techs || []).join(" ") + " " + (i.actors || []).join(" ")).toLowerCase(); }
function toast(m, hash) { const t = $("#toast"); t.textContent = m; t.onclick = () => { location.hash = hash; t.classList.remove("show"); }; t.classList.add("show"); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove("show"), 7000); }
async function pull() {
  try {
    const r = await fetch("/api/state?v=" + S.ver, { cache: "no-store" });
    if (r.status === 401) return location.reload();
    const j = await r.json();
    S.last = Date.now();
    if (!j.same) {
      const old = S.data && new Set([...S.data.news, ...S.data.exploits].map(i => i.id));
      S.data = j; S.ver = j.v; prep(); show();
      if (old && Date.now() - S.t0 > 9e4) {
        const nn = j.news.filter(i => !old.has(i.id)).length, ne = j.exploits.filter(i => !old.has(i.id)).length;
        if (nn + ne) toast("+ " + [ne && ne + " exploit" + (ne > 1 ? "s" : ""), nn && nn + " article" + (nn > 1 ? "s" : "")].filter(Boolean).join(" · "), ne ? "intel" : "overview");
      }
    }
  } catch (e) { /* offline: the LIVE badge turns red */ }
  live();
}
function live() { const e = $("#live"), off = Date.now() - S.last > 6e4; e.className = "live" + (off ? " off" : ""); $("#lt").textContent = off ? "OFFLINE" : "LIVE · " + (S.data ? "updated " + ago(S.data.now) + " ago" : "loading"); }
const who = () => { let n = ""; try { n = localStorage.getItem("sd_name") || ""; } catch (e) { /* ignore */ } if (!n) { n = (prompt("Your name (shown next to your triage actions):", "") || "").trim().slice(0, 40); try { localStorage.setItem("sd_name", n); } catch (e) { /* ignore */ } } return n; };
async function tpost(o) { o.owner = who(); await fetch("/api/triage", { method: "POST", headers: { "X-Requested-With": "secdash", "Content-Type": "application/json" }, body: JSON.stringify(o) }); S.ver = 0; pull(); }
const rerender = () => { if (mounted) Pg[mounted].update(); };

document.addEventListener("change", e => { const k = e.target.dataset && e.target.dataset.tri; if (k) tpost({ key: k, status: e.target.value }); });
document.addEventListener("input", e => {
  if (e.target.id === "flt") { S.q = e.target.value.trim().toLowerCase(); S.maxNews = 60; rerender(); if (mounted === "overview") Overview.graphSoon(true); }
});
document.addEventListener("submit", e => { if (e.target.id === "rfform") { e.preventDefault(); const q = $("#rfq").value.trim(); if (q) { const h = "#rf/" + encodeURIComponent(q); if (location.hash === h) RFPage.run(q); else location.hash = h; } return; } if (e.target.id === "sform") { e.preventDefault(); const q = $("#sq").value.trim(); if (q.length >= 2) { if (location.hash === "#search/" + encodeURIComponent(q)) { S.search = null; S.pendingSearch = q; show(); } else goSearch(q); } } });
document.addEventListener("click", e => {
  const t = e.target.closest("[data-toggle],[data-search],[data-rf],[data-page],[data-tab],[data-src],[data-more],[data-pin],[data-note],[data-act],[data-leg],[data-stype]");
  if (!t || !S.data) return;
  const d = t.dataset;
  if (d.toggle !== undefined) { if (e.target.closest("a,select,button:not(.chev)")) return; S.open.has(d.toggle) ? S.open.delete(d.toggle) : S.open.add(d.toggle); rerenderLists(); return; }
  if (d.search) { goSearch(d.search); return; }
  if (d.rf) { const h = "#rf/" + encodeURIComponent(d.rf); if (location.hash === h) RFPage.run(d.rf); else location.hash = h; return; }
  if (d.page) { location.hash = d.page; return; }
  if (d.pin) { tpost({ key: d.pin, pinned: !(S.data.triage[d.pin] || {}).pinned }); return; }
  if (d.note) { const n = prompt("Team note (visible to everyone):", (S.data.triage[d.note] || {}).note || ""); if (n !== null) tpost({ key: d.note, note: n }); return; }
  if (d.tab) { const [g, k] = d.tab.split(":"); S.tab[g] = k; }
  if (d.src) { S.src = d.src; S.maxNews = 60; }
  if (d.more) { if (d.more === "res") S.maxRes += 80; else S.maxNews += 60; if (d.more === "res") Search.paint(); else rerender(); return; }
  if (d.stype && S.search) { S.search.type = d.stype; Search.paint(); return; }
  if (d.leg) { const [ns, ty] = d.leg.split(":"), h = S.hidden[ns]; h.has(ty) ? h.delete(ty) : h.add(ty); ns === "ov" ? Overview.graph() : Search.paint(); return; }
  if (d.act === "ov-fit") ovGraph && ovGraph.fit();
  else if (d.act === "ov-layout") ovGraph && ovGraph.relayout();
  else if (d.act === "se-fit") seGraph && seGraph.fit();
  else if (d.act === "se-layout") seGraph && seGraph.relayout();
  else if (d.act === "to-graph") { const g = $("#ov-graph"); if (g) g.scrollIntoView({ behavior: "smooth", block: "start" }); }
  else rerender();
});
function rerenderLists() { if (mounted === "search") Search.paint(); else if (mounted === "overview") Overview.lists(); else rerender(); }
document.addEventListener("keydown", e => {
  if (/INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) { if (e.key === "Escape") e.target.blur(); return; }
  if (e.key === "/") { e.preventDefault(); const f = $("#flt") || $("#sq") || $("#rfq"); if (f) f.focus(); }
  else if (e.key === "Escape") $("#dlg").classList.remove("open");
  else if (/^[1-4]$/.test(e.key)) location.hash = PAGES[+e.key - 1];
});
window.addEventListener("hashchange", () => { route(); show(); });
document.addEventListener("click", e => { const b = e.target.closest("#nav button"); if (b) location.hash = b.dataset.page; });
$("#mine").onclick = e => { S.mine = !S.mine; e.target.classList.toggle("on", S.mine); rerender(); if (mounted === "overview") Overview.graphSoon(true); };
document.addEventListener("click", e => { if (e.target.id === "sort") { S.sort = S.sort === "new" ? "pri" : "new"; e.target.textContent = "Sort: " + (S.sort === "new" ? "Newest" : "Priority"); rerender(); } });
$("#rf").onclick = async () => { await fetch("/api/refresh", { method: "POST", headers: { "X-Requested-With": "secdash" } }); let n = 0; const t = setInterval(() => { pull(); if (++n > 20) clearInterval(t); }, 3000); };
const showBrief = async f => { $("#bt").value = await (await fetch("/api/export?fmt=" + f)).text(); $("#dlg").classList.add("open"); };
const copy = () => { const t = $("#bt"); t.select(); try { if (window.isSecureContext && navigator.clipboard) navigator.clipboard.writeText(t.value); else document.execCommand("copy"); } catch (e) { /* ignore */ } };
$("#brief").onclick = () => showBrief("md");
$("#cmd").onclick = async () => { await showBrief("md"); copy(); };
$("#csl").onclick = async () => { await showBrief("slack"); copy(); };
$("#cls").onclick = () => $("#dlg").classList.remove("open");

route(); pull(); setInterval(pull, 10000); setInterval(live, 5000);
window.__secdash = { S, buildGraphData, typeOf };   // handy in the browser console / tests
})();
