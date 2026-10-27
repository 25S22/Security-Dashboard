#!/usr/bin/env python3
"""Secdash: one script. Starts every collector in the background, serves the dashboard on a random port
reachable on your WiFi behind an access code. Standard library only.   Usage: python run.py"""
import atexit, csv, hashlib, html, io, json, os, random, re, secrets, socket, sys, threading, time, webbrowser
import urllib.error, urllib.request, xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse
import config as C

UA = "secdash/2.0 (+local dashboard)"
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secdash_state.json")
LOCK = threading.RLock()
ITEMS, STATUS, META = {}, {}, {"infocon": "n/a"}   # per-source items, per-source health, misc
KEV_IDS, MSF_IDS, EDB_IDS, NUC_IDS = set(), set(), set(), set()
STATE = {"v": 0, "data": b"{}", "obj": None}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SEC_RE = re.compile(r"secur|vuln|exploit|pentest|red.?team|malware|ransom|\bcve|forensic|dfir|osint|phish|fuzz|reverse.?eng|"
                    r"\bc2\b|offensive|hack|threat|\bctf\b|burp|nmap|decompil|obfuscat|payload|shellcode|\bedr\b|siem|recon|"
                    r"credential|jailbreak|prompt.?inject|pwn|infosec|cyber|bypass|rootkit|backdoor|stealer", re.I)
TOKEN = C.GITHUB_TOKEN
RF = C.RECORDED_FUTURE
GH_SLEEP = 2.2 if TOKEN else 6.5

# ───────────── helpers ─────────────
def http(url, headers=None, data=None, timeout=40, cap=40_000_000):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Accept-Encoding": "identity", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        b = r.read(cap + 1)
    if len(b) > cap:
        raise ValueError("response too large")
    return b

def ts(s):
    s = str(s or "").strip()
    if not s:
        return 0
    try:
        return int(parsedate_to_datetime(s).timestamp())
    except Exception:
        pass
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" +0000", "+00:00"))
        return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp())
    except Exception:
        return 0

def clean(s, n=240):
    t = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or ""))).strip()
    return t[:n] + ("…" if len(t) > n else "")

def mk(sec, src, kind, title, url, t, desc="", **meta):
    cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {desc} {meta.get('cves_raw', '')}")})
    meta.pop("cves_raw", None)
    return {"id": hashlib.sha1(f"{sec}|{src}|{url or title}".encode()).hexdigest()[:14], "sec": sec, "src": src,
            "kind": kind, "title": clean(title, 200), "url": url if str(url).startswith(("http://", "https://")) else "",
            "ts": min(int(t or time.time()), int(time.time()) + 3600), "desc": clean(desc), "cves": cves, "m": meta}

def child(e, *names):
    for n in names:
        for c in e:
            if c.tag.rsplit("}", 1)[-1] == n:
                return c

def parse_feed(b, src, sec="news", kind="news"):
    if b"<!ENTITY" in b:  # refuse entity-expansion tricks from untrusted feeds
        raise ValueError("unsafe XML")
    out = []
    for e in ET.fromstring(b).iter():
        if e.tag.rsplit("}", 1)[-1] not in ("item", "entry"):
            continue
        url = ""
        for l in (c for c in e if c.tag.rsplit("}", 1)[-1] == "link"):
            if l.get("href") and l.get("rel") in (None, "alternate"):
                url = l.get("href"); break
            if l.text and l.text.strip():
                url = l.text.strip(); break
        g = lambda *n: (getattr(child(e, *n), "text", "") or "")
        title = g("title")
        if title and url.startswith(("http://", "https://")):
            out.append(mk(sec, src, kind, title, url, ts(g("pubDate", "published", "updated", "date")) or time.time(),
                          g("description", "summary", "encoded", "content")))
    return out

# ───────────── collectors: each returns (items, note) ─────────────
def feeds():
    cut, bad, out = time.time() - C.NEWS_DAYS * 86400, [], []
    def one(f):
        try:
            return parse_feed(http(f[1], timeout=25), f[0])
        except Exception:
            bad.append(f[0]); return []
    with ThreadPoolExecutor(8) as ex:
        for items in ex.map(one, C.FEEDS):
            out += [i for i in items if i["ts"] >= cut]
    if bad and not out:
        raise RuntimeError("all feeds failed (offline?): " + ", ".join(bad[:4]) + "…")
    out.sort(key=lambda i: -i["ts"])
    return out[:300], f"{len(out)} articles" + (f"; failed: {', '.join(bad)}" if bad else "")

def hn():
    out, seen = [], set()
    for q in C.HN_QUERIES:
        d = json.loads(http("https://hn.algolia.com/api/v1/search_by_date?" + urlencode(
            {"tags": "story", "query": q, "numericFilters": "points>20", "hitsPerPage": 15})))
        for h in d.get("hits", []):
            if h["objectID"] in seen or not h.get("url"):
                continue
            seen.add(h["objectID"])
            out.append(mk("news", "Hacker News", "news", h["title"], h["url"], h.get("created_at_i"),
                          f'{h.get("points", 0)} points · {h.get("num_comments", 0)} comments', points=h.get("points", 0)))
    return out, f"{len(out)} stories"

def kev():
    global KEV_IDS
    v = json.loads(http("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))["vulnerabilities"]
    KEV_IDS = {x["cveID"] for x in v}
    v.sort(key=lambda x: x["dateAdded"], reverse=True)
    v = v[:C.KEV_COUNT]
    epss = {}
    try:
        for x in json.loads(http("https://api.first.org/data/v1/epss?cve=" + ",".join(i["cveID"] for i in v)))["data"]:
            epss[x["cve"]] = round(float(x["epss"]) * 100, 1)
    except Exception:
        pass
    return [mk("exploit", "CISA KEV", "itw", f'{x["cveID"]}: {x["vendorProject"]} {x["product"]}: {x["vulnerabilityName"]}',
               f'https://nvd.nist.gov/vuln/detail/{x["cveID"]}', ts(x["dateAdded"]), x["shortDescription"], due=x["dueDate"],
               ransom=x.get("knownRansomwareCampaignUse") == "Known", epss=epss.get(x["cveID"])) for x in v], f"{len(v)} newest of {len(KEV_IDS)}"

def edb():
    global EDB_IDS
    rows = list(csv.DictReader(io.StringIO(http("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv").decode("utf-8", "replace"))))
    EDB_IDS = {c.strip().upper() for r in rows for c in (r.get("codes") or "").split(";") if c.upper().startswith("CVE-")}
    rows.sort(key=lambda r: r.get("date_published") or "", reverse=True)
    return [mk("exploit", "Exploit-DB", "public", r["description"], f'https://www.exploit-db.com/exploits/{r["id"]}', ts(r["date_published"]),
               f'{r.get("platform", "")} · {r.get("type", "")}', cves_raw=r.get("codes", ""), verified=r.get("verified") == "1")
            for r in rows[:40]], f"{len(rows)} in DB"

def msf():
    global MSF_IDS
    m = json.loads(http("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json")).values()
    MSF_IDS = {r.upper() for v in m for r in v.get("references", []) if r.upper().startswith("CVE-")}
    ex = sorted((v for v in m if v.get("type") == "exploit"), key=lambda v: v.get("mod_time", ""), reverse=True)[:30]
    return [mk("exploit", "Metasploit", "public", v["name"], "https://github.com/rapid7/metasploit-framework/blob/master" + v["path"],
               ts(v.get("mod_time")), v.get("description", ""), cves_raw=" ".join(v.get("references", [])), module=v["fullname"])
            for v in ex], f"{len(ex)} recently updated modules"

def nuclei():
    global NUC_IDS
    ids = set()
    for line in http("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json").decode("utf-8", "replace").splitlines():
        try:
            ids.add(json.loads(line)["ID"].upper())
        except Exception:
            pass
    if not ids:
        raise RuntimeError("no templates parsed")
    NUC_IDS = ids
    return [], f"{len(ids)} CVEs have a ready Nuclei template"

def packet():
    out = []
    for name, url in C.EXPLOIT_FEEDS:
        out += parse_feed(http(url), name, "exploit", "public")
    return out[:30], f"{len(out)} entries"

GH = {"remaining": None, "limit": None, "reset": 0, "last": 0}
GH_LOCK = threading.Lock()   # all GitHub searches go through one lane, so groups can't burst together

def gh(q, sort="stars", n=30, tries=3):
    url = "https://api.github.com/search/repositories?" + urlencode({"q": q, "sort": sort, "order": "desc", "per_page": n})
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json", **({"Authorization": "Bearer " + TOKEN} if TOKEN else {})}
    for i in range(tries):
        with GH_LOCK:
            time.sleep(max(0, GH_SLEEP - (time.time() - GH["last"])))
            if GH["remaining"] == 0 and GH["reset"] > time.time():
                time.sleep(min(GH["reset"] - time.time() + 1, 70))
            GH["last"] = time.time()
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=40) as r:
                    GH.update(remaining=int(r.headers.get("X-RateLimit-Remaining", -1)), limit=int(r.headers.get("X-RateLimit-Limit", 0)),
                              reset=int(r.headers.get("X-RateLimit-Reset", 0)))
                    return json.loads(r.read()).get("items", [])
            except urllib.error.HTTPError as e:
                if e.code not in (403, 429):
                    raise RuntimeError(f"HTTP {e.code}: {e.read()[:120].decode('utf-8', 'replace')}")
                reset = int(e.headers.get("X-RateLimit-Reset") or 0)
                pause = int(e.headers.get("Retry-After") or 0) or (max(5, min(reset - time.time() + 1, 65)) if reset else 15 * (i + 1))
                GH.update(remaining=0, reset=time.time() + pause)
                time.sleep(pause)   # backoff, then retry
    raise RuntimeError("GitHub rate limit: gave up after retries")

def repo(r, kind):
    age = max(1, (time.time() - ts(r["created_at"])) / 86400)
    return mk("repo", "GitHub", kind, r["full_name"], r["html_url"], ts(r["pushed_at"]), r.get("description") or "",
              stars=r["stargazers_count"], lang=r.get("language"), created=ts(r["created_at"]),
              per_day=round(r["stargazers_count"] / age, 1), topics=(r.get("topics") or [])[:4])

def ghpoc():
    d = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    out = []
    for r in gh(f"CVE-{datetime.now().year} in:name created:>{d}", "updated", 40):
        it = repo(r, "poc"); it["sec"] = "exploit"; it["src"] = "GitHub PoC"; it["ts"] = ts(r["created_at"]); out.append(it)
    return out, f"{len(out)} new CVE repos (unvetted)"

def by_terms(kind, extra, n, key):
    seen, out, errs = set(), [], []
    for group in C.GITHUB["term_groups"]:
        terms = " OR ".join(f'"{t}"' if " " in t else t for t in group[:6])   # GitHub allows max 5 OR operators per query
        try:
            for r in gh(f"{terms} in:topics,description {extra}", "stars", n):
                if r["full_name"] not in seen:
                    seen.add(r["full_name"]); out.append(repo(r, kind))
        except Exception as e:  # keep partial results instead of losing everything
            errs.append(str(e)[:70])
    if errs and not out:
        raise RuntimeError("; ".join(errs))
    out.sort(key=key, reverse=True)
    return out[:40], f"{len(out)} repos" + (f" (partial: {errs[0]})" if errs else "")

def rising():
    d = (datetime.now(timezone.utc) - timedelta(days=C.GITHUB["rising_days"])).strftime("%Y-%m-%d")
    return by_terms("rising", f"created:>{d}", 30, lambda i: i["m"]["per_day"])

def active():
    d = (datetime.now(timezone.utc) - timedelta(days=C.GITHUB["active_days"])).strftime("%Y-%m-%d")
    return by_terms("active", f"stars:>1000 pushed:>{d}", 20, lambda i: i["m"]["stars"])

def trending():
    out, seen = [], set()
    for lang, since in [("", "daily"), ("", "weekly")] + [(l, "daily") for l in C.GITHUB["trending_langs"]]:
        try:
            t = http(f"https://github.com/trending/{lang}?since={since}").decode("utf-8", "replace")
        except Exception:
            continue
        for a in re.findall(r'<article class="Box-row">(.*?)</article>', t, re.S):
            m = re.search(r'<h2[^>]*>\s*<a[^>]*href="/([^"/]+/[^"/]+)"', a)
            if not m or m.group(1) in seen:
                continue
            d = re.search(r'<p class="[^"]*">\s*(.*?)\s*</p>', a, re.S)
            desc = clean(d.group(1)) if d else ""
            if not SEC_RE.search(m.group(1) + " " + desc):
                continue
            seen.add(m.group(1))
            today = re.search(r"([\d,]+)\s+stars?\s+(today|this week)", a)
            tot = re.search(r'href="/[^"]+/stargazers"[^>]*>(.*?)</a>', a, re.S)
            stars = int(re.sub(r"\D", "", clean(tot.group(1)) if tot else "") or 0)
            lg = re.search(r'itemprop="programmingLanguage">([^<]+)', a)
            out.append(mk("repo", "GitHub", "trending", m.group(1), "https://github.com/" + m.group(1), time.time(), desc,
                          stars=stars, lang=lg.group(1) if lg else None, today=int(re.sub(r"\D", "", today.group(1))) if today else 0,
                          window=today.group(2) if today else since))
        time.sleep(1)
    out.sort(key=lambda i: -i["m"]["today"])
    return out, f"{len(out)} security-related trending repos"

def rf_get(path, params):
    return json.loads(http("https://api.recordedfuture.com" + path + "?" + urlencode(params),
                           {"X-RFToken": RF["token"], "Accept": "application/json"}))

def rf_vulns():
    res = rf_get("/v2/vulnerability/search", {"limit": 25, "fields": "entity,risk,timestamps", **RF["vuln_params"]})["data"]["results"]
    out = []
    for r in res:
        e, k = r.get("entity", {}), r.get("risk", {})
        rules = [x.get("evidenceString") or x.get("rule") or "" for x in k.get("evidenceDetails", [])][:3]
        out.append(mk("rf", "Recorded Future", "vuln", e.get("name", "?"), "https://app.recordedfuture.com/live/sc/entity/" + e.get("id", ""),
                      ts((r.get("timestamps") or {}).get("lastSeen")), e.get("description", ""), score=k.get("score", 0),
                      label=k.get("criticalityLabel", ""), rules=[clean(x, 140) for x in rules]))
    out.sort(key=lambda i: -i["m"]["score"])
    return out, f"{len(out)} vulnerabilities"

def rf_alerts():
    res = rf_get("/v2/alert/search", {"limit": 25, "orderby": "triggered", "direction": "desc",
                                      "triggered": f'-{RF["alert_days"]}d', **RF["alert_params"]})["data"]["results"]
    return [mk("rf", "Recorded Future", "alert", r.get("title") or (r.get("rule") or {}).get("name", "alert"),
               r.get("url") or "https://app.recordedfuture.com", ts(r.get("triggered")), (r.get("rule") or {}).get("name", ""),
               status=(r.get("review") or {}).get("status", "")) for r in res], f"{len(res)} alerts"

def infocon():
    META["infocon"] = json.loads(http("https://isc.sans.edu/api/infocon?json")).get("status", "n/a")
    return [], f"level {META['infocon']}"

# (group, name, function, minimum minutes between runs of heavy sources)
SOURCES = [("news", "News feeds", feeds, 0), ("news", "Hacker News", hn, 0),
           ("exploits", "CISA KEV", kev, 0), ("exploits", "Exploit-DB", edb, 120), ("exploits", "Metasploit", msf, 120),
           ("exploits", "Nuclei templates", nuclei, 360), ("exploits", "Packet Storm", packet, 0), ("exploits", "GitHub PoCs", ghpoc, 0),
           ("github", "GitHub rising", rising, 0), ("github", "GitHub trending", trending, 0), ("github", "GitHub active", active, 0),
           ("meta", "InfoCon", infocon, 0)]
if RF.get("token"):
    SOURCES += [("rf", "RF vulnerabilities", rf_vulns, 0), ("rf", "RF alerts", rf_alerts, 0)]

# ───────────── state, scoring, publishing ─────────────
FIRST_RUN, PREV_SEEN, PREV_STARS, FIRST_STARS, SEEN, TRIAGE, DIRTY = True, set(), {}, {}, {}, {}, [False]
try:
    _s = json.load(open(STATE_FILE))
    FIRST_RUN, SEEN, PREV_STARS = False, _s.get("seen", {}), _s.get("stars", {})
    FIRST_STARS, TRIAGE = _s.get("first_stars", {}), _s.get("triage", {})
    PREV_SEEN = set(SEEN)
except Exception:
    pass
CUR_STARS, RUN_START = {}, int(time.time())

def save_state():
    with LOCK:
        cut = time.time() - 45 * 86400
        d = {"seen": {k: v for k, v in SEEN.items() if v > cut}, "stars": CUR_STARS or PREV_STARS,
             "first_stars": FIRST_STARS, "triage": TRIAGE}
    tmp = STATE_FILE + ".tmp"
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(d, f)
    os.replace(tmp, STATE_FILE)
atexit.register(lambda: DIRTY[0] and save_state())

def priority(it):
    """0-100: exploited > weaponized > fresh PoC > news; corroboration, ransomware, EPSS and YOUR stack push it up."""
    m = it["m"]
    s = {"itw": 50, "public": 30, "poc": 10}.get(it["kind"], 5 if it["sec"] == "news" else 0)
    s += 15 * bool(m.get("ransom")) + min(20, (m.get("epss") or 0) * 0.2)
    s += 8 * len([f for f in it["flags"] if not (it["kind"] == "itw" and f == "KEV")])
    s += C.STACK_BOOST * it["mine"] + 5 * it["new"]
    return int(min(100, s))

def publish():
    with LOCK:
        now, news, ex, repos, rfv, rfa = time.time(), [], [], {}, [], []
        kw = [k.lower() for k in C.KEYWORDS if len(k) > 2]
        sets = (("KEV", KEV_IDS), ("MSF", MSF_IDS), ("EDB", EDB_IDS), ("NUC", NUC_IDS))
        for items in ITEMS.values():
            for it in items:
                if it["id"] not in SEEN:
                    SEEN[it["id"]] = now; DIRTY[0] = True
                it["new"] = (not FIRST_RUN) and it["id"] not in PREV_SEEN
                hay = f'{it["title"]} {it["desc"]}'.lower()
                it["mine"] = any(k in hay for k in kw)
                it["flags"] = [f for f, st in sets if any(c in st for c in it["cves"])]
                it["tk"] = it["cves"][0] if it["cves"] else it["id"]   # team triage is shared per CVE
                if it["sec"] == "news": it["p"] = priority(it); news.append(it)
                elif it["sec"] == "exploit": it["p"] = priority(it); ex.append(it)
                elif it["sec"] == "rf": (rfv if it["kind"] == "vuln" else rfa).append(it)
                else:
                    n, stars = it["title"], it["m"].get("stars", 0)
                    CUR_STARS[n] = stars
                    if stars:
                        if n not in FIRST_STARS:
                            FIRST_STARS[n] = stars; DIRTY[0] = True
                        if n in PREV_STARS: it["m"]["gained"] = stars - PREV_STARS[n]
                        it["m"]["total_gain"] = stars - FIRST_STARS[n]
                    if n in repos:  # same repo found by several collectors: merge
                        o = repos[n]; o["m"]["kinds"].append(it["kind"])
                        for k, v in it["m"].items():
                            if o["m"].get(k) in (None, 0, "") and v: o["m"][k] = v
                        o["new"] = o["new"] or it["new"]
                    else:
                        it["m"]["kinds"] = [it["kind"]]; repos[n] = it
        news.sort(key=lambda i: -i["ts"]); ex.sort(key=lambda i: -i["ts"])
        mentions = {}
        for it in news + ex:
            for c in it["cves"]:
                mentions.setdefault(c, {"src": set(), "t": it["title"]})["src"].add(it["src"])
        hot = sorted(({"cve": c, "n": len(v["src"]), "kev": c in KEV_IDS, "msf": c in MSF_IDS, "edb": c in EDB_IDS, "nuc": c in NUC_IDS, "t": v["t"]}
                      for c, v in mentions.items() if len(v["src"]) >= 2 or (c in KEV_IDS or c in MSF_IDS)),
                     key=lambda h: (h["kev"], h["n"], h["msf"]), reverse=True)[:14]
        payload = {"v": STATE["v"] + 1, "now": int(now), "run_start": RUN_START, "first_run": FIRST_RUN, "infocon": META["infocon"],
                   "rf_on": bool(RF.get("token")), "status": STATUS, "hot": hot, "news": news[:250], "exploits": ex[:200],
                   "repos": list(repos.values()), "rf": {"vulns": rfv, "alerts": rfa}, "triage": TRIAGE,
                   "statuses": C.TRIAGE_STATUSES, "gh": {k: GH[k] for k in ("remaining", "limit", "reset")}}
        STATE["v"], STATE["data"], STATE["obj"] = payload["v"], json.dumps(payload).encode(), payload
        if DIRTY[0] and now - getattr(publish, "last", 0) > 15:
            publish.last = now; DIRTY[0] = False; save_state()

# ───────────── exports: daily brief (Markdown / Slack), CSV, JSON ─────────────
def brief(P, slack=False):
    B = (lambda t: f"*{t}*") if slack else (lambda t: f"**{t}**")
    def L(i):
        t = i["title"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") if slack else re.sub(r"([\[\]\\])", r"\\\1", i["title"])
        return (f"<{i['url']}|{t}>" if slack else f"[{t}]({i['url']})") if i["url"] else t
    def line(i):
        tg = P["triage"].get(i["tk"], {})
        bits = [i["src"], *i["flags"], *(["MY STACK"] if i["mine"] else []), *([f"P{i['p']}"] if i.get("p") else [])]
        if tg.get("status", "New") != "New":
            bits.append(tg["status"] + (f" · {tg['owner']}" if tg.get("owner") else ""))
        return f"{L(i)} ({', '.join(bits)})" + (f' — "{tg["note"][:140]}"' if tg.get("note") else "")
    day = time.strftime("%Y-%m-%d", time.localtime(P["now"]))
    out = [B(f"Threat brief {day}") if slack else f"# Threat brief {day}", f"InfoCon: {P['infocon']}"]
    def sec(title, rows):
        if rows: out.extend(["", B(title), *[("• " if slack else "- ") + line(i) for i in rows]])
    allx = P["exploits"] + P["news"]
    top = lambda l, n: sorted(l, key=lambda i: (-i.get("p", 0), -i["ts"]))[:n]
    seen, work = set(), []
    for i in allx:
        if P["triage"].get(i["tk"], {}).get("status") in ("Escalated", "Investigating") and i["tk"] not in seen:
            seen.add(i["tk"]); work.append(i)
    sec("Being worked (Escalated / Investigating)", work)
    sec("Hits on our stack", top([i for i in allx if i["mine"]], 8))
    sec("Exploited in the wild", top([i for i in P["exploits"] if i["kind"] == "itw"], 8))
    sec("New public exploits", [i for i in P["exploits"] if i["kind"] == "public"][:6])
    if P["hot"]:
        out.extend(["", B("Hot CVEs")] + [("• " if slack else "- ") + f'{h["cve"]} ({h["n"]} sources' + "".join(", " + k.upper() for k in ("kev", "msf", "edb", "nuc") if h[k]) + ")" for h in P["hot"][:8]])
    rr = sorted((r for r in P["repos"] if "rising" in r["m"]["kinds"]), key=lambda r: -(r["m"].get("per_day") or 0))[:5]
    if rr: out.extend(["", B("Rising security repos")] + [("• " if slack else "- ") + f'{L(r)} ({r["m"].get("stars", 0)}★, {r["m"].get("per_day", 0)}/day)' for r in rr])
    sec("Top news", top(P["news"], 8))
    return "\n".join(out)

def to_csv(P):
    buf, cell = io.StringIO(), (lambda v: "'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v)  # spreadsheet-formula safe
    w = csv.writer(buf)
    w.writerow(["section", "kind", "title", "url", "source", "published_utc", "cves", "flags", "priority", "my_stack", "triage_status", "triage_by", "triage_note"])
    for sec, rows in (("exploit", P["exploits"]), ("news", P["news"]), ("repo", P["repos"])):
        for i in rows:
            tg = P["triage"].get(i["tk"], {})
            w.writerow([cell(x) for x in [sec, i["kind"], i["title"], i["url"], i["src"], datetime.fromtimestamp(i["ts"], timezone.utc).strftime("%Y-%m-%d %H:%M"),
                                         " ".join(i["cves"]), " ".join(i["flags"]), i.get("p", ""), "yes" if i["mine"] else "", tg.get("status", ""), tg.get("owner", ""), tg.get("note", "")]])
    return buf.getvalue()

KICK = {g: threading.Event() for g in C.REFRESH_MINUTES}
LAST = {}

def run_group(group):
    while True:
        for g, name, fn, every in SOURCES:
            if g != group or (every and time.time() - LAST.get(name, 0) < every * 60 and STATUS.get(name, {}).get("ok") and not KICK[group].is_set()):
                continue
            try:
                items, note = fn()
                with LOCK:
                    ITEMS[name] = items; STATUS[name] = {"ok": 1, "msg": note, "ts": int(time.time())}
                LAST[name] = time.time()
            except Exception as e:
                with LOCK:
                    STATUS[name] = {"ok": 0, "msg": f"{type(e).__name__}: {str(e)[:120]}", "ts": int(time.time())}
            print(f"  [{'ok  ' if STATUS[name]['ok'] else 'FAIL'}] {name}: {STATUS[name]['msg']}", flush=True)
            publish()
        KICK[group].wait(C.REFRESH_MINUTES[group] * 60); KICK[group].clear()

# ───────────── web server ─────────────
CODE = (C.ACCESS_CODE or "".join(secrets.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(6))).upper()
SESSIONS, FAILS = {}, {}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def out(self, code, body, ctype="application/json", extra=()):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        for k, v in (("Content-Type", ctype + "; charset=utf-8"), ("Content-Length", str(len(b))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"), *extra):
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)
    def page(self, src, code=200):
        n = secrets.token_urlsafe(12)
        self.out(code, src.replace("__N__", n), "text/html", [("Content-Security-Policy",
                 f"default-src 'none'; script-src 'nonce-{n}'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")])
    def authed(self):
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        return "sd" in ck and SESSIONS.get(ck["sd"].value, 0) > time.time()
    def try_code(self, code):
        ip, now = self.client_address[0], time.time()
        FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < C.LOCKOUT_MINUTES * 60]
        if len(FAILS[ip]) >= C.MAX_LOGIN_FAILS: return None
        if secrets.compare_digest(code.strip().upper().encode(), CODE.encode()):
            t = secrets.token_urlsafe(24); SESSIONS[t] = now + 86400
            for k in [k for k, e in SESSIONS.items() if e < now]: del SESSIONS[k]
            return ("Set-Cookie", f"sd={t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400")
        FAILS[ip].append(now); return False
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/state":
            if not self.authed(): return self.out(401, '{"error":"auth"}')
            v = int(parse_qs(u.query).get("v", ["0"])[0] or 0)
            return self.out(200, b'{"same":true}' if v == STATE["v"] else STATE["data"])
        if u.path == "/api/export":
            if not self.authed(): return self.out(401, "{}")
            P, q = STATE["obj"], parse_qs(u.query)
            if not P: return self.out(503, "still loading", "text/plain")
            f, dl, day = q.get("fmt", ["md"])[0], q.get("dl"), time.strftime("%Y%m%d")
            body, ct, ext = {"md": (brief(P), "text/plain", "md"), "slack": (brief(P, True), "text/plain", "txt"),
                             "csv": (to_csv(P), "text/csv", "csv"),
                             "json": (json.dumps({k: P[k] for k in ("now", "infocon", "hot", "news", "exploits", "repos", "triage")}, indent=1), "application/json", "json")}.get(f, (None,) * 3)
            if body is None: return self.out(400, "bad fmt", "text/plain")
            return self.out(200, body, ct, [("Content-Disposition", f'attachment; filename="threat-{day}.{ext}"')] if dl else [])
        if u.path != "/": return self.out(404, "not found", "text/plain")
        code = parse_qs(u.query).get("code", [""])[0]
        if code:
            r = self.try_code(code)
            if r: return self.out(303, "", "text/plain", [("Location", "/"), r])
        if self.authed(): return self.page(PAGE)
        self.page(LOGIN.replace("__MSG__", ""))
    def do_POST(self):
        if self.path == "/api/refresh":
            if not self.authed() or self.headers.get("X-Requested-With") != "secdash": return self.out(403, "{}")
            for g, ev in KICK.items(): ev.set()
            return self.out(200, '{"ok":true}')
        if self.path == "/api/triage":
            if not self.authed() or self.headers.get("X-Requested-With") != "secdash": return self.out(403, "{}")
            try:
                b = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0) or 0), 4096)) or b"{}")
                key = str(b.get("key", ""))
                assert re.fullmatch(r"[A-Za-z0-9._-]{1,40}", key) and ("status" not in b or b["status"] in C.TRIAGE_STATUSES)
            except Exception:
                return self.out(400, '{"error":"bad request"}')
            with LOCK:
                cur = dict(TRIAGE.get(key, {}))
                if "status" in b: cur["status"] = b["status"]
                if "note" in b: cur["note"] = str(b["note"])[:500]
                if "pinned" in b: cur["pinned"] = bool(b["pinned"])
                cur["owner"], cur["ts"] = str(b.get("owner") or cur.get("owner", ""))[:40], int(time.time())
                if cur.get("status", "New") == "New" and not cur.get("note") and not cur.get("pinned"): TRIAGE.pop(key, None)
                elif len(TRIAGE) < 3000 or key in TRIAGE: TRIAGE[key] = cur
            save_state(); publish()
            return self.out(200, '{"ok":true}')
        if self.path != "/login": return self.out(404, "not found", "text/plain")
        body = self.rfile.read(min(int(self.headers.get("Content-Length", 0) or 0), 512)).decode("utf-8", "ignore")
        r = self.try_code(parse_qs(body).get("code", [""])[0])
        if r: return self.out(303, "", "text/plain", [("Location", "/"), r])
        self.page(LOGIN.replace("__MSG__", f"Too many attempts. Wait {C.LOCKOUT_MINUTES} minutes." if r is None else "Wrong code."), 429 if r is None else 401)

def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def main():
    srv = None
    for _ in range(80):
        port = C.PORT or random.randint(*C.PORT_RANGE)
        try:
            srv = ThreadingHTTPServer((C.HOST, port), H); break
        except OSError:
            if C.PORT: sys.exit(f"Port {port} is busy.")
    if not srv: sys.exit("Could not find a free port.")
    srv.daemon_threads = True
    for g in {s[0] for s in SOURCES}:
        threading.Thread(target=run_group, args=(g,), daemon=True).start()
    lan = lan_ip()
    print(f"\n  ┌─ SECDASH ─ live {'(first run: nothing is flagged NEW yet)' if FIRST_RUN else ''}\n  │ This machine : http://127.0.0.1:{port}/?code={CODE}")
    if C.HOST != "127.0.0.1": print(f"  │ On your WiFi : http://{lan}:{port}/      access code: {CODE}")
    print(f"  └─ Recorded Future: {'ON' if RF.get('token') else 'off (set RF token in config.py)'}   ·   plain HTTP: keep it on a trusted network\n")
    if C.OPEN_BROWSER:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{port}/?code={CODE}")).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")

LOGIN = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Secdash</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;color:#d8e0f0;font:16px system-ui,sans-serif;
background:radial-gradient(900px 500px at 75% -10%,#1b2a6b66,transparent),radial-gradient(700px 500px at 0% 100%,#0b4a5a55,transparent),#070a12}
form{width:min(360px,90vw);background:#0e1422cc;border:1px solid #1d2740;border-radius:14px;padding:28px;box-shadow:0 0 60px #38e1ff14}
h1{margin:0 0 4px;font-size:22px;letter-spacing:.18em;background:linear-gradient(90deg,#38e1ff,#9b7bff);-webkit-background-clip:text;background-clip:text;color:transparent}
p{margin:0 0 18px;color:#7d8aa6;font-size:14px}
input{width:100%;font:600 24px ui-monospace,Menlo,Consolas,monospace;letter-spacing:.4em;text-align:center;text-transform:uppercase;padding:12px;border-radius:8px;border:1px solid #26335a;background:#070a12;color:#38e1ff}
input:focus{outline:2px solid #38e1ff;outline-offset:1px}
button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:8px;font:600 15px system-ui;color:#04101a;background:linear-gradient(90deg,#38e1ff,#9b7bff);cursor:pointer}
.e{color:#ff4d6a;min-height:20px;margin-top:10px;font-size:14px;text-align:center}</style></head><body>
<form method="post" action="/login"><h1>SECDASH</h1><p>Enter the access code shown in the terminal.</p>
<input name="code" maxlength="32" autocomplete="off" autofocus aria-label="Access code"><button>Unlock</button><div class="e">__MSG__</div></form></body></html>"""

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Secdash</title><style>
:root{color-scheme:dark;--bg:#070a12;--p:#0d1321;--p2:#111a2e;--bd:#1c2640;--fg:#d8e0f0;--mut:#7d8aa6;--cy:#38e1ff;--vi:#9b7bff;--red:#ff4d6a;--org:#ff9a3c;--yel:#f5c542;--grn:#3ddc97;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;color:var(--fg);font:14.5px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh;
background:radial-gradient(1100px 600px at 85% -10%,#1a2a6c55,transparent),radial-gradient(900px 500px at -10% 5%,#0b4a5a44,transparent),linear-gradient(#ffffff05 1px,transparent 1px) 0 0/100% 34px,var(--bg)}
a{color:var(--fg);text-decoration:none}a:hover{color:var(--cy)}:focus-visible{outline:2px solid var(--cy);outline-offset:2px}
header{position:sticky;top:0;z-index:5;display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 18px;background:#070a12e6;backdrop-filter:blur(8px);border-bottom:1px solid var(--bd)}
.logo{font-weight:800;letter-spacing:.2em;font-size:17px;background:linear-gradient(90deg,var(--cy),var(--vi));-webkit-background-clip:text;background-clip:text;color:transparent}
.live{font:600 12px var(--mono);color:var(--grn);display:flex;align-items:center;gap:7px;white-space:nowrap}
.live i{width:8px;height:8px;border-radius:50%;background:var(--grn);box-shadow:0 0 10px var(--grn);animation:p 1.6s infinite}.live.off{color:var(--red)}.live.off i{background:var(--red);box-shadow:0 0 10px var(--red);animation:none}
@keyframes p{50%{opacity:.25}}@media(prefers-reduced-motion:reduce){.live i{animation:none}}
.sp{flex:1}
input[type=search]{flex:1 1 220px;max-width:420px;font:inherit;padding:7px 12px;border-radius:8px;border:1px solid var(--bd);background:var(--p);color:var(--fg)}
button{font:inherit;color:var(--fg);background:var(--p);border:1px solid var(--bd);border-radius:8px;padding:6px 12px;cursor:pointer}
button:hover{border-color:var(--cy)}button.on{background:linear-gradient(90deg,#38e1ff33,#9b7bff33);border-color:var(--cy);color:#fff}
main{max-width:1400px;margin:0 auto;padding:16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.tile{background:var(--p);border:1px solid var(--bd);border-radius:10px;padding:10px 14px;position:relative;overflow:hidden}
.tile:before{content:"";position:absolute;inset:0 0 auto 0;height:2px;background:linear-gradient(90deg,var(--cy),var(--vi))}
.tile b{display:block;font:700 26px var(--mono)}.tile span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.hot{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}.hot h3{margin:0;font:700 12px var(--mono);color:var(--org);letter-spacing:.1em}
.hot a{cursor:pointer;font:600 12.5px var(--mono);padding:4px 9px;border-radius:999px;border:1px solid #ff9a3c55;background:#ff9a3c14}.hot a:hover{border-color:var(--org)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}@media(max-width:920px){.grid{grid-template-columns:1fr}}
.pn{background:var(--p);border:1px solid var(--bd);border-radius:12px;min-width:0;display:flex;flex-direction:column}
.ph{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 12px;border-bottom:1px solid var(--bd)}
.ph h2{margin:0 auto 0 0;font:700 12.5px var(--mono);letter-spacing:.14em;color:var(--cy)}
.ph button{font-size:12.5px;padding:4px 10px}
.sc{max-height:72vh;overflow:auto;padding:4px 12px 8px}
.it{padding:10px 0;border-bottom:1px solid #ffffff0d}.it:last-child{border:0}
.tt{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;font-weight:600;overflow-wrap:anywhere}
.ds{color:#aab5cc;margin:3px 0;overflow-wrap:anywhere;font-size:13.5px}
.mt{display:flex;gap:6px 10px;flex-wrap:wrap;align-items:center;color:var(--mut);font-size:12px}
.b,.k{font:700 10.5px var(--mono);padding:1px 6px;border-radius:4px;letter-spacing:.04em;white-space:nowrap}
.b{background:#ffffff14;color:var(--fg)}.b.new{background:var(--cy);color:#04101a}.b.mine{background:var(--yel);color:#1a1300}.b.red{background:var(--red);color:#fff}.b.arm{background:#ff9a3c26;color:var(--org);border:1px solid #ff9a3c66}
.k.itw{background:#ff4d6a26;color:var(--red)}.k.public{background:#ff9a3c26;color:var(--org)}.k.poc{background:#9b7bff26;color:var(--vi)}
.k.rising{background:#3ddc9726;color:var(--grn)}.k.trending{background:#38e1ff26;color:var(--cy)}.k.active{background:#9b7bff26;color:var(--vi)}.k.alert{background:#f5c54226;color:var(--yel)}.k.vuln{background:#ff4d6a26;color:var(--red)}
.up{color:var(--grn);font-weight:600}.cv{cursor:pointer;color:var(--cy);font-family:var(--mono)}.cv:hover{text-decoration:underline}
.warn{margin:8px 0 2px;padding:8px 10px;border-radius:8px;background:#9b7bff1a;border:1px solid #9b7bff55;color:#cbbcff;font-size:12.5px}
.score{flex:0 0 46px;height:46px;border-radius:8px;display:grid;place-items:center;font:700 17px var(--mono);color:#fff}
.rf{display:flex;gap:12px;align-items:flex-start}
.chips{display:flex;gap:6px;flex-wrap:wrap;padding:8px 12px 0}.chips button{font-size:12px;padding:2px 9px;border-radius:999px}
.empty{padding:28px;text-align:center;color:var(--mut)}.more{width:100%;margin:8px 0}
footer{color:var(--mut);font:12px var(--mono);line-height:1.9;margin-top:6px}footer span{display:inline-block;margin-right:14px}.g{color:var(--grn)}.r{color:var(--red)}
.tri{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:6px}.tri select,.tri button{font:inherit;font-size:11.5px;padding:2px 6px;border-radius:6px;background:var(--p2);color:var(--fg);border:1px solid var(--bd)}
.tri .st-Escalated{border-color:var(--red)}.tri .st-Investigating{border-color:var(--yel)}.tri .st-Mitigated{border-color:var(--grn)}
.tn{margin-top:4px;color:#cdd6ea;font-size:12.5px;background:#ffffff0a;border-left:2px solid var(--cy);padding:3px 8px;border-radius:0 6px 6px 0;overflow-wrap:anywhere}
.dim{opacity:.45}.pin{border-left:2px solid var(--yel);padding-left:8px}.b.pr{background:#38e1ff22;color:var(--cy)}.q{font:12px var(--mono);color:var(--mut)}.q.low{color:var(--org)}
#dlg{position:fixed;inset:0;background:#000b;display:none;place-items:center;z-index:20}#dlg.open{display:grid}
#dlg>div{width:min(760px,94vw);background:var(--p);border:1px solid var(--bd);border-radius:12px;padding:14px;display:flex;flex-direction:column;gap:10px}
#dlg textarea{width:100%;height:50vh;background:#070a12;color:var(--fg);border:1px solid var(--bd);border-radius:8px;padding:10px;font:12.5px var(--mono)}
.dr{display:flex;gap:8px;flex-wrap:wrap;align-items:center}a.btn{font:inherit;color:var(--fg);background:var(--p);border:1px solid var(--bd);border-radius:8px;padding:6px 12px}a.btn:hover{border-color:var(--cy)}
</style></head><body>
<header><span class="logo">SECDASH</span><span class="live" id="live"><i></i><span id="lt">CONNECTING</span></span><span class="sp"></span>
<input type="search" id="q" placeholder="Filter everything: CVE, vendor, tool…" aria-label="Filter"><span class="q" id="ghq"></span><button id="sort" title="Sort exploits and news">Sort: Newest</button><button id="mine">My stack</button><button id="brief">Brief</button><button id="rf">↻ Refresh all</button></header>
<main><div class="tiles" id="tiles"></div><div class="hot" id="hot"></div><div id="rfp"></div>
<div class="grid"><section class="pn"><div class="ph"><h2>EXPLOITS</h2><span id="t-ex"></span></div><div id="w-ex"></div><div class="sc" id="l-ex"></div></section>
<section class="pn"><div class="ph"><h2>GITHUB REPOS</h2><span id="t-repo"></span></div><div class="sc" id="l-repo"></div></section></div>
<section class="pn"><div class="ph"><h2>NEWS</h2></div><div class="chips" id="c-news"></div><div class="sc" id="l-news"></div></section>
<footer id="foot"></footer></main>
<div id="dlg"><div><div class="dr"><b style="margin-right:auto">Threat brief</b><button id="cmd">Copy Markdown</button><button id="csl">Copy for Slack</button><a class="btn" href="/api/export?fmt=csv&dl=1" download>CSV</a><a class="btn" href="/api/export?fmt=json&dl=1" download>JSON</a><a class="btn" href="/api/export?fmt=md&dl=1" download>.md</a><button id="cls">Close</button></div><textarea id="bt" readonly aria-label="Brief text"></textarea></div></div>
<script nonce="__N__">
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safe=u=>/^https?:\/\//i.test(u)?u:"#";
const ago=t=>{const s=Math.max(0,Date.now()/1e3-t);return s<90?"just now":s<5400?Math.round(s/60)+"m ago":s<172800?Math.round(s/3600)+"h ago":Math.round(s/86400)+"d ago"};
const fmt=n=>n>=1e3?(n/1e3).toFixed(n>=1e4?0:1)+"k":String(n);
const b=(c,t)=>`<span class="b ${c}">${esc(t)}</span>`;
let ST=null,V=0,Q="",MINE=false,SRC="all",MAXN=60,LAST=0,SORT="new";
const FL={KEV:"KEV",MSF:"METASPLOIT",EDB:"EXPLOIT-DB",NUC:"NUCLEI"};
const TAB={ex:"itw",repo:"rising"};
const TABS={ex:[["itw","In the wild"],["public","Public exploits"],["poc","GitHub PoCs"]],repo:[["rising","Rising"],["trending","Trending"],["active","Active"]]};
const KL={itw:"EXPLOITED",public:"EXPLOIT",poc:"PoC"};
const ok=i=>(!Q||i.q.includes(Q))&&(!MINE||i.mine);
const chips=i=>i.cves.slice(0,3).map(c=>`<a class="cv" data-q="${esc(c)}">${esc(c)}</a>`).join(" ");
const link=i=>`<a href="${esc(safe(i.url))}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a>`;
const pr=i=>i.p?b("pr","P"+i.p):"";
const common=i=>(i.new?b("new","NEW"):"")+(i.mine?b("mine","MY STACK"):"")+pr(i);
const TR=i=>ST.triage[i.tk]||{};
const cls=i=>"it"+(TR(i).pinned?" pin":"")+(["Ignored","Mitigated"].includes(TR(i).status)?" dim":"");
const tri=i=>{const t=TR(i),s=t.status||"New";return `<div class="tri"><select data-tri="${esc(i.tk)}" class="st-${esc(s)}" aria-label="Triage status">${ST.statuses.map(x=>`<option${x==s?" selected":""}>${esc(x)}</option>`).join("")}</select><button data-pin="${esc(i.tk)}" title="Pin to top">${t.pinned?"📌 Pinned":"📌"}</button><button data-note="${esc(i.tk)}">✎ Note</button>${t.owner?`<span class="mt">${esc(t.owner)} · ${ago(t.ts)}</span>`:""}</div>${t.note?`<div class="tn">${esc(t.note)}</div>`:""}`};
const w=fn=>i=>fn(i).replace('<div class="it">',`<div class="${cls(i)}">`).replace(/<\/div>$/,tri(i)+"</div>");

const exRow0=i=>`<div class="it"><div class="tt"><span class="k ${i.kind}">${KL[i.kind]}</span>${link(i)}</div>${i.desc?`<div class="ds">${esc(i.desc)}</div>`:""}
<div class="mt">${common(i)}${i.m.ransom?b("red","RANSOMWARE"):""}${i.flags.filter(f=>!(i.kind=="itw"&&f=="KEV")).map(f=>b("arm",FL[f]||f)).join("")}${i.m.epss!=null?`<span>EPSS ${i.m.epss}%</span>`:""}${i.m.due?`<span>patch by ${esc(i.m.due)}</span>`:""}${i.m.verified?"<span>verified</span>":""}<span>${esc(i.src)}</span><span>${ago(i.ts)}</span>${chips(i)}</div></div>`;
const repoRow0=i=>{const m=i.m;return `<div class="it"><div class="tt">${link(i)}${m.kinds.map(k=>`<span class="k ${k}">${k}</span>`).join("")}</div>${i.desc?`<div class="ds">${esc(i.desc)}</div>`:""}
<div class="mt">${common(i)}<span>★ ${fmt(m.stars||0)}</span>${m.gained>0?`<span class="up">▲ +${fmt(m.gained)} since last run</span>`:""}${m.today?`<span class="up">+${fmt(m.today)} ${esc(m.window)}</span>`:""}${m.per_day?`<span>${m.per_day}/day</span>`:""}${m.lang?`<span>${esc(m.lang)}</span>`:""}${m.created?`<span>created ${ago(m.created)}</span>`:""}</div></div>`};
const newsRow0=i=>`<div class="it"><div class="tt">${link(i)}</div>${i.desc?`<div class="ds">${esc(i.desc)}</div>`:""}<div class="mt">${common(i)}<span>${esc(i.src)}</span><span>${ago(i.ts)}</span>${i.flags.map(f=>b("arm",FL[f]||f)).join("")}${chips(i)}</div></div>`;
const exRow=w(exRow0),repoRow=w(repoRow0),newsRow=w(newsRow0);
const heat=s=>s>=85?"var(--red)":s>=65?"var(--org)":s>=40?"#a8861a":"#2a3a58";
const rfRow=i=>i.kind=="vuln"?`<div class="it rf"><div class="score" style="background:${heat(i.m.score)}">${i.m.score}</div><div><div class="tt">${link(i)}<span class="k vuln">${esc(i.m.label||"vuln")}</span></div>${i.m.rules.map(r=>`<div class="ds">• ${esc(r)}</div>`).join("")}<div class="mt"><span>seen ${ago(i.ts)}</span></div></div></div>`
 :`<div class="it"><div class="tt"><span class="k alert">ALERT</span>${link(i)}</div><div class="mt"><span>${esc(i.desc)}</span>${i.m.status?`<span>${esc(i.m.status)}</span>`:""}<span>${ago(i.ts)}</span></div></div>`;

const srt=l=>[...l].sort((a,c)=>((TR(c).pinned?1:0)-(TR(a).pinned?1:0))||(SORT=='pri'?(c.p||0)-(a.p||0):0)||c.ts-a.ts);
function prep(){for(const l of [ST.news,ST.exploits,ST.repos,ST.rf.vulns,ST.rf.alerts])for(const i of l)i.q=(i.title+" "+i.desc+" "+i.cves.join(" ")+" "+i.src).toLowerCase()}
function list(id,rows,fn,empty){const e=$("#l-"+id);e.innerHTML=rows.length?rows.map(fn).join(""):`<div class="empty">${empty}</div>`}
function tabs(g){$("#t-"+g).innerHTML=TABS[g].map(([k,n])=>{const c=g=="ex"?ST.exploits.filter(i=>i.kind==k&&ok(i)).length:ST.repos.filter(i=>i.m.kinds.includes(k)&&ok(i)).length;return `<button data-tab="${g}:${k}" class="${TAB[g]==k?"on":""}">${n} · ${c}</button>`}).join(" ")}

function render(){
  const s=ST,all=[...s.news,...s.exploits,...s.repos];
  const IC={green:"var(--grn)",yellow:"var(--yel)",orange:"var(--org)",red:"var(--red)"};
  $("#tiles").innerHTML=[["INFOCON",s.infocon,IC[s.infocon]],["New this run",all.filter(i=>i.new).length],["Exploited ITW",s.exploits.filter(i=>i.kind=="itw").length],
   ["Public exploits",s.exploits.filter(i=>i.kind=="public").length],["Fresh PoCs",s.exploits.filter(i=>i.kind=="poc").length],["My stack hits",all.filter(i=>i.mine).length],["Escalated",Object.values(s.triage).filter(t=>t.status=="Escalated").length]]
   .map(([l,v,c])=>`<div class="tile"><b style="${c?"color:"+c:""}">${esc(v)}</b><span>${l}</span></div>`).join("");
  $("#hot").innerHTML=s.hot.length?`<h3>HOT CVEs</h3>`+s.hot.map(h=>`<a data-q="${esc(h.cve)}" title="${esc(h.t)}">${esc(h.cve)} ·${h.n}${h.kev?" KEV":""}${h.msf?" MSF":""}${h.nuc?" NUC":""}</a>`).join(""):"";
  const g=s.gh,gq=$("#ghq");gq.textContent=g&&g.limit?`GitHub API ${g.remaining}/${g.limit}`:"";gq.className="q"+(g&&g.limit&&g.remaining<=2?" low":"");
  tabs("ex");tabs("repo");
  const exw=$("#w-ex");exw.innerHTML=TAB.ex=="poc"?`<div class="warn" style="margin:8px 12px 0">⚠ Unvetted code. Fake PoCs on GitHub often carry malware. Read first, run only in an isolated lab.</div>`:"";
  list("ex",srt(s.exploits.filter(i=>i.kind==TAB.ex&&ok(i))),exRow,"Nothing yet for this view.");
  const rk={rising:i=>i.m.per_day||0,trending:i=>i.m.today||0,active:i=>(i.m.gained||0)*1e6+(i.m.stars||0)}[TAB.repo];
  list("repo",s.repos.filter(i=>i.m.kinds.includes(TAB.repo)&&ok(i)).sort((a,c)=>rk(c)-rk(a)),repoRow,"Nothing yet for this view.");
  const cnt={};s.news.forEach(i=>cnt[i.src]=(cnt[i.src]||0)+1);
  $("#c-news").innerHTML=[["all","All"],...Object.entries(cnt).sort((a,c)=>c[1]-a[1]).slice(0,10).map(([k,v])=>[k,k+" "+v])].map(([k,n])=>`<button data-src="${esc(k)}" class="${SRC==k?"on":""}">${esc(n)}</button>`).join("");
  const nr=srt(s.news.filter(i=>ok(i)&&(SRC=="all"||i.src==SRC)));
  list("news",nr.slice(0,MAXN),newsRow,"No matching articles.");
  if(nr.length>MAXN)$("#l-news").insertAdjacentHTML("beforeend",`<button class="more" data-more="1">Show more (${nr.length-MAXN})</button>`);
  $("#rfp").innerHTML=s.rf_on?`<div class="grid"><section class="pn"><div class="ph"><h2>RECORDED FUTURE · VULNERABILITIES</h2></div><div class="sc" id="rv"></div></section><section class="pn"><div class="ph"><h2>RECORDED FUTURE · ALERTS</h2></div><div class="sc" id="ra"></div></section></div>`:"";
  if(s.rf_on){const f=(id,rows)=>$(id).innerHTML=rows.length?rows.filter(ok).map(rfRow).join(""):'<div class="empty">No data (see source status below).</div>';f("#rv",s.rf.vulns);f("#ra",s.rf.alerts)}
  $("#foot").innerHTML=Object.entries(s.status).map(([k,v])=>`<span class="${v.ok?"g":"r"}" title="${esc(v.msg)}">${v.ok?"●":"✕"} ${esc(k)}: ${esc(v.msg)}</span>`).join("");
}
function live(){const e=$("#live"),off=Date.now()-LAST>60000;e.className="live"+(off?" off":"");$("#lt").textContent=off?"OFFLINE":"LIVE · "+(ST?"updated "+ago(ST.now):"loading")}
async function pull(){try{const r=await fetch("/api/state?v="+V,{cache:"no-store"});if(r.status==401){location.reload();return}
  const j=await r.json();LAST=Date.now();if(!j.same){ST=j;V=j.v;prep();render()}}catch(e){}live()}
const who=()=>{let n="";try{n=localStorage.getItem("sd_name")||""}catch(e){}if(!n){n=(prompt("Your name (shown next to your triage actions):","")||"").trim().slice(0,40);try{localStorage.setItem("sd_name",n)}catch(e){}}return n};
async function tpost(o){o.owner=who();await fetch("/api/triage",{method:"POST",headers:{"X-Requested-With":"secdash","Content-Type":"application/json"},body:JSON.stringify(o)});V=0;pull()}
document.addEventListener("change",e=>{const k=e.target.dataset&&e.target.dataset.tri;if(k)tpost({key:k,status:e.target.value})});
document.addEventListener("click",e=>{const t=e.target.closest("[data-tab],[data-q],[data-src],[data-more],[data-pin],[data-note]");if(!t||!ST)return;
  if(t.dataset.pin){tpost({key:t.dataset.pin,pinned:!(ST.triage[t.dataset.pin]||{}).pinned});return}
  if(t.dataset.note){const n=prompt("Team note (visible to everyone):",(ST.triage[t.dataset.note]||{}).note||"");if(n!==null)tpost({key:t.dataset.note,note:n});return}
  if(t.dataset.tab){const[g,k]=t.dataset.tab.split(":");TAB[g]=k}
  if(t.dataset.q){Q=t.dataset.q.toLowerCase();$("#q").value=t.dataset.q}
  if(t.dataset.src){SRC=t.dataset.src;MAXN=60}if(t.dataset.more)MAXN+=100;render()});
$("#q").oninput=e=>{Q=e.target.value.trim().toLowerCase();MAXN=60;if(ST)render()};
$("#mine").onclick=e=>{MINE=!MINE;e.target.classList.toggle("on",MINE);if(ST)render()};
$("#rf").onclick=async()=>{await fetch("/api/refresh",{method:"POST",headers:{"X-Requested-With":"secdash"}});let n=0;const t=setInterval(()=>{pull();if(++n>20)clearInterval(t)},3000)};
$("#sort").onclick=e=>{SORT=SORT=="new"?"pri":"new";e.target.textContent="Sort: "+(SORT=="new"?"Newest":"Priority");if(ST)render()};
const show=async f=>{$("#bt").value=await(await fetch("/api/export?fmt="+f)).text();$("#dlg").classList.add("open")};
const copy=()=>{const t=$("#bt");t.select();try{if(window.isSecureContext&&navigator.clipboard)navigator.clipboard.writeText(t.value);else document.execCommand("copy")}catch(e){}};
$("#brief").onclick=()=>show("md");$("#cmd").onclick=async()=>{await show("md");copy()};$("#csl").onclick=async()=>{await show("slack");copy()};$("#cls").onclick=()=>$("#dlg").classList.remove("open");
pull();setInterval(pull,10000);setInterval(live,5000);
</script></body></html>"""

if __name__ == "__main__":
    main()
