#!/usr/bin/env python3
"""Secdash: one script. Starts every collector in the background, serves the dashboard on a random port
reachable on your WiFi behind an access code. Standard library only.   Usage: python run.py"""
import atexit, csv, ipaddress, ssl, hashlib, html, io, json, os, random, re, secrets, socket, sys, threading, time, webbrowser
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
ITEMS, STATUS = {}, {}   # per-source items, per-source health
KEV_IDS, MSF_IDS, EDB_IDS, NUC_IDS, SIG_IDS = set(), set(), set(), set(), set()
STATE = {"v": 0, "data": b"{}", "obj": None}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SEC_RE = re.compile(r"secur|vuln|exploit|pentest|red.?team|malware|ransom|\bcve|forensic|dfir|osint|phish|fuzz|reverse.?eng|"
                    r"\bc2\b|offensive|hack|threat|\bctf\b|burp|nmap|decompil|obfuscat|payload|shellcode|\bedr\b|siem|recon|"
                    r"credential|jailbreak|prompt.?inject|pwn|infosec|cyber|bypass|rootkit|backdoor|stealer", re.I)
TOKEN = C.GITHUB_TOKEN
RF = C.RECORDED_FUTURE
GH_SLEEP = 2.2 if TOKEN else 6.5
TLS = getattr(C, "TLS", None) or {}               # HTTPS for the dashboard itself: {"cert": "...pem", "key": "...key", "password": "", "hostname": ""}
VERIFY_SSL = getattr(C, "VERIFY_SSL", True)       # verify certificates on outgoing requests (feeds, GitHub, APIs)
CA_BUNDLE = getattr(C, "CA_BUNDLE", "")           # extra root CA (.pem), e.g. your company / Citrix proxy that re-signs HTTPS

def make_ctx():
    ctx = ssl.create_default_context()
    if not VERIFY_SSL:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    elif CA_BUNDLE:
        ctx.load_verify_locations(cafile=CA_BUNDLE)   # adds to the system trust store
    return ctx
CTX = make_ctx()
TLS_CTX = None

# ───────────── helpers ─────────────
def http(url, headers=None, data=None, timeout=40, cap=40_000_000):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Accept-Encoding": "identity", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
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

def sigma():
    """Which CVEs already have a community Sigma detection rule (SigmaHQ), found from rule file names."""
    global SIG_IDS
    for br in ("master", "main"):
        try:
            tree = json.loads(http(f"https://api.github.com/repos/SigmaHQ/sigma/git/trees/{br}?recursive=1", GH_H)).get("tree", [])
            break
        except urllib.error.HTTPError as e:
            if e.code != 404: raise
    else:
        raise RuntimeError("Sigma repository tree not found")
    ids = {f"CVE-{y}-{n}" for t in tree for y, n in re.findall(r"cve[-_](\d{4})[-_](\d{4,7})", t["path"], re.I)}
    if not ids: raise RuntimeError("no CVE-named Sigma rules found")
    SIG_IDS = ids
    return [], f"{len(ids)} CVEs have a Sigma detection rule"

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
                with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=40, context=CTX) as r:
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

class Skip(Exception):
    """Source not configured (e.g. free API key not set). Shown as 'skipped', not as a failure."""

EPSS, ACT = {}, {"re": None, "map": {}, "by": {}}
GH_H = {"Accept": "application/vnd.github+json", **({"Authorization": "Bearer " + TOKEN} if TOKEN else {})}
JSON_H = {"Content-Type": "application/json"}

def epss():
    with LOCK:
        ids = sorted({c for items in ITEMS.values() for it in items for c in it["cves"]})[:600]
    for i in range(0, len(ids), 100):
        for x in json.loads(http("https://api.first.org/data/v1/epss?cve=" + ",".join(ids[i:i + 100]))).get("data", []):
            EPSS[x["cve"].upper()] = round(float(x["epss"]) * 100, 1)
    return [], f"{len(EPSS)} exploit-probability scores"

def ghsa():
    out, errs = [], []
    for sev in ("critical", "high"):
        try:
            rows = json.loads(http(f"https://api.github.com/advisories?severity={sev}&per_page=25&type=reviewed", GH_H))
        except Exception as e:   # keep the other severity if one call is rate-limited
            errs.append(f"{sev}: {str(e)[:50]}"); continue
        for a in rows:
            pk = ", ".join(sorted({f'{(v.get("package") or {}).get("name", "?")} ({(v.get("package") or {}).get("ecosystem", "")})'
                                   for v in a.get("vulnerabilities", [])}))[:160]
            out.append(mk("exploit", "GitHub Advisory", "adv", f'{a["ghsa_id"]}: {a["summary"]}', a["html_url"], ts(a["published_at"]),
                          f"{sev.upper()} · {pk}", cves_raw=a.get("cve_id") or "", sev=sev))
    if errs and not out:
        raise RuntimeError("; ".join(errs) + (" (set GITHUB_TOKEN to raise the limit)" if not TOKEN else ""))
    out.sort(key=lambda i: -i["ts"])
    return out[:40], f"{len(out)} critical/high advisories" + (f" (partial: {errs[0]})" if errs else "")

def feodo():
    d = json.loads(http("https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
    d = d if isinstance(d, list) else next((v for v in d.values() if isinstance(v, list)), [])
    d.sort(key=lambda x: x.get("first_seen") or x.get("first_seen_utc") or "", reverse=True)
    return [mk("ioc", "Feodo C2", "c2", f'{x["ip_address"]}:{x.get("port", "")}', "", ts(x.get("first_seen") or x.get("first_seen_utc")),
               f'{x.get("malware", "")} · {x.get("country", "")} · {x.get("status", "")}', ioc=x["ip_address"]) for x in d[:100]], f"{len(d)} C2s tracked (newest 100)"

def need_abusech():
    if not C.ABUSECH_KEY:
        raise Skip("set ABUSECH_AUTH_KEY (free at abuse.ch)")

def threatfox():
    need_abusech()
    d = json.loads(http("https://threatfox-api.abuse.ch/api/v1/", {"Auth-Key": C.ABUSECH_KEY, **JSON_H}, json.dumps({"query": "get_iocs", "days": 1}).encode()))
    if d.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox: {d.get('query_status')}")
    rows = sorted(d["data"], key=lambda x: x.get("first_seen_utc", ""), reverse=True)[:100]
    return [mk("ioc", "ThreatFox", "ioc", x["ioc"], "", ts(x.get("first_seen_utc")),
               f'{x.get("malware_printable", "")} · {x.get("ioc_type", "")} · confidence {x.get("confidence_level", "?")}%', ioc=x["ioc"]) for x in rows], f"{len(rows)} IOCs (24h)"

def urlhaus():
    need_abusech()
    d = json.loads(http("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/", {"Auth-Key": C.ABUSECH_KEY}))
    if d.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus: {d.get('query_status')}")
    return [mk("ioc", "URLhaus", "url", re.sub(r"^http", "hxxp", x["url"]), "", ts(x.get("date_added")),   # defanged, never a live link
               f'{x.get("threat", "")} · {", ".join(x.get("tags") or [])} · {x.get("url_status", "")}', ioc=x["url"]) for x in d["urls"]], f"{len(d['urls'])} malware URLs"

def ransomware():
    if not C.RANSOMWARE_KEY:
        raise Skip("set RANSOMWARE_LIVE_API_KEY (free at ransomware.live)")
    d = json.loads(http("https://api-pro.ransomware.live/victims/recent", {"X-API-KEY": C.RANSOMWARE_KEY, "Accept": "application/json"}))
    d = d if isinstance(d, list) else next((v for v in d.values() if isinstance(v, list)), [])
    out = []
    for v in d[:150]:
        name = v.get("victim") or v.get("post_title") or v.get("name") or "?"
        grp, when = v.get("group") or v.get("group_name") or "?", v.get("discovered") or v.get("attackdate") or ""
        out.append(mk("ransom", "ransomware.live", "ransom", f"{name}", "", ts(when), f'{grp} · {v.get("country") or "?"} · {v.get("activity") or v.get("sector") or "?"}', grp=grp))
    return out, f"{len(out)} recent victims"

def breaches():
    d = json.loads(http("https://haveibeenpwned.com/api/v3/breaches"))
    d.sort(key=lambda b: b.get("AddedDate", ""), reverse=True)
    return [mk("breach", "HIBP", "breach", b["Title"] + (f' ({b["Domain"]})' if b.get("Domain") else ""),
               f'https://haveibeenpwned.com/PwnedWebsites#{b["Name"]}', ts(b.get("AddedDate")),
               f'{b.get("PwnCount", 0):,} accounts · ' + ", ".join(b.get("DataClasses", [])[:5])) for b in d[:40]], f"{len(d)} breaches on record"

def osv():
    if not C.PACKAGES:
        raise Skip("add PACKAGES in config.py")
    out = []
    for p in C.PACKAGES:
        d = json.loads(http("https://api.osv.dev/v1/query", JSON_H, json.dumps(
            {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": str(p["version"])}).encode()))
        for v in d.get("vulns", []):
            out.append(mk("dep", "OSV", "dep", f'{p["name"]} {p["version"]}: {v["id"]}', "https://osv.dev/vulnerability/" + v["id"],
                          ts(v.get("published") or v.get("modified")), v.get("summary") or v.get("details", ""), cves_raw=" ".join(v.get("aliases", []))))
    return out, f"{len(out)} known vulns across {len(C.PACKAGES)} packages"

ACTOR_STOP = {"Silence", "Equation", "Dragonfly", "Inception", "Strider", "Machete", "Patchwork", "Poseidon", "Moonlight", "Rocke", "Windshift", "Sowbug", "Suckfly"}

def actors():
    """Named threat groups (MITRE ATT&CK via MISP galaxy) mentioned in the news."""
    names = {}
    for v in json.loads(http("https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-intrusion-set.json"))["values"]:
        base, meta = v["value"].rsplit(" - ", 1)[0], v.get("meta", {})
        url = "https://attack.mitre.org/groups/" + meta.get("external_id", "")
        ACT["by"][base] = url
        for n in {base, *meta.get("synonyms", [])}:
            n = n.strip()
            if n not in ACTOR_STOP and (" " in n or re.search(r"\d", n) or len(n) >= 6):   # skip short/ambiguous names
                names[n] = (base, url)
    ACT["map"] = names
    ACT["re"] = re.compile(r"(?<![\w-])(" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True)) + r")(?![\w-])")
    return [], f"{len(names)} actor names tracked"

LOOKUPS = {}

def lookup(ip):
    out = {"ip": ip}
    for name, url, h in (("shodan_internetdb", f"https://internetdb.shodan.io/{ip}", {}),
                         ("greynoise_community", f"https://api.greynoise.io/v3/community/{ip}", {"key": C.GREYNOISE_KEY} if C.GREYNOISE_KEY else {})):
        try:
            out[name] = json.loads(http(url, h, timeout=15))
        except urllib.error.HTTPError as e:
            try: out[name] = json.loads(e.read())
            except Exception: out[name] = {"error": f"HTTP {e.code}"}
        except Exception as e:
            out[name] = {"error": str(e)[:80]}
    with LOCK:
        out["seen_in_local_feeds"] = [f'{it["title"]} ({it["src"]})' for items in ITEMS.values() for it in items
                                      if it["sec"] == "ioc" and it["m"].get("ioc", "").split(":")[0] == ip][:10]
    return out

def notify(items):
    url = C.ALERTS.get("webhook")
    for it in items:
        txt = f'🚨 {it["title"]} [{", ".join(it["flags"] + (["MY STACK"] if it["mine"] else []))}] P{it["p"]} {it["url"]}'
        try:
            http(url, JSON_H, json.dumps({"text": txt, "content": txt}).encode(), timeout=10)   # Slack/Teams use "text", Discord "content"
        except Exception as e:
            print(f"  [alert failed] {e}")

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

# (group, name, function, minimum minutes between runs of heavy sources)
SOURCES = [("news", "News feeds", feeds, 0), ("news", "Hacker News", hn, 0),
           ("exploits", "CISA KEV", kev, 0), ("exploits", "Exploit-DB", edb, 120), ("exploits", "Metasploit", msf, 120),
           ("exploits", "Nuclei templates", nuclei, 360), ("exploits", "Sigma rules", sigma, 360), ("exploits", "Packet Storm", packet, 0), ("exploits", "GitHub PoCs", ghpoc, 0), ("exploits", "GitHub advisories", ghsa, 0), ("exploits", "EPSS scores", epss, 0),
           ("github", "GitHub rising", rising, 0), ("github", "GitHub trending", trending, 0), ("github", "GitHub active", active, 0),
           ("threats", "Feodo C2", feodo, 0), ("threats", "ThreatFox", threatfox, 0), ("threats", "URLhaus", urlhaus, 0),
           ("threats", "Ransomware victims", ransomware, 0), ("threats", "Breaches (HIBP)", breaches, 60),
           ("intel", "Threat actors (MITRE)", actors, 1440), ("intel", "My dependencies (OSV)", osv, 0)]
if RF.get("token"):
    SOURCES += [("rf", "RF vulnerabilities", rf_vulns, 0), ("rf", "RF alerts", rf_alerts, 0)]

# ───────────── state, scoring, publishing ─────────────
FIRST_RUN, PREV_SEEN, PREV_STARS, FIRST_STARS, SEEN, TRIAGE, DIRTY, ALERTED = True, set(), {}, {}, {}, {}, [False], set()
try:
    _s = json.load(open(STATE_FILE))
    FIRST_RUN, SEEN, PREV_STARS = False, _s.get("seen", {}), _s.get("stars", {})
    FIRST_STARS, TRIAGE, ALERTED = _s.get("first_stars", {}), _s.get("triage", {}), set(_s.get("alerted", []))
    PREV_SEEN = set(SEEN)
except Exception:
    pass
CUR_STARS, RUN_START = {}, int(time.time())

def save_state():
    with LOCK:
        cut = time.time() - 45 * 86400
        d = {"seen": {k: v for k, v in SEEN.items() if v > cut}, "stars": CUR_STARS or PREV_STARS,
             "first_stars": FIRST_STARS, "triage": TRIAGE, "alerted": list(ALERTED)[-2000:]}
    tmp = STATE_FILE + ".tmp"
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(d, f)
    os.replace(tmp, STATE_FILE)
atexit.register(lambda: DIRTY[0] and save_state())

def priority(it):
    """0-100: exploited > weaponized > fresh PoC > news; corroboration, ransomware, EPSS and YOUR stack push it up."""
    m = it["m"]
    s = {"itw": 50, "public": 30, "poc": 10, "adv": 35, "dep": 40}.get(it["kind"], 5 if it["sec"] == "news" else 0)
    s += 15 * bool(m.get("ransom")) + min(20, (m.get("epss") or 0) * 0.2)
    s += 8 * len([f for f in it["flags"] if not (it["kind"] == "itw" and f == "KEV")])
    s += C.STACK_BOOST * it["mine"] + 5 * it["new"]
    return int(min(100, s))

def publish():
    with LOCK:
        now, news, ex, repos, rfv, rfa = time.time(), [], [], {}, [], []
        oth, acount = {"ioc": [], "ransom": [], "breach": [], "dep": []}, {}
        kw = [k.lower() for k in C.KEYWORDS if len(k) > 2]
        sets = (("KEV", KEV_IDS), ("MSF", MSF_IDS), ("EDB", EDB_IDS), ("NUC", NUC_IDS), ("SIG", SIG_IDS))
        for items in ITEMS.values():
            for it in items:
                if it["id"] not in SEEN:
                    SEEN[it["id"]] = now; DIRTY[0] = True
                it["new"] = (not FIRST_RUN) and it["id"] not in PREV_SEEN
                hay = f'{it["title"]} {it["desc"]}'.lower()
                it["mine"] = any(k in hay for k in kw)
                it["flags"] = [f for f, st in sets if any(c in st for c in it["cves"])]
                it["tk"] = it["cves"][0] if it["cves"] else it["id"]   # team triage is shared per CVE
                if it["cves"] and it["m"].get("epss") is None:
                    e = [EPSS[c] for c in it["cves"] if c in EPSS]
                    if e: it["m"]["epss"] = max(e)
                if it["sec"] == "news":
                    it["actors"] = sorted({ACT["map"][x][0] for x in ACT["re"].findall(f'{it["title"]} {it["desc"]}')}) if ACT["re"] else []
                    for x in it["actors"]: acount[x] = acount.get(x, 0) + 1
                    it["p"] = priority(it); news.append(it)
                elif it["sec"] == "exploit": it["p"] = priority(it); ex.append(it)
                elif it["sec"] in oth: it["p"] = priority(it) if it["sec"] == "dep" else 0; oth[it["sec"]].append(it)
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
        for l in oth.values(): l.sort(key=lambda i: -i["ts"])
        mentions = {}
        for it in news + ex:
            for c in it["cves"]:
                mentions.setdefault(c, {"src": set(), "t": it["title"]})["src"].add(it["src"])
        hot = sorted(({"cve": c, "n": len(v["src"]), "kev": c in KEV_IDS, "msf": c in MSF_IDS, "edb": c in EDB_IDS, "nuc": c in NUC_IDS, "sig": c in SIG_IDS, "t": v["t"]}
                      for c, v in mentions.items() if len(v["src"]) >= 2 or (c in KEV_IDS or c in MSF_IDS)),
                     key=lambda h: (h["kev"], h["n"], h["msf"]), reverse=True)[:14]
        acts = [{"name": a, "n": n, "url": ACT["by"].get(a, "")} for a, n in sorted(acount.items(), key=lambda kv: -kv[1])[:12]]
        payload = {"v": STATE["v"] + 1, "now": int(now), "run_start": RUN_START, "first_run": FIRST_RUN,
                   "rf_on": bool(RF.get("token")), "status": STATUS, "hot": hot, "actors": acts, "news": news[:250], "exploits": ex[:250],
                   "repos": list(repos.values()), "rf": {"vulns": rfv, "alerts": rfa}, "triage": TRIAGE,
                   "ioc": oth["ioc"][:150], "ransom": oth["ransom"][:150], "breach": oth["breach"][:60], "deps": oth["dep"],
                   "statuses": C.TRIAGE_STATUSES, "keywords": C.KEYWORDS, "gh": {k: GH[k] for k in ("remaining", "limit", "reset")}}
        STATE["v"], STATE["data"], STATE["obj"] = payload["v"], json.dumps(payload).encode(), payload
        if C.ALERTS.get("webhook") and not FIRST_RUN:   # push brand-new high-priority items to Slack/Teams/Discord
            fresh = [i for i in ex + oth["dep"] if i["new"] and i["kind"] in ("itw", "public", "adv", "dep")
                     and i["p"] >= C.ALERTS.get("min_priority", 70) and i["id"] not in ALERTED][:10]
            if fresh:
                ALERTED.update(i["id"] for i in fresh); DIRTY[0] = True
                threading.Thread(target=notify, args=(fresh,), daemon=True).start()
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
    out = [B(f"Threat brief {day}") if slack else f"# Threat brief {day}"]
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
        out.extend(["", B("Hot CVEs")] + [("• " if slack else "- ") + f'{h["cve"]} ({h["n"]} sources' + "".join(", " + k.upper() for k in ("kev", "msf", "edb", "nuc", "sig") if h[k]) + ")" for h in P["hot"][:8]])
    rr = sorted((r for r in P["repos"] if "rising" in r["m"]["kinds"]), key=lambda r: -(r["m"].get("per_day") or 0))[:5]
    if rr: out.extend(["", B("Rising security repos")] + [("• " if slack else "- ") + f'{L(r)} ({r["m"].get("stars", 0)}★, {r["m"].get("per_day", 0)}/day)' for r in rr])
    if P.get("actors"): out.extend(["", B("Threat actors in the news")] + [("• " if slack else "- ") + f'{a["name"]} ({a["n"]} articles)' for a in P["actors"][:8]])
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

KICK = {g: threading.Event() for g in {x[0] for x in SOURCES}}
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
            except Skip as e:
                with LOCK:
                    STATUS[name] = {"ok": 2, "msg": str(e), "ts": int(time.time())}
            except Exception as e:
                with LOCK:
                    STATUS[name] = {"ok": 0, "msg": f"{type(e).__name__}: {str(e)[:120]}", "ts": int(time.time())}
            print(f"  [{['FAIL', 'ok  ', 'skip'][STATUS[name]['ok']]}] {name}: {STATUS[name]['msg']}", flush=True)
            publish()
        KICK[group].wait(C.REFRESH_MINUTES.get(group, 30) * 60); KICK[group].clear()

# ───────────── web server ─────────────
CODE = (C.ACCESS_CODE or "".join(secrets.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(6))).upper()
SESSIONS, FAILS = {}, {}

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address): pass   # port scanners / bad TLS handshakes: stay quiet

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def setup(self):
        if TLS_CTX:   # TLS handshake happens here, in the request's own thread (a slow client can't block the server)
            self.request.settimeout(15)
            self.request = TLS_CTX.wrap_socket(self.request, server_side=True)
        super().setup()
    def out(self, code, body, ctype="application/json", extra=()):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        for k, v in (("Content-Type", ctype + "; charset=utf-8"), ("Content-Length", str(len(b))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"), *(("Strict-Transport-Security", "max-age=31536000"),) * bool(TLS_CTX), *extra):
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
            return ("Set-Cookie", f"sd={t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400" + ("; Secure" if TLS_CTX else ""))
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
                             "json": (json.dumps({k: P[k] for k in ("now", "hot", "news", "exploits", "repos", "triage")}, indent=1), "application/json", "json")}.get(f, (None,) * 3)
            if body is None: return self.out(400, "bad fmt", "text/plain")
            return self.out(200, body, ct, [("Content-Disposition", f'attachment; filename="threat-{day}.{ext}"')] if dl else [])
        if u.path == "/api/lookup":
            if not self.authed(): return self.out(401, "{}")
            ip, now = parse_qs(u.query).get("ip", [""])[0].strip(), time.time()
            try:
                assert ipaddress.ip_address(ip).is_global
            except Exception:
                return self.out(400, '{"error":"Enter a valid PUBLIC IP address (private addresses are never sent to third parties)."}')
            LOOKUPS[self.client_address[0]] = [t for t in LOOKUPS.get(self.client_address[0], []) if now - t < 60] + [now]
            if len(LOOKUPS[self.client_address[0]]) > 20: return self.out(429, '{"error":"Slow down: 20 lookups per minute."}')
            return self.out(200, json.dumps(lookup(ip), indent=1))
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

def build_tls():
    global TLS_CTX
    if not TLS.get("cert"): return
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(TLS["cert"], TLS.get("key") or None, TLS.get("password") or None)
    except Exception as e:
        sys.exit(f"\n  ✕ Could not load your TLS certificate ({TLS['cert']}): {e}\n    Check TLS in config.py (cert = PEM file, key = PEM private key).")
    TLS_CTX = ctx

def main():
    build_tls()
    srv = None
    for _ in range(80):
        port = C.PORT or random.randint(*C.PORT_RANGE)
        try:
            srv = Server((C.HOST, port), H); break
        except OSError:
            if C.PORT: sys.exit(f"Port {port} is busy.")
    if not srv: sys.exit("Could not find a free port.")
    for g in {x[0] for x in SOURCES}:
        threading.Thread(target=run_group, args=(g,), daemon=True).start()
    sch, lan = ("https" if TLS_CTX else "http"), lan_ip()
    name = TLS.get("hostname") or lan
    print(f"\n  ┌─ SECDASH ─ live {'(first run: nothing is flagged NEW yet)' if FIRST_RUN else ''}\n  │ This machine : {sch}://127.0.0.1:{port}/?code={CODE}")
    if C.HOST != "127.0.0.1": print(f"  │ On your WiFi : {sch}://{name}:{port}/      access code: {CODE}")
    print(f"  │ Recorded Future: {'ON' if RF.get('token') else 'off (set RF token in config.py)'}")
    print(f"  │ Dashboard TLS  : {'ON (HTTPS)' if TLS_CTX else 'off (plain HTTP: keep it on a trusted network, or set TLS in config.py)'}")
    print(f"  └─ Outgoing TLS  : {'verified' + (' + custom CA' if CA_BUNDLE else '') if VERIFY_SSL else 'NOT VERIFIED (VERIFY_SSL = False)'}\n")
    if C.OPEN_BROWSER:
        threading.Timer(1.5, lambda: webbrowser.open(f"{sch}://127.0.0.1:{port}/?code={CODE}")).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")

LOGIN = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Secdash</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;color:#fff;font:16px system-ui,sans-serif;background:#000}
form{width:min(360px,90vw);background:#070707;border:1px solid #262626;border-radius:14px;padding:28px;box-shadow:0 0 70px #ff7a0018}
h1{margin:0 0 4px;font-size:22px;letter-spacing:.22em;color:#ff7a00;text-shadow:0 0 18px #ff7a0066}
p{margin:0 0 18px;color:#a6a6a6;font-size:14px}
input{width:100%;font:700 24px ui-monospace,Menlo,Consolas,monospace;letter-spacing:.4em;text-align:center;text-transform:uppercase;padding:12px;border-radius:8px;border:1px solid #333;background:#000;color:#ff7a00}
input:focus{outline:2px solid #ff7a00;outline-offset:1px}
button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:8px;font:700 15px system-ui;color:#000;background:#ff7a00;cursor:pointer}button:hover{background:#ffa040}
.e{color:#ff3d2e;min-height:20px;margin-top:10px;font-size:14px;text-align:center}</style></head><body>
<form method="post" action="/login"><h1>◢ SECDASH</h1><p>Enter the access code shown in the terminal.</p>
<input name="code" maxlength="32" autocomplete="off" autofocus aria-label="Access code"><button>Unlock</button><div class="e">__MSG__</div></form></body></html>"""

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Secdash</title><style>
:root{color-scheme:dark;--bg:#000;--p:#060606;--p2:#0c0c0c;--bd:#1f1f1f;--fg:#e6e6e6;--hd:#fff;--mut:#9a9a9a;--or:#ff7a00;--or2:#ffa040;--red:#ff3d2e;--amb:#ffb020;--grn:#35d07f;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:#000;color:var(--fg);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;min-height:100vh;scrollbar-color:#333 #000}
a{color:inherit;text-decoration:none}a:hover{color:var(--or)}:focus-visible{outline:2px solid var(--or);outline-offset:2px}
header{position:sticky;top:0;z-index:5;background:#000;border-bottom:1px solid var(--bd);padding:10px 28px;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center}
.logo{font-weight:900;letter-spacing:.22em;font-size:17px;color:var(--or);text-shadow:0 0 18px #ff7a0066}
nav{display:flex;gap:4px;flex-wrap:wrap}nav button{border:0;background:transparent;color:var(--mut);padding:6px 12px;font-weight:600}nav button:hover{color:#fff}nav button.on{background:var(--or);color:#000}
i{font-style:normal}nav i,.tbs i{font:700 10.5px var(--mono);background:#ffffff24;border-radius:999px;padding:0 6px;margin-left:4px}nav .on i,.tbs .on i{background:#0003}
.live{font:700 12px var(--mono);color:var(--grn);display:flex;align-items:center;gap:7px;white-space:nowrap}
.live:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--grn);box-shadow:0 0 10px var(--grn);animation:p 1.6s infinite}.live.off{color:var(--red)}.live.off:before{background:var(--red);box-shadow:0 0 10px var(--red);animation:none}
@keyframes p{50%{opacity:.25}}
.tools{display:flex;gap:8px;flex:1 1 560px;justify-content:flex-end;flex-wrap:wrap;align-items:center}
input[type=search]{flex:1 1 180px;max-width:360px;font:inherit;padding:7px 12px;border-radius:8px;border:1px solid var(--bd);background:#000;color:#fff}#ipq{flex:0 1 130px}
button{font:inherit;color:#fff;background:#0a0a0a;border:1px solid var(--bd);border-radius:8px;padding:6px 12px;cursor:pointer}button:hover{border-color:var(--or)}
button.on{background:var(--or);border-color:var(--or);color:#000;font-weight:700}
.q{font:12px var(--mono);color:var(--mut)}.q.low{color:var(--red)}.grow{flex:1}
.tick{overflow:hidden;white-space:nowrap;border-bottom:1px solid var(--bd);background:#040404;font-size:12.5px;color:var(--mut)}
.trk{display:inline-flex;gap:38px;padding:7px 0;animation:tk 160s linear infinite}.tick:hover .trk{animation-play-state:paused}
.trk b{font:700 10.5px var(--mono);color:var(--or);margin-right:6px}.trk b.r{color:var(--red)}@keyframes tk{to{transform:translateX(-50%)}}
@media(prefers-reduced-motion:reduce){.trk,.live:before,.b.new,.skel i{animation:none}}
main{max-width:1500px;margin:0 auto;padding:24px 28px}
.pgt{margin:0 0 6px;font-size:26px;font-weight:700;color:var(--hd)}.pgt span{font:600 13px var(--mono);color:var(--mut);margin-left:10px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.tile{background:var(--p);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;position:relative;overflow:hidden;cursor:pointer;transition:.15s}
.tile:hover{border-color:var(--or);box-shadow:0 0 22px #ff7a0026}.tile:before{content:"";position:absolute;inset:0 0 auto 0;height:2px;background:var(--or)}
.tile b{display:block;font:800 26px var(--mono);color:var(--hd)}.tile span{color:var(--mut);font-size:11.5px;text-transform:uppercase;letter-spacing:.09em}
.spk{position:absolute;right:12px;top:14px;width:70px;height:20px}
.hot{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:24px}.hot h3{margin:0 6px 0 0;font:800 12px var(--mono);color:var(--or);letter-spacing:.12em}
.hot a{cursor:pointer;font:600 12.5px var(--mono);padding:4px 10px;border-radius:999px;border:1px solid #ff7a0055;background:#ff7a0010}.hot a:hover{background:var(--or);color:#000}.hot a i{color:var(--or2)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:24px}.grid.home{grid-template-columns:minmax(0,1.3fr) minmax(0,1fr)}@media(max-width:1000px){.grid,.grid.home{grid-template-columns:1fr}}
.pn{background:var(--p);border:1px solid var(--bd);border-radius:14px;display:flex;flex-direction:column;min-width:0;margin-bottom:24px}.grid .pn{margin-bottom:0}
.ph{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:14px 22px;border-bottom:1px solid var(--bd)}
.ph h2{margin:0 auto 0 0;font:800 12.5px var(--mono);letter-spacing:.16em;color:var(--or)}.tbs{display:flex;gap:6px;flex-wrap:wrap}
.tbs button,.chips button{font-size:12.5px;padding:3px 11px;border-radius:999px;color:var(--mut)}.tbs button.on,.chips button.on{color:#000}.chips{display:flex;gap:6px;flex-wrap:wrap;padding:14px 22px 4px}
.sc{max-height:78vh;overflow:auto;padding:4px 22px 18px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(440px,1fr));gap:14px;padding-top:14px}
.cards .it{border:1px solid var(--bd);border-radius:12px;background:var(--p2);padding:16px 18px}
.it{padding:18px 4px 18px 14px;border-bottom:1px solid #161616}.it:last-child{border-bottom:0}
.it.h4{box-shadow:inset 2px 0 0 var(--red)}.it.h3{box-shadow:inset 2px 0 0 var(--or)}
.tt{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;overflow-wrap:anywhere}
.tt a{font-size:16px;line-height:1.4;font-weight:600;color:var(--hd)}.tt a:hover{color:var(--or)}
.ds{color:#bdbdbd;margin:6px 0 10px;overflow-wrap:anywhere;font-size:14px;line-height:1.55;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.cards .ds{-webkit-line-clamp:3}
.mt{display:flex;gap:4px 12px;flex-wrap:wrap;align-items:center;color:var(--mut);font-size:12.5px}.mt .src{color:#cfcfcf;font-weight:600}
.mt.x{margin-top:8px;opacity:0;max-height:0;overflow:hidden;transition:.15s}.it:hover .mt.x,.it:focus-within .mt.x,body.compact .mt.x{opacity:1;max-height:70px}
@media(hover:none){.mt.x{opacity:1;max-height:70px}}
body.compact .it{padding:10px 4px 10px 12px}body.compact .tt a{font-size:14.5px}body.compact .ds{-webkit-line-clamp:1;margin:3px 0 5px;font-size:13px}body.compact main{padding-top:16px}
.b,.k{font:700 10.5px var(--mono);padding:1px 6px;border-radius:4px;letter-spacing:.04em;white-space:nowrap;background:#ffffff1f;color:#fff}
.b.new{background:var(--or);color:#000;animation:gl 2.4s infinite}@keyframes gl{50%{box-shadow:0 0 12px #ff7a00cc}}
.b.mine{background:#fff;color:#000}.b.red{background:var(--red);color:#fff}.b.arm{background:transparent;color:var(--or);border:1px solid var(--or)}.b.pr{color:var(--or2)}
.k.itw,.k.vuln{background:#ff3d2e26;color:var(--red)}.k.public,.k.rising{background:#ff7a0026;color:var(--or)}.k.poc,.k.alert{background:#ffb02026;color:var(--amb)}.k.adv,.k.trending{background:#ffffff1f;color:#fff}.k.active{background:#ffffff12;color:var(--mut)}
.up{color:var(--or2);font-weight:600}.cv{cursor:pointer;color:var(--or);font-family:var(--mono)}.cv:hover{text-decoration:underline}.mono{font-family:var(--mono);font-size:13px}
.warn{margin:12px 22px 0;padding:10px 12px;border-radius:8px;background:#ff7a0014;border:1px solid #ff7a0066;color:var(--or2);font-size:13px}
.score{flex:0 0 46px;height:46px;border-radius:8px;display:grid;place-items:center;font:800 17px var(--mono);color:#fff}.rf{display:flex;gap:12px;align-items:flex-start}
.tri{display:none;gap:6px;align-items:center;flex-wrap:wrap;margin-top:8px}.tri.show,.it:hover .tri,.it:focus-within .tri,.card .tri,.cards .tri{display:flex}@media(hover:none){.tri{display:flex}}
.tri select,.tri button{font:inherit;font-size:11.5px;padding:2px 6px;border-radius:6px;background:#000;color:#fff;border:1px solid var(--bd)}
.tri .st-Escalated{border-color:var(--red)}.tri .st-Investigating{border-color:var(--or)}.tri .st-Mitigated{border-color:var(--grn)}
.tn{margin-top:6px;color:#e6e6e6;font-size:12.5px;background:#ffffff0d;border-left:2px solid var(--or);padding:4px 10px;border-radius:0 6px 6px 0;overflow-wrap:anywhere}
.dim{opacity:.45}.pin{outline:1px solid #ff7a0055;outline-offset:-1px}
.board{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;padding:14px 0}.col{background:var(--p2);border:1px solid var(--bd);border-radius:12px;padding:10px}
.col h3{margin:0 0 10px;font:800 11.5px var(--mono);letter-spacing:.12em;color:var(--or)}.card{background:#000;border:1px solid var(--bd);border-radius:8px;padding:10px 12px;margin-bottom:10px}
.ab{display:grid;grid-template-columns:1fr 1.2fr auto;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid #161616}
.bar{height:8px;background:#1a1a1a;border-radius:4px;overflow:hidden}.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--or),var(--or2))}
.kw{margin-bottom:18px;color:var(--mut);font-size:13px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.empty{padding:30px;text-align:center;color:var(--mut)}.empty.sm{padding:10px;font-size:12.5px}.more{width:100%;margin:12px 0}
.reader{max-width:820px;margin:0 auto}.reader .chips{padding:10px 0 18px}.reader .it{padding:26px 4px}.reader .tt a{font-size:20px;line-height:1.35}
.reader .ds{font-size:15.5px;line-height:1.65;color:#c9c9c9;-webkit-line-clamp:3;margin:8px 0 12px}.reader .mt{font-size:13px}
.day{padding:26px 4px 8px;font:800 12px var(--mono);letter-spacing:.16em;color:var(--or);border-bottom:1px solid var(--bd)}
.gbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}.gbar input{flex:1 1 320px;max-width:520px;font-size:16px;padding:10px 14px}.gbar button{font-size:12.5px;padding:4px 10px}
.gleg{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}.lg{font-size:12px;padding:3px 10px;border-radius:999px;display:inline-flex;gap:6px;align-items:center}.lg.off{opacity:.35}.lg b{color:var(--mut)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.gwrap{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:20px}@media(max-width:1000px){.gwrap{grid-template-columns:1fr}}
.gbox{position:relative;border:1px solid var(--bd);border-radius:14px;overflow:hidden;background:#000}#gc{width:100%;height:680px;display:block;cursor:grab;touch-action:none}@media(max-width:700px){#gc{height:480px}}
.gtip{position:absolute;display:none;pointer-events:none;background:#111;border:1px solid var(--bd);padding:5px 9px;border-radius:6px;font-size:12px;max-width:260px}
.ghint{position:absolute;left:12px;bottom:10px;color:#666;font-size:11.5px;font-family:var(--mono)}
.gside{padding:18px;max-height:680px;overflow:auto;margin-bottom:0}.gside h3{margin:0 0 6px;font-size:16px;color:var(--hd)}.gside h4{margin:16px 0 6px;font:800 11px var(--mono);letter-spacing:.12em;color:var(--or)}
.gi{padding:8px 0;border-bottom:1px solid #161616;font-size:13.5px}
footer{color:var(--mut);font:12px var(--mono);line-height:1.9;margin-top:6px}footer span{display:inline-block;margin-right:14px}.g{color:var(--grn)}.r{color:var(--red)}.sk{color:var(--mut)}
.toast{position:fixed;right:16px;bottom:16px;z-index:30;background:var(--or);color:#000;font-weight:800;padding:10px 16px;border-radius:10px;box-shadow:0 8px 30px #ff7a0066;cursor:pointer;transform:translateY(90px);opacity:0;transition:.3s}.toast.show{transform:none;opacity:1}
.skel i{display:block;height:84px;border-radius:12px;margin-bottom:12px;background:linear-gradient(90deg,#0a0a0a 25%,#1c1c1c 50%,#0a0a0a 75%);background-size:200% 100%;animation:sk 1.2s infinite}@keyframes sk{to{background-position:-200% 0}}
#dlg{position:fixed;inset:0;background:#000c;display:none;place-items:center;z-index:20}#dlg.open{display:grid}
#dlg>div{width:min(760px,94vw);background:var(--p);border:1px solid var(--bd);border-radius:12px;padding:14px;display:flex;flex-direction:column;gap:10px}
#dlg textarea{width:100%;height:50vh;background:#000;color:#fff;border:1px solid var(--bd);border-radius:8px;padding:10px;font:12.5px var(--mono)}
.dr{display:flex;gap:8px;flex-wrap:wrap;align-items:center}a.btn{font:inherit;color:#fff;background:#0a0a0a;border:1px solid var(--bd);border-radius:8px;padding:6px 12px}a.btn:hover{border-color:var(--or);color:var(--or)}
@media(max-width:700px){header{position:static;padding:10px 14px}main{padding:16px 14px}.cards{grid-template-columns:1fr}.sc{padding:4px 14px 14px}nav{flex-wrap:nowrap;overflow-x:auto;max-width:100%}nav button{white-space:nowrap}.tools{flex:1 1 100%;flex-wrap:nowrap;overflow-x:auto;justify-content:flex-start;padding-bottom:4px}.tools>*{flex:0 0 auto}#ipq,#ipgo,#ghq{display:none}input[type=search]{flex:0 0 170px}}
</style></head><body>
<header><span class="logo">◢ SECDASH</span><nav id="nav"></nav><span class="live" id="live"><span id="lt">CONNECTING</span></span>
<div class="tools"><input type="search" id="q" placeholder="Filter everything  ( / )" aria-label="Filter"><input type="search" id="ipq" placeholder="IP lookup" aria-label="IP lookup"><button id="ipgo">Lookup</button>
<span class="q" id="ghq"></span><button id="dens" title="Reading density">Comfortable</button><button id="sort" title="Sort exploits and news">Sort: Newest</button><button id="mine">My stack</button><button id="brief">Brief</button><button id="rf">↻ Refresh</button></div></header>
<div class="tick"><div class="trk" id="trk"></div></div>
<main id="main"><div class="skel"><i></i><i></i><i></i></div></main>
<main style="padding-top:0"><footer id="foot"></footer></main>
<div class="toast" id="toast"></div>
<div id="dlg"><div><div class="dr"><b id="dt" style="margin-right:auto">Threat brief</b><span id="dx" class="dr"><button id="cmd">Copy Markdown</button><button id="csl">Copy for Slack</button><a class="btn" href="/api/export?fmt=csv&dl=1" download>CSV</a><a class="btn" href="/api/export?fmt=json&dl=1" download>JSON</a><a class="btn" href="/api/export?fmt=md&dl=1" download>.md</a></span><button id="cls">Close</button></div><textarea id="bt" readonly aria-label="Output"></textarea></div></div>
<script nonce="__N__">
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safe=u=>/^https?:\/\//i.test(u)?u:"#";
const ago=t=>{const s=Math.max(0,Date.now()/1e3-t);return s<90?"just now":s<5400?Math.round(s/60)+"m ago":s<172800?Math.round(s/3600)+"h ago":Math.round(s/86400)+"d ago"};
const fmt=n=>n>=1e3?(n/1e3).toFixed(n>=1e4?0:1)+"k":String(n);
const b=(c,t)=>`<span class="b ${c}">${esc(t)}</span>`;
let ST=null,V=0,Q="",MINE=false,SRC="all",MAXN=40,LAST=0,SORT="new",PAGE="home",TK="",TT,G=null,GT;const T0=Date.now(),HOMEN=20;
const TAB={ex:"itw",repo:"rising",th:"ioc"};
const TABS={ex:[["itw","In the wild"],["public","Public exploits"],["poc","GitHub PoCs"],["adv","Advisories"]],repo:[["rising","Rising"],["trending","Trending"],["active","Active"]],th:[["ioc","IOCs & C2"],["ransom","Ransomware"],["breach","Breaches"]]};
const KL={itw:"EXPLOITED",public:"EXPLOIT",poc:"PoC",adv:"ADVISORY"},FL={KEV:"KEV",MSF:"METASPLOIT",EDB:"EXPLOIT-DB",NUC:"NUCLEI",SIG:"SIGMA"};
const STP=["home","news","exploits","threats","stack","graph","rf"],NAMES={home:"Home",news:"News",exploits:"Exploits",threats:"Threats",stack:"My Stack",graph:"Graph",rf:"Recorded Future"};
const EMPTY={ioc:"Feodo needs no key. ThreatFox and URLhaus need a free abuse.ch key (config.py).",ransom:"Needs a free ransomware.live key (config.py).",breach:"Waiting for Have I Been Pwned."};
const pagesOf=()=>STP.filter(p=>p!="rf"||ST.rf_on);
const ok=i=>(!Q||i.q.includes(Q))&&(!MINE||i.mine);
const TR=i=>ST.triage[i.tk]||{};
const srt=l=>[...l].sort((a,c)=>((TR(c).pinned?1:0)-(TR(a).pinned?1:0))||(SORT=="pri"?(c.p||0)-(a.p||0):0)||c.ts-a.ts);
const chips=i=>i.cves.slice(0,3).map(c=>`<a class="cv" data-q="${esc(c)}">${esc(c)}</a>`).join(" ");
const link=i=>`<a href="${esc(safe(i.url))}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a>`;
const pr=i=>i.p?b("pr","P"+i.p):"";
const common=i=>(i.new?b("new","NEW"):"")+(i.mine?b("mine","MY STACK"):"")+pr(i);
const keyb=i=>(i.new?b("new","NEW"):"")+(i.mine?b("mine","MY STACK"):"")+(i.flags.includes("KEV")&&i.kind!="itw"?b("red","EXPLOITED"):"");
const hl=p=>p>=75?4:p>=50?3:p>=30?2:1;
const cls=i=>"it"+(i.p?" h"+hl(i.p):"")+(TR(i).pinned?" pin":"")+(["Ignored","Mitigated"].includes(TR(i).status)?" dim":"");
const tri=i=>{const t=TR(i),s=t.status||"New";return `<div class="tri${s!="New"||t.pinned||t.note?" show":""}"><select data-tri="${esc(i.tk)}" class="st-${esc(s)}" aria-label="Triage status">${ST.statuses.map(x=>`<option${x==s?" selected":""}>${esc(x)}</option>`).join("")}</select><button data-pin="${esc(i.tk)}" title="Pin to top">${t.pinned?"📌 Pinned":"📌"}</button><button data-note="${esc(i.tk)}">✎ Note</button>${t.owner?`<span class="mt">${esc(t.owner)} · ${ago(t.ts)}</span>`:""}</div>${t.note?`<div class="tn">${esc(t.note)}</div>`:""}`};
const w=fn=>i=>fn(i).replace('<div class="it">',`<div class="${cls(i)}">`).replace(/<\/div>$/,tri(i)+"</div>");
const flags=i=>i.flags.map(f=>b("arm",FL[f]||f)).join("");
const ds=i=>i.desc?`<div class="ds">${esc(i.desc)}</div>`:"";
const xrow=i=>{const x=pr(i)+flags(i)+chips(i)+(i.actors||[]).map(a=>`<a class="cv" data-q="${esc(a)}">${esc(a)}</a>`).join(" ");return x?`<div class="mt x">${x}</div>`:""};
const exRow=w(i=>`<div class="it"><div class="tt"><span class="k ${i.kind}">${KL[i.kind]}</span>${link(i)}</div>${ds(i)}
<div class="mt">${common(i)}${i.m.ransom?b("red","RANSOMWARE"):""}${i.flags.filter(f=>!(i.kind=="itw"&&f=="KEV")).map(f=>b("arm",FL[f]||f)).join("")}${i.m.epss!=null?`<span>EPSS ${i.m.epss}%</span>`:""}${i.m.due?`<span>patch by ${esc(i.m.due)}</span>`:""}${i.m.verified?"<span>verified</span>":""}<span>${esc(i.src)}</span><span>${ago(i.ts)}</span>${chips(i)}</div></div>`);
const repoRow=w(i=>{const m=i.m;return `<div class="it"><div class="tt">${link(i)}${m.kinds.map(k=>`<span class="k ${k}">${k}</span>`).join("")}</div>${ds(i)}
<div class="mt"><span class="src">★ ${fmt(m.stars||0)}</span>${m.per_day?`<span>${m.per_day}/day</span>`:""}${m.gained>0?`<span class="up">▲ +${fmt(m.gained)} since last run</span>`:""}${m.today?`<span class="up">+${fmt(m.today)} ${esc(m.window)}</span>`:""}${m.lang?`<span>${esc(m.lang)}</span>`:""}${m.created?`<span>created ${ago(m.created)}</span>`:""}${keyb(i)}</div></div>`});
const newsRow=w(i=>`<div class="it"><div class="tt">${link(i)}</div>${ds(i)}<div class="mt"><span class="src">${esc(i.src)}</span><span>${ago(i.ts)}</span>${keyb(i)}</div>${xrow(i)}</div>`);
const depRow=w(i=>`<div class="it"><div class="tt"><span class="k itw">DEP</span>${link(i)}</div>${ds(i)}<div class="mt">${common(i)}${flags(i)}<span>${ago(i.ts)}</span>${chips(i)}</div></div>`);
const iocRow=i=>`<div class="it"><div class="tt"><span class="k itw">${esc(i.kind.toUpperCase())}</span><span class="mono">${esc(i.title)}</span></div>${ds(i)}<div class="mt">${common(i)}<span>${esc(i.src)}</span><span>${ago(i.ts)}</span>${/^\d+\.\d+\.\d+\.\d+/.test(i.title)?`<a class="cv" data-ip="${esc(i.title.split(":")[0])}">lookup</a>`:""}</div></div>`;
const ransomRow=i=>`<div class="it"><div class="tt"><span class="k itw">RANSOM</span>${esc(i.title)}</div><div class="mt">${common(i)}<span>${esc(i.desc)}</span><span>${ago(i.ts)}</span></div></div>`;
const breachRow=i=>`<div class="it"><div class="tt">${link(i)}</div>${ds(i)}<div class="mt">${common(i)}<span>${esc(i.src)}</span><span>${ago(i.ts)}</span></div></div>`;
const heat=s=>s>=85?"var(--red)":s>=65?"var(--or)":s>=40?"#a8761a":"#2a2a2a";
const rfRow=i=>i.kind=="vuln"?`<div class="it rf"><div class="score" style="background:${heat(i.m.score)}">${i.m.score}</div><div><div class="tt">${link(i)}<span class="k vuln">${esc(i.m.label||"vuln")}</span></div>${i.m.rules.map(r=>`<div class="ds">• ${esc(r)}</div>`).join("")}<div class="mt"><span>seen ${ago(i.ts)}</span></div></div></div>`
 :`<div class="it"><div class="tt"><span class="k alert">ALERT</span>${link(i)}</div><div class="mt"><span>${esc(i.desc)}</span>${i.m.status?`<span>${esc(i.m.status)}</span>`:""}<span>${ago(i.ts)}</span></div></div>`;
const card=i=>`<div class="card"><div class="tt">${i.url?link(i):esc(i.title)}</div><div class="mt">${i.src?`<span>${esc(i.src)}</span>`:""}${i.ts?`<span>${ago(i.ts)}</span>`:""}${i.desc&&!i.src?`<span>${esc(i.desc)}</span>`:""}</div>${tri(i)}</div>`;
const dayLbl=t=>{const d=new Date(t*1e3),n=new Date(),s=x=>x.toDateString();return s(d)==s(n)?"Today":s(d)==s(new Date(n-864e5))?"Yesterday":d.toLocaleDateString(undefined,{weekday:"short",day:"numeric",month:"short"})};

const cnt=(g,k)=>g=="ex"?ST.exploits.filter(i=>i.kind==k&&ok(i)).length:g=="repo"?ST.repos.filter(i=>i.m.kinds.includes(k)&&ok(i)).length:ST[k].filter(ok).length;
const tabsH=g=>TABS[g].map(([k,n])=>`<button data-tab="${g}:${k}" class="${TAB[g]==k?"on":""}">${n} <i>${cnt(g,k)}</i></button>`).join("");
const rows=(l,fn,e)=>l.length?l.map(fn).join(""):`<div class="empty">${e}</div>`;
const panel=(id,t,tb,body,pre="")=>`<section class="pn"><div class="ph"><h2>${t}</h2><span class="tbs">${tb}</span></div>${pre}<div class="sc" id="${id}">${body}</div></section>`;
const spark=(l,d=7)=>{const n=Array(d).fill(0),t=Date.now()/1e3;l.forEach(i=>{const k=Math.floor((t-i.ts)/86400);if(k>=0&&k<d)n[d-1-k]++});const m=Math.max(1,...n);return `<svg class="spk" viewBox="0 0 70 20" preserveAspectRatio="none"><polyline points="${n.map((v,x)=>`${x*70/(d-1)},${19-v/m*18}`).join(" ")}" fill="none" stroke="#ff7a00" stroke-width="1.6"/></svg>`};
const tiles=()=>{const s=ST,all=[...s.news,...s.exploits,...s.repos];
 const T=[["Hot CVEs",s.hot.length,"exploits"],["New this run",all.filter(i=>i.new).length,"home"],["Articles · 7d",s.news.filter(i=>i.ts>Date.now()/1e3-6048e2).length,"news","",spark(s.news)],
  ["Exploited ITW",s.exploits.filter(i=>i.kind=="itw").length,"exploits:itw"],["Public exploits",s.exploits.filter(i=>i.kind=="public").length,"exploits:public","",spark(s.exploits.filter(i=>i.kind=="public"))],
  ["Fresh PoCs",s.exploits.filter(i=>i.kind=="poc").length,"exploits:poc"],["My stack hits",all.filter(i=>i.mine).length,"stack"],["Escalated",Object.values(s.triage).filter(t=>t.status=="Escalated").length,"stack"]];
 return `<div class="tiles">${T.map(([l,v,g,c,sp])=>`<div class="tile" data-go="${g}"><b>${esc(v)}</b><span>${l}</span>${sp||""}</div>`).join("")}</div>`};
const hotH=()=>ST.hot.length?`<div class="hot"><h3>HOT CVEs</h3>${ST.hot.map(h=>`<a data-q="${esc(h.cve)}" title="${esc(h.t)}">${esc(h.cve)} <i>${h.n}</i>${h.kev?" KEV":""}${h.msf?" MSF":""}${h.nuc?" NUC":""}${h.sig?" SIG":""}</a>`).join("")}</div>`:"";

/* ───────── knowledge graph (inspired by graphify: clusters, most-connected nodes, extracted vs inferred links) ───────── */
const GCOL={cve:"#ff7a00",hub:"#ffffff",itw:"#ff3d2e",public:"#ffb020",poc:"#ffe08a",adv:"#cfcfcf",news:"#7d7d7d",repo:"#f5f5f5",actor:"#ff9a3c",dep:"#ff6a4d"};
const GLAB={hub:"Search",cve:"CVE",itw:"Exploited (KEV)",public:"Public exploit",poc:"PoC",adv:"Advisory",news:"News",repo:"GitHub repo",actor:"Threat actor",dep:"My dependency"};
const TL={itw:"EXPLOITED",public:"EXPLOIT",poc:"PoC",adv:"ADVISORY",repo:"REPO",dep:"DEP"};
function gBuild(){
  const q=Q,rx=q?new RegExp((q.length<=4?"\\b":"")+q.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),"i"):null;
  const pool=[...ST.exploits,...ST.news,...ST.deps,...ST.repos].filter(i=>!MINE||i.mine),hc=new Set(ST.hot.map(h=>h.cve));
  const seeds=pool.filter(i=>rx?rx.test(i.q):i.cves.some(c=>hc.has(c))).sort((a,c)=>(c.p||0)-(a.p||0)||c.ts-a.ts).slice(0,70);
  const seedSet=new Set(seeds),cv=new Set(seeds.flatMap(i=>i.cves));
  const items=[...seeds,...pool.filter(i=>!seedSet.has(i)&&i.cves.some(c=>cv.has(c))).slice(0,60)];   // pull in everything that shares a CVE
  const N=new Map(),E=[];
  const node=(id,type,label,o)=>{if(!N.has(id))N.set(id,{id,type,label,x:(Math.random()-.5)*320,y:(Math.random()-.5)*320,vx:0,vy:0,deg:0,nb:[],...o});return N.get(id)};
  const edge=(a,b,kind)=>{E.push({a,b,kind,len:kind=="inf"?140:90});a.deg++;b.deg++;a.nb.push(b);b.nb.push(a)};
  const hub=q&&seeds.length?node("hub","hub",q.toUpperCase(),{}):null;
  for(const i of items){const ty=i.sec=="news"?"news":i.sec=="exploit"?i.kind:i.sec=="dep"?"dep":"repo",n=node("i:"+i.id,ty,i.title,{item:i});
    for(const c of i.cves.slice(0,4))edge(n,node("c:"+c,"cve",c,{items:[]}),"ext");        // EXTRACTED: the CVE is literally in the text
    for(const a of i.actors||[])edge(n,node("a:"+a,"actor",a,{}),"ext");
    if(hub&&seedSet.has(i)&&!i.cves.length&&!(i.actors||[]).length)edge(hub,n,"inf")}      // INFERRED: matched your search words only
  if(hub)for(const c of new Set(seeds.flatMap(i=>i.cves.slice(0,4))))edge(hub,N.get("c:"+c),"inf");
  for(const e of E)if(e.b.type=="cve"&&e.a.item)e.b.items.push(e.a.item);
  const nodes=[...N.values()];
  for(const n of nodes){if(n.type=="cve"){n.flags=[...new Set(n.items.flatMap(i=>i.flags))];const ep=n.items.map(i=>i.m.epss).filter(v=>v!=null);n.epss=ep.length?Math.max(...ep):null}
    n.r=n.type=="hub"?18:n.type=="cve"?10+Math.min(14,n.deg*1.3):n.type=="actor"?10+Math.min(8,n.deg):6+Math.min(4,((n.item&&n.item.p)||0)/25)}
  const seen=new Set();let comps=0;for(const n of nodes){if(n.type=="hub"||seen.has(n.id))continue;comps++;const st=[n];seen.add(n.id);while(st.length){const x=st.pop();for(const y of x.nb)if(y.type!="hub"&&!seen.has(y.id)){seen.add(y.id);st.push(y)}}}
  G={nodes,edges:E,comps,hidden:new Set(),tx:null,ty:null,k:1,sel:null,hov:null,t:0,dirty:1,v:V,q}}
function tick(){const N=G.nodes;for(const a of N){a.fx=0;a.fy=0}
  for(let i=0;i<N.length;i++)for(let j=i+1;j<N.length;j++){const a=N[i],c=N[j];let dx=a.x-c.x,dy=a.y-c.y;const d2=dx*dx+dy*dy+.5,d=Math.sqrt(d2),f=2800/d2;dx/=d;dy/=d;a.fx+=dx*f;a.fy+=dy*f;c.fx-=dx*f;c.fy-=dy*f}
  for(const e of G.edges){let dx=e.b.x-e.a.x,dy=e.b.y-e.a.y;const d=Math.sqrt(dx*dx+dy*dy)||1,f=(d-e.len)*.03;dx/=d;dy/=d;e.a.fx+=dx*f;e.a.fy+=dy*f;e.b.fx-=dx*f;e.b.fy-=dy*f}
  const cool=Math.max(.2,1-G.t/520);for(const a of N){if(a.drag)continue;a.fx-=a.x*.006;a.fy-=a.y*.006;a.vx=Math.max(-30,Math.min(30,(a.vx+a.fx)*.78));a.vy=Math.max(-30,Math.min(30,(a.vy+a.fy)*.78));a.x+=a.vx*cool;a.y+=a.vy*cool}}
function draw(x){const{W,H}=G,dpr=window.devicePixelRatio||1;x.setTransform(dpr,0,0,dpr,0,0);x.clearRect(0,0,W,H);
  const act=G.sel||G.hov,nb=act?new Set([act.id,...act.nb.map(n=>n.id)]):null,P=n=>[n.x*G.k+G.tx,n.y*G.k+G.ty];
  x.lineWidth=1;for(const e of G.edges){if(G.hidden.has(e.a.type)||G.hidden.has(e.b.type))continue;const on=nb&&(e.a===act||e.b===act);x.globalAlpha=nb?(on?.95:.06):.4;x.strokeStyle=on?"#ff7a00":"#888";x.setLineDash(e.kind=="inf"?[4,4]:[]);x.beginPath();x.moveTo(...P(e.a));x.lineTo(...P(e.b));x.stroke()}
  x.setLineDash([]);
  for(const n of G.nodes){if(G.hidden.has(n.type))continue;const[sx,sy]=P(n),on=!nb||nb.has(n.id);x.globalAlpha=on?1:.12;x.fillStyle=GCOL[n.type];x.beginPath();x.arc(sx,sy,n.r*G.k,0,6.283);x.fill();if(n===G.sel){x.strokeStyle="#fff";x.lineWidth=2;x.stroke()}
    if(on&&(n.type=="cve"||n.type=="hub"||n.type=="actor"||n===act||G.k>1.8)){x.fillStyle="#fff";x.font=(n.type=="cve"?"600 ":"")+"11px ui-monospace,Menlo,monospace";x.fillText(n.label.slice(0,n.type=="cve"?18:34),sx+n.r*G.k+4,sy+4)}}
  x.globalAlpha=1}
const gitem=i=>`<div class="gi"><span class="k ${i.sec=="news"?"adv":i.kind}">${i.sec=="news"?"NEWS":TL[i.kind]||"REPO"}</span> <a href="${esc(safe(i.url))}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a><div class="mt">${esc(i.src)} · ${ago(i.ts)}</div></div>`;
function report(){if(!G.nodes.length)return `<h3>No matches</h3><div class="ds">Nothing in the live feeds matches "${esc(G.q)}". Try a technology, vendor or CVE.</div>`;
  const li=n=>`<div class="gi"><a class="cv" data-gsel="${esc(n.id)}">${esc(n.label.slice(0,44))}</a> <span class="mt">${n.deg} links</span></div>`;
  const gods=G.nodes.filter(n=>n.type!="hub").sort((a,c)=>c.deg-a.deg).slice(0,6),weap=G.nodes.filter(n=>n.type=="cve"&&n.items.some(i=>i.sec=="news")&&n.items.some(i=>i.sec!="news")).sort((a,c)=>c.deg-a.deg).slice(0,6);
  return `<h3>Graph report</h3><div class="mt">${G.nodes.length} nodes · ${G.edges.length} links · ${G.comps} clusters</div><h4>Most connected</h4>${gods.map(li).join("")}<h4>In the news AND exploitable</h4>${weap.map(li).join("")||'<div class="mt">None in this view.</div>'}`}
function renderSel(){const n=G&&G.sel,el=$("#gs");if(!el)return;if(!n){el.innerHTML=report();return}
  let h=`<button class="more" data-gsel="" style="margin-top:0">← Graph report</button>`;
  if(n.type=="cve")h+=`<h3>${esc(n.label)}</h3><div class="mt">${(n.flags||[]).map(f=>b("arm",FL[f]||f)).join(" ")}${n.epss!=null?`<span>EPSS ${n.epss}%</span>`:""}<a class="cv" href="https://nvd.nist.gov/vuln/detail/${esc(n.label)}" target="_blank" rel="noopener noreferrer">NVD ↗</a></div><h4>${n.items.length} linked items</h4>`+n.items.map(gitem).join("");
  else if(n.type=="actor"){const a=ST.actors.find(x=>x.name==n.label);h+=`<h3>${esc(n.label)}</h3><div class="mt"><a class="cv" href="${esc(safe(a?a.url:""))}" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK ↗</a></div><h4>Mentioned in</h4>`+n.nb.filter(x=>x.item).map(x=>gitem(x.item)).join("")}
  else if(n.type=="hub")h+=`<h3>${esc(n.label)}</h3><div class="ds">Your search. Dashed links are inferred from text matching; solid links are extracted (the CVE or actor is named in the item).</div>`;
  else{const i=n.item;h+=gitem(i)+`<div class="ds">${esc(i.desc)}</div>`+(i.cves.length?`<h4>CVEs</h4>`+i.cves.map(c=>`<a class="cv" data-gsel="c:${esc(c)}">${esc(c)}</a>`).join(" "):"")}
  el.innerHTML=h}
function legend(){const c={};G.nodes.forEach(n=>c[n.type]=(c[n.type]||0)+1);$("#gl").innerHTML=Object.keys(GLAB).filter(t=>c[t]).map(t=>`<button class="lg ${G.hidden.has(t)?"off":""}" data-gt="${t}"><span class="dot" style="background:${GCOL[t]}"></span>${GLAB[t]} <b>${c[t]}</b></button>`).join("")+`<span class="mt">dashed = inferred from your search</span>`}
function fit(){if(!G||!G.nodes.length||G.touched)return;let x0=1e9,x1=-1e9,y0=1e9,y1=-1e9;for(const n of G.nodes){x0=Math.min(x0,n.x-n.r);x1=Math.max(x1,n.x+n.r);y0=Math.min(y0,n.y-n.r);y1=Math.max(y1,n.y+n.r)}
  const k=Math.max(.4,Math.min(2.4,Math.min((G.W-140)/Math.max(80,x1-x0),(G.H-120)/Math.max(80,y1-y0))));G.k=k;G.tx=G.W/2-(x0+x1)/2*k;G.ty=G.H/2-(y0+y1)/2*k;G.dirty=1}
function gStart(){const c=$("#gc");if(!c||!G)return;cancelAnimationFrame(G.raf);const dpr=window.devicePixelRatio||1,r=c.getBoundingClientRect();c.width=Math.round(r.width*dpr);c.height=Math.round(r.height*dpr);G.W=r.width;G.H=r.height;if(G.tx==null){G.tx=G.W/2;G.ty=G.H/2}
  const x=c.getContext("2d"),pos=e=>{const bb=c.getBoundingClientRect();return[e.clientX-bb.left,e.clientY-bb.top]};
  const pick=(px,py)=>{let best=null,bd=1e9;for(const n of G.nodes){if(G.hidden.has(n.type))continue;const d=Math.hypot(px-(n.x*G.k+G.tx),py-(n.y*G.k+G.ty));if(d<=n.r*G.k+4&&d<bd){best=n;bd=d}}return best};
  let drag=null,pan=null,moved=false;
  c.onpointerdown=e=>{G.touched=true;c.setPointerCapture(e.pointerId);const[px,py]=pos(e),n=pick(px,py);moved=false;if(n){drag=n;n.drag=true}else pan=[px-G.tx,py-G.ty]};
  c.onpointermove=e=>{const[px,py]=pos(e);if(drag){moved=true;drag.x=(px-G.tx)/G.k;drag.y=(py-G.ty)/G.k;drag.vx=drag.vy=0;G.t=Math.min(G.t,400)}else if(pan){moved=true;G.tx=px-pan[0];G.ty=py-pan[1]}
    else{const n=pick(px,py),t=$("#gt");if(n!==G.hov){G.hov=n;c.style.cursor=n?"pointer":"grab"}if(n){t.textContent=n.label+" · "+GLAB[n.type];t.style.cssText=`display:block;left:${Math.min(px+14,G.W-270)}px;top:${py+14}px`}else t.style.display="none"}G.dirty=1};
  c.onpointerup=()=>{if(drag){drag.drag=false;if(!moved){G.sel=drag;renderSel()}}else if(pan&&!moved){G.sel=null;renderSel()}drag=pan=null;G.dirty=1};
  c.onpointerleave=()=>{$("#gt").style.display="none";G.hov=null;G.dirty=1};
  c.onwheel=e=>{G.touched=true;e.preventDefault();const[px,py]=pos(e),k=Math.min(4,Math.max(.3,G.k*(e.deltaY<0?1.12:1/1.12)));G.tx=px-(px-G.tx)*k/G.k;G.ty=py-(py-G.ty)*k/G.k;G.k=k;G.dirty=1};
  legend();renderSel();for(let i=0;i<150;i++)tick();fit();
  const loop=()=>{if(!document.body.contains(c))return;if(G.t<520){tick();tick();G.t++;G.dirty=1;if(G.t==260||G.t==519)fit()}if(G.dirty){draw(x);G.dirty=0}G.raf=requestAnimationFrame(loop)};loop()}
const gStop=()=>{if(G)cancelAnimationFrame(G.raf)};
const gRe=()=>{gBuild();gStart()};
function dl(name,mime,text){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type:mime}));a.download=name;document.body.appendChild(a);a.click();a.remove()}
function gExport(kind){const X=s=>String(s).replace(/[<>&"']/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;","'":"&apos;"}[c])),conf=e=>e.kind=="inf"?"INFERRED":"EXTRACTED";
  if(kind=="json")dl("secdash-graph.json","application/json",JSON.stringify({query:Q,nodes:G.nodes.map(n=>({id:n.id,type:n.type,label:n.label,url:n.item?n.item.url:"",links:n.deg})),edges:G.edges.map(e=>({source:e.a.id,target:e.b.id,confidence:conf(e)}))},null,1));
  else dl("secdash-graph.graphml","application/xml",'<?xml version="1.0" encoding="UTF-8"?>\n<graphml xmlns="http://graphml.graphdrawing.org/xmlns"><key id="t" for="node" attr.name="type" attr.type="string"/><key id="l" for="node" attr.name="label" attr.type="string"/><key id="c" for="edge" attr.name="confidence" attr.type="string"/><graph edgedefault="undirected">'+G.nodes.map(n=>`<node id="${X(n.id)}"><data key="t">${n.type}</data><data key="l">${X(n.label)}</data></node>`).join("")+G.edges.map((e,i)=>`<edge id="e${i}" source="${X(e.a.id)}" target="${X(e.b.id)}"><data key="c">${conf(e)}</data></edge>`).join("")+"</graph></graphml>")}

const PG={
 home(){const s=ST,rk={rising:i=>i.m.per_day||0,trending:i=>i.m.today||0,active:i=>(i.m.gained||0)*1e6+(i.m.stars||0)}[TAB.repo];
  const nr=srt(s.news.filter(i=>ok(i)&&(SRC=="all"||i.src==SRC))),cn={};s.news.forEach(i=>cn[i.src]=(cn[i.src]||0)+1);
  const ch=`<div class="chips">${[["all","All"],...Object.entries(cn).sort((a,c)=>c[1]-a[1]).slice(0,6).map(([k,v])=>[k,k])].map(([k,n])=>`<button data-src="${esc(k)}" class="${SRC==k?"on":""}">${esc(n)}</button>`).join("")}</div>`;
  const nb=rows(nr.slice(0,HOMEN),newsRow,"No matching articles yet.")+`<button class="more" data-page="news">Open the news reader (${nr.length} articles) →</button>`;
  const rb=rows(s.repos.filter(i=>i.m.kinds.includes(TAB.repo)&&ok(i)).sort((a,c)=>rk(c)-rk(a)),repoRow,"Nothing yet for this view.");
  return tiles()+hotH()+`<div class="grid home">${panel("l-news","LATEST NEWS","",nb,ch)}${panel("l-repo","GITHUB · SECURITY REPOS",tabsH("repo"),rb)}</div>`},
 news(){const s=ST,cn={};s.news.forEach(i=>cn[i.src]=(cn[i.src]||0)+1);
  const nr=s.news.filter(i=>ok(i)&&(SRC=="all"||i.src==SRC)).sort((a,c)=>c.ts-a.ts);
  const ch=`<div class="chips">${[["all","All"],...Object.entries(cn).sort((a,c)=>c[1]-a[1]).slice(0,12).map(([k,v])=>[k,k+" "+v])].map(([k,n])=>`<button data-src="${esc(k)}" class="${SRC==k?"on":""}">${esc(n)}</button>`).join("")}</div>`;
  let last="",out="";nr.slice(0,MAXN).forEach(i=>{const d=dayLbl(i.ts);if(d!=last){last=d;out+=`<div class="day">${esc(d)}</div>`}out+=newsRow(i)});
  return `<div class="reader"><h1 class="pgt">Latest news<span>${nr.length} articles</span></h1>${ch}${out||'<div class="empty">No matching articles yet.</div>'}${nr.length>MAXN?`<button class="more" data-more="1">Show more (${nr.length-MAXN})</button>`:""}</div>`},
 exploits(){const l=srt(ST.exploits.filter(i=>i.kind==TAB.ex&&ok(i)));
  const warn=TAB.ex=="poc"?`<div class="warn">⚠ Unvetted code. Fake PoCs on GitHub often carry malware. Read first, run only in an isolated lab.</div>`:"";
  return hotH()+panel("l-ex","EXPLOITS & ADVISORIES",tabsH("ex"),`<div class="cards">${rows(l,exRow,"Nothing yet for this view.")}</div>`,warn)},
 threats(){const mx=Math.max(1,...ST.actors.map(a=>a.n));
  const act=ST.actors.length?ST.actors.map(a=>`<div class="ab"><a href="${esc(safe(a.url))}" target="_blank" rel="noopener noreferrer">${esc(a.name)}</a><span class="bar"><i style="width:${a.n/mx*100}%"></i></span><a class="cv" data-q="${esc(a.name)}" data-go="news">${a.n} articles</a></div>`).join(""):'<div class="empty">No named threat groups in the current news.</div>';
  const fn={ioc:iocRow,ransom:ransomRow,breach:breachRow}[TAB.th];
  return `<div class="grid">${panel("l-act","THREAT ACTORS IN THE NEWS · MITRE ATT&CK","",act)}${panel("l-th","ACTIVE THREATS",tabsH("th"),rows(ST[TAB.th].filter(ok),fn,EMPTY[TAB.th]))}</div>`},
 stack(){const s=ST,idx={};[...s.exploits,...s.news,...s.deps,...s.repos].forEach(i=>{if(!idx[i.tk])idx[i.tk]=i});
  const ghost=k=>({id:k,tk:k,title:k,url:/^CVE-/.test(k)?"https://nvd.nist.gov/vuln/detail/"+k:"",desc:"no longer in the live feeds",src:"",cves:[],flags:[],m:{},ts:(s.triage[k]||{}).ts||0});
  const col=st=>{const l=Object.entries(s.triage).filter(([k,t])=>st=="Pinned"?!!t.pinned:(t.status||"New")==st).map(([k])=>idx[k]||ghost(k));return `<div class="col"><h3>${st} <i>${l.length}</i></h3>${l.map(card).join("")||'<div class="empty sm">Nothing here</div>'}</div>`};
  const mine=srt([...s.exploits,...s.news].filter(i=>i.mine&&ok(i))),od=s.status["My dependencies (OSV)"];
  return `<div class="kw">Watching: ${s.keywords.map(k=>b("",k)).join(" ")}</div>`+panel("l-board","TEAM TRIAGE BOARD","",`<div class="board">${["Escalated","Investigating","Mitigated","Pinned"].map(col).join("")}</div>`)+
   `<div class="grid">${panel("l-mine","MATCHES FOR YOUR STACK","",rows(mine.slice(0,80),i=>i.sec=="news"?newsRow(i):exRow(i),"Nothing in the current feeds matches your keywords."))}${panel("l-dep","MY DEPENDENCIES (OSV)","",rows(s.deps.filter(ok),depRow,od&&od.ok==2?"Add your packages to PACKAGES in config.py.":"No known vulnerabilities in your listed packages."))}</div>`},
 graph(){const sug=[...new Set(["php","wordpress","exchange","fortinet","log4j",...ST.keywords.slice(0,5)])];
  return `<h1 class="pgt">Knowledge graph<span>news · exploits · PoCs · actors, linked by CVE</span></h1><div class="gbar"><input type="search" id="gq" value="${esc(Q)}" placeholder="Graph a technology, vendor or CVE: PHP, Exchange, Fortinet…" aria-label="Graph search">${sug.map(k=>`<button data-gq="${esc(k)}">${esc(k)}</button>`).join("")}<span class="grow"></span><button data-gx="rebuild">↻ Rebuild</button><button data-gx="graphml">GraphML</button><button data-gx="json">JSON</button></div>
  <div class="gleg" id="gl"></div><div class="gwrap"><div class="gbox"><canvas id="gc"></canvas><div class="gtip" id="gt"></div><div class="ghint">drag nodes · scroll to zoom · click to inspect</div></div><aside class="pn gside" id="gs"></aside></div>`},
 rf(){const f=l=>rows(l.filter(ok),rfRow,"No data (see source status below).");return `<div class="grid">${panel("rv","RECORDED FUTURE · VULNERABILITIES","",f(ST.rf.vulns))}${panel("ra","RECORDED FUTURE · ALERTS","",f(ST.rf.alerts))}</div>`}
};

function ticker(){const it=[...ST.exploits.filter(i=>i.kind=="itw").slice(0,6).map(i=>["EXPLOITED",i]),...[...ST.news].sort((a,c)=>(c.p||0)-(a.p||0)||c.ts-a.ts).slice(0,10).map(i=>["NEWS",i])];
 const h=it.map(([k,i])=>`<a href="${esc(safe(i.url))}" target="_blank" rel="noopener noreferrer"><b class="${k=="EXPLOITED"?"r":""}">${k}</b>${esc(i.title)}</a>`).join("");
 if(h!==TK){TK=h;$("#trk").innerHTML=h+h}}
function render(){
  if(!ST)return;const s=ST,pages=pagesOf();if(!pages.includes(PAGE))PAGE="home";
  const nw=[...s.news,...s.exploits,...s.repos].filter(i=>i.new).length;document.title=(nw?`(${nw}) `:"")+"Secdash";
  const bd={news:s.news.filter(i=>i.new).length,exploits:s.exploits.filter(i=>i.kind=="itw"&&i.new).length,threats:s.ioc.filter(i=>i.new).length+s.ransom.filter(i=>i.new).length,stack:[...s.exploits,...s.news].filter(i=>i.mine).length};
  $("#nav").innerHTML=pages.map((p,n)=>`<button data-page="${p}" class="${PAGE==p?"on":""}" title="Key ${n+1}">${NAMES[p]}${bd[p]?` <i>${bd[p]}</i>`:""}</button>`).join("");
  const g=s.gh,gq=$("#ghq");gq.textContent=g&&g.limit?`GitHub API ${g.remaining}/${g.limit}`:"";gq.className="q"+(g&&g.limit&&g.remaining<=2?" low":"");
  ticker();const m=$("#main");
  if(PAGE=="graph"){if(!$("#gc")){m.innerHTML=PG.graph();gRe()}}   // the graph keeps its layout across live updates; press Rebuild to refresh its data
  else{gStop();const sc={};document.querySelectorAll(".sc").forEach(e=>sc[e.id]=e.scrollTop);m.innerHTML=PG[PAGE]();document.querySelectorAll(".sc").forEach(e=>{if(sc[e.id])e.scrollTop=sc[e.id]})}
  $("#foot").innerHTML=Object.entries(s.status).map(([k,v])=>`<span class="${["r","g","sk"][v.ok]}" title="${esc(v.msg)}">${["✕","●","○"][v.ok]} ${esc(k)}: ${esc(v.msg)}</span>`).join("")+`<br><span class="sk">Keys: 1-${pages.length} pages · / filter · Esc close</span>`;
}
function prep(){for(const l of [ST.news,ST.exploits,ST.repos,ST.rf.vulns,ST.rf.alerts,ST.ioc,ST.ransom,ST.breach,ST.deps])for(const i of l)i.q=(i.title+" "+i.desc+" "+i.cves.join(" ")+" "+i.src+" "+(i.actors||[]).join(" ")).toLowerCase()}
const fromHash=()=>{const p=location.hash.slice(1);PAGE=STP.includes(p)?p:"home"};
const go=p=>{if(location.hash=="#"+p){fromHash();render()}else location.hash=p};
function toast(m,p){const t=$("#toast");t.textContent=m;t.onclick=()=>{go(p);t.classList.remove("show")};t.classList.add("show");clearTimeout(TT);TT=setTimeout(()=>t.classList.remove("show"),7000)}
async function pull(){try{const r=await fetch("/api/state?v="+V,{cache:"no-store"});if(r.status==401){location.reload();return}
  const j=await r.json();LAST=Date.now();if(!j.same){const old=ST&&new Set([...ST.news,...ST.exploits].map(i=>i.id));ST=j;V=j.v;prep();render();
   if(old&&Date.now()-T0>9e4){const nn=ST.news.filter(i=>!old.has(i.id)).length,ne=ST.exploits.filter(i=>!old.has(i.id)).length;if(nn+ne)toast("+ "+[ne&&ne+" exploit"+(ne>1?"s":""),nn&&nn+" article"+(nn>1?"s":"")].filter(Boolean).join(" · "),ne?"exploits":"news")}}}catch(e){}live()}
function live(){const e=$("#live"),off=Date.now()-LAST>6e4;e.className="live"+(off?" off":"");$("#lt").textContent=off?"OFFLINE":"LIVE · "+(ST?"updated "+ago(ST.now):"loading")}
const who=()=>{let n="";try{n=localStorage.getItem("sd_name")||""}catch(e){}if(!n){n=(prompt("Your name (shown next to your triage actions):","")||"").trim().slice(0,40);try{localStorage.setItem("sd_name",n)}catch(e){}}return n};
async function tpost(o){o.owner=who();await fetch("/api/triage",{method:"POST",headers:{"X-Requested-With":"secdash","Content-Type":"application/json"},body:JSON.stringify(o)});V=0;pull()}
const setQ=v=>{Q=v.trim().toLowerCase();$("#q").value=v;const g=$("#gq");if(g)g.value=v};
document.addEventListener("change",e=>{const k=e.target.dataset&&e.target.dataset.tri;if(k)tpost({key:k,status:e.target.value})});
document.addEventListener("input",e=>{if(e.target.id=="gq"){clearTimeout(GT);GT=setTimeout(()=>{setQ(e.target.value);gRe()},300)}});
document.addEventListener("click",e=>{const t=e.target.closest("[data-tab],[data-q],[data-src],[data-more],[data-pin],[data-note],[data-ip],[data-page],[data-go],[data-gq],[data-gt],[data-gsel],[data-gx]");if(!t||!ST)return;const d=t.dataset;
  if(d.ip){lookup(d.ip);return}
  if(d.pin){tpost({key:d.pin,pinned:!(ST.triage[d.pin]||{}).pinned});return}
  if(d.note){const n=prompt("Team note (visible to everyone):",(ST.triage[d.note]||{}).note||"");if(n!==null)tpost({key:d.note,note:n});return}
  if(d.gq!==undefined){setQ(d.gq);gRe();return}
  if(d.gt){G.hidden.has(d.gt)?G.hidden.delete(d.gt):G.hidden.add(d.gt);legend();G.dirty=1;return}
  if(d.gsel!==undefined){G.sel=d.gsel?G.nodes.find(n=>n.id==d.gsel)||null:null;renderSel();G.dirty=1;return}
  if(d.gx){d.gx=="rebuild"?gRe():gExport(d.gx);return}
  if(d.page){go(d.page);return}
  if(d.tab){const[g,k]=d.tab.split(":");TAB[g]=k}
  if(d.q){setQ(d.q);if(PAGE=="graph"){gRe();return}}
  if(d.src){SRC=d.src;MAXN=40}
  if(d.more)MAXN+=60;
  if(d.go){const[p,k]=d.go.split(":");if(k)TAB.ex=k;go(p);return}
  render()});
document.addEventListener("keydown",e=>{if(/INPUT|TEXTAREA|SELECT/.test(e.target.tagName)){if(e.key=="Escape")e.target.blur();return}
  if(e.key=="/"){e.preventDefault();$("#q").focus()}else if(e.key=="Escape")$("#dlg").classList.remove("open");
  else if(/^[1-7]$/.test(e.key)&&ST){const p=pagesOf()[+e.key-1];if(p)go(p)}});
window.addEventListener("hashchange",()=>{fromHash();render();window.scrollTo(0,0)});
$("#q").oninput=e=>{MAXN=40;if(PAGE=="graph"){clearTimeout(GT);GT=setTimeout(()=>{setQ(e.target.value);gRe()},300)}else{Q=e.target.value.trim().toLowerCase();render()}};
$("#mine").onclick=e=>{MINE=!MINE;e.target.classList.toggle("on",MINE);PAGE=="graph"?gRe():render()};
$("#sort").onclick=e=>{SORT=SORT=="new"?"pri":"new";e.target.textContent="Sort: "+(SORT=="new"?"Newest":"Priority");render()};
const dens=()=>{$("#dens").textContent=document.body.classList.contains("compact")?"Compact":"Comfortable"};
try{if(localStorage.getItem("sd_compact")=="1")document.body.classList.add("compact")}catch(e){}dens();
$("#dens").onclick=()=>{const c=document.body.classList.toggle("compact");try{localStorage.setItem("sd_compact",c?"1":"0")}catch(e){}dens()};
$("#rf").onclick=async()=>{await fetch("/api/refresh",{method:"POST",headers:{"X-Requested-With":"secdash"}});let n=0;const t=setInterval(()=>{pull();if(++n>20)clearInterval(t)},3000)};
async function lookup(ip){$("#dt").textContent="IP lookup · "+ip;$("#dx").style.display="none";$("#bt").value="Looking up…";$("#dlg").classList.add("open");
  try{$("#bt").value=JSON.stringify(await(await fetch("/api/lookup?ip="+encodeURIComponent(ip))).json(),null,2)}catch(e){$("#bt").value="Lookup failed."}}
$("#ipgo").onclick=()=>{const v=$("#ipq").value.trim();if(v)lookup(v)};$("#ipq").onkeydown=e=>{if(e.key=="Enter")$("#ipgo").onclick()};
const show=async f=>{$("#dt").textContent="Threat brief";$("#dx").style.display="";$("#bt").value=await(await fetch("/api/export?fmt="+f)).text();$("#dlg").classList.add("open")};
const copy=()=>{const t=$("#bt");t.select();try{if(window.isSecureContext&&navigator.clipboard)navigator.clipboard.writeText(t.value);else document.execCommand("copy")}catch(e){}};
$("#brief").onclick=()=>show("md");$("#cmd").onclick=async()=>{await show("md");copy()};$("#csl").onclick=async()=>{await show("slack");copy()};$("#cls").onclick=()=>$("#dlg").classList.remove("open");
fromHash();pull();setInterval(pull,10000);setInterval(live,5000);
</script></body></html>"""

if __name__ == "__main__":
    main()
