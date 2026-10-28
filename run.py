#!/usr/bin/env python3
"""Secdash: live security dashboard. One command starts every collector in the background and serves the UI on a random
port behind an access code.   Usage:  pip install -r requirements.txt  &&  python run.py
Libraries: requests (HTTP, retries, TLS), feedparser (RSS/Atom), cachetools (search/lookup caches), d3 (graph, vendored in static/)."""
import atexit, calendar, csv, gzip, hashlib, io, ipaddress, json, os, random, re, secrets, socket, ssl, sys, tempfile, threading, time, webbrowser
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

try:
    import certifi, feedparser, requests
    from cachetools import TTLCache
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as e:
    sys.exit(f"\n  Missing library '{e.name}'.  Run:  pip install -r requirements.txt\n")
import config as C

UA = "secdash/3.0 (+local dashboard)"
BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
STATE_FILE = os.path.join(BASE, ".secdash_state.json")
LOCK = threading.RLock()
ITEMS, STATUS = {}, {}                                   # per-source items, per-source health
KEV_IDS, MSF_IDS, EDB_IDS, NUC_IDS, SIG_IDS = set(), set(), set(), set(), set()
KEV_ALL, EDB_ROWS, MSF_MODS = [], [], []                 # full local indexes, used by search
STATE = {"v": 0, "data": b"{}", "gz": b"", "obj": None}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SEC_RE = re.compile(r"secur|vuln|exploit|pentest|red.?team|malware|ransom|\bcve|forensic|dfir|osint|phish|fuzz|reverse.?eng|"
                    r"\bc2\b|offensive|hack|threat|\bctf\b|burp|nmap|decompil|obfuscat|payload|shellcode|\bedr\b|siem|recon|"
                    r"credential|jailbreak|prompt.?inject|pwn|infosec|cyber|bypass|rootkit|backdoor|stealer", re.I)
TOKEN, RF = C.GITHUB_TOKEN, C.RECORDED_FUTURE
GH_SLEEP = 2.2 if TOKEN else 6.5
TLS = getattr(C, "TLS", None) or {}
VERIFY_SSL = getattr(C, "VERIFY_SSL", True)
CA_BUNDLE = getattr(C, "CA_BUNDLE", "")
TLS_CTX = None


# ───────────── HTTP layer (requests) ─────────────
def build_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    retry = Retry(total=2, connect=2, read=1, backoff_factor=0.7, status_forcelist=(500, 502, 503, 504),
                  allowed_methods=frozenset({"GET", "POST"}), respect_retry_after_header=True, raise_on_status=False)
    ad = HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=48)
    s.mount("https://", ad); s.mount("http://", ad)
    if not VERIFY_SSL:
        s.verify = False
        requests.packages.urllib3.disable_warnings()
    elif CA_BUNDLE:   # extra CA is ADDED to the normal roots (requests would otherwise replace them)
        path = os.path.join(tempfile.gettempdir(), f"secdash-ca-{os.getpid()}.pem")
        with open(path, "wb") as o, open(certifi.where(), "rb") as a, open(CA_BUNDLE, "rb") as b:
            o.write(a.read() + b"\n" + b.read())
        s.verify = path
        atexit.register(lambda: os.path.exists(path) and os.remove(path))
    return s
SESSION = build_session()


class HTTPFail(Exception):
    def __init__(self, status, body=b"", headers=None):
        self.status, self.body, self.headers = status, body, headers or {}
        super().__init__(f"HTTP {status}: {body[:120].decode('utf-8', 'replace')}")


def request(url, headers=None, data=None, params=None, timeout=40, cap=40_000_000):
    """GET (POST when data is given). Returns (status, headers, body). Raises HTTPFail on >= 400."""
    try:
        r = SESSION.request("POST" if data is not None else "GET", url, headers=headers, data=data, params=params, timeout=timeout, stream=True)
    except requests.RequestException as e:
        raise ConnectionError(f"{type(e).__name__}: {str(e)[:100]}") from None
    try:
        body = bytearray()
        if r.status_code != 304:
            for chunk in r.iter_content(1 << 16):
                body += chunk
                if len(body) > cap:
                    raise ValueError("response too large")
        if r.status_code >= 400:
            raise HTTPFail(r.status_code, bytes(body), r.headers)
        return r.status_code, r.headers, bytes(body)
    finally:
        r.close()

def fetch(url, headers=None, **kw): return request(url, headers, **kw)[2]
def jget(url, headers=None, **kw): return json.loads(fetch(url, headers, **kw))
JSON_H = {"Content-Type": "application/json"}


# ───────────── helpers ─────────────
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
    import html
    t = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or ""))).strip()
    return t[:n] + ("…" if len(t) > n else "")

def mk(sec, src, kind, title, url, t, desc="", **meta):
    cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {desc} {meta.get('cves_raw', '')}")})
    meta.pop("cves_raw", None)
    return {"id": hashlib.sha1(f"{sec}|{src}|{url or title}".encode()).hexdigest()[:14], "sec": sec, "src": src,
            "kind": kind, "title": clean(title, 200), "url": url if str(url).startswith(("http://", "https://")) else "",
            "ts": min(int(t or time.time()), int(time.time()) + 3600), "desc": clean(desc), "cves": cves, "m": meta}

def parse_feed(b, src, sec="news", kind="news"):
    if b"<!ENTITY" in b:   # refuse entity-expansion tricks from untrusted feeds
        raise ValueError("unsafe XML")
    d = feedparser.parse(b)
    if d.bozo and not d.entries:
        raise ValueError(f"unparseable feed ({type(d.bozo_exception).__name__})")
    out = []
    for e in d.entries:
        url, title = e.get("link") or "", e.get("title") or ""
        if not title or not url.startswith(("http://", "https://")):
            continue
        tm = e.get("published_parsed") or e.get("updated_parsed")
        desc = e.get("summary") or ((e.get("content") or [{}])[0].get("value") or "")
        out.append(mk(sec, src, kind, title, url, calendar.timegm(tm) if tm else time.time(), desc))
    return out


# ───────────── collectors: each returns (items, note) ─────────────
class Skip(Exception):
    """Source not configured (e.g. free API key not set). Shown as 'skipped', not as a failure."""

FEED_CACHE = {}   # url -> (etag, last-modified, items): unchanged feeds answer 304 and cost nothing

def feeds():
    cut, bad, out = time.time() - C.NEWS_DAYS * 86400, [], []
    def one(f):
        name, url = f[0], f[1]
        c, h = FEED_CACHE.get(url), {}
        if c and c[0]: h["If-None-Match"] = c[0]
        if c and c[1]: h["If-Modified-Since"] = c[1]
        try:
            st, hd, body = request(url, h, timeout=25, cap=8_000_000)
            if st == 304 and c:
                return c[2]
            items = parse_feed(body, name)
            FEED_CACHE[url] = (hd.get("ETag"), hd.get("Last-Modified"), items)
            return items
        except Exception:
            bad.append(name)
            return c[2] if c else []
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
        d = jget("https://hn.algolia.com/api/v1/search_by_date",
                 params={"tags": "story", "query": q, "numericFilters": "points>20", "hitsPerPage": 15})
        for h in d.get("hits", []):
            if h["objectID"] in seen or not h.get("url") or not h.get("title"):
                continue
            seen.add(h["objectID"])
            out.append(mk("news", "Hacker News", "news", h["title"], h["url"], h.get("created_at_i"),
                          f'{h.get("points", 0)} points · {h.get("num_comments", 0)} comments', points=h.get("points", 0)))
    return out, f"{len(out)} stories"

def kev():
    global KEV_IDS, KEV_ALL
    v = jget("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")["vulnerabilities"]
    KEV_IDS, KEV_ALL = {x["cveID"] for x in v}, v
    v = sorted(v, key=lambda x: x["dateAdded"], reverse=True)[:C.KEV_COUNT]
    epss = {}
    try:
        for x in jget("https://api.first.org/data/v1/epss", params={"cve": ",".join(i["cveID"] for i in v)})["data"]:
            epss[x["cve"]] = round(float(x["epss"]) * 100, 1)
    except Exception:
        pass
    return [kev_item(x, epss.get(x["cveID"])) for x in v], f"{len(v)} newest of {len(KEV_IDS)}"

def kev_item(x, epss=None):
    return mk("exploit", "CISA KEV", "itw", f'{x["cveID"]}: {x["vendorProject"]} {x["product"]}: {x["vulnerabilityName"]}',
              f'https://nvd.nist.gov/vuln/detail/{x["cveID"]}', ts(x["dateAdded"]), x["shortDescription"], due=x["dueDate"],
              ransom=x.get("knownRansomwareCampaignUse") == "Known", epss=epss)

def edb_item(r):
    return mk("exploit", "Exploit-DB", "public", r[1], f"https://www.exploit-db.com/exploits/{r[0]}", ts(r[2]),
              f"{r[3]} · {r[4]}", cves_raw=r[5], verified=r[6])

def edb():
    global EDB_IDS, EDB_ROWS
    rows = list(csv.DictReader(io.StringIO(fetch("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv").decode("utf-8", "replace"))))
    EDB_IDS = {c.strip().upper() for r in rows for c in (r.get("codes") or "").split(";") if c.upper().startswith("CVE-")}
    EDB_ROWS = sorted(((r["id"], r["description"], r.get("date_published") or "", r.get("platform", ""), r.get("type", ""),
                        r.get("codes", ""), r.get("verified") == "1") for r in rows if r.get("id")), key=lambda r: r[2], reverse=True)
    return [edb_item(r) for r in EDB_ROWS[:40]], f"{len(rows)} in DB"

def msf_item(v):
    return mk("exploit", "Metasploit", "public", v["name"], "https://github.com/rapid7/metasploit-framework/blob/master" + v["path"],
              ts(v.get("mod_time")), v.get("description", ""), cves_raw=" ".join(v.get("references", [])), module=v["fullname"])

def msf():
    global MSF_IDS, MSF_MODS
    m = list(jget("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json", cap=150_000_000).values())
    MSF_IDS = {r.upper() for v in m for r in v.get("references", []) if r.upper().startswith("CVE-")}
    MSF_MODS = sorted((v for v in m if v.get("type") == "exploit"), key=lambda v: v.get("mod_time", ""), reverse=True)
    return [msf_item(v) for v in MSF_MODS[:30]], f"{len(MSF_MODS)} exploit modules"

def nuclei():
    global NUC_IDS
    ids = set()
    for line in fetch("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json").decode("utf-8", "replace").splitlines():
        try:
            ids.add(json.loads(line)["ID"].upper())
        except Exception:
            pass
    if not ids:
        raise RuntimeError("no templates parsed")
    NUC_IDS = ids
    return [], f"{len(ids)} CVEs have a ready Nuclei template"

def sigma():
    """CVEs that already have a community Sigma rule, read from rule file names. Each rules* folder is fetched on its own because the
    whole-repo tree is too large for one GitHub API call (it comes back truncated)."""
    global SIG_IDS
    root, ids = None, set()
    for br in ("master", "main"):
        try:
            root = jget(f"https://api.github.com/repos/SigmaHQ/sigma/git/trees/{br}", GH_H).get("tree", [])
            break
        except HTTPFail as e:
            if e.status != 404: raise
    if root is None:
        raise RuntimeError("Sigma repository tree not found")
    for d in (t for t in root if t["type"] == "tree" and t["path"].startswith("rules")):
        tree = jget(f'https://api.github.com/repos/SigmaHQ/sigma/git/trees/{d["sha"]}', GH_H, params={"recursive": 1})
        ids |= {f"CVE-{y}-{n}" for t in tree.get("tree", []) for y, n in re.findall(r"cve[-_](\d{4})[-_](\d{4,7})", t["path"], re.I)}
    if not ids: raise RuntimeError("no CVE-named Sigma rules found")
    SIG_IDS = ids
    return [], f"{len(ids)} CVEs have a Sigma detection rule"

def packet():
    out = []
    for name, url in C.EXPLOIT_FEEDS:
        out += parse_feed(fetch(url, cap=8_000_000), name, "exploit", "public")
    return out[:30], f"{len(out)} entries"

GH = {"remaining": None, "limit": None, "reset": 0, "last": 0}
GH_LOCK = threading.Lock()   # every GitHub search goes through one lane, so groups can't burst together
GH_H = {"Accept": "application/vnd.github+json", **({"Authorization": "Bearer " + TOKEN} if TOKEN else {})}

def gh(q, sort="stars", n=30, tries=3):
    params = {"q": q, "sort": sort, "order": "desc", "per_page": n}
    for i in range(tries):
        with GH_LOCK:
            time.sleep(max(0, GH_SLEEP - (time.time() - GH["last"])))
            if GH["remaining"] == 0 and GH["reset"] > time.time():
                time.sleep(min(GH["reset"] - time.time() + 1, 70))
            GH["last"] = time.time()
            try:
                _, h, body = request("https://api.github.com/search/repositories", GH_H, params=params)
                GH.update(remaining=int(h.get("X-RateLimit-Remaining", -1)), limit=int(h.get("X-RateLimit-Limit", 0)), reset=int(h.get("X-RateLimit-Reset", 0)))
                return json.loads(body).get("items", [])
            except HTTPFail as e:
                if e.status not in (403, 429):
                    raise
                reset = int(e.headers.get("X-RateLimit-Reset") or 0)
                pause = int(e.headers.get("Retry-After") or 0) or (max(5, min(reset - time.time() + 1, 65)) if reset else 15 * (i + 1))
                GH.update(remaining=0, reset=time.time() + pause)
                time.sleep(pause)   # back off, then retry
    raise RuntimeError("GitHub rate limit: gave up after retries" + ("" if TOKEN else " (set GITHUB_TOKEN to triple the limit)"))

def repo(r, kind):
    age = max(1, (time.time() - ts(r["created_at"])) / 86400)
    return mk("repo", "GitHub", kind, r["full_name"], r["html_url"], ts(r["pushed_at"]), r.get("description") or "",
              stars=r["stargazers_count"], lang=r.get("language"), created=ts(r["created_at"]),
              per_day=round(r["stargazers_count"] / age, 1), topics=(r.get("topics") or [])[:4])

def ghpoc():
    d = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    out, seen, now = [], set(), datetime.now(timezone.utc)
    for yr in sorted({now.year, (now - timedelta(days=7)).year}, reverse=True):   # also finds repos around New Year
        for r in gh(f"CVE-{yr} in:name created:>{d}", "updated", 40):
            if r["full_name"] in seen: continue
            seen.add(r["full_name"])
            it = repo(r, "poc"); it["sec"], it["src"], it["ts"] = "exploit", "GitHub PoC", ts(r["created_at"]); out.append(it)
    return out, f"{len(out)} new CVE repos (unvetted)"

def by_terms(kind, extra, n, key):
    seen, out, errs = set(), [], []
    for group in C.GITHUB["term_groups"]:
        terms = " OR ".join(f'"{t}"' if " " in t else t for t in group[:6])   # GitHub allows max 5 OR operators per query
        try:
            for r in gh(f"{terms} in:topics,description {extra}", "stars", n):
                if r["full_name"] not in seen:
                    seen.add(r["full_name"]); out.append(repo(r, kind))
        except Exception as e:   # keep partial results instead of losing everything
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
            t = fetch(f"https://github.com/trending/{lang}?since={since}", timeout=25).decode("utf-8", "replace")
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
    if not out:
        raise RuntimeError("no trending repos parsed (GitHub changed its page, or it is unreachable); Rising/Active still work")
    out.sort(key=lambda i: -i["m"]["today"])
    return out, f"{len(out)} security-related trending repos"

EPSS = {}
ACT = {"re": None, "map": {}, "by": {}}

def epss():
    with LOCK:
        ids = sorted({c for items in ITEMS.values() for it in items for c in it["cves"]}, reverse=True)[:600]   # newest CVE ids first
    for i in range(0, len(ids), 100):
        for x in jget("https://api.first.org/data/v1/epss", params={"cve": ",".join(ids[i:i + 100])}).get("data", []):
            EPSS[x["cve"].upper()] = round(float(x["epss"]) * 100, 1)
    return [], f"{len(EPSS)} exploit-probability scores"

def ghsa():
    out, errs = [], []
    for sev in ("critical", "high"):
        try:
            rows = jget("https://api.github.com/advisories", GH_H, params={"severity": sev, "per_page": 25, "type": "reviewed"})
        except Exception as e:   # keep the other severity if one call is rate-limited
            errs.append(f"{sev}: {str(e)[:50]}"); continue
        out += [ghsa_item(a, sev) for a in rows]
    if errs and not out:
        raise RuntimeError("; ".join(errs) + (" (set GITHUB_TOKEN to raise the limit)" if not TOKEN else ""))
    out.sort(key=lambda i: -i["ts"])
    return out[:40], f"{len(out)} critical/high advisories" + (f" (partial: {errs[0]})" if errs else "")

def ghsa_item(a, sev=None):
    sev = sev or a.get("severity") or ""
    pk = ", ".join(sorted({f'{(v.get("package") or {}).get("name", "?")} ({(v.get("package") or {}).get("ecosystem", "")})'
                           for v in a.get("vulnerabilities", [])}))[:160]
    return mk("exploit", "GitHub Advisory", "adv", f'{a["ghsa_id"]}: {a["summary"]}', a["html_url"], ts(a["published_at"]),
              f"{sev.upper()} · {pk}", cves_raw=a.get("cve_id") or "", sev=sev)

def feodo():
    d = jget("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    d = d if isinstance(d, list) else next((v for v in d.values() if isinstance(v, list)), [])
    d.sort(key=lambda x: x.get("first_seen") or x.get("first_seen_utc") or "", reverse=True)
    return [mk("ioc", "Feodo C2", "c2", f'{x["ip_address"]}:{x.get("port", "")}', "", ts(x.get("first_seen") or x.get("first_seen_utc")),
               f'{x.get("malware", "")} · {x.get("country", "")} · {x.get("status", "")}', ioc=x["ip_address"]) for x in d[:100]], f"{len(d)} C2s tracked (newest 100)"

def need_abusech():
    if not C.ABUSECH_KEY:
        raise Skip("set ABUSECH_AUTH_KEY (free at abuse.ch)")

def threatfox():
    need_abusech()
    d = json.loads(fetch("https://threatfox-api.abuse.ch/api/v1/", {"Auth-Key": C.ABUSECH_KEY, **JSON_H}, data=json.dumps({"query": "get_iocs", "days": 1}).encode()))
    if d.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox: {d.get('query_status')}")
    rows = sorted(d["data"], key=lambda x: x.get("first_seen_utc", ""), reverse=True)[:100]
    return [mk("ioc", "ThreatFox", "ioc", x["ioc"], "", ts(x.get("first_seen_utc")),
               f'{x.get("malware_printable", "")} · {x.get("ioc_type", "")} · confidence {x.get("confidence_level", "?")}%', ioc=x["ioc"]) for x in rows], f"{len(rows)} IOCs (24h)"

def urlhaus():
    need_abusech()
    d = jget("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/", {"Auth-Key": C.ABUSECH_KEY})
    if d.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus: {d.get('query_status')}")
    return [mk("ioc", "URLhaus", "url", re.sub(r"^http", "hxxp", x["url"]), "", ts(x.get("date_added")),   # defanged, never a live link
               f'{x.get("threat", "")} · {", ".join(x.get("tags") or [])} · {x.get("url_status", "")}', ioc=x["url"]) for x in d["urls"]], f"{len(d['urls'])} malware URLs"

def ransomware():
    if not C.RANSOMWARE_KEY:
        raise Skip("set RANSOMWARE_LIVE_API_KEY (free at ransomware.live)")
    d = jget("https://api-pro.ransomware.live/victims/recent", {"X-API-KEY": C.RANSOMWARE_KEY, "Accept": "application/json"})
    d = d if isinstance(d, list) else next((v for v in d.values() if isinstance(v, list)), [])
    out = []
    for v in d[:150]:
        name = v.get("victim") or v.get("post_title") or v.get("name") or "?"
        grp, when = v.get("group") or v.get("group_name") or "?", v.get("discovered") or v.get("attackdate") or ""
        out.append(mk("ransom", "ransomware.live", "ransom", f"{name}", "", ts(when), f'{grp} · {v.get("country") or "?"} · {v.get("activity") or v.get("sector") or "?"}', grp=grp))
    return out, f"{len(out)} recent victims"

def breaches():
    d = jget("https://haveibeenpwned.com/api/v3/breaches")
    d.sort(key=lambda b: b.get("AddedDate", ""), reverse=True)
    return [mk("breach", "HIBP", "breach", b["Title"] + (f' ({b["Domain"]})' if b.get("Domain") else ""),
               f'https://haveibeenpwned.com/PwnedWebsites#{b["Name"]}', ts(b.get("AddedDate")),
               f'{b.get("PwnCount", 0):,} accounts · ' + ", ".join(b.get("DataClasses", [])[:5])) for b in d[:40]], f"{len(d)} breaches on record"

def osv():
    if not C.PACKAGES:
        raise Skip("add PACKAGES in config.py")
    out = []
    for p in C.PACKAGES:
        d = json.loads(fetch("https://api.osv.dev/v1/query", JSON_H, data=json.dumps(
            {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": str(p["version"])}).encode()))
        for v in d.get("vulns", []):
            out.append(mk("dep", "OSV", "dep", f'{p["name"]} {p["version"]}: {v["id"]}', "https://osv.dev/vulnerability/" + v["id"],
                          ts(v.get("published") or v.get("modified")), v.get("summary") or v.get("details", ""), cves_raw=" ".join(v.get("aliases", []))))
    return out, f"{len(out)} known vulns across {len(C.PACKAGES)} packages"

ACTOR_STOP = {"Silence", "Equation", "Dragonfly", "Inception", "Strider", "Machete", "Patchwork", "Poseidon", "Moonlight", "Rocke", "Windshift", "Sowbug", "Suckfly"}

def actors():
    """Named threat groups (MITRE ATT&CK via the MISP galaxy) mentioned in the news."""
    names = {}
    for v in jget("https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-intrusion-set.json")["values"]:
        base, meta = v["value"].rsplit(" - ", 1)[0], v.get("meta", {})
        url = "https://attack.mitre.org/groups/" + meta.get("external_id", "")
        ACT["by"][base] = url
        for n in {base, *meta.get("synonyms", [])}:
            n = n.strip()
            if n not in ACTOR_STOP and (" " in n or re.search(r"\d", n) or len(n) >= 6):   # skip short / ambiguous names
                names[n] = (base, url)
    ACT["map"] = names
    ACT["re"] = re.compile(r"(?<![\w-])(" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True)) + r")(?![\w-])")
    return [], f"{len(names)} actor names tracked"

def rf_get(path, params):
    return jget("https://api.recordedfuture.com" + path, {"X-RFToken": RF["token"], "Accept": "application/json"}, params=params)

def rf_vuln_item(r):
    e, k = r.get("entity", {}), r.get("risk", {})
    rules = [x.get("evidenceString") or x.get("rule") or "" for x in k.get("evidenceDetails", [])][:3]
    return mk("rf", "Recorded Future", "vuln", e.get("name", "?"), "https://app.recordedfuture.com/live/sc/entity/" + e.get("id", ""),
              ts((r.get("timestamps") or {}).get("lastSeen")), e.get("description", ""), score=k.get("score", 0),
              label=k.get("criticalityLabel", ""), rules=[clean(x, 140) for x in rules])

def rf_alert_item(r):
    return mk("rf", "Recorded Future", "alert", r.get("title") or (r.get("rule") or {}).get("name", "alert"),
              r.get("url") or "https://app.recordedfuture.com", ts(r.get("triggered")), (r.get("rule") or {}).get("name", ""),
              status=(r.get("review") or {}).get("status", ""))

def rf_vulns():
    res = rf_get("/v2/vulnerability/search", {"limit": 25, "fields": "entity,risk,timestamps", **RF["vuln_params"]})["data"]["results"]
    out = sorted((rf_vuln_item(r) for r in res), key=lambda i: -i["m"]["score"])
    return out, f"{len(out)} vulnerabilities"

def rf_alerts():
    res = rf_get("/v2/alert/search", {"limit": 25, "orderby": "triggered", "direction": "desc", "triggered": f'-{RF["alert_days"]}d', **RF["alert_params"]})["data"]["results"]
    return [rf_alert_item(r) for r in res], f"{len(res)} alerts"


# ───────────── Recorded Future IOC lookup (one request per IOC; pasted input is cleaned, typed and validated first) ─────────────
RF_PORTAL = "https://app.recordedfuture.com/live/sc/entity/"
RF_DEFANG = [(re.compile(r"\[://\]"), "://"), (re.compile(r"^hxxp", re.I), "http"), (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.I), "."), (re.compile(r"\[:\]"), ":")]
HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$", re.I)
RF_MAX_IOCS, RF_TIER = 10, {}   # RF_TIER remembers, per IOC type, which field set the API accepted

def rf_classify(raw):
    """One pasted token -> (type, value). Defanged input (hxxp://, [.]) is repaired. Raises ValueError(reason) for anything else."""
    v = raw.strip().strip("\"'<>()")
    for pat, rep in RF_DEFANG:
        v = pat.sub(rep, v)
    if not v:
        raise ValueError("empty")
    if CVE_RE.fullmatch(v):
        return "vulnerability", v.upper()
    if re.match(r"^https?://", v, re.I):
        if len(v) > 1500:
            raise ValueError("URL longer than 1500 characters")
        try:
            host = urlparse(v).hostname or ""
        except ValueError:
            host = ""
        if not host:
            raise ValueError("URL has no valid host")
        try:
            if not ipaddress.ip_address(host).is_global:
                raise ValueError("URL points at a private / non-routable address")
        except ValueError as e:
            if "private" in str(e):
                raise
        return "url", v
    try:
        ip = ipaddress.ip_address(v.strip("[]"))
    except ValueError:
        ip = None
    if ip:
        if not ip.is_global:
            raise ValueError("private / non-routable address (never sent to third parties)")
        return "ip", str(ip)
    if HASH_RE.fullmatch(v):
        return "hash", v.lower()
    if DOMAIN_RE.fullmatch(v.rstrip(".")):
        return "domain", v.rstrip(".").lower()
    raise ValueError("not an IP, domain, URL, file hash (MD5/SHA-1/SHA-256) or CVE")

def rf_parse_input(q):
    out, bad, seen = [], [], set()
    for tok in re.split(r"[\s,;]+", q.strip()):
        if not tok:
            continue
        try:
            t, v = rf_classify(tok)
        except ValueError as e:
            bad.append({"input": tok[:120], "reason": str(e)})
            continue
        if (t, v) not in seen:
            seen.add((t, v)); out.append((tok[:200], t, v))
    return out, bad

def rf_tiers(t):   # richest field set first; the API answers 400 for fields a plan or entity type does not have, so we step down
    return [f"entity,risk,timestamps,intelCard,aiInsights{',location' if t == 'ip' else ''}", f"entity,risk,intelCard{',location' if t == 'ip' else ''}", "entity,risk"]

def rf_ids(t, v):   # current docs use typed ids (ip:1.2.3.4); the bare value is kept as a fallback spelling
    return {"ip": ["ip:" + v, v], "domain": ["idn:" + v, v], "hash": ["hash:" + v, v], "url": ["url:" + v, v]}.get(t, [v])

def rf_fetch(t, v):
    tiers, last = rf_tiers(t), None
    for ident in rf_ids(t, v):
        i = RF_TIER.get(t, 0)
        while True:
            try:
                resp = rf_get(f"/v2/{t}/{quote(ident, safe='')}", {"fields": tiers[i]})
                RF_TIER[t] = i
                return resp, ident
            except HTTPFail as e:
                if e.status == 400 and b"field" in e.body.lower() and i + 1 < len(tiers):
                    i += 1; continue   # field not available: retry with fewer fields
                if e.status in (400, 404):
                    last = e; break    # unknown id spelling: try the next one
                raise
    raise last

def _txt(x):
    if isinstance(x, dict):
        x = x.get("name") or x.get("id") or ""
    return clean(str(x), 120) if x not in (None, "") else ""

def rf_norm(resp, ident):
    """Tolerant mapping of an RF enrichment response; anything unexpected is still visible in 'raw'."""
    d = (resp.get("data") if isinstance(resp, dict) else None) or {}
    d = d if isinstance(d, dict) else {}
    ent, risk, st = (d.get(k) if isinstance(d.get(k), dict) else {} for k in ("entity", "risk", "timestamps"))
    rule = risk.get("rule") if isinstance(risk.get("rule"), dict) else {}
    ev = [{"rule": clean(e.get("rule") or e.get("name") or "", 120), "crit": e.get("criticality"), "label": e.get("criticalityLabel") or "",
           "text": clean(e.get("evidenceString") or e.get("description") or "", 280), "ts": ts(e.get("timestamp"))}
          for e in (risk.get("evidenceDetails") or []) if isinstance(e, dict)]
    ev.sort(key=lambda x: (-(x["crit"] if isinstance(x["crit"], (int, float)) else 0), -x["ts"]))
    score = risk.get("score") if isinstance(risk.get("score"), (int, float)) else None
    ai = d.get("aiInsights")
    insight = ai if isinstance(ai, str) else next((ai[k] for k in ("text", "insight", "summary", "comment", "description") if isinstance(ai.get(k), str) and ai[k]), "") if isinstance(ai, dict) else ""
    loc = d.get("location") if isinstance(d.get("location"), dict) else {}
    card = d.get("intelCard") if isinstance(d.get("intelCard"), str) else ""
    link = card if card.startswith("https://app.recordedfuture.com/") else RF_PORTAL + quote(ent.get("id") or ident, safe="")
    raw = json.dumps(resp, indent=1)
    return {"risk": {"score": score, "label": risk.get("criticalityLabel") or "", "hit": rule.get("count", risk.get("ruleCount", len(ev) if ev else None)),
                     "max": rule.get("maxCount"), "evidence": ev[:30]},
            "first": ts(st.get("firstSeen")), "last": ts(st.get("lastSeen")), "name": _txt(ent.get("name")), "insight": clean(insight, 700),
            "location": {k: _txt(loc.get(k)) for k in ("country", "city", "organization", "asn", "cidr") if _txt(loc.get(k))}, "url": link,
            "raw": raw[:30000] + ("\n… (truncated)" if len(raw) > 30000 else "")}

def rf_lookup_one(inp, t, v):
    key, base = ("rf", t, v), {"input": inp, "ioc": v, "type": t}
    with CACHE_LOCK:
        hit = LOOKUP_CACHE.get(key)
    if hit:
        return {**hit, "input": inp, "cached": True}
    try:
        resp, ident = rf_fetch(t, v)
        out = {**base, "ok": 1, **rf_norm(resp, ident)}
    except HTTPFail as e:
        msg = {404: "Recorded Future has no record of this IOC.",
               401: "Recorded Future rejected the API token (HTTP 401). Check RF_TOKEN.",
               403: f"Recorded Future refused the request (HTTP 403): check RF_TOKEN and that your plan includes {t} lookups.",
               429: "Recorded Future rate limit reached. Wait a minute and try again."}.get(e.status, f"Recorded Future error: HTTP {e.status} {clean(e.body.decode('utf-8', 'replace'), 120)}")
        out = {**base, "ok": 2 if e.status == 404 else 0, "msg": msg}
    except Exception as e:
        out = {**base, "ok": 0, "msg": f"{type(e).__name__}: {str(e)[:120]}"}
    if out["ok"]:
        with CACHE_LOCK:
            LOOKUP_CACHE[key] = dict(out)
    return out

# (group, name, function, minimum minutes between runs of heavy sources)
SOURCES = [("news", "News feeds", feeds, 0), ("news", "Hacker News", hn, 0),
           ("exploits", "CISA KEV", kev, 0), ("exploits", "Exploit-DB", edb, 120), ("exploits", "Metasploit", msf, 120),
           ("exploits", "Nuclei templates", nuclei, 360), ("exploits", "Sigma rules", sigma, 360), ("exploits", "Packet Storm", packet, 0),
           ("exploits", "GitHub PoCs", ghpoc, 0), ("exploits", "GitHub advisories", ghsa, 0), ("exploits", "EPSS scores", epss, 0),
           ("github", "GitHub rising", rising, 0), ("github", "GitHub trending", trending, 0), ("github", "GitHub active", active, 0),
           ("threats", "Feodo C2", feodo, 0), ("threats", "ThreatFox", threatfox, 0), ("threats", "URLhaus", urlhaus, 0),
           ("threats", "Ransomware victims", ransomware, 0), ("threats", "Breaches (HIBP)", breaches, 60),
           ("intel", "Threat actors (MITRE)", actors, 1440), ("intel", "My dependencies (OSV)", osv, 0)]
if RF.get("token"):
    SOURCES += [("rf", "RF vulnerabilities", rf_vulns, 0), ("rf", "RF alerts", rf_alerts, 0)]


# ───────────── search: one query fans out to every source in parallel, results stream back as each finishes ─────────────
SEARCH_CACHE, LOOKUP_CACHE = TTLCache(maxsize=64, ttl=600), TTLCache(maxsize=256, ttl=900)
CACHE_LOCK = threading.Lock()
RATE = {}

def toks(q): return [t for t in re.split(r"\s+", q.lower().strip()) if t]
def match(hay, tk): return all(t in hay for t in tk)

def s_local(q):
    tk, out = toks(q), []
    with LOCK:
        for items in ITEMS.values():
            for it in items:
                hay = f'{it["title"]} {it["desc"]} {" ".join(it["cves"])} {it["src"]} {" ".join(it.get("techs", []))} {" ".join(it.get("actors", []))}'.lower()
                if match(hay, tk): out.append(dict(it))
    out.sort(key=lambda i: (-i.get("p", 0), -i["ts"]))
    return out[:150], f"{len(out)} matches in the live feeds"

def s_edb(q):
    if not EDB_ROWS: raise Skip("Exploit-DB index still loading")
    tk = toks(q)
    hits = [r for r in EDB_ROWS if match(f"{r[1]} {r[3]} {r[5]}".lower(), tk)]
    return [edb_item(r) for r in hits[:40]], f"{len(hits)} exploits" + (" (newest 40 shown)" if len(hits) > 40 else "")

def s_msf(q):
    if not MSF_MODS: raise Skip("Metasploit index still loading")
    tk = toks(q)
    hits = [v for v in MSF_MODS if match(f'{v["name"]} {v.get("description", "")} {v["fullname"]} {" ".join(v.get("references", []))}'.lower(), tk)]
    return [msf_item(v) for v in hits[:25]], f"{len(hits)} modules" + (" (newest 25 shown)" if len(hits) > 25 else "")

def s_kev(q):
    if not KEV_ALL: raise Skip("KEV catalogue still loading")
    tk = toks(q)
    hits = sorted((x for x in KEV_ALL if match(f'{x["cveID"]} {x["vendorProject"]} {x["product"]} {x["vulnerabilityName"]} {x["shortDescription"]}'.lower(), tk)),
                  key=lambda x: x["dateAdded"], reverse=True)
    return [kev_item(x) for x in hits[:30]], f"{len(hits)} known-exploited CVEs"

def s_github(q):
    qq = q.replace('"', " ").strip()
    term, out, errs = (f'"{qq}"' if " " in qq else qq), {}, []
    for extra, sort in (("exploit", "stars"), ("cve", "updated"), ("pentest", "stars"))[:3 if TOKEN else 2]:
        try:
            for r in gh(f"{term} {extra} in:name,description,topics", sort, 12, tries=2):
                out.setdefault(r["full_name"], repo(r, "search"))
        except Exception as e:
            errs.append(str(e)[:70])
    if errs and not out: raise RuntimeError("; ".join(errs))
    return list(out.values()), f"{len(out)} repos" + (f" (partial: {errs[0]})" if errs else "")

def s_nvd(q):
    p = {"resultsPerPage": 40}
    p["cveId" if CVE_RE.fullmatch(q.strip()) else "keywordSearch"] = q.strip().upper() if CVE_RE.fullmatch(q.strip()) else q
    d = jget("https://services.nvd.nist.gov/rest/json/cves/2.0", {"apiKey": C.NVD_KEY} if C.NVD_KEY else {}, params=p, timeout=30)
    out = []
    for v in d.get("vulnerabilities", []):
        c = v["cve"]
        desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
        score, sev = None, ""
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(k):
                e = c["metrics"][k][0]; score = e["cvssData"].get("baseScore"); sev = e.get("baseSeverity") or e["cvssData"].get("baseSeverity", ""); break
        out.append(mk("exploit", "NVD", "cve", f'{c["id"]}: {desc}', f'https://nvd.nist.gov/vuln/detail/{c["id"]}', ts(c.get("published")), desc, cvss=score, sev=sev))
    out.sort(key=lambda i: -i["ts"])
    return out, f'{d.get("totalResults", len(out))} CVE records' + (" (newest 40 shown)" if d.get("totalResults", 0) > 40 else "")

def s_ghsa(q):
    qq = q.strip()
    if CVE_RE.fullmatch(qq): p = {"cve_id": qq.upper(), "per_page": 10}
    elif re.fullmatch(r"[\w.@/-]{2,60}", qq): p = {"affects": qq, "per_page": 15}
    else: raise Skip("advisories are searched by CVE id or package name")
    rows = jget("https://api.github.com/advisories", GH_H, params=p)
    return [ghsa_item(a) for a in rows], f"{len(rows)} advisories"

def s_osv(q):
    if not CVE_RE.fullmatch(q.strip()): raise Skip("OSV is queried for CVE ids")
    v = jget("https://api.osv.dev/v1/vulns/" + quote(q.strip().upper(), safe=""))
    return [mk("exploit", "OSV", "adv", f'{v["id"]}: {v.get("summary") or clean(v.get("details", ""), 120)}', "https://osv.dev/vulnerability/" + v["id"],
               ts(v.get("published") or v.get("modified")), v.get("details", ""), cves_raw=" ".join(v.get("aliases", [])) + " " + v["id"])], "1 record"

def s_hn(q):
    d = jget("https://hn.algolia.com/api/v1/search", params={"query": q, "tags": "story", "hitsPerPage": 20})
    out = [mk("news", "Hacker News", "news", h["title"], h.get("url") or f'https://news.ycombinator.com/item?id={h["objectID"]}', h.get("created_at_i"),
              f'{h.get("points", 0)} points · {h.get("num_comments", 0)} comments', points=h.get("points", 0))
           for h in d.get("hits", []) if h.get("title") and (h.get("points") or 0) >= 3]
    return out, f"{len(out)} stories"

def s_rf(q):
    if not RF.get("token"): raise Skip("set RF_TOKEN in config.py to search Recorded Future")
    out, notes = [], []
    if CVE_RE.fullmatch(q.strip()):
        r = rf_get("/v2/vulnerability/" + quote(q.strip().upper(), safe=""), {"fields": "entity,risk,timestamps"}).get("data", {})
        if r: out.append(rf_vuln_item(r))
    else:
        for name, path, extra, fn in (("vulnerabilities", "/v2/vulnerability/search", {"fields": "entity,risk,timestamps"}, rf_vuln_item), ("alerts", "/v2/alert/search", {}, rf_alert_item)):
            try:
                out += [fn(r) for r in rf_get(path, {"freetext": q, "limit": 25, **extra})["data"]["results"]]
            except Exception as e:
                notes.append(f"{name}: {str(e)[:60]}")
    if notes and not out: raise RuntimeError("; ".join(notes))
    return out, f"{len(out)} results" + (f" (partial: {notes[0]})" if notes else "")

SEARCH_SOURCES = [("Live feeds", s_local), ("Exploit-DB", s_edb), ("Metasploit", s_msf), ("CISA KEV", s_kev), ("GitHub repos", s_github),
                  ("NVD", s_nvd), ("GitHub advisories", s_ghsa), ("OSV", s_osv), ("Hacker News", s_hn), ("Recorded Future", s_rf)]

def run_source(name, fn, q):
    t0 = time.time()
    try:
        items, msg = fn(q)
        items = [i if "flags" in i else enrich(i) for i in items]
        return {"source": name, "ok": 1, "msg": msg, "items": items, "ms": int((time.time() - t0) * 1000)}
    except Skip as e:
        return {"source": name, "ok": 2, "msg": str(e), "items": []}
    except Exception as e:
        return {"source": name, "ok": 0, "msg": f"{type(e).__name__}: {str(e)[:110]}", "items": []}


# ───────────── IP lookup ─────────────
def lookup(ip):
    with CACHE_LOCK:
        out = dict(LOOKUP_CACHE.get(ip) or {})
    if not out:
        out = {"ip": ip}
        for name, url, h in (("shodan_internetdb", f"https://internetdb.shodan.io/{ip}", {}),
                             ("greynoise_community", f"https://api.greynoise.io/v3/community/{ip}", {"key": C.GREYNOISE_KEY} if C.GREYNOISE_KEY else {})):
            try:
                out[name] = jget(url, h, timeout=15)
            except HTTPFail as e:
                try: out[name] = json.loads(e.body)
                except Exception: out[name] = {"error": f"HTTP {e.status}"}
            except Exception as e:
                out[name] = {"error": str(e)[:80]}
        with CACHE_LOCK:
            LOOKUP_CACHE[ip] = dict(out)
    with LOCK:
        out["seen_in_local_feeds"] = [f'{it["title"]} ({it["src"]})' for items in ITEMS.values() for it in items
                                      if it["sec"] == "ioc" and it["m"].get("ioc", "").split(":")[0] == ip][:10]
    return out

def notify(items):
    url = C.ALERTS.get("webhook")
    for it in items:
        txt = f'🚨 {it["title"]} [{", ".join(it["flags"] + (["MY STACK"] if it["mine"] else []))}] P{it["p"]} {it["url"]}'
        try:
            fetch(url, JSON_H, data=json.dumps({"text": txt, "content": txt}).encode(), timeout=10)   # Slack/Teams use "text", Discord "content"
        except Exception as e:
            print(f"  [alert failed] {e}")


# ───────────── state, scoring, publishing ─────────────
FIRST_RUN, PREV_SEEN, PREV_STARS, FIRST_STARS, SEEN, TRIAGE, DIRTY, ALERTED = True, set(), {}, {}, {}, {}, [False], set()
try:
    with open(STATE_FILE) as _f:
        _s = json.load(_f)
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

def _alt(words, short=4):
    words = [w for w in words if w and len(w) > 2]
    if not words: return None
    return re.compile("|".join((r"\b" + re.escape(w) + r"\b") if len(w) <= short else re.escape(w) for w in sorted(set(words), key=len, reverse=True)), re.I)
KW_RE = _alt([k.lower() for k in C.KEYWORDS])
TECH_RE = re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in sorted(set(C.TECH_TERMS), key=len, reverse=True)) + r")(?![\w-])", re.I) if C.TECH_TERMS else None

def priority(it):
    """0-100: exploited > weaponized > fresh PoC > news; corroboration, ransomware, EPSS and YOUR stack push it up."""
    if it["sec"] in ("ioc", "ransom", "breach", "rf"):
        return 0
    m = it["m"]
    s = {"itw": 50, "public": 30, "poc": 10, "adv": 35, "dep": 40, "cve": 12}.get(it["kind"], 5 if it["sec"] == "news" else 0)
    s += 15 * bool(m.get("ransom")) + min(20, (m.get("epss") or 0) * 0.2)
    s += 8 * len([f for f in it["flags"] if not (it["kind"] == "itw" and f == "KEV")])
    s += C.STACK_BOOST * it["mine"] + 5 * it["new"]
    return int(min(100, s))

def enrich(it, new=False):
    """Adds the derived fields the UI relies on. Used for the live feeds and for search results."""
    txt = f'{it["title"]} {it["desc"]}'
    it["new"] = new
    it["mine"] = bool(KW_RE and KW_RE.search(txt))
    it["flags"] = [f for f, st in (("KEV", KEV_IDS), ("MSF", MSF_IDS), ("EDB", EDB_IDS), ("NUC", NUC_IDS), ("SIG", SIG_IDS)) if any(c in st for c in it["cves"])]
    it["tk"] = it["cves"][0] if it["cves"] else it["id"]   # team triage is shared per CVE
    if it["cves"] and it["m"].get("epss") is None:
        e = [EPSS[c] for c in it["cves"] if c in EPSS]
        if e: it["m"]["epss"] = max(e)
    it["actors"] = sorted({ACT["map"][x][0] for x in ACT["re"].findall(txt)}) if ACT["re"] and it["sec"] in ("news", "exploit") else []
    it["techs"] = sorted({x.lower() for x in TECH_RE.findall(txt)})[:6] if TECH_RE else []
    it["p"] = priority(it)
    return it

def publish():
    with LOCK:
        now, news, ex, repos, kinds, rfv, rfa = time.time(), [], [], {}, {}, [], []
        oth, acount = {"ioc": [], "ransom": [], "breach": [], "dep": []}, {}
        for items in ITEMS.values():
            for it in items:
                if it["id"] not in SEEN:
                    SEEN[it["id"]] = now; DIRTY[0] = True
                enrich(it, (not FIRST_RUN) and it["id"] not in PREV_SEEN)
                if it["sec"] == "news":
                    for x in it["actors"]: acount[x] = acount.get(x, 0) + 1
                    news.append(it)
                elif it["sec"] == "exploit": ex.append(it)
                elif it["sec"] in oth: oth[it["sec"]].append(it)
                elif it["sec"] == "rf": (rfv if it["kind"] == "vuln" else rfa).append(it)
                else:
                    n, stars = it["title"], it["m"].get("stars", 0)
                    CUR_STARS[n] = stars
                    if stars:
                        if n not in FIRST_STARS:
                            FIRST_STARS[n] = stars; DIRTY[0] = True
                        if n in PREV_STARS: it["m"]["gained"] = stars - PREV_STARS[n]
                        it["m"]["total_gain"] = stars - FIRST_STARS[n]
                    if n in repos:   # same repo found by several collectors: merge
                        o = repos[n]; kinds[n].append(it["kind"])
                        for k, v in it["m"].items():
                            if k != "kinds" and o["m"].get(k) in (None, 0, "") and v: o["m"][k] = v
                        o["new"] = o["new"] or it["new"]
                    else:
                        kinds[n] = [it["kind"]]; repos[n] = it
        for n, o in repos.items(): o["m"]["kinds"] = kinds[n]
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
        data = json.dumps(payload).encode()
        STATE.update(v=payload["v"], data=data, gz=gzip.compress(data, 5), obj=payload)
        if C.ALERTS.get("webhook") and not FIRST_RUN:   # push brand-new high-priority items to Slack / Teams / Discord
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
    buf, cell = io.StringIO(), (lambda v: "'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v)   # spreadsheet-formula safe
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
SESSIONS, FAILS, LOOKUPS, RFRATE = {}, {}, {}, {}
MIME = {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
       "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

def rate(bucket, ip, limit, window=60):
    now = time.time()
    b = bucket[ip] = [t for t in bucket.get(ip, []) if now - t < window] + [now]
    return len(b) <= limit

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
    def head(self, code, ctype, extra=None, length=None):
        h = {"Content-Type": ctype if "charset" in ctype or not ctype.startswith(("text/", "application/json")) else ctype + "; charset=utf-8",
             "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}
        if length is not None: h["Content-Length"] = str(length)
        if TLS_CTX: h["Strict-Transport-Security"] = "max-age=31536000"
        h.update(extra or {})
        self.send_response(code)
        for k, v in h.items(): self.send_header(k, v)
        for c in getattr(self, "cookies", []): self.send_header("Set-Cookie", c)
        self.end_headers()
    def out(self, code, body, ctype="application/json", extra=None, cookie=None):
        b = body if isinstance(body, bytes) else body.encode()
        self.cookies = [cookie] if cookie else []
        self.head(code, ctype, extra, len(b))
        self.wfile.write(b)
    def redirect(self, cookie):
        self.out(303, "", "text/plain", {"Location": "/"}, cookie)
    def page(self, src, code=200):
        self.out(code, src, "text/html", {"Content-Security-Policy": CSP})
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
            return f"sd={t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400" + ("; Secure" if TLS_CTX else "")
        FAILS[ip].append(now); return False
    def static(self, rel):
        p = os.path.realpath(os.path.join(STATIC, rel))
        ext = os.path.splitext(p)[1].lower()
        if os.path.commonpath([p, STATIC]) != STATIC or not os.path.isfile(p) or ext not in MIME:
            return self.out(404, "not found", "text/plain")
        with open(p, "rb") as f: body = f.read()
        self.out(200, body, MIME[ext], {"Cache-Control": "private, max-age=86400" if "/vendor/" in p.replace(os.sep, "/") else "no-cache"})
    def stream_search(self, q):
        self.cookies = []
        self.head(200, "application/x-ndjson", {"X-Accel-Buffering": "no", "Connection": "close"})   # HTTP/1.0: body ends when the connection closes
        def send(o):
            self.wfile.write(json.dumps(o).encode() + b"\n"); self.wfile.flush()
        try:
            key = q.lower()
            with CACHE_LOCK: cached = SEARCH_CACHE.get(key)
            if cached:
                for part in cached: send(part)
                return send({"done": True, "cached": True})
            parts = []
            try:
                ipaddress.ip_address(q)
                is_ip = True
            except ValueError:
                is_ip = False
            send({"plan": ["IP intel", "Live feeds"] if is_ip else [n for n, _ in SEARCH_SOURCES]})
            if is_ip:   # an IP address: local IOC matches + Shodan InternetDB + GreyNoise (public addresses only)
                if not ipaddress.ip_address(q).is_global:
                    return send({"error": "Private / non-routable addresses are never sent to third parties.", "done": True})
                for p in ({"source": "IP intel", "ok": 1, "msg": "Shodan InternetDB + GreyNoise", "items": [], "lookup": lookup(q)}, run_source("Live feeds", s_local, q)):
                    parts.append(p); send(p)
            else:
                ex = ThreadPoolExecutor(len(SEARCH_SOURCES))
                futs = {ex.submit(run_source, n, fn, q): n for n, fn in SEARCH_SOURCES}
                try:
                    for f in as_completed(futs, timeout=100):
                        parts.append(f.result()); send(parts[-1])
                except FutTimeout:
                    for f, n in futs.items():
                        if not f.done(): send({"source": n, "ok": 0, "msg": "timed out", "items": []})
                ex.shutdown(wait=False, cancel_futures=True)
            if not is_ip and all(p["ok"] != 0 for p in parts):
                with CACHE_LOCK: SEARCH_CACHE[key] = parts
            send({"done": True})
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, TimeoutError):
            pass   # the browser navigated away mid-search
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/state":
            if not self.authed(): return self.out(401, '{"error":"auth"}')
            v = int(parse_qs(u.query).get("v", ["0"])[0] or 0)
            if v == STATE["v"]: return self.out(200, b'{"same":true}')
            if "gzip" in self.headers.get("Accept-Encoding", ""): return self.out(200, STATE["gz"], "application/json", {"Content-Encoding": "gzip"})
            return self.out(200, STATE["data"])
        if u.path == "/api/search":
            if not self.authed(): return self.out(401, "{}")
            q = re.sub(r"[\x00-\x1f\x7f]", " ", parse_qs(u.query).get("q", [""])[0]).strip()[:80]
            if len(q) < 2: return self.out(400, '{"error":"Type at least 2 characters."}')
            if not rate(RATE, self.client_address[0], 15): return self.out(429, '{"error":"Slow down: 15 searches per minute."}')
            return self.stream_search(q)
        if u.path == "/api/export":
            if not self.authed(): return self.out(401, "{}")
            P, q = STATE["obj"], parse_qs(u.query)
            if not P: return self.out(503, "still loading", "text/plain")
            f, dl, day = q.get("fmt", ["md"])[0], q.get("dl"), time.strftime("%Y%m%d")
            body, ct, ext = {"md": (brief(P), "text/plain", "md"), "slack": (brief(P, True), "text/plain", "txt"),
                             "csv": (to_csv(P), "text/csv", "csv"),
                             "json": (json.dumps({k: P[k] for k in ("now", "hot", "news", "exploits", "repos", "triage")}, indent=1), "application/json", "json")}.get(f, (None,) * 3)
            if body is None: return self.out(400, "bad fmt", "text/plain")
            return self.out(200, body, ct, {"Content-Disposition": f'attachment; filename="threat-{day}.{ext}"'} if dl else None)
        if u.path == "/api/lookup":
            if not self.authed(): return self.out(401, "{}")
            ip = parse_qs(u.query).get("ip", [""])[0].strip()
            try:
                assert ipaddress.ip_address(ip).is_global
            except Exception:
                return self.out(400, '{"error":"Enter a valid PUBLIC IP address (private addresses are never sent to third parties)."}')
            if not rate(LOOKUPS, self.client_address[0], 20): return self.out(429, '{"error":"Slow down: 20 lookups per minute."}')
            return self.out(200, json.dumps(lookup(ip), indent=1))
        if u.path == "/api/rf/lookup":
            if not self.authed(): return self.out(401, "{}")
            if not RF.get("token"): return self.out(400, json.dumps({"error": "Recorded Future is not connected. Set RF_TOKEN (Connect API token) and restart."}))
            q = re.sub(r"[\x00-\x1f\x7f]", " ", parse_qs(u.query).get("q", [""])[0])[:2500]
            items, bad = rf_parse_input(q)
            if not items and not bad: return self.out(400, '{"error":"Paste at least one IOC."}')
            if not rate(RFRATE, self.client_address[0], 12): return self.out(429, '{"error":"Slow down: 12 lookups per minute."}')
            cut = len(items) > RF_MAX_IOCS
            items = items[:RF_MAX_IOCS]
            with ThreadPoolExecutor(max(1, min(4, len(items)))) as ex:
                res = list(ex.map(lambda a: rf_lookup_one(*a), items))
            return self.out(200, json.dumps({"results": res, "invalid": bad, "truncated": cut}))
        if u.path.startswith("/static/"):
            if not self.authed(): return self.out(401, "{}")
            return self.static(u.path[len("/static/"):])
        if u.path == "/favicon.ico": return self.out(204, b"", "image/x-icon")
        if u.path != "/": return self.out(404, "not found", "text/plain")
        code = parse_qs(u.query).get("code", [""])[0]
        if code:
            r = self.try_code(code)
            if r: return self.redirect(r)
        if self.authed():
            with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f: return self.page(f.read())
        self.page(LOGIN.replace("__MSG__", f"Too many attempts. Wait {C.LOCKOUT_MINUTES} minutes." if code and r is None else ""))
    def do_POST(self):
        if self.path == "/api/refresh":
            if not self.authed() or self.headers.get("X-Requested-With") != "secdash": return self.out(403, "{}")
            for ev in KICK.values(): ev.set()
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
        if r: return self.redirect(r)
        self.page(LOGIN.replace("__MSG__", f"Too many attempts. Wait {C.LOCKOUT_MINUTES} minutes." if r is None else "Wrong code."), 429 if r is None else 401)

def lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1)); return s.getsockname()[0]
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
    print(f"  │ GitHub token   : {'set' if TOKEN else 'not set (searches limited to 10/min; set GITHUB_TOKEN)'}")
    print(f"  │ Recorded Future: {'ON' if RF.get('token') else 'off (set RF_TOKEN)'}")
    print(f"  │ Dashboard TLS  : {'ON (HTTPS)' if TLS_CTX else 'off (plain HTTP: keep it on a trusted network, or set TLS in config.py)'}")
    print(f"  └─ Outgoing TLS  : {'verified' + (' + custom CA' if CA_BUNDLE else '') if VERIFY_SSL else 'NOT VERIFIED (SECDASH_VERIFY_SSL=0)'}\n")
    if C.OPEN_BROWSER:
        threading.Timer(1.5, lambda: webbrowser.open(f"{sch}://127.0.0.1:{port}/?code={CODE}")).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")

LOGIN = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Secdash</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;color:#f3ede2;font:16px system-ui,sans-serif;background:#0e0d0c}
form{width:min(360px,90vw);background:#171513;border:1px solid #2c2824;border-radius:14px;padding:28px;box-shadow:0 20px 60px #0008}
h1{margin:0 0 4px;font-size:22px;letter-spacing:.2em;color:#e9895a}
p{margin:0 0 18px;color:#a9a092;font-size:14px}
input{width:100%;font:700 24px ui-monospace,Menlo,Consolas,monospace;letter-spacing:.4em;text-align:center;text-transform:uppercase;padding:12px;border-radius:8px;border:1px solid #3d3731;background:#0e0d0c;color:#e9895a}
input:focus{outline:2px solid #e9895a;outline-offset:1px}
button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:8px;font:700 15px system-ui;color:#1a0e08;background:#e9895a;cursor:pointer}button:hover{background:#f1a07a}
.e{color:#f0605d;min-height:20px;margin-top:10px;font-size:14px;text-align:center}</style></head><body>
<form method="post" action="/login"><h1>◢ SECDASH</h1><p>Enter the access code shown in the terminal.</p>
<input name="code" maxlength="32" autocomplete="off" autofocus aria-label="Access code"><button>Unlock</button><div class="e">__MSG__</div></form></body></html>"""

if __name__ == "__main__":
    main()
