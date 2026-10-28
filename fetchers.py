"""One function per source. Each takes (conn, cfg, now) and returns an item count."""
import csv, datetime as dt, hashlib, io, json, os, re, time
import feedparser, requests
from db import upsert

H = {"User-Agent": "secdash/1.0"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

def get(url, **kw):
    r = requests.get(url, headers={**H, **kw.pop("headers", {})}, timeout=45, **kw)
    r.raise_for_status()
    return r

class Skip(Exception):
    """Source not configured (e.g. missing free API key). Shown as 'skipped', not as a failure."""

def key(cfg, name, required=False):
    k = os.getenv(cfg["keys"][name], "")
    if required and not k:
        raise Skip(f"set {cfg['keys'][name]} (free key)")
    return k

def gh(cfg):
    t = key(cfg, "github")
    return {"Authorization": f"Bearer {t}"} if t else {}

def kev(c, cfg, now):
    vs = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json()["vulnerabilities"]
    for v in vs:
        upsert(c, "cves", "id", v["cveID"], now, descr=v.get("shortDescription"),
               vendors=f'{v["vendorProject"]} {v["product"]}', kev=1, kev_added=v["dateAdded"],
               kev_due=v["dueDate"], ransomware=int(v.get("knownRansomwareCampaignUse") == "Known"))
    return len(vs)

def nvd(c, cfg, now):
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=min(cfg["nvd_days"], 120))
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    nk = key(cfg, "nvd")
    h = {"apiKey": nk} if nk else {}
    idx = n = 0
    while True:
        d = get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=h, params={
            "pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
            "resultsPerPage": 2000, "startIndex": idx}).json()
        for it in d["vulnerabilities"]:
            v, m, cvss = it["cve"], it["cve"].get("metrics", {}), None
            for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if m.get(k):
                    cvss = m[k][0]["cvssData"]["baseScore"]
                    break
            desc = next((x["value"] for x in v["descriptions"] if x["lang"] == "en"), "")
            upsert(c, "cves", "id", v["id"], now, cvss=cvss, published=v["published"][:10])
            c.execute("UPDATE cves SET descr=COALESCE(descr,?) WHERE id=?", (desc, v["id"]))
            n += 1
        idx += d["resultsPerPage"]
        if idx >= d["totalResults"]:
            return n
        time.sleep(1 if nk else 6)  # NVD rate limit

def ghsa(c, cfg, now):
    n = 0
    for sev in ("critical", "high"):
        for a in get("https://api.github.com/advisories", headers=gh(cfg),
                     params={"severity": sev, "per_page": 50, "type": "reviewed"}).json():
            if not a.get("cve_id"):
                continue
            upsert(c, "cves", "id", a["cve_id"], now, ghsa=1, published=(a.get("published_at") or "")[:10])
            c.execute("UPDATE cves SET descr=COALESCE(descr,?), cvss=COALESCE(cvss,?) WHERE id=?",
                      (a["summary"], (a.get("cvss") or {}).get("score"), a["cve_id"]))
            n += 1
    return n

def news(c, cfg, now):
    """RSS feeds. CVE IDs found in new articles bump that CVE's 'mentions' (early exploitation signal)."""
    n, bad = 0, []
    for f in cfg["feeds"]:
        try:
            entries = feedparser.parse(get(f["url"]).content).entries[:30]
        except Exception:
            bad.append(f["name"])
            continue
        for e in entries:
            url = e.get("link")
            if not url:
                continue
            cur = c.execute("INSERT OR IGNORE INTO news(url,title,source,published,first_seen) VALUES(?,?,?,?,?)",
                            (url, e.get("title", ""), f["name"], e.get("published", ""), now))
            if cur.rowcount:
                n += 1
                text = e.get("title", "") + " " + e.get("summary", "")
                for cid in {x.upper() for x in CVE_RE.findall(text)}:
                    upsert(c, "cves", "id", cid, now)
                    c.execute("UPDATE cves SET mentions=mentions+1 WHERE id=?", (cid,))
    return f"{n} new articles" + (f"; feeds failed: {', '.join(bad)}" if bad else "")

def epss(c, cfg, now):
    ids = [r[0] for r in c.execute("SELECT id FROM cves")]
    n = 0
    for i in range(0, len(ids), 100):
        for x in get("https://api.first.org/data/v1/epss", params={"cve": ",".join(ids[i:i + 100])}).json()["data"]:
            c.execute("UPDATE cves SET epss=?, epss_pct=? WHERE id=?", (float(x["epss"]), float(x["percentile"]), x["cve"]))
            n += 1
    return n

def tools(c, cfg, now):
    since = (dt.date.today() - dt.timedelta(days=cfg["tool_days"])).isoformat()
    n = 0
    for t in cfg["tool_topics"]:
        d = get("https://api.github.com/search/repositories", headers=gh(cfg), params={
            "q": f"topic:{t} created:>{since}", "sort": "stars", "order": "desc", "per_page": 20}).json()
        for r in d.get("items", []):
            old = c.execute("SELECT base_stars FROM tools WHERE repo=?", (r["full_name"],)).fetchone()
            upsert(c, "tools", "repo", r["full_name"], now, descr=r["description"], stars=r["stargazers_count"],
                   base_stars=old[0] if old and old[0] is not None else r["stargazers_count"],
                   lang=r["language"], pushed=r["pushed_at"][:10], created=r["created_at"][:10], url=r["html_url"])
            n += 1
        time.sleep(3)  # unauthenticated search limit is ~10 req/min
    return n

# ---------- exploit availability (enriches CVEs already in the DB) ----------
MSF = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
NUCLEI = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
EDB = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

def exploits(c, cfg, now):
    """Which CVEs have a Metasploit module, a Nuclei template, or an Exploit-DB entry."""
    sets, notes = {"metasploit": set(), "nuclei": set(), "exploit_db": set()}, []
    try:
        for m in get(MSF).json().values():
            sets["metasploit"] |= {x.upper() for x in m.get("references", []) if x.upper().startswith("CVE-")}
    except Exception as e:
        notes.append(f"metasploit failed: {str(e)[:60]}")
    try:
        for line in get(NUCLEI).text.splitlines():
            try:
                sets["nuclei"].add(json.loads(line)["ID"].upper())
            except Exception:
                pass
    except Exception as e:
        notes.append(f"nuclei failed: {str(e)[:60]}")
    try:
        for r in csv.DictReader(io.StringIO(get(EDB).text)):
            sets["exploit_db"] |= {x.strip().upper() for x in (r.get("codes") or "").split(";") if x.upper().startswith("CVE-")}
    except Exception as e:
        notes.append(f"exploit-db failed: {str(e)[:60]}")
    for col, ids in sets.items():
        if ids:  # keep old flags if a source failed
            c.execute(f"UPDATE cves SET {col}=0")
            c.executemany(f"UPDATE cves SET {col}=1 WHERE id=?", [(i,) for i in ids])
    if not any(sets.values()):
        raise RuntimeError("; ".join(notes))
    return f"{sum(len(s) for s in sets.values())} exploit refs" + (f" ({'; '.join(notes)})" if notes else "")

# ---------- IOCs ----------
def add_ioc(c, now, source, value, typ, malware, seen):
    return c.execute("INSERT OR IGNORE INTO iocs(id,value,ioc_type,malware,source,seen,first_seen) VALUES(?,?,?,?,?,?,?)",
                     (f"{source}|{value}", value, typ, malware, source, seen, now)).rowcount

def feodo(c, cfg, now):
    d = get("https://feodotracker.abuse.ch/downloads/ipblocklist.json").json()
    d = d if isinstance(d, list) else next((v for v in d.values() if isinstance(v, list)), [])
    return sum(add_ioc(c, now, "Feodo C2", f'{x["ip_address"]}:{x.get("port", "")}', "ip:port",
                       x.get("malware"), x.get("first_seen")) for x in d)

def threatfox(c, cfg, now):
    k = key(cfg, "abusech", True)
    d = requests.post("https://threatfox-api.abuse.ch/api/v1/", headers={**H, "Auth-Key": k},
                      json={"query": "get_iocs", "days": 1}, timeout=45).json()
    if d.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox: {d.get('query_status')} {str(d.get('data', ''))[:80]}")
    return sum(add_ioc(c, now, "ThreatFox", x["ioc"], x["ioc_type"], x.get("malware_printable"), x.get("first_seen_utc"))
               for x in d["data"])

def urlhaus(c, cfg, now):
    k = key(cfg, "abusech", True)
    d = get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/", headers={"Auth-Key": k}).json()
    if d.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus: {d.get('query_status')}")
    return sum(add_ioc(c, now, "URLhaus", x["url"], "url", x.get("threat") or ",".join(x.get("tags") or []), x.get("date_added"))
               for x in d["urls"])

# ---------- ransomware victims (ransomware.live PRO, free key) ----------
def ransomware(c, cfg, now):
    k = key(cfg, "ransomware_live", True)
    d = get("https://api-pro.ransomware.live/victims/recent", headers={"X-API-KEY": k}).json()
    d = d if isinstance(d, list) else next((v for v in d.values() if isinstance(v, list)), [])
    n = 0
    for v in d:
        name = v.get("victim") or v.get("post_title") or v.get("name") or "?"
        grp, when = v.get("group") or v.get("group_name") or "?", v.get("discovered") or v.get("attackdate") or ""
        rid = str(v.get("id") or hashlib.sha1(f"{name}{grp}{when}".encode()).hexdigest()[:16])
        n += c.execute("INSERT OR IGNORE INTO ransom(id,victim,grp,country,sector,discovered,first_seen) VALUES(?,?,?,?,?,?,?)",
                       (rid, name, grp, v.get("country"), v.get("activity") or v.get("sector"), str(when)[:10], now)).rowcount
    return n

# ---------- your dependencies (OSV.dev, no key) ----------
def osv(c, cfg, now):
    if not cfg.get("packages"):
        raise Skip("add packages to config.yaml")
    n = 0
    for p in cfg["packages"]:
        d = requests.post("https://api.osv.dev/v1/query", headers=H, timeout=30, json={
            "package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": str(p["version"])}).json()
        for v in d.get("vulns", []):
            cves = ",".join(a for a in v.get("aliases", []) if a.startswith("CVE-"))
            n += c.execute("INSERT OR IGNORE INTO deps(id,pkg,ecosystem,version,vuln,summary,cves,published,first_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                           (f'{p["name"]}@{p["version"]}|{v["id"]}', p["name"], p["ecosystem"], str(p["version"]), v["id"],
                            v.get("summary") or (v.get("details") or "")[:200], cves, (v.get("published") or "")[:10], now)).rowcount
    return n

# ---------- global threat level (SANS ISC InfoCon) ----------
def infocon(c, cfg, now):
    lvl = get("https://isc.sans.edu/api/infocon?json").json().get("status", "unknown")
    c.execute("INSERT OR REPLACE INTO kv VALUES('infocon',?)", (lvl,))
    return f"level {lvl}"

# ---------- on-demand IP lookup (not stored) ----------
def lookup_ip(ip, cfg):
    out = {}
    try:
        out["shodan_internetdb"] = requests.get(f"https://internetdb.shodan.io/{ip}", headers=H, timeout=15).json()
    except Exception as e:
        out["shodan_internetdb"] = {"error": str(e)[:100]}
    gk = key(cfg, "greynoise")
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers={**H, **({"key": gk} if gk else {})}, timeout=15)
        out["greynoise_community"] = r.json()
    except Exception as e:
        out["greynoise_community"] = {"error": str(e)[:100]}
    return out
