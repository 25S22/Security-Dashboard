# ───────────── SECDASH CONFIG ─────────────  edit, save, then:  python run.py
import os

# ── Access ─────────────────────────────────────────────
ACCESS_CODE   = ""             # "" = new random 6-character code every run. Or set your own (6+ chars).
PORT          = 0              # 0 = pick a random free port from PORT_RANGE every run
PORT_RANGE    = (20000, 60000)
HOST          = "0.0.0.0"      # 0.0.0.0 = reachable on your WiFi/LAN. "127.0.0.1" = this machine only.
OPEN_BROWSER  = True

# ── How often each group refreshes (minutes). Everything also refreshes on every launch. ──
REFRESH_MINUTES = {"news": 10, "exploits": 45, "github": 30, "rf": 15, "meta": 30}

# ── Your stack: items mentioning these get a "MY STACK" badge + filter ──
KEYWORDS = ["apache", "nginx", "fortinet", "fortigate", "cisco", "palo alto", "openssl", "log4j",
            "microsoft", "exchange", "vmware", "citrix", "ivanti", "okta", "aws", "azure", "kubernetes"]

# ── Team triage + security ──
STACK_BOOST = 18           # priority points added when an item mentions something in KEYWORDS
TRIAGE_STATUSES = ["New", "Investigating", "Escalated", "Mitigated", "Ignored"]
MAX_LOGIN_FAILS = 5        # wrong codes allowed per device ...
LOCKOUT_MINUTES = 5        # ... before that device is locked out for this long

# ── Optional keys (config value, or the environment variable). Everything works without them. ──
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")   # free; makes GitHub refresh much faster (30 vs 10 searches/min)

# Recorded Future: leave token empty = feature OFF. With a token, an "RF Intelligence" panel appears
# (risk-scored vulnerabilities + your triggered alerts).  Keep the token private.
RECORDED_FUTURE = {
    "token": os.getenv("RF_TOKEN", ""),
    "vuln_params": {},     # extra /v2/vulnerability/search filters, e.g. {"riskRule": "recentMalwareActivity"}
    "alert_days": 7,       # alerts triggered in the last N days
    "alert_params": {},    # extra /v2/alert/search filters
}

# ── Content ────────────────────────────────────────────
NEWS_DAYS = 10             # drop articles older than this
KEV_COUNT = 30             # newest CISA "exploited in the wild" additions to show

GITHUB = {
    # Free-text OR groups: each group = ONE search call (x2 for Rising and Active, +1 for CVE PoCs = ~5 searches per cycle). GitHub caps queries at 5 ORs..
    "term_groups": [["pentest", "red team", "exploit", "osint", "bug bounty", "recon"],          # max 6 terms per group
                    ["dfir", "malware", "threat hunting", "ransomware", "siem", "incident response"]],
    "rising_days": 30,     # "Rising" = repos created in the last N days, ranked by stars/day
    "active_days": 3,      # "Active" = established repos (1000+ stars) pushed in the last N days
    "trending_langs": ["python", "go", "rust", "c", "c++", "javascript"],   # plus overall daily + weekly
}

FEEDS = [  # (name, url)  — add/remove freely; a dead feed just gets reported
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("The Record", "https://therecord.media/feed"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Talos", "https://blog.talosintelligence.com/rss/"),
    ("DFIR Report", "https://thedfirreport.com/feed/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Schneier", "https://www.schneier.com/feed/atom/"),
    ("r/netsec", "https://www.reddit.com/r/netsec/.rss"),
]
HN_QUERIES = ["CVE", "vulnerability", "exploit", "ransomware", "malware", "zero-day"]   # Hacker News, 20+ points
EXPLOIT_FEEDS = [("Packet Storm", "https://rss.packetstormsecurity.com/files/tags/exploit/")]
