"""Secdash settings. Edit freely. Secrets can also come from environment variables so they never hit disk."""
import os

E = os.environ.get

# ── server ────────────────────────────────────────────────────────────────
HOST = E("SECDASH_HOST", "0.0.0.0")          # "127.0.0.1" = this machine only; "0.0.0.0" = reachable on your WiFi (access code required)
PORT = int(E("SECDASH_PORT", "0"))           # 0 = random free port from PORT_RANGE
PORT_RANGE = (20000, 60000)
OPEN_BROWSER = E("SECDASH_OPEN_BROWSER", "1") == "1"
ACCESS_CODE = E("SECDASH_CODE", "")          # empty = random 6-character code printed at start-up
MAX_LOGIN_FAILS, LOCKOUT_MINUTES = 5, 10

# HTTPS for the dashboard itself, e.g. {"cert": "cert.pem", "key": "key.pem", "password": "", "hostname": "box.local"}
TLS = {}
# Outgoing requests (feeds, GitHub, APIs)
VERIFY_SSL = E("SECDASH_VERIFY_SSL", "1") == "1"
CA_BUNDLE = E("SECDASH_CA_BUNDLE", "")       # extra root CA (.pem), e.g. a corporate proxy that re-signs HTTPS; added to certifi's roots

# ── API keys (all optional) ───────────────────────────────────────────────
GITHUB_TOKEN = E("GITHUB_TOKEN", "")         # no scopes needed; raises the search limit from 10/min to 30/min
NVD_KEY = E("NVD_API_KEY", "")               # free at nvd.nist.gov/developers; speeds up NVD search
ABUSECH_KEY = E("ABUSECH_AUTH_KEY", "")      # free at abuse.ch: enables ThreatFox + URLhaus
RANSOMWARE_KEY = E("RANSOMWARE_LIVE_API_KEY", "")
GREYNOISE_KEY = E("GREYNOISE_API_KEY", "")
RECORDED_FUTURE = {
    "token": E("RF_TOKEN", ""),              # Connect API token; empty = Recorded Future is off
    "vuln_params": {"orderby": "Criticality", "direction": "desc"},
    "alert_params": {},
    "alert_days": 7,
}

# ── what to collect ───────────────────────────────────────────────────────
REFRESH_MINUTES = {"news": 15, "exploits": 30, "github": 45, "threats": 30, "intel": 120, "rf": 30}
NEWS_DAYS = 10
KEV_COUNT = 40
HN_QUERIES = ["vulnerability", "exploit", "ransomware", "zero-day", "malware", "CVE"]

FEEDS = [  # (name, url). A feed that is unreachable is reported in the footer and skipped.
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Schneier", "https://www.schneier.com/feed/atom/"),
    ("Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("Talos", "https://blog.talosintelligence.com/rss/"),
    ("Unit 42", "https://feeds.feedburner.com/Unit42"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed.xml"),
    ("PortSwigger Research", "https://portswigger.net/research/rss"),
    ("Zero Day Initiative", "https://www.zerodayinitiative.com/rss/published/"),
    ("MSRC", "https://msrc.microsoft.com/blog/feed"),
    ("CISA Alerts", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
]
EXPLOIT_FEEDS = [("Packet Storm", "https://rss.packetstormsecurity.com/files/tags/exploit/")]

GITHUB = {
    "term_groups": [   # each group = one search (max 6 terms, OR-ed). Add your own.
        ["exploit", "poc", "cve", "vulnerability", "rce", "0day"],
        ["pentest", "red-team", "redteam", "offensive-security", "c2", "post-exploitation"],
        ["malware", "ransomware", "malware-analysis", "reverse-engineering", "dfir", "threat-hunting"],
        ["osint", "recon", "nuclei", "fuzzing", "burp", "bug-bounty"],
        ["edr", "siem", "detection-engineering", "sigma", "yara", "ctf"],
        ["llm-security", "prompt-injection", "jailbreak", "ai-security"],
    ],
    "rising_days": 14,
    "active_days": 7,
    "trending_langs": ["python", "go", "rust", "c", "javascript", "shell"],
}

PACKAGES = [   # your own dependencies, checked against OSV.  {"name": "django", "ecosystem": "PyPI", "version": "4.2.1"}
]

# ── your stack and how things are ranked ──────────────────────────────────
KEYWORDS = ["wordpress", "php", "exchange", "fortinet", "citrix", "vmware", "log4j", "openssl", "linux kernel"]
STACK_BOOST = 15
# Vendors / products / technologies recognised in titles so related items link up in the graph.
TECH_TERMS = [
    "microsoft", "windows", "exchange", "sharepoint", "active directory", "office", "outlook", "azure", "entra",
    "linux", "linux kernel", "android", "ios", "macos", "chrome", "firefox", "safari", "edge",
    "fortinet", "fortigate", "fortios", "palo alto", "pan-os", "cisco", "juniper", "sonicwall", "f5", "big-ip", "checkpoint",
    "citrix", "netscaler", "vmware", "esxi", "vcenter", "ivanti", "connect secure", "veeam", "solarwinds", "progress", "moveit",
    "apache", "nginx", "tomcat", "struts", "openssl", "openssh", "log4j", "spring", "php", "wordpress", "drupal", "joomla",
    "jenkins", "gitlab", "github", "atlassian", "confluence", "jira", "docker", "kubernetes", "terraform",
    "oracle", "sap", "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
    "aws", "google cloud", "cloudflare", "okta", "zoom", "slack", "npm", "pypi", "chatgpt", "openai", "copilot",
]

TRIAGE_STATUSES = ["New", "Investigating", "Escalated", "Mitigated", "Ignored"]
ALERTS = {"webhook": E("SECDASH_WEBHOOK", ""), "min_priority": 70}   # Slack / Teams / Discord incoming webhook URL
