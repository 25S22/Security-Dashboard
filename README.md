# Secdash

Live security dashboard. Four tabs:

1. **Overview**: news first, one article per line (scrollable), then the threat graph below it (one zone per node type, linked by shared CVE / technology / threat actor).
2. **Repos & Exploits**: GitHub trending / rising / active security repos, exploits in the wild (CISA KEV), public exploits (Exploit-DB, Metasploit), fresh GitHub PoCs, advisories, plus IOCs, ransomware, breaches.
3. **Recorded Future**: your RF vulnerabilities and alerts (pulled via the Connect API) plus an IOC lookup bar. Paste IPs, domains, URLs, file hashes or CVEs (several at once; defanged `hxxp://x[.]com` is repaired, private addresses are never sent). Each IOC gets its risk score, triggered rules with evidence, first/last seen, and a link to the RF portal. Needs `RF_TOKEN`.
4. **Search**: one keyword fans out to GitHub, NVD, Exploit-DB, Metasploit, CISA KEV, GitHub Advisories, OSV, Hacker News and Recorded Future (if configured); results stream in and become a navigable graph. Double-click a CVE / technology / actor node to search it next. An IP address gets Shodan InternetDB + GreyNoise.

## Run
    pip install -r requirements.txt
    python run.py
The terminal prints the URL and a one-time access code.

Optional (all via environment variables or config.py): `GITHUB_TOKEN` (3x search limit), `RF_TOKEN` (Recorded Future), `ABUSECH_AUTH_KEY`, `RANSOMWARE_LIVE_API_KEY`, `NVD_API_KEY`, `SECDASH_WEBHOOK`.
Behind a corporate proxy that re-signs HTTPS: set `SECDASH_CA_BUNDLE=/path/to/ca.pem`.

## Libraries
requests (HTTP + retries), feedparser (RSS/Atom), cachetools (TTL caches), d3 v7.9 (graph; vendored in static/vendor, no CDN).
