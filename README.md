# Secdash
Self-hosted threat-intel dashboard. No external AI or paid services; everything is free public data.

    pip install -r requirements.txt
    python app.py            # prints the LAN URL with access token
    python refresh.py        # optional one-off / cron refresh

Edit `config.yaml` for your watchlist, packages (OSV), feeds, port and refresh interval.

## Sources
| Source | Key? | Feeds |
|---|---|---|
| CISA KEV | no | actively exploited CVEs, ransomware flag, due dates |
| FIRST EPSS | no | exploit probability |
| NVD | optional | new CVEs + CVSS |
| GitHub advisories / new-tool search | optional token | advisories, trending new security repos |
| Metasploit + Nuclei + Exploit-DB | no | "public exploit exists" flags |
| OSV.dev | no | vulns in packages you list |
| Feodo Tracker (abuse.ch) | no | botnet C2 IPs |
| ThreatFox, URLhaus (abuse.ch) | free key | recent IOCs / malware URLs |
| ransomware.live PRO | free key | ransomware victims |
| SANS ISC InfoCon | no | global threat level |
| Shodan InternetDB, GreyNoise community | no / optional | on-demand IP lookup |
| 10 RSS feeds | no | news; CVE IDs in articles raise a CVE's score |

Keys go in environment variables named in `config.yaml`. Sources without keys show as "skipped".
LAN: allow the port in your firewall. Traffic is plain HTTP; keep it on a trusted network.
