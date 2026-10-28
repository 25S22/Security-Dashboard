def compute(r, watchlist):
    """Priority 0-100: exploited > likely to be exploited > weaponized > severe. Watchlist hit adds a boost."""
    s = (40 * r["kev"] + 30 * (r["epss"] or 0) + 15 * (r["cvss"] or 0) / 10
         + 5 * min(r["mentions"], 3) / 3 + 10 * r["ransomware"]
         + 8 * int(bool(r["metasploit"] or r["nuclei"] or r["exploit_db"])))
    hay = f'{r["vendors"] or ""} {r["descr"] or ""}'.lower()
    w = int(any(t.lower() in hay for t in watchlist))
    return round(min(100, s + 10 * w), 1), w
