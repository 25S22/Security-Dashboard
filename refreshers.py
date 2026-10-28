"""Pull every source, rescore everything. Run standalone: python refresh.py"""
import time
import config, fetchers as F
from db import conn
from score import compute

# (name, function, minimum hours between runs). Order matters: exploit flags apply to CVEs already collected.
STEPS = [("CISA KEV", F.kev, 0), ("NVD recent", F.nvd, 0), ("GitHub advisories", F.ghsa, 0), ("News feeds", F.news, 0),
         ("Exploit availability", F.exploits, 12), ("EPSS", F.epss, 0), ("Feodo C2", F.feodo, 0),
         ("ThreatFox", F.threatfox, 0), ("URLhaus", F.urlhaus, 0), ("Ransomware victims", F.ransomware, 0),
         ("Your dependencies (OSV)", F.osv, 0), ("InfoCon", F.infocon, 0), ("New tools", F.tools, 0)]

def run(cfg, first=False, force=False):
    c = conn()
    now = 0 if first else int(time.time())  # first run: nothing is flagged "new"
    for name, fn, hours in STEPS:
        last = c.execute("SELECT ok, ts FROM status WHERE src=?", (name,)).fetchone()
        if hours and last and last["ok"] == 1 and time.time() - last["ts"] < hours * 3600 and not force:
            continue  # heavy downloads don't need to run every cycle
        try:
            r = fn(c, cfg, now)
            ok, msg = 1, r if isinstance(r, str) else f"{r} items"
        except F.Skip as e:
            ok, msg = 2, str(e)
        except Exception as e:  # one dead source must not stop the rest
            ok, msg = 0, str(e)[:200]
        c.execute("INSERT OR REPLACE INTO status VALUES(?,?,?,?)", (name, ok, msg, int(time.time())))
        c.commit()
        print(f"[{['FAIL', 'ok', 'skip'][ok]}] {name}: {msg}")
    for r in c.execute("SELECT * FROM cves").fetchall():
        s, w = compute(r, cfg["watchlist"])
        c.execute("UPDATE cves SET score=?, watch=? WHERE id=?", (s, w, r["id"]))
    c.commit()

if __name__ == "__main__":
    c = conn()
    first = c.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0
    c.execute("INSERT INTO runs(ts) VALUES(?)", (int(time.time()),))
    c.commit()
    run(config.load(), first, force=True)
