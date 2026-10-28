import sqlite3

DB = "secdash.db"
SCHEMA = """
CREATE TABLE IF NOT EXISTS cves(id TEXT PRIMARY KEY, descr TEXT, cvss REAL, published TEXT, vendors TEXT,
  kev INTEGER DEFAULT 0, kev_added TEXT, kev_due TEXT, ransomware INTEGER DEFAULT 0,
  epss REAL DEFAULT 0, epss_pct REAL DEFAULT 0, ghsa INTEGER DEFAULT 0, mentions INTEGER DEFAULT 0,
  score REAL DEFAULT 0, watch INTEGER DEFAULT 0, first_seen INTEGER DEFAULT 0, summary TEXT,
  exploit_db INTEGER DEFAULT 0, metasploit INTEGER DEFAULT 0, nuclei INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tools(repo TEXT PRIMARY KEY, descr TEXT, stars INTEGER DEFAULT 0,
  base_stars INTEGER, lang TEXT, pushed TEXT, created TEXT, url TEXT, first_seen INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS news(url TEXT PRIMARY KEY, title TEXT, source TEXT, published TEXT, first_seen INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS iocs(id TEXT PRIMARY KEY, value TEXT, ioc_type TEXT, malware TEXT, source TEXT, seen TEXT, first_seen INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS ransom(id TEXT PRIMARY KEY, victim TEXT, grp TEXT, country TEXT, sector TEXT, discovered TEXT, first_seen INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS deps(id TEXT PRIMARY KEY, pkg TEXT, ecosystem TEXT, version TEXT, vuln TEXT, summary TEXT, cves TEXT, published TEXT, first_seen INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER);
CREATE TABLE IF NOT EXISTS status(src TEXT PRIMARY KEY, ok INTEGER, msg TEXT, ts INTEGER);
"""

def conn():
    c = sqlite3.connect(DB, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    have = {r[1] for r in c.execute("PRAGMA table_info(cves)")}
    for col in ("exploit_db", "metasploit", "nuclei"):  # migrate databases from earlier versions
        if col not in have:
            c.execute(f"ALTER TABLE cves ADD COLUMN {col} INTEGER DEFAULT 0")
    return c

def upsert(c, table, key, val, now, **fields):
    """Insert the row if new (stamping first_seen), then update only the given columns."""
    c.execute(f"INSERT OR IGNORE INTO {table}({key},first_seen) VALUES(?,?)", (val, now))
    if fields:
        sets = ",".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE {table} SET {sets} WHERE {key}=?", [*fields.values(), val])
