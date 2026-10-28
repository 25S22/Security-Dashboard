import ipaddress, pathlib, secrets, socket, threading, time
from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import config, fetchers, refresh
from db import conn

cfg = config.load()
lock = threading.Lock()

def do_refresh(first=False, force=False):
    if lock.acquire(blocking=False):  # ignore if a refresh is already running
        try:
            refresh.run(cfg, first, force)
        finally:
            lock.release()

def loop():
    c = conn()
    first = c.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0
    c.execute("INSERT INTO runs(ts) VALUES(?)", (int(time.time()),))  # "new" = new since this launch
    c.commit()
    do_refresh(first)
    while True:
        time.sleep(cfg["refresh_minutes"] * 60)
        do_refresh()

@asynccontextmanager
async def lifespan(app):
    threading.Thread(target=loop, daemon=True).start()
    yield

app = FastAPI(lifespan=lifespan)

@app.middleware("http")
async def auth(req: Request, nxt):
    tok = cfg["server"].get("token")
    if not tok:
        return await nxt(req)
    given = req.query_params.get("token") or req.cookies.get("sd") or ""
    if not secrets.compare_digest(given, tok):
        return JSONResponse({"error": "Access token required. Open the URL printed at startup."}, status_code=401)
    resp = await nxt(req)
    if req.query_params.get("token"):
        resp.set_cookie("sd", tok, httponly=True, samesite="lax")
    return resp

def since(c):
    return c.execute("SELECT MAX(ts) FROM runs").fetchone()[0] or 0

def flag(rows, s):
    return [{**dict(r), "new": r["first_seen"] >= s and r["first_seen"] > 0} for r in rows]

@app.get("/", response_class=HTMLResponse)
def index():
    return pathlib.Path("static/index.html").read_text()

@app.get("/api/overview")
def overview():
    c = conn(); s = since(c)
    q = lambda sql, *a: c.execute(sql, a).fetchone()[0]
    kv = {r["k"]: r["v"] for r in c.execute("SELECT * FROM kv")}
    return {"kev": q("SELECT COUNT(*) FROM cves WHERE kev=1"),
            "new": q("SELECT COUNT(*) FROM cves WHERE first_seen>=? AND first_seen>0", s),
            "watch": q("SELECT COUNT(*) FROM cves WHERE watch=1"),
            "armed": q("SELECT COUNT(*) FROM cves WHERE kev=1 AND (metasploit=1 OR nuclei=1 OR exploit_db=1)"),
            "infocon": kv.get("infocon", "n/a"), "refreshing": lock.locked(),
            "status": [dict(r) for r in c.execute("SELECT * FROM status")]}

@app.get("/api/cves")
def cves(q: str = "", f: str = "", limit: int = 300):
    c = conn(); s = since(c)
    where, args = ["1=1"], []
    if f == "kev": where.append("kev=1")
    elif f == "ransom": where.append("ransomware=1")
    elif f == "watch": where.append("watch=1")
    elif f == "exploit": where.append("(metasploit=1 OR nuclei=1 OR exploit_db=1)")
    elif f == "new": where.append("first_seen>=? AND first_seen>0"); args.append(s)
    if q:
        where.append("(id LIKE ? OR descr LIKE ? OR vendors LIKE ?)"); args += [f"%{q}%"] * 3
    rows = c.execute(f"SELECT * FROM cves WHERE {' AND '.join(where)} ORDER BY score DESC, published DESC LIMIT ?",
                     [*args, min(limit, 1000)]).fetchall()
    return flag(rows, s)

@app.get("/api/tools")
def tools():
    c = conn(); s = since(c)
    rows = c.execute("""SELECT *, stars*1.0/MAX(1, julianday('now')-julianday(created)) AS per_day
                        FROM tools ORDER BY per_day DESC LIMIT 100""").fetchall()
    return [{**r, "gained": r["stars"] - (r["base_stars"] or r["stars"])} for r in flag(rows, s)]

def simple(table, order):
    def handler():
        c = conn()
        return flag(c.execute(f"SELECT * FROM {table} ORDER BY {order} LIMIT 150").fetchall(), since(c))
    return handler

app.get("/api/news")(simple("news", "first_seen DESC, rowid DESC"))
app.get("/api/iocs")(simple("iocs", "first_seen DESC, seen DESC"))
app.get("/api/ransom")(simple("ransom", "discovered DESC, rowid DESC"))
app.get("/api/deps")(simple("deps", "first_seen DESC, rowid DESC"))

@app.post("/api/refresh")
def refresh_now():
    threading.Thread(target=do_refresh, kwargs={"force": True}, daemon=True).start()
    return {"started": True}

@app.get("/api/lookup/{ip}")
def lookup(ip: str):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse({"error": "Not a valid IP address."}, status_code=400)
    if not a.is_global:  # never send private/internal addresses to third parties
        return JSONResponse({"error": "Only public IP addresses can be looked up."}, status_code=400)
    c = conn()
    local = [dict(r) for r in c.execute("SELECT value,ioc_type,malware,source,seen FROM iocs WHERE value LIKE ? LIMIT 20", (f"{ip}%",))]
    return {"ip": ip, "local_iocs": local, **fetchers.lookup_ip(ip, cfg)}

def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    s = cfg["server"]
    host = lan_ip() if s["host"] == "0.0.0.0" else s["host"]
    print(f"\n  Dashboard: http://{host}:{s['port']}/" + (f"?token={s['token']}" if s.get("token") else "") + "\n")
    uvicorn.run(app, host=s["host"], port=s["port"], log_level="warning")
