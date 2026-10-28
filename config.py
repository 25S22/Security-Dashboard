import pathlib, secrets, yaml

def load():
    cfg = yaml.safe_load(open("config.yaml"))
    s = cfg["server"]
    if s["host"] not in ("127.0.0.1", "localhost") and not s.get("token"):
        p = pathlib.Path(".token")
        if not p.exists():
            p.write_text(secrets.token_urlsafe(16))
        s["token"] = p.read_text().strip()
    return cfg
