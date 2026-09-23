"""Config for Powerwall Dashboard — Fernet-encrypted secrets in config.json."""
import base64
import json
import os

from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
KEY_PATH = os.path.join(BASE_DIR, "config.key")

SECRET_KEYS = ("local_api_password", "enphase_token")

DEFAULTS = {
    "source": "tesla",   # "tesla" | "enphase"
    "gateway": "",    # e.g. https://192.168.x.x — set via dashboard config UI
    "username": "customer",
    "email": "",      # Tesla app account email (optional — set via config UI)
    "local_api_password": "",  # Fernet-encrypted on disk when set
    "enphase_token": "",       # IQ Gateway JWT (Bearer) — Fernet-encrypted when set
    "poll_interval_seconds": 10,
    "grid_import_rate": 0.0,   # ZAR per kWh imported from grid (user sets)
    "grid_export_credit": 0.0,  # ZAR per kWh exported (user said no credit)
}


def _fernet() -> Fernet:
    if os.path.isfile(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return Fernet(f.read())
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return Fernet(key)


def _enc(f: Fernet, plain: str) -> str:
    return base64.urlsafe_b64encode(f.encrypt(plain.encode())).decode()


def _dec(f: Fernet, token: str) -> str:
    return f.decrypt(base64.urlsafe_b64decode(token.encode())).decode()


def load() -> dict:
    cfg = dict(DEFAULTS)
    if os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        f = _fernet()
        for k, v in raw.items():
            if isinstance(v, str) and v.startswith("enc:"):
                try:
                    cfg[k] = _dec(f, v[len("enc:"):])
                except Exception:
                    cfg[k] = ""
            else:
                cfg[k] = v
    return cfg


def save(cfg: dict) -> None:
    f = _fernet()
    raw = {}
    for k, v in cfg.items():
        if k in SECRET_KEYS and v:
            raw[k] = "enc:" + _enc(f, v)
        else:
            raw[k] = v
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2)
    os.replace(tmp, CONFIG_PATH)


def ensure_config() -> dict:
    """Load config; if no file exists yet, persist the defaults."""
    cfg = load()
    if not os.path.isfile(CONFIG_PATH):
        save(cfg)
    return cfg
