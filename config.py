# -*- coding: utf-8 -*-
"""Config for Powerwall Dashboard — Fernet-encrypted secrets in config.json.

Fix 5 (secrets at rest): on Windows the Fernet key is protected with DPAPI
(win32crypt.CryptProtectData) and stored as config.key.dpapi; the plaintext
config.key is migrated automatically and then deleted. On non-Windows (or if
pywin32 is unavailable) it falls back to the plaintext config.key and logs a
warning. Where the platform allows, config.json and the key file are chmod 0600.
"""
import base64
import json
import logging
import os

from cryptography.fernet import Fernet

log = logging.getLogger("config")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
KEY_PATH = os.path.join(BASE_DIR, "config.key")
KEY_DPAPI_PATH = os.path.join(BASE_DIR, "config.key.dpapi")

SECRET_KEYS = ("local_api_password", "enphase_token", "ui_password_hash")


def _restrict(path):
    """Tighten a file to owner-only (chmod 0600) where the platform allows it."""
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass  # e.g. Windows, or a path that cannot be chmod'd


def _dpapi_available():
    if os.name != "nt":
        return False
    try:
        import win32crypt  # noqa: F401
        return True
    except Exception:
        return False


def _dpapi_protect(blob: bytes) -> bytes:
    import win32crypt
    return win32crypt.CryptProtectData(blob)


def _dpapi_unprotect(blob: bytes) -> bytes:
    import win32crypt
    return win32crypt.CryptUnprotectData(blob)[1]

DEFAULTS = {
    "source": "tesla",   # "tesla" | "enphase"
    "gateway": "",    # Tesla gateway, e.g. https://192.168.x.x (set via config API/UI)
    "enphase_gateway": "",  # Enphase IQ Gateway, e.g. https://<ip> (falls back to "gateway")
    "username": "customer",
    "email": "",      # Tesla app account email (optional — set via config UI)
    "local_api_password": "",  # Fernet-encrypted on disk when set
    "enphase_token": "",       # IQ Gateway JWT (Bearer) — Fernet-encrypted when set
    "poll_interval_seconds": 10,
    "grid_import_rate": 0.0,   # ZAR per kWh imported from grid (user sets)
    "grid_export_credit": 0.0,  # ZAR per kWh exported (user said no credit)
    # --- web security ---
    "ui_username": "admin",       # HTTP Basic username for the dashboard
    "ui_password_hash": "",       # werkzeug hash (Fernet-encrypted at rest when set)
    "bind_host": "127.0.0.1",    # set "0.0.0.0" to listen on the LAN (auth still applies)
    "allowed_hosts": [],          # extra Host values to allow (merged with defaults + LAN IPs)
    "gateway_cert_sha256": "",    # Tesla gateway TLS SHA-256 pin (hex; TOFU on first connect)
    "enphase_cert_sha256": "",    # Enphase IQ Gateway TLS SHA-256 pin (hex; TOFU)
}


def _fernet() -> Fernet:
    # 1) DPAPI-protected key (preferred on Windows).
    if os.path.isfile(KEY_DPAPI_PATH):
        try:
            with open(KEY_DPAPI_PATH, "rb") as f:
                blob = f.read()
            return Fernet(_dpapi_unprotect(blob))
        except Exception as e:
            log.warning("DPAPI key read failed (%s); falling back", e)
    # 2) Plaintext key (fallback, or the pre-migration state).
    if os.path.isfile(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            key = f.read()
        if _dpapi_available():
            try:  # migrate: protect + replace the plaintext key
                with open(KEY_DPAPI_PATH, "wb") as f:
                    f.write(_dpapi_protect(key))
                _restrict(KEY_DPAPI_PATH)
                os.remove(KEY_PATH)
                log.info("migrated config.key -> config.key.dpapi (DPAPI); "
                         "plaintext key removed")
                return Fernet(key)
            except Exception as e:
                log.warning("DPAPI migration failed (%s); using plaintext key", e)
        else:
            log.warning("config.key is plaintext (DPAPI unavailable) — the "
                        "Fernet key is unencrypted at rest")
        return Fernet(key)
    # 3) Generate a fresh key.
    key = Fernet.generate_key()
    if _dpapi_available():
        try:
            with open(KEY_DPAPI_PATH, "wb") as f:
                f.write(_dpapi_protect(key))
            _restrict(KEY_DPAPI_PATH)
        except Exception as e:
            log.warning("could not store DPAPI key (%s); using plaintext", e)
            with open(KEY_PATH, "wb") as f:
                f.write(key)
            _restrict(KEY_PATH)
    else:
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        _restrict(KEY_PATH)
        log.warning("config.key stored as plaintext (DPAPI unavailable)")
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
    _restrict(tmp)
    os.replace(tmp, CONFIG_PATH)
    _restrict(CONFIG_PATH)


def hash_password(pw: str) -> str:
    from werkzeug.security import generate_password_hash
    return generate_password_hash(pw)


def set_ui_password(pw: str) -> dict:
    """Set a new UI password (hash only; the plaintext is never stored or logged)."""
    cfg = load()
    cfg["ui_password_hash"] = hash_password(pw)
    save(cfg)
    print("UI password updated (hash stored; plaintext not kept).", flush=True)
    return cfg


def ensure_config() -> dict:
    """Load config; if no file exists yet, persist the defaults."""
    cfg = load()
    if not os.path.isfile(CONFIG_PATH):
        save(cfg)
    return cfg
