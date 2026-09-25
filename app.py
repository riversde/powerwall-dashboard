"""Powerwall Dashboard — Flask + Waitress + APScheduler.

Serves the SPA at /, REST endpoints under /api/, and polls the Powerwall
gateway on a fixed interval (threaded timeout per cycle).
"""
import logging
import os
import socket
import threading
import time
from getpass import getpass
from werkzeug.security import check_password_hash

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, Response, abort, g, jsonify, render_template, request

import config
import powerwall
import storage

# ---- logging ----
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
from logging.handlers import RotatingFileHandler
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        RotatingFileHandler(
            os.path.join(LOG_DIR, "powerwall.log"),
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=5,
            encoding="utf-8",
        ),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("app")

app = Flask(__name__)
# Re-read templates on change so edits are never served stale across restarts.
app.config["TEMPLATES_AUTO_RELOAD"] = True


def _lan_ips() -> list:
    """Best-effort list of this machine's LAN IPv4 addresses."""
    ips = set()
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    try:
        # the address the OS would use to reach the public internet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    return sorted(ips)


# Item 7: the LAN interface IPs (gethostbyname + a UDP connect) must NOT be
# recomputed on every request (DNS/UDP on the hot path). Compute once,
# refresh at most every 10 minutes.
_LAN_IPS_TTL_S = 600.0
_lan_ips_lock = threading.Lock()
_lan_ips_cache = {"ts": 0.0, "ips": []}


def _lan_ips_cached() -> list:
    with _lan_ips_lock:
        now = time.time()
        if not _lan_ips_cache["ips"] or now - _lan_ips_cache["ts"] >= _LAN_IPS_TTL_S:
            _lan_ips_cache["ips"] = _lan_ips()
            _lan_ips_cache["ts"] = now
        return _lan_ips_cache["ips"]


def _allowed_hosts(cfg) -> set:
    hosts = {"127.0.0.1", "localhost"}
    hosts.update(_lan_ips_cached())
    for h in (cfg.get("allowed_hosts") or []):
        h = str(h).strip().lower()
        if h:
            hosts.add(h)
    return hosts


@app.before_request
def _csp_nonce_request():
    # Per-request CSP nonce (shared by the inline <script>/<style> and the header).
    import base64, secrets as _s
    g.csp_nonce = base64.b64encode(_s.token_bytes(16)).decode("ascii")


@app.after_request
def _security_headers(resp):
    nonce = getattr(g, "csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        # style-src uses 'unsafe-inline' (no nonce): a nonce on style-src makes
        # the browser IGNORE 'unsafe-inline', and a nonce never covers the 78+
        # inline style="…" attributes in the markup. So the inline styles are
        # permitted via 'unsafe-inline'; the <style> block is covered too.
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ---- failed-login throttle (per-IP sliding window) ----
# 10 failed credential attempts within a 10-minute window -> locked out for
# 5 minutes. The lockout is checked BEFORE the credentials are evaluated, so a
# correct password cannot win while an IP is locked (the throttle actually
# slows brute force). Thread-safe (Waitress runs 8 threads) and bounded
# (at most 10,000 tracked IPs; the oldest are evicted).

_throttle = {}  # {ip: {"fails": int, "first": ts, "locked_until": ts}}
_throttle_lock = threading.Lock()
_THR_MAX_IPS = 10_000
_THR_WINDOW_S = 600   # 10 minutes
_THR_MAX_FAILS = 10
_THR_LOCK_S = 300     # 5 minutes


def _record_failure(ip: str, now: float) -> bool:
    """Record one failed credential attempt. Returns True if this attempt
    *triggered* a new lockout (so the caller can log it at WARNING)."""
    with _throttle_lock:
        rec = _throttle.get(ip)
        if rec is None:
            rec = {"fails": 0, "first": now, "locked_until": 0.0}
        elif now - rec["first"] > _THR_WINDOW_S:
            # window expired -> reset the counter
            rec["fails"], rec["first"], rec["locked_until"] = 0, now, 0.0
        was_locked = now < rec["locked_until"]
        if not was_locked:
            rec["fails"] += 1
            if rec["fails"] >= _THR_MAX_FAILS:
                rec["locked_until"] = now + _THR_LOCK_S
        _throttle[ip] = rec
        # cap the size: evict the oldest (longest-standing window start)
        if len(_throttle) > _THR_MAX_IPS:
            for k in sorted(_throttle, key=lambda k: _throttle[k]["first"])[:100]:
                _throttle.pop(k, None)
        return (not was_locked) and rec["fails"] == _THR_MAX_FAILS


@app.before_request
def _security_gate():
    # /health is the one route that must work with no auth (health checks).
    if request.path == "/health":
        return None
    ip = request.remote_addr or "unknown"
    # DNS-rebinding guard: the Host header must be a known interface, no port.
    # Item 7: a MISSING or EMPTY Host is a bypass of that guard — reject it
    # with 400 (never fall through to the un-checked path).
    raw_host = request.headers.get("Host") or ""
    if not raw_host.strip():
        log.warning("rejected request: missing/empty Host header from %s", ip)
        abort(400)
    req_host = raw_host.split(":")[0].lower()
    if req_host not in _allowed_hosts(cfg):
        log.warning("rejected request: disallowed Host %r", req_host)
        abort(400)
    # 1) Lockout check FIRST — never evaluate the credentials while the IP is
    #    locked, so a correct password cannot win during the lockout.
    now = time.time()
    with _throttle_lock:
        rec = _throttle.get(ip)
        locked_until = rec["locked_until"] if rec else 0.0
        fails = rec["fails"] if rec else 0
    if fails >= _THR_MAX_FAILS and now < locked_until:
        resp = make_response_401()
        resp.headers["Retry-After"] = str(max(1, int(locked_until - now)))
        return resp
    # 2) Credential check (constant-time via werkzeug).
    auth = request.authorization
    if auth and auth.username == cfg.get("ui_username", "admin") and check_password_hash(
            cfg.get("ui_password_hash") or "", auth.password or ""):
        # success -> reset this IP's counter
        with _throttle_lock:
            _throttle.pop(ip, None)
        return None
    # 3) A credential attempt that failed -> record it (log any new lockout).
    if auth is not None and _record_failure(ip, time.time()):
        log.warning("login lockout triggered for %s (10 failures in 10 min; "
                   "locked for 5 min)", ip)
    return make_response_401()


def make_response_401():
    from flask import Response
    r = Response("Authentication required.", status=401, mimetype="text/plain")
    r.headers["WWW-Authenticate"] = 'Basic realm="powerwall-dashboard"'
    return r


# ---- CSRF guard for state-changing (POST) routes ----
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "powerwall-dashboard"


def _csrf_check():
    """Reject non-browser/SPA cross-origin mutations. Returns an error response
    or None. Order: missing custom header -> 403; wrong content-type -> 400;
    Origin present but mismatched -> 403."""
    if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        return Response("Missing %s header." % CSRF_HEADER, status=403,
                       mimetype="text/plain")
    if not (request.content_type or "").startswith("application/json"):
        return Response("Content-Type must be application/json.", status=400,
                       mimetype="text/plain")
    origin = request.headers.get("Origin")
    if origin:
        from urllib.parse import urlparse
        try:
            ohost = urlparse(origin).hostname or ""
        except Exception:
            ohost = ""
        req_host = (request.host or "").split(":")[0].lower()
        if ohost and ohost.lower() != req_host:
            return Response("Origin does not match request host.", status=403,
                           mimetype="text/plain")
    return None

# ---- Fix 3: gateway URL + field validation ----
import ipaddress
from urllib.parse import urlparse


def _valid_gateway(value) -> bool:
    """An https:// URL whose host is a private/link-local IP (not loopback,
    not multicast) or a hostname ending in .local. No path, query or userinfo."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    try:
        p = urlparse(v)
    except Exception:
        return False
    if p.scheme != "https":
        return False
    host = (p.hostname or "").lower()
    if not host or p.query or p.path or p.fragment:
        return False
    if p.username is not None:  # userinfo (https://user:pass@host)
        return False
    if host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_multicast or not ip.is_private:
        return False
    return True


def _validate_updatable(data: dict) -> list:
    """Type/whitelist checks; returns a list of error strings (empty = OK).
    Unknown keys are silently ignored by the caller."""
    errs = []
    if "source" in data and data["source"] not in ("tesla", "enphase"):
        errs.append("source must be 'tesla' or 'enphase'")
    if "poll_interval_seconds" in data:
        v = data["poll_interval_seconds"]
        if not isinstance(v, int) or isinstance(v, bool) or not (10 <= v <= 3600):
            errs.append("poll_interval_seconds must be an int 10-3600")
    for k in ("grid_import_rate", "grid_export_credit"):
        if k in data:
            v = data[k]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not (0 <= float(v) <= 100):
                errs.append(f"{k} must be a number 0-100")
    for k in ("username", "email"):
        if k in data:
            v = data[k]
            if not isinstance(v, str) or len(v) > 128:
                errs.append(f"{k} must be a string of 128 chars or fewer")
    return errs


# ---- state (module scope — NOT in before_request, per SQLite WAL rules) ----
cfg = config.ensure_config()
# Item 7: one-shot migration — if the source is enphase but enphase_gateway
# is empty, copy gateway into it ONCE, save, and log. After this, the
# Enphase client uses ONLY enphase_gateway (no fallback), so a Tesla
# gateway change can never redirect the Enphase JWT.
if cfg.get("source", "tesla") == "enphase" and not (cfg.get("enphase_gateway") or "").strip() \
        and (cfg.get("gateway") or "").strip():
    cfg["enphase_gateway"] = cfg["gateway"]
    config.save(cfg)
    log.warning("enphase_gateway was empty — one-shot migration: copied "
                "gateway (%s) into enphase_gateway. Enphase now uses only "
                "enphase_gateway.", cfg["enphase_gateway"])
storage.init_db()
storage.maybe_rollup()


def build_source(cfg):
    """Return (module, client) for the configured source.
    powerwall: Tesla gateway; enphase: IQ Gateway (backbone v07)."""
    if cfg.get("source", "tesla") == "enphase":
        import enphase
        return enphase, enphase.EnphaseIQGateway(cfg)
    return powerwall, powerwall.PowerwallClient(cfg)


poll_mod, client = build_source(cfg)
scheduler = None
storage.latest_snapshot = storage.get_latest()

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 8771


# ---- polling ----
def _poll_cycle():
    global scheduler
    try:
        res = poll_mod.poll_once(cfg, client)
        storage.poll_state["last_poll"] = time.strftime("%Y-%m-%d %H:%M:%S")
        storage.poll_state["poll_count"] += 1
        if res.get("ok"):
            storage.latest_snapshot = res["snapshot"]
            storage.poll_state["last_error"] = None
        else:
            storage.poll_state["last_error"] = res.get("error")
            if storage.latest_snapshot is not None:
                storage.latest_snapshot["reachable"] = False
    except Exception as e:
        log.exception("poll cycle failed")
        storage.poll_state["last_error"] = str(e)
    storage.maybe_rollup()


def start_polling():
    global scheduler
    try:
        if scheduler is None:
            scheduler = BackgroundScheduler(daemon=True)
        interval = max(int(cfg.get("poll_interval_seconds", 30)), 10)
        scheduler.add_job(_poll_cycle, "interval", seconds=interval,
                         id="powerwall_poll", max_instances=1, coalesce=True)
        if not scheduler.running:
            scheduler.start()
        storage.poll_state["polling_active"] = True
        log.info("polling started, interval=%ss", interval)
    except NameError:
        log.exception("scheduler not initialised")


# ---- API routes ----
@app.route("/")
def index():
    return render_template("dashboard.html", port=FLASK_PORT, nonce=g.csp_nonce)


# energy cache (recomputed max once/60s — the page polls status every 5s)
_energy_cache = {"ts": 0, "val": None}


def _today_energy_cached():
    global _energy_cache
    now_ts = time.time()
    if _energy_cache["val"] is None or now_ts - _energy_cache["ts"] > 60:
        import datetime as dt
        n = dt.datetime.now()
        ts = dt.datetime(n.year, n.month, n.day).timestamp()
        _energy_cache = {"ts": now_ts, "val": storage.period_energy(ts, now_ts)}
    return _energy_cache["val"]


@app.route("/api/status")
def api_status():
    snap = storage.latest_snapshot
    data = {
        "polling_active": storage.poll_state["polling_active"],
        "last_poll": storage.poll_state["last_poll"],
        "last_error": storage.poll_state["last_error"],
        "poll_count": storage.poll_state["poll_count"],
        "snapshot": snap,
        "today_energy": _today_energy_cached() if snap else None,
    }
    return jsonify(data)


@app.route("/api/history")
def api_history():
    try:
        hours = float(request.args.get("hours", 24))
        hours = min(max(hours, 0.25), 24 * 7)
    except ValueError:
        hours = 24
    return jsonify({"hours": hours, "rows": storage.get_history(hours)})


@app.route("/api/energy")
def api_energy():
    """Energy summary (kWh) for a period. 'period' is one of:
    today, yesterday, this_month, last_month, last_n_days?n=, this_quarter,
    last_quarter, this_year, last_year."""
    import datetime as dt
    period = request.args.get("period", "today")
    now = dt.datetime.now()
    import time as _t
    n = 7
    if "n_days" in period:
        try:
            n = int(request.args.get("n", 7))
        except (ValueError, TypeError):
            return jsonify({"error": "invalid n (must be an integer)"}), 400
        n = max(1, min(3650, n))  # clamp to 1–3650
    start = end = None
    if period == "today":
        start = dt.datetime(now.year, now.month, now.day).timestamp()
        end = _t.time()
    elif period == "yesterday":
        d = dt.datetime(now.year, now.month, now.day) - dt.timedelta(days=1)
        start, end = d.timestamp(), (d + dt.timedelta(days=1)).timestamp()
    elif period == "this_month":
        start = dt.datetime(now.year, now.month, 1).timestamp()
        end = _t.time()
    elif period == "last_month":
        d = dt.datetime(now.year, now.month, 1) - dt.timedelta(days=1)
        start = dt.datetime(d.year, d.month, 1).timestamp()
        end = (dt.datetime(now.year, now.month, 1)).timestamp()
    elif "n_days" in period:
        end = _t.time()
        start = end - n * 86400
    elif period == "this_quarter":
        q = (now.month - 1) // 3
        start = dt.datetime(now.year, 3 * q + 1, 1).timestamp()
        end = _t.time()
    elif period == "last_quarter":
        q = (now.month - 1) // 3
        start = (dt.datetime(now.year, 3 * q + 1, 1) - dt.timedelta(days=1)).timestamp()
        end = dt.datetime(now.year, 3 * q + 1, 1).timestamp()
    elif period == "this_year":
        start = dt.datetime(now.year, 1, 1).timestamp()
        end = _t.time()
    elif period == "last_year":
        start = dt.datetime(now.year - 1, 1, 1).timestamp()
        end = dt.datetime(now.year, 1, 1).timestamp()
    if start is None:
        return jsonify({"error": "unknown period"}), 400
    e = storage.period_energy(start, end)
    # apply tariffs (config) — import cost; no export credit (per user)
    rate = float(cfg.get("grid_import_rate", 0) or 0)
    e["import_cost"] = round(e["import_kwh"] * rate, 2) if rate else 0
    e["tariff_zar_kwh"] = rate
    e["period"] = period
    return jsonify(e)


# The ONLY config keys that never leave to the client. One constant so the
# GET and POST handlers can't drift apart.
PRIVATE_KEYS = {"local_api_password", "enphase_token", "email",
               "ui_password_hash"}


def _public_cfg(cfg: dict) -> dict:
    """Config for clients: never the secret values, plus has_* presence flags.

    Used by BOTH the GET and POST /api/config handlers. Excludes the single
    PRIVATE_KEYS constant and adds has_* presence flags (the flag names are
    stable: has_password, has_enphase_token, has_email, has_ui_password).
    """
    out = {k: v for k, v in cfg.items() if k not in PRIVATE_KEYS}
    out["has_password"] = bool(cfg.get("local_api_password"))
    out["has_enphase_token"] = bool(cfg.get("enphase_token"))
    out["has_email"] = bool(cfg.get("email"))
    out["has_ui_password"] = bool(cfg.get("ui_password_hash"))
    return out


@app.route("/api/config", methods=["GET"])
def api_config_get():
    """Config for clients — never the secret values (see _public_cfg)."""
    return jsonify(_public_cfg(cfg))


@app.route("/api/config", methods=["POST"])
def api_config_set():
    """Update config — single storage backend (config.save) for all writes."""
    global cfg, client, poll_mod
    err = _csrf_check()
    if err is not None:
        return err
    data = request.get_json(silent=True) or {}
    # Item 6: bind_host / allowed_hosts are NOT API-writable (they are
    # network-level keys — a remote writer must not be able to expose the
    # server to the world or open the Host gate). They are edited in
    # config.json or via the CLI:
    #   python app.py --set-bind-host <ip>
    #   python app.py --add-allowed-host <host>
    # (both validated; see config.set_bind_host / add_allowed_host).
    for k in ("bind_host", "allowed_hosts"):
        if k in data and data[k] not in (None, ""):
            return jsonify(ok=False, error=f"{k} is not API-writable; "
                "edit config.json or use the CLI "
                f"(python app.py --set-bind-host / --add-allowed-host)"), 400
    updatable = ("gateway", "enphase_gateway", "username", "email", "source",
                "poll_interval_seconds", "grid_import_rate", "grid_export_credit")

    # ---- Fix 3: validate everything BEFORE writing anything ----
    errs = _validate_updatable(data)
    if data.get("gateway") not in (None, "") and not _valid_gateway(data["gateway"]):
        errs.append("gateway must be an https:// private-IP or *.local URL (no path/query/userinfo)")
    if data.get("enphase_gateway") not in (None, "") and not _valid_gateway(data["enphase_gateway"]):
        errs.append("enphase_gateway must be an https:// private-IP or *.local URL (no path/query/userinfo)")
    if errs:
        return jsonify(ok=False, errors=errs), 400

    # Changing a host requires the matching secret in the SAME request —
    # otherwise the saved secret could be silently pointed at a new host.
    gw_changed = (data.get("gateway") not in (None, "")
                 and data.get("gateway") != cfg.get("gateway"))
    egw_changed = (data.get("enphase_gateway") not in (None, "")
                  and data.get("enphase_gateway") != cfg.get("enphase_gateway"))
    if gw_changed and not data.get("local_api_password"):
        return jsonify(ok=False, error="changing gateway requires "
                                       "local_api_password in the same request"), 400
    if egw_changed and not data.get("enphase_token"):
        return jsonify(ok=False, error="changing enphase_gateway requires "
                                       "enphase_token in the same request"), 400
    # Switching the source to enphase requires a configured enphase_gateway:
    # the Enphase client no longer falls back to the Tesla gateway, so
    # without it the poller would point the IQ gateway at nothing.
    if data.get("source") == "enphase" and not (
            data.get("enphase_gateway") or cfg.get("enphase_gateway")):
        return jsonify(ok=False,
                       error="set enphase_gateway (and enphase_token) first"), 400

    # Apply validated fields (whitelist; unknown keys are ignored).
    for k in updatable:
        if k in data and data[k] not in (None, ""):
            cfg[k] = data[k]
    if data.get("local_api_password"):
        cfg["local_api_password"] = data["local_api_password"]
    if data.get("enphase_token"):
        cfg["enphase_token"] = data["enphase_token"]
    # Fix 4: changing a host clears that source's TLS cert pin (the new host has
    # a different certificate; the old pin would now block all requests).
    if gw_changed:
        cfg["gateway_cert_sha256"] = ""
    if egw_changed:
        cfg["enphase_cert_sha256"] = ""
    config.save(cfg)
    # Rebuild the client on a source OR gateway change (a gateway change
    # used to only take effect after a restart).
    if ("source" in data) or gw_changed or egw_changed:
        new_mod, new_client = build_source(cfg)
        client = new_client
        poll_mod = new_mod
        log.info("rebuilt client: %s", type(client).__name__)
    # pick up new interval on the fly
    if "poll_interval_seconds" in data:
        interval = max(int(cfg["poll_interval_seconds"]), 10)
        if scheduler is not None and scheduler.running:
            try:
                scheduler.reschedule_job("powerwall_poll", trigger="interval",
                                        seconds=interval)
            except Exception:
                log.exception("reschedule failed")
    # re-auth immediately after a credential/source/gateway change
    if (data.get("local_api_password") or data.get("enphase_token")
            or "source" in data or gw_changed or egw_changed):
        client.auth_failed = False
        client.token = None
        # a new token/source is a fresh start — clear the class-level
        # lockout (it survives client rebuilds and would otherwise
        # block the new token's first attempt)
        type(client)._last_auth_fail = 0.0
        client.authenticate(force=True)
    # Mirror the GET endpoint exactly: never echo secrets in the
    # confirmation; expose has_* flags instead (shared _public_cfg so the
    # two handlers can't drift apart).
    public = _public_cfg(cfg)
    return jsonify({"ok": True, "config": public,
                   "source": cfg.get("source")})


@app.route("/api/reauth", methods=["POST"])
def api_reauth():
    err = _csrf_check()
    if err is not None:
        return err
    request.get_json(silent=True)  # require a JSON body (may be {})
    client.auth_failed = False
    client.token = None
    ok = client.authenticate(force=True)
    return jsonify({"ok": ok, "auth_failed": client.auth_failed})


@app.route("/health")
def health():
    return jsonify({"ok": True,
                   "polling_active": storage.poll_state["polling_active"],
                   "snapshot_age_s": (time.time() - storage.latest_snapshot["ts"])
                   if storage.latest_snapshot else None})


# ---- first-run + main ----
def _first_run_banner():
    """If no UI password hash exists yet, generate one, persist it, and print the
    plaintext ONCE to the console (not the log file)."""
    global cfg
    if not cfg.get("ui_password_hash"):
        import secrets
        pw = secrets.token_urlsafe(15)  # 20-char URL-safe password
        cfg["ui_password_hash"] = config.hash_password(pw)
        config.save(cfg)
        print("\n" + "=" * 62, flush=True)
        print("  POWERWALL DASHBOARD — first run (console only, not in logs)", flush=True)
        print(f"  UI username : {cfg.get('ui_username', 'admin')}", flush=True)
        print(f"  UI password : {pw}", flush=True)
        print("  The dashboard now requires HTTP Basic auth. Save this password;", flush=True)
        print("  reset it later with:  python app.py --set-ui-password", flush=True)
        print("=" * 62 + "\n", flush=True)


if __name__ == "__main__":
    import sys
    if "--set-ui-password" in sys.argv:
        new = getpass("New UI password (input hidden): ")
        if len(new) < 8:
            print("Rejected: password must be at least 8 characters.", file=sys.stderr)
            sys.exit(1)
        config.set_ui_password(new)
        sys.exit(0)

    # Item 6 CLI: network keys are set from the command line (validated),
    # never via the API.
    def _arg_value(name):
        if name in sys.argv:
            i = sys.argv.index(name)
            if i + 1 < len(sys.argv):
                return sys.argv[i + 1]
            print(f"Missing value for {name}", file=sys.stderr)
            sys.exit(2)
        return None

    val = _arg_value("--set-bind-host")
    if val is not None:
        try:
            config.set_bind_host(val)
        except ValueError as e:
            print(f"Rejected: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    val = _arg_value("--add-allowed-host")
    if val is not None:
        try:
            config.add_allowed_host(val)
        except ValueError as e:
            print(f"Rejected: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    _first_run_banner()
    # one poll immediately so the page isn't empty on first load
    _poll_cycle()
    start_polling()
    host = (cfg.get("bind_host") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        from waitress import serve
        log.info("serving on %s:%s", host, FLASK_PORT)
        serve(app, host=host, port=FLASK_PORT, threads=8, recv_bytes=65536)
    except ImportError:
        log.warning("waitress missing — falling back to dev server")
        app.run(host=host, port=FLASK_PORT)
