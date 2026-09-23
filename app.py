"""Powerwall Dashboard — Flask + Waitress + APScheduler.

Serves the SPA at /, REST endpoints under /api/, and polls the Powerwall
gateway on a fixed interval (threaded timeout per cycle).
"""
import logging
import os
import time

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, jsonify, render_template, request

import config
import powerwall
import storage

# ---- logging ----
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "powerwall.log"), encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("app")

app = Flask(__name__)
# Re-read templates on change so edits are never served stale across restarts.
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ---- state (module scope — NOT in before_request, per SQLite WAL rules) ----
cfg = config.ensure_config()
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
    return render_template("dashboard.html", port=FLASK_PORT)


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
    n = int(request.args.get("n", 7)) if "n_days" in period else 7
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


@app.route("/api/config", methods=["GET"])
def api_config_get():
    # Never expose the secrets in plaintext.
    public = {k: v for k, v in cfg.items()
             if k not in ("local_api_password", "enphase_token", "email")}
    public["has_password"] = bool(cfg.get("local_api_password"))
    public["has_enphase_token"] = bool(cfg.get("enphase_token"))
    public["has_email"] = bool(cfg.get("email"))
    return jsonify(public)


@app.route("/api/config", methods=["POST"])
def api_config_set():
    """Update config — single storage backend (config.save) for all writes."""
    global cfg, client, poll_mod
    data = request.get_json(silent=True) or {}
    updatable = ("gateway", "enphase_gateway", "username", "email", "source",
                "poll_interval_seconds", "grid_import_rate", "grid_export_credit")
    for k in updatable:
        if k in data and data[k] not in (None, ""):
            cfg[k] = data[k]
    if data.get("local_api_password"):
        cfg["local_api_password"] = data["local_api_password"]
    if data.get("enphase_token"):
        cfg["enphase_token"] = data["enphase_token"]
    config.save(cfg)  # same backend as reads (config.load/save)
    # source changed? rebuild the client for the new system
    new_mod, new_client = build_source(cfg)
    if type(new_client) is not type(client):
        client = new_client
        poll_mod = new_mod
        log.info("source switched — rebuilt client: %s", type(client).__name__)
    # pick up new interval on the fly
    if "poll_interval_seconds" in data:
        interval = max(int(cfg["poll_interval_seconds"]), 10)
        if scheduler is not None and scheduler.running:
            try:
                scheduler.reschedule_job("powerwall_poll", trigger="interval",
                                        seconds=interval)
            except Exception:
                log.exception("reschedule failed")
    # re-auth immediately after a credential/source change
    if (data.get("local_api_password") or data.get("enphase_token")
            or "source" in data or "gateway" in data
            or "enphase_gateway" in data):
        client.auth_failed = False
        client.token = None
        client.authenticate(force=True)
    return jsonify({"ok": True, "config": {k: v for k, v in cfg.items()
                                          if k not in ("local_api_password",
                                                       "enphase_token")},
                   "source": cfg.get("source")})


@app.route("/api/reauth", methods=["POST"])
def api_reauth():
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


# ---- main ----
if __name__ == "__main__":
    # one poll immediately so the page isn't empty on first load
    _poll_cycle()
    start_polling()
    try:
        from waitress import serve
        log.info("serving on %s:%s", FLASK_HOST, FLASK_PORT)
        serve(app, host=FLASK_HOST, port=FLASK_PORT,
              threads=8, recv_bytes=65536)
    except ImportError:
        log.warning("waitress missing — falling back to dev server")
        app.run(host=FLASK_HOST, port=FLASK_PORT)
