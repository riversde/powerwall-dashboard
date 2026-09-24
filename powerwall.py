"""Powerwall Gateway client + poller.

Auth: POST {gateway}/api/login/Basic  {"username": "customer", "password": ...}
     -> {"token": "..."} used as Authorization: Bearer <token>
Data: /api/system_status/soe, /api/meters/aggregates, /api/system_status,
      /api/sitemaster, /api/operation  (all with the same Bearer token).

IMPORTANT: the gateway TLS-fingerprints clients — urllib's handshake is
rejected (403 on data endpoints) even with a valid token. `requests` is
accepted, so all HTTP goes through a shared requests.Session.

Every poll is wrapped in a thread with a timeout so an unreachable gateway
can never hang the APScheduler job.
"""
import logging
import threading
import time

import requests
import urllib3
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("powerwall")

# Meter key synonyms (firmware variance) -> canonical name
METER_KEY_MAP = {
    "site": "grid",
    "utility_meter": "grid",
    "grid": "grid",
    "load": "house",
    "house": "house",
    "battery": "battery",
    "solar": "solar",
    "generator": "generator",
}

POWER_FIELDS = ("instant_power", "watts", "W")


class PowerwallClient:
    _AUTH_LOCKOUT_S = 30  # don't hammer the gateway after a failed login

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.base = cfg["gateway"].rstrip("/")
        self.token = None
        self.auth_failed = False
        self._last_auth_fail = 0.0
        self._reauthed = False  # reset per poll: re-auth at most once per poll
        self.stop_event = None  # set by the poll guard to abort a slow poll
        # Fix 4: TLS cert-fingerprint pinning (TOFU) instead of verify=False.
        import certpin
        self._pin = certpin.CertPinner(
            "tesla",
            pin_getter=lambda: (config.load() or {}).get("gateway_cert_sha256", ""),
            save_pin=lambda fp: config.save(
                {**config.load(), "gateway_cert_sha256": fp}))
        self.session = certpin.make_pinning_session(self._pin)

    def _aborted(self) -> bool:
        return bool(self.stop_event and self.stop_event.is_set())

    # ---------- auth ----------
    def authenticate(self, force: bool = False) -> bool:
        if self._aborted():
            return bool(self.token)
        if not force and (time.time() - self._last_auth_fail) < self._AUTH_LOCKOUT_S:
            return bool(self.token)
        payload = {"username": self.cfg.get("username", "customer")}
        if self.cfg.get("local_api_password"):
            payload["password"] = self.cfg["local_api_password"]
        if self.cfg.get("email"):
            payload["email"] = self.cfg["email"]
        try:
            r = self.session.post(self.base + "/api/login/Basic",
                                 json=payload, timeout=10)
            data = r.json()
            self.token = data.get("token")
            self.auth_failed = not bool(self.token)
            if self.token:
                log.info("authenticated, token acquired")
            else:
                self._last_auth_fail = time.time()
                log.warning("authenticate: no token in response (HTTP %s): keys=%s — "
                           "%d s lockout", r.status_code,
                           sorted(data.keys()) if isinstance(data, dict) else "non-dict",
                           self._AUTH_LOCKOUT_S)
            return bool(self.token)
        except Exception as e:
            self.auth_failed = True
            self._last_auth_fail = time.time()
            log.warning("authenticate error: %s — %d s lockout", e, self._AUTH_LOCKOUT_S)
            return False

    def _headers(self):
        return {"Authorization": "Bearer " + self.token} if self.token else {}

    def _get_or_reauth(self, path):
        try:
            if self._aborted():
                return {"error": "aborted"}
            r = self.session.get(self.base + path,
                                headers=self._headers(), timeout=8)
            if r.status_code == 401 and not self._reauthed:
                self._reauthed = True  # at most one re-auth per poll
                log.info("401 on %s — re-authenticating", path)
                self.authenticate()
                if self._aborted():
                    return {"error": "aborted"}
                r = self.session.get(self.base + path,
                                    headers=self._headers(), timeout=8)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    # ---------- data ----------
    def fetch_all(self) -> dict:
        """Fetch every endpoint; re-auth once on 401. Returns raw dicts."""
        out = {}
        endpoints = {
            "soe": "/api/system_status/soe",
            "aggregates": "/api/meters/aggregates",
            "system_status": "/api/system_status",
            "sitemaster": "/api/sitemaster",
            "operation": "/api/operation",
        }
        for name, path in endpoints.items():
            out[name] = self._get_or_reauth(path)
        return out

    # ---------- normalisation ----------
    @staticmethod
    def _meter_power(meter: dict):
        for field in POWER_FIELDS:
            if field in meter:
                try:
                    return float(meter[field])
                except (TypeError, ValueError):
                    continue
        return None

    def normalise(self, raw: dict) -> dict:
        """Raw endpoint dicts -> canonical snapshot dict."""
        snap = {
            "ts": time.time(),
            "soe_pct": None,
            "battery_w": None,
            "grid_w": None,
            "house_w": None,
            "solar_w": None,
            "generator_w": None,
            "capacity_wh": self.cfg.get("capacity_wh"),
            "energy_remaining_wh": None,
            "hours_remaining": None,
            "mode": None,
            "backup_reserve_pct": None,
            "sitemaster_up": None,
            "reachable": True,
        }
        # SoE
        soe = raw.get("soe")
        if isinstance(soe, dict) and "error" not in soe:
            for k in ("percentage", "soe", "soc"):
                if k in soe:
                    v = soe[k]
                    if isinstance(v, (int, float)):
                        # ratio (0-1) vs percentage (0-100)
                        snap["soe_pct"] = v * 100 if (k != "percentage" and v <= 1.0001) else float(v)
                    break
        # Meter aggregates
        agg = raw.get("aggregates")
        if isinstance(agg, dict) and "error" not in agg:
            for key, val in agg.items():
                if not isinstance(val, dict):
                    continue
                canon = METER_KEY_MAP.get(key)
                if canon is None:
                    continue
                p = self._meter_power(val)
                if p is not None:
                    snap[canon + "_w"] = p
        # System status (capacity / remaining)
        ss = raw.get("system_status")
        if isinstance(ss, dict) and "error" not in ss:
            if "nominal_full_pack_energy" in ss:
                try:
                    snap["capacity_wh"] = float(ss["nominal_full_pack_energy"])
                except (TypeError, ValueError):
                    pass
            if "nominal_energy_remaining" in ss:
                try:
                    snap["energy_remaining_wh"] = float(ss["nominal_energy_remaining"])
                except (TypeError, ValueError):
                    pass
        # Operation mode
        op = raw.get("operation")
        if isinstance(op, dict) and "error" not in op:
            if "real_mode" in op:
                snap["mode"] = op.get("real_mode")
            if "backup_reserve_percent" in op:
                try:
                    snap["backup_reserve_pct"] = float(op["backup_reserve_percent"])
                except (TypeError, ValueError):
                    pass
        # Sitemaster health
        sm = raw.get("sitemaster")
        if isinstance(sm, dict) and "error" not in sm:
            snap["sitemaster_up"] = (str(sm.get("status", "")).lower().endswith("up")
                                    and bool(sm.get("running", False)))
        # Any per-endpoint error -> mark unreachable if critical ones failed
        critical_failed = any(
            isinstance(raw.get(k), dict) and "error" in raw.get(k, {})
            for k in ("soe", "aggregates")
        )
        snap["reachable"] = not critical_failed
        # Derived: hours remaining at current draw
        if snap["energy_remaining_wh"] and snap["house_w"]:
            snap["hours_remaining"] = round(
                snap["energy_remaining_wh"] / max(snap["house_w"], 1.0), 2)
        return snap


def _poll_with_timeout(client: PowerwallClient, timeout_s: int = 42) -> dict:
    """Run one full poll in a worker thread; return {ok, snapshot, error}.

    The join budget must exceed the worker's worst case (login 8s +
    5 endpoints x 8s + one re-auth 8s ≈ 40s) or the thread leaks and the
    next job is skipped. stop_event aborts a slow poll so a leaked
    thread never holds a gateway connection."""
    result = {}
    stop = threading.Event()
    client.stop_event = stop
    client._reauthed = False  # fresh per poll: at most one re-auth

    def worker():
        try:
            if not client.token:
                client.authenticate()
            raw = client.fetch_all()
            snap = client.normalise(raw)
            if not snap["reachable"]:
                result["ok"] = False
                result["error"] = "gateway endpoints erroring"
            else:
                result["ok"] = True
                result["snapshot"] = snap
        except Exception as e:
            result["ok"] = False
            result["error"] = str(e)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        stop.set()  # don't leak
        return {"ok": False, "error": f"poll timed out after {timeout_s}s"}
    return result


def poll_once(cfg: dict, client: PowerwallClient) -> dict:
    """One poll cycle. Returns {ok, snapshot?, error?, auth_failed}."""
    res = _poll_with_timeout(client, timeout_s=15)
    res["auth_failed"] = client.auth_failed
    # persist latest for instant page load
    if res.get("ok"):
        import storage
        storage.insert_row(res["snapshot"])
    return res
