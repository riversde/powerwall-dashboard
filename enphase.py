"""Enphase IQ Gateway (backbone v07.00.x) client + poller.

Auth protocol (verified against the live gateway):
  * GET {gateway}/auth/check_jwt  Authorization: Bearer <token>
    -> 200 + Set-Cookie: sessionId=...   (the token is bound to ONE session)
  * API calls must use the sessionId cookie ONLY. Any request carrying the
    Bearer token on an API endpoint gets a connection reset (HTTP 000).
  * The Bearer may only be presented to check_jwt when a session can be
    established or re-issued; presenting it while a foreign session is bound
    to the token -> 401. So: persist the cookie, reuse it, re-auth sparingly.
  * The sessionId cookie survives across process restarts, so it is saved to
    .ig_session next to the config and re-validated on startup.

Data: GET {gateway}/production.json?details=1
     -> { production: [...], consumption: [...], storage: [...] }

production[0] (type "inverters")  -> wNow = total solar output, activeCount = inverter count
production[1] (type "eim")        -> optional EIM production meter
consumption[0] (total-consumption)-> wNow = home load
consumption[1] (net-consumption)  -> wNow = grid (positive = importing, negative = exporting)
storage[0] (acb)                  -> wNow = battery (0 when absent/idle)

Same self-signed TLS handling as the Tesla client. Every poll is wrapped in a
thread with a timeout so an unreachable gateway can never hang the scheduler.
"""
import logging
import os
import threading
import time

import requests
import urllib3
import config
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("enphase")


def _pin_mismatch_msg(e, host: str, pin_key: str):
    """If e is a TLS fingerprint-pin rejection (the handshake was refused
    before any bytes left the process), return the diagnostic message to
    surface as last_error; otherwise return None. A mismatch means the
    stored pin no longer matches the gateway certificate — the fix is to
    clear that pin in config.json so the next request re-pins.

    The refusal may surface as a bare SSLError or, after urllib3's
    retry, wrapped in a MaxRetryError; check the exception chain."""
    for x in (e,) + (getattr(e, "__cause__", None),):
        if isinstance(x, requests.exceptions.SSLError) \
                and "Fingerprints did not match" in str(x):
            return ("certificate fingerprint mismatch for %s — refusing to send "
                    "credentials; clear %s in config.json to re-pin"
                    % (host, pin_key))
    return None

# Where the persisted session cookie lives (git-ignored runtime file)
_SESSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ig_session")
# How long to wait after a failed check_jwt before trying the token again
_AUTH_LOCKOUT_S = 300


def _save_cookie(name: str, value: str):
    try:
        with open(_SESSION_FILE, "w") as f:
            f.write(f"{name}={value}")
    except OSError as e:
        log.warning("could not persist session cookie: %s", e)


def _load_cookie() -> str:
    try:
        with open(_SESSION_FILE) as f:
            data = f.read().strip()
        return data.split("=", 1)[1] if "=" in data else data
    except (OSError, IndexError):
        return ""


class EnphaseIQGateway:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        # Item 7: NO fallback to cfg["gateway"]. The Enphase JWT must only
        # ever be sent to the configured enphase_gateway, so a Tesla gateway
        # change can never redirect it. (At startup, app.py copies
        # gateway -> enphase_gateway ONCE if enphase_gateway is empty.)
        self.base = (cfg.get("enphase_gateway") or "").rstrip("/")
        self._host = urlparse(self.base).hostname or "enphase_gateway"
        self.token = None
        self.auth_failed = False
        self.last_error = None  # surfaced via poll_state -> /api/status
        self.stop_event = None  # set by the poll guard to abort a slow poll
        # Fix 4: TLS cert-fingerprint pinning (TOFU) instead of verify=False.
        # Item 4: the pin lives in the SHARED self.cfg (the one app.py holds
        # and saves). pin_getter reads self.cfg and save_pin writes self.cfg
        # then config.save(self.cfg) — so an unrelated UI save can never
        # erase the pin (the old code wrote a disk copy config.load() and
        # left the in-memory cfg holding "").
        import certpin
        self._pin = certpin.CertPinner(
            "enphase",
            pin_getter=lambda: self.cfg.get("enphase_cert_sha256", ""),
            save_pin=lambda fp: (self.cfg.__setitem__("enphase_cert_sha256", fp),
                                config.save(self.cfg)))
        self.session = certpin.make_pinning_session(self._pin)
        # Restore a previously established session (survives restarts).
        # Stored with the host domain so a later check_jwt Set-Cookie
        # replaces it (same name+domain+path) instead of creating a
        # second sessionId cookie the gateway rejects with a 401.
        saved = _load_cookie()
        if saved:
            self._set_session_cookie(saved)

    def _aborted(self) -> bool:
        return bool(self.stop_event and self.stop_event.is_set())

    # ---------- auth ----------
    _last_auth_fail = 0.0  # class-level lockout timestamp

    def _have_session(self) -> bool:
        return bool(self._get_cookie("sessionId"))

    def _get_cookie(self, name: str) -> str:
        """Read a cookie value from the jar (handles the gateway's
        Set-Cookie domain — a plain cookies.get() can miss it)."""
        for c in self.session.cookies:
            if c.name == name:
                return c.value
        return ""

    def _set_session_cookie(self, value: str) -> None:
        """Keep exactly ONE sessionId cookie in the jar.

        The gateway rejects a request that carries two sessionId cookies
        (e.g. the restored empty-domain one plus the freshly issued
        host-domain one) with a 401. So before recording a new session
        we drop any stale sessionId entries and store a single cookie
        with the host domain, so a later Set-Cookie (same domain+path+
        name) replaces it rather than piling on top."""
        if not value:
            return
        jar = self.session.cookies
        for c in list(jar):
            if c.name == "sessionId":
                try:
                    jar.delete(c.name, domain=c.domain, path=c.path)
                except Exception:
                    pass
        jar.set("sessionId", value, domain=self._host, path="/")

    def _session_works(self):
        """Probe the (persisted) session against a DATA endpoint.
        Returns True (works), False (definitively 401), or None (unknown —
        a hang/timeout, which must NOT trigger a check_jwt: re-firing the
        Bearer on a slow gateway is what rate-limits the token)."""
        if self._aborted():
            return False
        try:
            r = self.session.get(self.base + "/production.json",
                                params={"details": 1}, timeout=8)
        except Exception as e:
            # A pin mismatch is a TLS refusal, not a definitive 401: map it
            # to None (unknown) so a bad pin can NEVER trigger check_jwt or
            # burn the token. Record it for the status page.
            m = _pin_mismatch_msg(e, self._host, "enphase_cert_sha256")
            if m:
                self.last_error = m
                log.warning("enphase probe: %s", m)
            return None  # timeout/connection error — session state unknown
        if r.status_code == 401:
            return False
        if r.status_code == 200 and self._have_session():
            return True
        return None  # some other status — don't burn the token over it

    def authenticate(self, force: bool = False) -> bool:
        """Establish the sessionId cookie.

        Order of attempts (sparingly — the gateway rate-limits the token):
        1. If a persisted session is still accepted by the gateway, keep it
           (no token is ever sent). This is the common case — including
           force=True, because a *working* session must never be
           invalidated: check_jwt with the Bearer re-issues the session
           and kills the previous one (one live session per token), so
           calling it when the cookie still works is purely harmful.
        2. Otherwise present the Bearer to check_jwt, honouring the
           lockout (force bypasses the lockout, e.g. after a token change).
        A failed check_jwt locks the token out for _AUTH_LOCKOUT_S so we
        never hammer the gateway."""
        probe = None
        if self._have_session():
            probe = self._session_works()
        if self._have_session() and probe is not False:
            # working, OR unknown (a hang) — in both cases the cookie is
            # the right thing to use; never burn the token over a hang
            new = self._get_cookie("sessionId")
            if new:
                _save_cookie("sessionId", new)
            self.token = self.cfg.get("enphase_token")
            self.auth_failed = False
            log.debug("enphase: keeping persisted session (probe: %s)",
                      "ok" if probe else "unknown")
            return True
        token = self.cfg.get("enphase_token")
        if not token:
            self.auth_failed = True
            log.warning("enphase: no enphase_token in config")
            return False
        if not force and time.time() - self._last_auth_fail < _AUTH_LOCKOUT_S:
            log.info("enphase: re-auth skipped (lockout, %d s remain)",
                     int(_AUTH_LOCKOUT_S - (time.time() - self._last_auth_fail)))
            return False
        try:
            if self._aborted():
                return False
            r = self.session.get(self.base + "/auth/check_jwt",
                                headers={"Authorization": "Bearer " + token},
                                timeout=8)
            if r.status_code == 200 and self._have_session():
                self.token = token
                self.auth_failed = False
                # Take the freshly issued value straight from the Set-Cookie
                # header (not the jar — the jar may also still hold a stale
                # cookie under a different domain) and force it to be the
                # ONLY sessionId cookie.
                sc = r.headers.get("Set-Cookie", "")
                fresh = sc.split("sessionId=")[1].split(";")[0] if "sessionId=" in sc else self._get_cookie("sessionId")
                self._set_session_cookie(fresh)
                _save_cookie("sessionId", fresh)
                log.info("enphase: session established via JWT")
                return True
            self._last_auth_fail = time.time()
            self.auth_failed = True
            log.warning("enphase: JWT rejected (HTTP %s) — %d s lockout",
                        r.status_code, _AUTH_LOCKOUT_S)
            return False
        except Exception as e:
            # A pin mismatch here is a TLS refusal, not a rejected JWT:
            # record it (status page) and honour the lockout so we don't
            # re-hammer the gateway on every poll.
            m = _pin_mismatch_msg(e, self._host, "enphase_cert_sha256")
            if m:
                self.last_error = m
                log.warning("enphase check_jwt: %s", m)
            self._last_auth_fail = time.time()
            self.auth_failed = True
            log.warning("enphase: auth error: %s", e)
            return False

    def _get(self, path):
        """API calls use the sessionId cookie (never the Bearer — the
        gateway resets those connections). On a definitive 401, try to
        re-establish the session once, then retry. A *timeout* is NOT
        treated as auth failure — it just means the gateway was slow;
        re-firing check_jwt on a hang is what rate-limits the token."""
        for attempt in (1, 2):
            if self._aborted():
                return {"error": "aborted"}
            try:
                r = self.session.get(self.base + path, timeout=8)
            except Exception as e:
                # A pin mismatch is a TLS refusal (nothing was sent): record
                # it and return the diagnostic. It never reaches the 401
                # branch, so it can't trigger a re-auth / check_jwt.
                m = _pin_mismatch_msg(e, self._host, "enphase_cert_sha256")
                if m:
                    self.last_error = m
                    log.warning("enphase get %s: %s", path, m)
                    return {"error": m}
                return {"error": f"{type(e).__name__}: {e}"}
            if r.status_code == 401 and self.token and attempt == 1:
                log.info("401 on %s — re-establishing session", path)
                self.authenticate()
                continue
            try:
                r.raise_for_status()
                data = r.json()
                c = self._get_cookie("sessionId")
                if c:
                    _save_cookie("sessionId", c)
                return data
            except Exception as e:
                return {"error": f"HTTP {r.status_code}: {str(e)[:80]}"}
        return {"error": "unreachable after re-auth"}

    # ---------- data ----------
    def fetch_production(self):
        return self._get("/production.json?details=1")

    @staticmethod
    def _find_entry(items, type_name, measurement_type=None):
        """Find the first entry of `type_name`; optionally by measurementType."""
        for it in items or []:
            if it.get("type") != type_name:
                continue
            if measurement_type and it.get("measurementType") != measurement_type:
                continue
            return it
        return None

    def normalise(self, raw: dict) -> dict:
        """Raw /production.json dict -> canonical snapshot dict (Tesla-compatible)."""
        snap = {
            "ts": time.time(),
            "source": "enphase",
            "soe_pct": None,
            "battery_w": None,
            "grid_w": None,
            "house_w": None,
            "solar_w": None,
            "generator_w": None,
            "capacity_wh": None,
            "energy_remaining_wh": None,
            "hours_remaining": None,
            "mode": None,
            "backup_reserve_pct": None,
            "sitemaster_up": None,
            "reachable": True,
            "inverter_count": None,
            "inverter_active": None,
        }
        if not isinstance(raw, dict) or "error" in raw:
            snap["reachable"] = False
            return snap

        prod = raw.get("production") or []
        cons = raw.get("consumption") or []
        stor = raw.get("storage") or []

        # Solar: the "inverters" entry is the aggregate
        inv = self._find_entry(prod, "inverters")
        if inv:
            try:
                snap["solar_w"] = float(inv.get("wNow", 0))
            except (TypeError, ValueError):
                pass
            if inv.get("activeCount") is not None:
                try:
                    snap["inverter_count"] = int(inv.get("activeCount") or 0)
                except (TypeError, ValueError):
                    pass
            snap["inverter_active"] = (snap["inverter_count"] or 0) > 0

        # Home load: total-consumption EIM
        home = self._find_entry(cons, "eim", "total-consumption")
        if home is not None:
            try:
                snap["house_w"] = float(home.get("wNow", 0))
            except (TypeError, ValueError):
                pass

        # Grid: net-consumption EIM (positive = importing, negative = exporting)
        net = self._find_entry(cons, "eim", "net-consumption")
        if net is not None:
            try:
                snap["grid_w"] = float(net.get("wNow", 0))
            except (TypeError, ValueError):
                pass

        # Battery: acb (battery); 0/absent when no battery
        batt = self._find_entry(stor, "acb")
        if batt is not None:
            try:
                snap["battery_w"] = float(batt.get("wNow", 0))
            except (TypeError, ValueError):
                pass
            state = str(batt.get("state") or "").lower()
            snap["mode"] = state if state else None
        else:
            snap["battery_w"] = 0.0

        # reachable: true if we got at least one of solar/home/grid
        snap["reachable"] = (
            snap["solar_w"] is not None
            or snap["house_w"] is not None
            or snap["grid_w"] is not None
        )
        return snap


def _poll_with_timeout(client: EnphaseIQGateway, timeout_s: int = 34) -> dict:
    """Run one full poll in a worker thread; return {ok, snapshot, error}.

    The join budget (timeout_s) must exceed the worker's worst case
    (probe 8s + check_jwt 8s + fetch 2x8s + retry ≈ 32s), otherwise the
    thread outlives the join and leaks — and the next job is skipped by
    max_instances=1. stop_event lets the worker bail promptly if the
    scheduler moves on, so a leaked thread never holds a gateway
    connection for long."""
    result = {}
    stop = threading.Event()
    client.stop_event = stop
    client.last_error = None  # fresh per poll: no stale TLS message

    def worker():
        try:
            if not client.token:
                client.authenticate()
            raw = client.fetch_production()
            snap = client.normalise(raw)
            if not snap["reachable"]:
                result["ok"] = False
                # A pin mismatch (or other TLS refusal) is the real cause —
                # surface it instead of the generic message.
                result["error"] = client.last_error or "gateway endpoints erroring"
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
        # don't leak: tell the worker to abort its pending requests
        stop.set()
        return {"ok": False, "error": f"poll timed out after {timeout_s}s"}
    return result


def poll_once(cfg: dict, client: EnphaseIQGateway) -> dict:
    """One poll cycle. Returns {ok, snapshot?, error?, auth_failed}."""
    res = _poll_with_timeout(client, timeout_s=15)
    res["auth_failed"] = client.auth_failed
    if res.get("ok"):
        import storage
        storage.insert_row(res["snapshot"])
    return res
