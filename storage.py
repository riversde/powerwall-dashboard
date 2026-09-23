"""SQLite storage: rolling 90-day raw samples + persistent monthly energy aggregates."""
import os
import sqlite3
import time
import datetime as dt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "powerwall.db")
RETENTION_S = 90 * 86400


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY, ts REAL,
                soe_pct REAL, battery_w REAL, grid_w REAL, house_w REAL,
                solar_w REAL, generator_w REAL, capacity_wh REAL,
                energy_remaining_wh REAL, hours_remaining REAL,
                mode TEXT, backup_reserve_pct REAL, sitemaster_up INTEGER,
                reachable INTEGER);
            CREATE INDEX IF NOT EXISTS idx_history_ts ON history(ts);
            CREATE TABLE IF NOT EXISTS monthly_agg (
                month TEXT PRIMARY KEY,
                import_kwh REAL, export_kwh REAL, solar_kwh REAL,
                house_kwh REAL, batt_charge_kwh REAL, batt_discharge_kwh REAL,
                samples INTEGER, completed INTEGER DEFAULT 0);
        """)
        purge()


def insert_row(s: dict):
    with _connect() as conn:
        conn.execute(
            "INSERT INTO history (ts, soe_pct, battery_w, grid_w, house_w, solar_w, generator_w, "
            "capacity_wh, energy_remaining_wh, hours_remaining, mode, backup_reserve_pct, sitemaster_up, reachable) "
            "VALUES (:ts, :soe_pct, :battery_w, :grid_w, :house_w, :solar_w, :generator_w, "
            ":capacity_wh, :energy_remaining_wh, :hours_remaining, :mode, :backup_reserve_pct, :sitemaster_up, :reachable)",
            s,
        )


def _row_to_dict(row):
    if row is None:
        return None
    if hasattr(row, "keys"):
        return dict(row)
    return row


def get_history(hours: float = 24) -> list:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM history WHERE ts >= ? ORDER BY ts", (time.time() - hours * 3600,))
        return [_row_to_dict(r) for r in cur.fetchall()]


def get_range(ts0: float, ts1: float) -> list:
    with _connect() as conn:
        cur = conn.execute(
            "SELECT ts, battery_w, grid_w, house_w, solar_w FROM history WHERE ts >= ? AND ts < ? ORDER BY ts",
            (ts0, ts1),
        )
        return [_row_to_dict(r) for r in cur.fetchall()]


def get_latest() -> dict:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM history ORDER BY ts DESC LIMIT 1")
        return _row_to_dict(cur.fetchone())


def purge():
    with _connect() as conn:
        conn.execute("DELETE FROM history WHERE ts < ?", (time.time() - RETENTION_S,))


# In-memory state for instant page load (not persisted per-poll).
latest_snapshot = None
poll_state = {
    "polling_active": False,
    "last_poll": None,
    "last_error": None,
    "poll_count": 0,
}


# ---------------------------------------------------------------- integration
def integrate(rows: list, key: str):
    """Trapezoidal signed integration of a power (W) column over time.
    Returns (positive_kwh, negative_kwh) — energy in kWh, split by sign."""
    pos = neg = 0.0
    prev = None
    for r in rows:
        v = r.get(key)
        if v is None:
            prev = None
            continue
        if prev is not None:
            dtsec = r["ts"] - prev[0]
            if 0 < dtsec <= 600:  # tolerate gaps up to 10 min
                # W * s = joules; / 3600 = Wh; / 1000 = kWh
                e = (v + prev[1]) / 2.0 * dtsec / 3600000.0
                if e > 0:
                    pos += e
                else:
                    neg += -e
        prev = (r["ts"], v)
    return pos, neg


# ---------------------------------------------------------------- month helpers
def _month_bounds(y: int, m: int):
    first = dt.datetime(y, m, 1)
    nxt = dt.datetime(y + 1, 1, 1) if m == 12 else dt.datetime(y, m + 1, 1)
    return first.timestamp(), nxt.timestamp()


def _month_key(y: int, m: int) -> str:
    return f"{y:04d}-{m:02d}"


def get_monthly(month: str) -> dict:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM monthly_agg WHERE month=?", (month,)).fetchone()
        return dict(row) if row else None


def rollup_month(month: str) -> bool:
    y, m = int(month[:4]), int(month[5:7])
    m0, m1 = _month_bounds(y, m)
    rows = get_range(m0, m1)
    if not rows:
        return False
    imp, exp = integrate(rows, "grid_w")
    sol, _ = integrate(rows, "solar_w")
    house, _ = integrate(rows, "house_w")
    dis, chg = integrate(rows, "battery_w")
    with _connect() as conn:
        conn.execute(
            """INSERT INTO monthly_agg (month, import_kwh, export_kwh, solar_kwh, house_kwh,
               batt_charge_kwh, batt_discharge_kwh, samples, completed)
               VALUES (?,?,?,?,?,?,?,?,1)
               ON CONFLICT(month) DO UPDATE SET
                 import_kwh=excluded.import_kwh, export_kwh=excluded.export_kwh,
                 solar_kwh=excluded.solar_kwh, house_kwh=excluded.house_kwh,
                 batt_charge_kwh=excluded.batt_charge_kwh, batt_discharge_kwh=excluded.batt_discharge_kwh,
                 samples=excluded.samples, completed=1""",
            (month, imp, exp, sol, house, chg, dis, len(rows)),
        )
    return True


def maybe_rollup():
    """Once a month boundary is crossed, persist the just-finished month."""
    now = dt.datetime.now()
    if now.day > 1:
        prev = now.replace(day=1) - dt.timedelta(days=1)
        month = _month_key(prev.year, prev.month)
        if get_monthly(month) is None and rollup_month(month):
            print(f"[rollup] monthly aggregate saved for {month}", flush=True)


# ---------------------------------------------------------------- period energy
def period_energy(ts0: float, ts1: float) -> dict:
    """Energy (kWh) summary over a period. Whole past months use the persistent
    monthly aggregate; partial months integrate raw samples (90-day retention)."""
    res = dict(import_kwh=0.0, export_kwh=0.0, solar_kwh=0.0, house_kwh=0.0,
              batt_charge_kwh=0.0, batt_discharge_kwh=0.0, months_missing=0)
    d0, d1 = dt.datetime.fromtimestamp(ts0), dt.datetime.fromtimestamp(ts1)
    y, m = d0.year, d0.month
    while not (y > d1.year or (y == d1.year and m > d1.month)):
        mb0, mb1 = _month_bounds(y, m)
        s0, s1 = max(mb0, ts0), min(mb1, ts1)
        if s1 > s0:
            full = (s0 <= mb0 + 1) and (s1 >= mb1 - 1)
            key = _month_key(y, m)
            agg = None
            if full and (y, m) != (dt.datetime.now().year, dt.datetime.now().month):
                agg = get_monthly(key)
            if agg and agg.get("completed"):
                res["import_kwh"] += agg["import_kwh"] or 0
                res["export_kwh"] += agg["export_kwh"] or 0
                res["solar_kwh"] += agg["solar_kwh"] or 0
                res["house_kwh"] += agg["house_kwh"] or 0
                res["batt_charge_kwh"] += agg["batt_charge_kwh"] or 0
                res["batt_discharge_kwh"] += agg["batt_discharge_kwh"] or 0
            else:
                rows = get_range(s0, s1)
                imp, exp = integrate(rows, "grid_w")
                sol, _ = integrate(rows, "solar_w")
                house, _ = integrate(rows, "house_w")
                dis, chg = integrate(rows, "battery_w")
                res["import_kwh"] += imp
                res["export_kwh"] += exp
                res["solar_kwh"] += sol
                res["house_kwh"] += house
                res["batt_charge_kwh"] += chg
                res["batt_discharge_kwh"] += dis
                if not rows and s0 < time.time() - RETENTION_S:
                    res["months_missing"] += 1
        m += 1
        if m > 12:
            m = 1
            y += 1
    return res
