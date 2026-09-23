# Powerwall 2 Dashboard

A local, self-hosted live dashboard for a Tesla Powerwall 2 system. Polls the
Tesla gateway every 10 seconds (burst-tested safe) and renders:

- **KPI cards** — solar, home, grid, battery (kW now + kWh today), SoE gauge
- **4-view power-flow widget** — Flow hub, Schematic, Summary, and a Sankey
  with animated power-flow particles
- **Grid-import verdict banner** (importing / exporting / balanced)
- **History charts** (SoE + grid power, 6h / 24h / 3d / 7d)
- **Energy summaries** with a rolling SQLite store (90 days raw + permanent
  monthly rollups)

Dark theme, responsive (mobile: zoom + swipe-to-pan, reflowed data rows),
click ⓘ tooltips, local API password option.

## Quick start

1. **Python 3.10+** (3.14 tested). Dependencies:

   ```
   pip install flask waitress requests cryptography apscheduler
   ```

   (Or use the bundled `start.bat`, which prefers a local `.venv` if present.)

2. **Launch:**

   ```
   start.bat            (Windows)
   python app.py        (anywhere)
   ```

   The server binds `0.0.0.0:8771`.

3. **Configure via the dashboard** — open `http://<your-host>:8771`, use the
   settings page to enter:

   - `gateway` — your Powerwall gateway address (e.g. `https://192.168.x.x`)
   - `email` — your Tesla app account email (optional; sent at login)
   - `local_api_password` — the gateway sticker password (stored **Fernet-
     encrypted** on disk in `config.json`; never exposed by the API)
   - tariff rates (`grid_import_rate`, `grid_export_credit`) — optional

   No code changes are needed to point the app at a different gateway or
   switch credentials.

## Security notes

- **No secrets in the repo.** `config.json` and `config.key` are gitignored;
  the local API password is Fernet-encrypted at rest (key in `config.key`,
  also gitignored) and is never returned by `GET /api/config`.
- **Auth modes** — the gateway client logs in with the sticker password
  (`/api/login/Basic`, username `customer`). The Bearer token it receives is
  held in memory only.
- **Gateway TLS quirk** — the gateway fingerprints clients: `urllib` handshakes
  are rejected (403) even with a valid token, so all HTTP goes through a
  shared `requests.Session` with cert verification disabled (self-signed cert).
- **Bind address** — the server listens on all interfaces on port 8771. Keep
  it on your LAN; do not expose port 8771 to the internet.

## Storage

- SQLite (WAL mode) — raw 10-second snapshots kept for 90 days, then rolled up
  into permanent monthly aggregates.

## Project layout

| File | Purpose |
|---|---|
| `app.py` | Flask app, REST API, scheduler, config UI backend |
| `config.py` | Config load/save with Fernet-encrypted secrets |
| `powerwall.py` | Tesla gateway client + poller (requests-based) |
| `storage.py` | SQLite persistence, retention, rollups |
| `templates/dashboard.html` | Dashboard UI (KPI cards, power-flow widget, charts) |
| `start.bat` | Windows launcher (uses `.venv` if present) |
