# Energy Dashboard

A local, self-hosted live dashboard for home solar + storage systems.
Polls your inverter/gateway every 10 seconds (burst-tested safe) and renders:

- **KPI cards** — solar, home, grid, battery (kW now + kWh today), SoE gauge
- **4-view power-flow widget** — Flow hub, Schematic, Summary, and a Sankey
  with animated power-flow particles
- **Grid-import verdict banner** (importing / exporting / balanced)
- **History charts** (SoE + grid power, 6h / 24h / 3d / 7d)
- **Energy summaries** with a rolling SQLite store (90 days raw + permanent
  monthly rollups)
- **Source switcher** — run Tesla *and* Enphase (or any future source) from
  the same dashboard, switching live from the header without restarting

Dark theme, responsive (mobile: zoom + swipe-to-pan, reflowed data rows),
click ⓘ tooltips, local API password option.

## Supported sources

| Source | What it talks to | Battery? |
|---|---|---|
| `tesla` (default) | Powerwall 2 gateway (`/api/...`, sticker-password login) | Yes |
| `enphase` | IQ Gateway, backbone API (`/auth/check_jwt` + `/production.json`) | Optional — the UI degrades to "no battery" when `soe_pct` is null |

A source is selected in `config.json` (`"source": "tesla"` / `"enphase"`)
or live from the header buttons. Each source implements the same
`poll_once() -> normalised snapshot` interface, so charts, cards and the
widget are source-agnostic.

Adding a new source = one module with `poll_once()` + a name in
`build_source()` in `app.py`. Nothing else changes.

## Enphase notes

- Auth: `GET /auth/check_jwt` with `Authorization: Bearer <token>` (a token
  from the Enphase portal's gateway credentials) issues a `sessionId` cookie;
  all subsequent API calls use **the cookie only** — the gateway resets
  connections that carry the Bearer token.
- The gateway rate-limits the token: the client authenticates only on 401,
  honours a 5-minute lockout after a rejected attempt, and **persists the
  session cookie** (`.ig_session`, gitignored) so restarts reuse the session
  instead of re-presenting the token.

![Energy Dashboard](assets/screenshot-home.png)

> *Live dashboard — KPI cards (battery SoE, battery, home, grid, solar), the
> 4-view power-flow widget (Flow / Schematic / Summary / Sankey), history
> charts, rolling energy summaries, and a grid-import verdict banner. All data
> is polled from your gateway every 10 seconds. The header source switcher
> flips between Tesla and Enphase live.*

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

   - `source` — `tesla` (default) or `enphase`
   - `gateway` — the gateway address (Tesla: `https://192.168.x.x`; Enphase
     IQ Gateway: `https://<iq-gateway-ip>`)
   - `email` — your Tesla app account email (optional; sent at login)
   - `local_api_password` — the gateway sticker password (Tesla only)
   - `enphase_token` — the IQ Gateway JWT (Enphase only)
   - tariff rates (`grid_import_rate`, `grid_export_credit`) — optional
   (Both secret fields are stored **Fernet-encrypted** on disk in
   `config.json` and are never exposed by the API.)

   No code changes are needed to point the app at a different gateway or
   switch credentials.

## Security notes

- **No secrets in the repo.** `config.json`, `config.key` and `.ig_session`
  (Enphase session cookie) are gitignored; the local API password and the
  Enphase token are Fernet-encrypted at rest (key in `config.key`, also
  gitignored) and are never returned by `GET /api/config`.
- **Auth modes** — the Tesla client logs in with the sticker password
  (`/api/login/Basic`, username `customer`) and holds the Bearer token in
  memory only. The Enphase client exchanges the portal JWT for a `sessionId`
  cookie once and reuses it (see *Enphase notes* above).
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
| `app.py` | Flask app, REST API, scheduler, config UI, source factory |
| `config.py` | Config load/save with Fernet-encrypted secrets |
| `powerwall.py` | Tesla gateway client + poller (requests-based) |
| `enphase.py` | Enphase IQ Gateway client + poller (JWT → session cookie) |
| `storage.py` | SQLite persistence, retention, rollups (`source` column) |
| `templates/dashboard.html` | Dashboard UI (KPI cards, power-flow widget, charts) |
| `start.bat` | Windows launcher (uses `.venv` if present) |
