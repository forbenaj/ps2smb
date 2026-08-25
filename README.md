# PS2SMB — HTTP-backed PS2 SMB Game Server

Serve PS2 game ISOs to **OPL (Open PS2 Loader)** over SMB, where the actual
ISO data lives behind remote HTTP/HTTPS URLs. The PS2 sees a normal SMB share
with `.iso` files; the server transparently fetches only the bytes OPL asks
for, using HTTP Range requests, and caches them locally.

```
PS2 + OPL
    │
    │  SMB (LAN)
    ▼
PC running ps2smb ──── status UI on http://localhost:9090
    │
    │  HTTP Range requests (only needed chunks)
    ▼
Remote ISO host (e.g. archive.org)
```

The PS2 never needs to know anything about HTTP or the Internet. No custom
PS2 software is required — stock OPL in SMB mode works as-is.

---

## Status

| Component | State |
|---|---|
| Chunk cache (`ps2smb/cache.py`) | ✅ Working, persistent, tested |
| HTTP virtual file (`ps2smb/remote.py`) | ✅ Working: range reads, probing, prefetch, no-range rejection |
| Catalog / filenames (`ps2smb/catalog.py`) | ✅ Working, collision-free deterministic names |
| Admin/status HTTP interface (`ps2smb/admin.py`) | ✅ Working (`/games`, `/cache`, `/downloads`, `/errors`, `/health`) |
| CLI entrypoint (`python -m ps2smb.server`) | ✅ Working |
| Core tests (21) | ✅ All passing |
| SMB layer (`ps2smb/smb.py`) | ✅ Working: create/read/query/list hooked for SMB1 + SMB2 |
| SMB integration tests (4) | ✅ All passing (SMB1 dialect, matching OPL) |

### Known issues (as of this snapshot)

1. **Windows Defender false positive**: Defender may quarantine files inside
   `venv\Lib\site-packages\impacket\` (known AV issue with that package).
   Reinstall with `.\venv\Scripts\pip install --force-reinstall impacket`
   if files go missing.
2. **SMB2 is disabled by default** in impacket's `SimpleSMBServer`
   (`SMB2Support=False`). OPL speaks SMB1, so this is fine for the target use
   case; the integration test client uses `preferredDialect=SMB_DIALECT`.
3. **SMB1 reads are capped at 64 KiB per request** (protocol `MaxCount` is
   16-bit). Clients loop automatically; no action needed.

### Next steps

1. Real-hardware test: configure OPL against the share and boot one game.
2. Write `ARCHITECTURE.md` (data-flow document; content largely covered below).

---

## Requirements

- Windows, Linux, or macOS
- Python 3.10+ (developed on 3.11)
- A LAN where the PC and PS2 can reach each other
- Remote ISO host that supports **HTTP byte ranges** (archive.org does)

## Setup

```powershell
# from the project root
python -m venv venv
.\venv\Scripts\pip install impacket requests pytest   # Windows
# source venv/bin/activate && pip install ...          # Linux/macOS
```

## Running

```powershell
.\venv\Scripts\python -m ps2smb.server --catalog catalogs\playstation-2-games-iso.json --cache .\cache
```

Useful options:

| Option | Default | Meaning |
|---|---|---|
| `--catalog` | *(required)* | JSON catalog of `{name, download_url}` entries |
| `--cache` | `./cache` | Local chunk-cache directory (persists across restarts) |
| `--share` | `PS2` | SMB share name |
| `--smb-host` / `--smb-port` | `0.0.0.0` / `445` | SMB listener (use port 445 for OPL; admin rights may be needed on Windows/Linux for <1024) |
| `--admin-host` / `--admin-port` | `127.0.0.1` / `9090` | Status web interface |
| `--chunk-mib` | `8` | Cache chunk size |
| `--prefetch` | `2` | Chunks to prefetch ahead of sequential reads |
| `-v` | off | Debug logging (per-read logs, cache hits/misses, HTTP ranges) |

On startup it prints the exact OPL settings to use, including the PC's LAN IP.

## Example catalog

```json
[
  { "name": "Ace Combat 04: Shattered Skies",
    "download_url": "https://example.host/ac4ss.iso" },
  { "name": "Gran Turismo 3: A-Spec",
    "download_url": "https://example.host/gt3.iso" }
]
```

Names are sanitized into filesystem-safe filenames; collisions get `-1`,
`-2`, … suffixes deterministically. The catalog remains the source of truth.

## Configuring OPL

1. Put OPL on your PS2 (memory card / HDD / USB as usual).
2. In OPL settings → **ETH**, set:
   - **IP Address Type**: Static or DHCP (PS2 must reach the PC)
   - **Server IP**: the PC's LAN IP (printed by ps2smb at startup)
   - **Server Port**: `445`
   - **Share**: `PS2` (or your `--share` value)
   - Username/password: leave empty (guest access)
3. Save, restart OPL, open the ETH game list. Games appear by filename.
4. Launching a game streams only the chunks OPL reads — no full download.

> Tip: if port 445 is taken on the PC (Windows Server service), stop the
> "Server"/"LanmanServer" service or run ps2smb with `--smb-port 445` after
> freeing it; OPL's port field must match.

## Status interface

With the server running:

- `http://localhost:9090/games` — every game, size, probe state, cached chunk count/bytes, errors
- `http://localhost:9090/cache` — cache root, chunk size, total cached bytes
- `http://localhost:9090/downloads` — active background prefetches
- `http://localhost:9090/errors` — recent errors

## How it works (architecture summary)

```
SMB read(offset, length)
      │
      ▼
VirtualFileHandle (registered by hooked SMB CREATE)
      │
      ▼
RemoteFile.read(offset, length)
      ├── probe(): HEAD → Content-Length, Accept-Ranges; tiny test GET → 206?
      │            No range support ⇒ loud error, never downloads whole ISO
      ▼
ChunkCache.get_or_download(chunk_index)
      ├── cached?  → read chunk file from disk        (cache HIT)
      └── missing? → HTTP GET Range: bytes=a-b        (cache MISS)
                     → write atomically to <cache>/<urlhash>/chunks/NNNNNNNN.chunk
      ▼
slice requested bytes out of the chunk(s) → return to SMB client
      +
background prefetch of next N chunks (sequential read-ahead)
```

Key properties:

- **Sparse/random access** — only touched chunks are ever downloaded.
- **Persistent** — cache survives restarts; chunk presence is re-scanned at startup.
- **Safe concurrency** — a global lock prevents duplicate downloads of the same chunk; partial writes are atomic (`.tmp` + rename).
- **Honest failures** — servers without range support or with bad URLs produce clear errors surfaced via `/errors` and logs.

## Tests

```powershell
.\venv\Scripts\python -m pytest tests\test_virtual_file.py tests\test_catalog.py -q
```

Covers: uncached reads, repeat-read cache hits, cross-chunk reads, random
seeks, EOF handling, restart persistence, concurrent readers, two clients on
one game, HTTP 404, no-range-support rejection, multi-game isolation, catalog
sanitization/collisions, and the real shipped catalogs.

```powershell
.\venv\Scripts\python -m pytest tests\test_smb_integration.py -q
```

Full-stack integration: a real SMB client (SMB1 dialect, like OPL) lists the
share, opens a virtual ISO, and reads arbitrary regions through cache + HTTP.

`smb_smoke.py` is a runnable end-to-end script with progress output — handy
for debugging without pytest.

## Project layout

```
ps2smb/
  cache.py     persistent chunk cache
  remote.py    HTTP-backed sparse virtual file (+ probing, prefetch)
  catalog.py   JSON catalog → sanitized filenames
  smb.py       impacket-based SMB server with virtual-file hooks
  admin.py     status HTTP interface
  server.py    CLI entrypoint (python -m ps2smb.server)
tests/
  conftest.py              fake HTTP range server fixture
  test_virtual_file.py     core layer tests
  test_catalog.py          catalog tests
  test_smb_integration.py  full-stack SMB tests
catalogs/                   real scraped catalogs (JSON)
smb_smoke.py                standalone end-to-end smoke script
```

## Scope & limitations (intentional, PoC)

- No authentication (guest-only share) — fine for a home LAN.
- No cache eviction — disk fills up over time; delete `<cache>` manually.
- Single-process; no performance tuning beyond simple prefetch.
- Filenames are derived from catalog names, not OPL's internal game IDs.
