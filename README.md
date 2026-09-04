# Network Map

Crawl CometBFT / Cosmos-SDK networks from a single endpoint, geolocate every
node (with ISP + WHOIS), and plot them on a map with an insights dashboard.
A dropdown in the header switches between supported networks.

Live deployment: https://netmap.basementnodes.ca

## Supported networks

Defined in `networks.js`. Each network keeps its own data in `data/<slug>/`.

| Network | Slug | Chain-id |
|---|---|---|
| Secret Network | `secretnetwork` | `secret-4` |
| Nomic | `nomic` | `nomic-stakenet-3` |
| GenesisL1 | `genesisl1` | `genesis_29-2` |

## What it does

1. **Crawl** (`crawler.py`) — seeds from your endpoint (RPC/REST/gRPC) and/or the
   cosmos chain-registry, BFS-crawls `/net_info`, and probes peer IPs across
   common + digit-variation RPC ports (port-first, polite, rate-limited).
2. **P2P expansion** (`pex/`) — a Go helper that speaks the real CometBFT P2P
   protocol (SecretConnection + MConnection + PEX reactor) to ask every node for
   its peer address book. This reveals the full network even when nodes hide RPC.
3. **Geolocate** (`geolocate.py`) — ipinfo.io primary, ip-api.com fallback, RDAP
   WHOIS per IP. Cached on disk.
4. **Analyze** (`analyze.py`) — ISP / regional / ASN / WHOIS / timezone /
   hosting distribution dashboard.
5. **Serve** — a local static server with the Leaflet map and the dashboards.

## Quick start

```bash
./run.sh --network secretnetwork
./run.sh --network nomic
```

`--network <slug>` selects the network (default: the first `--chain` given,
else `secretnetwork`) and runs the whole pipeline into `data/<slug>/`. The
chain-id is auto-detected from the live network; if you pass `--chain`, the
chain-registry name is used (it usually matches the slug):

```bash
./run.sh --network nomic --chain nomic --deep --workers 80 --time 600
```

Seed from a single endpoint instead (chain-id auto-detected):

```bash
./run.sh --network secretnetwork --seed https://rpc.secretnetwork.pathrocknetwork.org
```

More options (deep port scan, workers, time, ...):

```bash
python3 crawler.py --help
```

## Requirements

- Python 3.11+ with `requests` (`pip install requests`)
- Go 1.21+ (only needed for the P2P/PEX expansion; `pex_crawler` builds on
  first run against the published CometBFT module — no local checkout needed)

## Setup

```bash
git clone git@github.com:Cordtus/network-map.git
cd network-map
pip install requests
```

The geolocation step uses a bundled ipinfo.io token by default (legacy free
plan, ~50k lookups/month). To use your own token:

```bash
export IPINFO_TOKEN=your_token
```

Optionally enrich each IP with ip-api datacenter flags (`hosting` / `mobile` /
`proxy`) — opt-in, rate-limited to ~45/min so a full network takes a while:

```bash
python3 geolocate.py --data-dir data/nomic --ipapi-enrich
```

## Web data layout

Each network's web assets live in its own data dir, so the dropdown can switch
without server-side logic:

| File | Contents |
|---|---|
| `data/<slug>/geolocations.js` | map data (loaded by `index.html`) |
| `data/<slug>/insights.json` | insights data (fetched by `insights.html`) |
| `data/<slug>/nodes.csv` | full flat export |

Open `index.html?network=<slug>` (or `insights.html?network=<slug>`) to view a
specific network; the header dropdown navigates between them.

### Basemap (optional CARTO API key)

The map uses keyless OpenStreetMap tiles by default (dark mode applies a
night-view filter). To use CARTO basemaps instead, set your API key in
`config.js` (create it from `config.example.js`; it is git-ignored):

```js
window.BASEMAP_KEY = "your_carto_basemap_key";
```

With a key, the map serves CARTO `voyager` (light) / `dark_all` (dark) tiles.
CARTO's free tier permits 5M tile requests/month and requires prominent
attribution to both OpenStreetMap and CARTO. Do not proxy or cache the tiles
server-side.

## Per-node data fields

| Field | Meaning |
|---|---|
| `host`, `ip`, `latitude`, `longitude` | node identifier + coordinates |
| `city`, `region`, `country`, `countryCode` | geographic location |
| `timezone` | IANA timezone (e.g. `Asia/Kolkata`) |
| `postal` | postal / ZIP code |
| `hostname` | reverse-DNS / PTR name (e.g. `ns5021787.ip-148-113-1.net`) |
| `asn`, `org` | autonomous system number + provider/ISP (e.g. `AS16276`, `OVH SAS`) |
| `whois.{netname,org,cidr,abuse}` | RDAP registry record (allocated block, registrant, abuse contact) |
| `hosting`, `mobile`, `proxy` | ip-api datacenter flags (via `--ipapi-enrich`) |
| `moniker`, `chain`, `archive`, `fresh` | on-chain node metadata |
| `rpc`, `rest` | live endpoints when the node exposes them |

## Outputs

Per network under `data/<slug>/`:

| File | Contents |
|---|---|
| `peer_ips.json` | all discovered node IPs |
| `good_ips.json` | hosts that expose RPC |
| `nodes.json` | node metadata (moniker, archive, endpoints) |
| `all_nodes.json` | geo + ISP + WHOIS + flags per node |
| `nodes.csv` | full flat export (host, geo, timezone, ASN, ISP, WHOIS, ...) |
| `geolocations.js` | map data (loaded by `index.html`) |
| `insights.json` | insights data (fetched by `insights.html`) |

## Layout

- `crawler.py` — RPC crawler + port probing + chain-registry seeding
- `pex/main.go` — P2P/PEX peer-gossip crawler (Go, uses CometBFT)
- `geolocate.py` — geolocation + WHOIS + enrichment (cached)
- `analyze.py` — insights data generator
- `networks.js` — supported network registry (drives the header dropdown)
- `index.html` — Leaflet map
- `insights.html` — ISP / regional / WHOIS / timezone dashboards
- `run.sh` — end-to-end pipeline + local server