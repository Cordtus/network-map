# Network Map

Crawl a CometBFT / Cosmos-SDK network from a single endpoint, geolocate every
node (with ISP + WHOIS), and plot it on a map with an analysis dashboard.

Live deployment: https://netmap.basementnodes.ca

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
./run.sh --seed https://rpc.secretnetwork.pathrocknetwork.org
```

That single endpoint seeds the crawl, chain-id is auto-detected (`secret-4`),
the peer network is expanded over P2P/PEX, everything is geolocated + enriched,
and a local server opens the map and analysis at http://127.0.0.1:8000.

Seeds from the chain registry too:

```bash
./run.sh --chain secretnetwork
```

More options (deep port scan, workers, time, ...):

```bash
python3 crawler.py --help
./run.sh --chain secretnetwork --deep --workers 80 --time 600
```

## Requirements

- Python 3.11+ with `requests` (`pip install requests`)
- Go 1.21+ (only needed for the P2P/PEX expansion; the pex_crawler binary is
  built on first use)

## Outputs

| File | Contents |
|---|---|
| `data/peer_ips.json` | all discovered node IPs |
| `data/good_ips.json` | hosts that expose RPC |
| `data/nodes.json` | node metadata (moniker, archive, endpoints) |
| `data/all_nodes.json` | geo + ISP + WHOIS + flags per node |
| `nodes.csv` | full flat export (host, geo, timezone, ASN, ISP, WHOIS, ...) |
| `geolocations.js` | map data (loaded by `index.html`) |
| `analysis.html` | ISP / regional / WHOIS / timezone dashboards |

## Layout

- `crawler.py` — RPC crawler + port probing + chain-registry seeding
- `pex/main.go` — P2P/PEX peer-gossip crawler (Go, uses CometBFT)
- `geolocate.py` — geolocation + WHOIS + enrichment (cached)
- `analyze.py` — analysis dashboard generator
- `index.html` — Leaflet map
- `run.sh` — end-to-end pipeline + local server