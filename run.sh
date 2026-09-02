#!/usr/bin/env bash
# One-shot pipeline: crawl the network -> geolocate -> serve a local map.
#
# Usage:
#   ./run.sh --chain secretnetwork
#   ./run.sh --seed https://rpc.secretnetwork.pathrocknetwork.org --time 120
#   ./run.sh --chain secretnetwork --deep --workers 80
#
# Extra flags are passed through to crawler.py (see `python3 crawler.py --help`).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

PORT="${PORT:-8000}"
DATA_DIR="${DATA_DIR:-$DIR/data}"

echo "==> Crawling network"
python3 crawler.py --data-dir "$DATA_DIR" "$@"

echo "==> Expanding network via P2P/PEX peer gossip"
PEX_BIN="$DIR/pex/pex_crawler"
if [ -f "$DATA_DIR/pex_seeds.json" ] && [ -s "$DATA_DIR/pex_seeds.json" ]; then
    if [ ! -x "$PEX_BIN" ]; then
        echo "    building pex_crawler..."
        (cd "$DIR/pex" && go build -buildvcs=false -o pex_crawler .)
    fi
    SEEDS=$(python3 -c "import json,sys;print(','.join(json.load(open('$DATA_DIR/pex_seeds.json'))))" 2>/dev/null || true)
    NETWORK=$(python3 -c "
import json,sys
d=json.load(open('$DATA_DIR/endpoints.json'))
print(next(iter(d.values()))['chain_id'])" 2>/dev/null || true)
    if [ -n "$SEEDS" ] && [ -n "$NETWORK" ]; then
        "$PEX_BIN" --seeds "$SEEDS" --network "$NETWORK" --time 180 --depth 8 \
            --out "$DATA_DIR/peer_ips.json" --json "$DATA_DIR/pex_peers.json"
    else
        echo "    no pex seeds/chain-id available; skipping PEX expansion"
    fi
else
    echo "    no pex_seeds.json (run with --chain=<name> or RPC-reachable seeds); skipping PEX expansion"
fi

echo "==> Geolocating hosts"
python3 geolocate.py --data-dir "$DATA_DIR"

echo "==> Building analysis dashboard"
python3 analyze.py --data-dir "$DATA_DIR"

echo "==> Serving at http://127.0.0.1:$PORT/index.html (map) and /analysis.html (dashboards)"
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$DIR" >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 1
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:$PORT/index.html" >/dev/null 2>&1 || true
fi
echo "Press Ctrl-C to stop the server."
wait "$SERVER_PID"