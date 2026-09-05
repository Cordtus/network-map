#!/usr/bin/env bash
# One-shot pipeline: crawl the network -> geolocate -> serve a local map.
#
# Usage:
#   ./run.sh --network nomic
#   ./run.sh --network secretnetwork --seed https://rpc.secretnetwork.pathrocknetwork.org --time 120
#   ./run.sh --network nomic --deep --workers 80
#
# --network <slug> selects the network (data lives in data/<slug>/); it defaults
# to the first --chain name given, else "secretnetwork". Extra flags are passed
# through to crawler.py (see `python3 crawler.py --help`).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

PORT="${PORT:-8000}"

# Consume run.sh-level flags; everything else goes to crawler.py.
NETWORK=""
CHAIN=""
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --network=*) NETWORK="${1#--network=}"; shift ;;
        --network) NETWORK="$2"; shift 2 ;;
        --chain=*) CHAIN="${1#--chain=}"; ARGS+=("$1"); shift ;;
        --chain) CHAIN="$2"; ARGS+=("$1" "$2"); shift 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

NETWORK="${NETWORK:-${CHAIN:-secretnetwork}}"
DATA_DIR="${DATA_DIR:-$DIR/data/$NETWORK}"

# No explicit chain: seed from the chain-registry using the network slug.
if [[ -z "$CHAIN" ]]; then
    ARGS+=(--chain "$NETWORK")
fi

# Local basemap config (CARTO key goes here, not in git)
[ -f config.js ] || cp config.example.js config.js

echo "==> Crawling network: $NETWORK"
python3 crawler.py --data-dir "$DATA_DIR" "${ARGS[@]}"

echo "==> Expanding network via P2P/PEX peer gossip"
PEX_BIN="$DIR/pex/pex_crawler"
if [ -f "$DATA_DIR/pex_seeds.json" ] && [ -s "$DATA_DIR/pex_seeds.json" ]; then
    if [ ! -x "$PEX_BIN" ]; then
        echo "    building pex_crawler..."
        (cd "$DIR/pex" && go build -buildvcs=false -o pex_crawler .)
    fi
    SEEDS=$(python3 -c "import json,sys;print(','.join(json.load(open('$DATA_DIR/pex_seeds.json'))))" 2>/dev/null || true)
    NETWORK_ID=$(python3 -c "
import json,sys
d=json.load(open('$DATA_DIR/endpoints.json'))
print(next(iter(d.values()))['chain_id'])" 2>/dev/null || true)
    if [ -n "$SEEDS" ] && [ -n "$NETWORK_ID" ]; then
        "$PEX_BIN" --seeds "$SEEDS" --network "$NETWORK_ID" --time 240 \
            --out "$DATA_DIR/peer_ips.json" --json "$DATA_DIR/pex_peers.json"
    else
        echo "    no pex seeds/chain-id available; skipping PEX expansion"
    fi
else
    echo "    no pex_seeds.json (run with --chain=<name> or RPC-reachable seeds); skipping PEX expansion"
fi

echo "==> Geolocating hosts"
python3 geolocate.py --data-dir "$DATA_DIR" --network "$NETWORK"

echo "==> Building insights dashboard"
python3 analyze.py --data-dir "$DATA_DIR" --network "$NETWORK"

echo "==> Serving at http://127.0.0.1:$PORT/index.html?network=$NETWORK (map) and /insights.html?network=$NETWORK (insights)"
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$DIR" >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 1
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:$PORT/index.html?network=$NETWORK" >/dev/null 2>&1 || true
fi
echo "Press Ctrl-C to stop the server."
wait "$SERVER_PID"