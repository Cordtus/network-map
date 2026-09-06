#!/usr/bin/env python3
"""Rank supported networks by distribution and decentralization.

Reads every data/<slug>/all_nodes.json and computes, per network:

- **distribution** — how geographically spread out the nodes are. Normalized
  Shannon entropy over countries (H / ln(nodes)); 1.0 = every node in its own
  country, 0.0 = all nodes in one country. Same provider in many countries
  scores high here (spread out geographically, not independent).
- **decentralization** — how spread out the nodes are across hosting
  providers/ISPs. Normalized Shannon entropy over provider names; 1.0 = every
  node on its own provider, 0.0 = all nodes on one provider. Many providers in
  the same region score high here.

Writes data/chain_ranking.json, consumed by insights.html.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from analyze import CONTINENTS


def provider_name(org: str | None) -> str | None:
    """Strip the leading ASN from an ipinfo/ip-api org string."""
    if not org:
        return None
    parts = str(org).split(" ", 1)
    if parts[0].startswith("AS") and len(parts) > 1:
        return parts[1]
    return org


def norm_entropy(values, n: int) -> float:
    """Shannon entropy over a count distribution, normalized to 0..1.

    H / ln(n) is 1.0 when every node occupies its own category and 0.0 when all
    nodes share a single category.
    """
    if n <= 1:
        return 0.0
    h = -sum((c / n) * math.log(c / n) for c in values if c > 0)
    return h / math.log(n)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Rank networks by distribution and decentralization")
    p.add_argument("--data-dir", default=None,
                   help="Parent dir holding per-network subdirs (default <script_dir>/data)")
    args = p.parse_args(argv)
    data_dir = Path(args.data_dir) if args.data_dir else Path(__file__).resolve().parent / "data"

    networks = []
    for net_dir in sorted(data_dir.iterdir()):
        if not net_dir.is_dir():
            continue
        src = net_dir / "all_nodes.json"
        if not src.exists():
            continue
        try:
            doc = json.loads(src.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        nodes = doc.get("good", []) + doc.get("peers", [])
        if not nodes:
            continue
        n = len(nodes)
        countries = Counter(g.get("countryCode") or g.get("country") or "?" for g in nodes)
        providers = Counter(p for g in nodes if (p := provider_name(g.get("org"))) is not None)
        networks.append({
            "slug": net_dir.name,
            "nodes": n,
            "countries": len(countries),
            "regions": len({CONTINENTS.get(c, "Other") for c in countries}),
            "isps": len(providers),
            "distribution": round(norm_entropy(countries.values(), n), 3),
            "decentralization": round(norm_entropy(providers.values(), n), 3),
            "generatedAt": doc.get("generatedAt", ""),
        })

    networks.sort(key=lambda x: (-x["distribution"], -x["decentralization"], x["slug"]))
    out = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "networks": networks,
    }
    out_path = data_dir / "chain_ranking.json"
    out_path.write_text(json.dumps(out, indent=2))
    for net in networks:
        print(f"{net['slug']}: nodes={net['nodes']} countries={net['countries']} "
              f"isps={net['isps']} dist={net['distribution']} dec={net['decentralization']}")
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())