#!/usr/bin/env python3
"""Rank supported networks by distribution and decentralization.

Reads every data/<slug>/all_nodes.json and computes, per network:

- **distribution** - geographic spread: the share of nodes OUTSIDE the most
  hosted country. Higher = more spread out (e.g. 75% means three quarters of
  nodes are outside the top country).
- **decentralization** - provider spread: the share of nodes OFF the most used
  hosting provider/ISP. Higher = more decentralized.

Writes data/chain_ranking.json, consumed by insights.html.
"""

from __future__ import annotations

import argparse
import json
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
        asns = Counter(g.get("asn") for g in nodes if g.get("asn"))
        top_country, top_country_n = countries.most_common(1)[0]
        top_asn, top_asn_n = asns.most_common(1)[0] if asns else ("?", 0)
        networks.append({
            "slug": net_dir.name,
            "nodes": n,
            "countries": len(countries),
            "regions": len({CONTINENTS.get(c, "Other") for c in countries}),
            "isps": len({provider_name(g.get("org")) for g in nodes if provider_name(g.get("org"))}),
            "topCountryShare": round(top_country_n / n, 3),
            "topAsnShare": round(top_asn_n / n, 3),
            "generatedAt": doc.get("generatedAt", ""),
        })

    # Most distributed first (lowest share of nodes in the top country).
    networks.sort(key=lambda x: (x["topCountryShare"], x["slug"]))
    out = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "networks": networks,
    }
    out_path = data_dir / "chain_ranking.json"
    out_path.write_text(json.dumps(out, indent=2))
    for net in networks:
        outside_country = round(100 * (1 - net["topCountryShare"]))
        outside_asn = round(100 * (1 - net["topAsnShare"]))
        print(f"{net['slug']}: n={net['nodes']} countries={net['countries']} isps={net['isps']} "
              f"{outside_country}% outside top region | {outside_asn}% outside top ASN")
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())