#!/usr/bin/env python3
"""Analyze the crawled node dataset and emit an interactive HTML dashboard.

Reads data/all_nodes.json (geo + ISP + whois + flags) and writes analysis.html
next to the map with Chart.js visualizations:
  ISP distribution, ISP regional distribution, countries, continents, ASNs,
  whois registrant orgs, timezone distribution, hosting/mobile/proxy, RPC/peer.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

CONTINENTS = {
    # ISO 3166-1 alpha-2 -> continent
    "US": "North America", "CA": "North America", "MX": "North America", "PA": "North America",
    "BR": "South America", "AR": "South America", "CL": "South America", "CO": "South America",
    "GB": "Europe", "DE": "Europe", "NL": "Europe", "FR": "Europe", "PL": "Europe",
    "FI": "Europe", "SE": "Europe", "CH": "Europe", "AT": "Europe", "BE": "Europe",
    "IT": "Europe", "ES": "Europe", "CZ": "Europe", "IE": "Europe", "UA": "Europe",
    "RO": "Europe", "BG": "Europe", "LV": "Europe", "LT": "Europe", "EE": "Europe",
    "NO": "Europe", "DK": "Europe", "PT": "Europe", "GR": "Europe", "SK": "Europe",
    "SI": "Europe", "HR": "Europe", "HU": "Europe", "RS": "Europe", "RU": "Europe",
    "TR": "Asia", "IN": "Asia", "SG": "Asia", "JP": "Asia", "KR": "Asia", "HK": "Asia",
    "TW": "Asia", "VN": "Asia", "TH": "Asia", "ID": "Asia", "MY": "Asia", "AE": "Asia",
    "SA": "Asia", "IL": "Asia", "PK": "Asia", "BD": "Asia", "UZ": "Asia", "GE": "Asia",
    "AU": "Oceania", "NZ": "Oceania", "FJ": "Oceania",
    "ZA": "Africa", "NG": "Africa", "KE": "Africa", "EG": "Africa", "GH": "Africa",
    "NZ": "Oceania", "VI": "North America", "SC": "Africa", "KY": "North America",
    "MC": "Europe", "IM": "Europe", "JE": "Europe", "LU": "Europe", "MT": "Europe",
}


def provider_name(org: str | None) -> str:
    """Strip the leading ASN from an ipinfo/ip-api org string."""
    if not org:
        return "(unknown)"
    parts = org.split(" ", 1)
    if parts[0].startswith("AS") and len(parts) > 1:
        return parts[1]
    return org


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyze crawled node data -> insights dashboard")
    p.add_argument("--data-dir", default=None, help="Crawler data dir (default <script_dir>/data)")
    p.add_argument("--network", default=None, help="Network slug for output paths (default from data-dir basename)")
    args = p.parse_args(argv)
    data_dir = Path(args.data_dir) if args.data_dir else Path(__file__).resolve().parent / "data"
    if args.network is None:
        args.network = data_dir.name

    src = data_dir / "all_nodes.json"
    if not src.exists():
        print("all_nodes.json missing. Run crawler.py then geolocate.py first.", file=sys.stderr)
        return 1
    doc = json.loads(src.read_text())
    good, peers = doc.get("good", []), doc.get("peers", [])
    nodes = good + peers

    if not nodes:
        print("no node data", file=sys.stderr)
        return 1

    def node_type(g: dict) -> str:
        return "RPC" if g.get("rpc") else "peer"

    countries = Counter(g.get("countryCode") or g.get("country") or "?" for g in nodes)
    isps = Counter(provider_name(g.get("org")) for g in nodes)
    whois_orgs = Counter((g.get("whois") or {}).get("org") or "(no whois org)" for g in nodes)
    timezones = Counter(g.get("timezone") or "(unknown)" for g in nodes)
    continents = Counter(CONTINENTS.get(c, "Other") for c in countries)
    types = Counter(node_type(g) for g in nodes)

    # ISP x country cross-tab for the top ISPs
    top_isps = [name for name, _ in isps.most_common(6)]
    top_countries = [c for c, _ in countries.most_common(6)]
    isp_by_country = {}
    for isp in top_isps:
        cc = Counter()
        for g in nodes:
            if provider_name(g.get("org")) == isp:
                cc[g.get("countryCode") or g.get("country") or "?"] += 1
        isp_by_country[isp] = {
            c: cc.get(c, 0) for c in top_countries
        } | {"Other": sum(v for k, v in cc.items() if k not in top_countries)}

    stats = {
        "total": len(nodes),
        "rpc": types.get("RPC", 0),
        "peers": types.get("peer", 0),
        "countries": len(countries),
        "isps": len(isps),
        "whoisOrgs": len([k for k in whois_orgs if k and k != "(no whois org)"]),
    }

    data = {
        "generatedAt": doc.get("generatedAt", ""),
        "network": args.network,
        "stats": stats,
        "countries": {"labels": [c for c, _ in countries.most_common(15)],
                      "values": [v for _, v in countries.most_common(15)]},
        "continents": {"labels": [c for c, _ in continents.most_common()],
                       "values": [v for _, v in continents.most_common()]},
        "isps": {"labels": [i for i, _ in isps.most_common(15)],
                 "values": [v for _, v in isps.most_common(15)]},
        "ispByCountry": {"isps": top_isps, "countries": top_countries + ["Other"],
                         "rows": {i: [isp_by_country[i][c] for c in top_countries + ["Other"]] for i in top_isps}},
        "whoisOrgs": {"labels": [w for w, _ in whois_orgs.most_common(12)],
                      "values": [v for _, v in whois_orgs.most_common(12)]},
        "timezones": {"labels": [t for t, _ in timezones.most_common(12)],
                      "values": [v for _, v in timezones.most_common(12)]},
        "table": [
            {
                "host": g.get("host") or g.get("ip"),
                "ip": g.get("ip"),
                "type": node_type(g),
                "country": g.get("countryCode") or g.get("country"),
                "city": g.get("city"),
                "timezone": g.get("timezone"),
                "isp": provider_name(g.get("org")),
                "asn": g.get("asn"),
                "whois": (g.get("whois") or {}).get("org"),
                "hostname": g.get("hostname"),
                "hosting": "yes" if g.get("hosting") is True else ("no" if g.get("hosting") is False else "?"),
                "moniker": g.get("moniker") or "",
            }
            for g in nodes
        ],
    }

    data_dir.mkdir(parents=True, exist_ok=True)
    out = data_dir / "insights.json"
    out.write_text(json.dumps(data, indent=2))

    print("insights.json written to", out)
    print(json.dumps(stats, indent=2))
    print("top countries:", countries.most_common(6))
    print("top ISPs:", isps.most_common(6))
    return 0


if __name__ == "__main__":
    sys.exit(main())
