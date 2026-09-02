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
    p = argparse.ArgumentParser(description="Analyze crawled node data -> analysis.html")
    p.add_argument("--data-dir", default=None, help="Crawler data dir (default <script_dir>/data)")
    args = p.parse_args(argv)
    data_dir = Path(args.data_dir) if args.data_dir else Path(__file__).resolve().parent / "data"

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
    asns = Counter((g.get("asn") or "").strip() for g in nodes)
    whois_orgs = Counter((g.get("whois") or {}).get("org") or "(no whois org)" for g in nodes)
    timezones = Counter(g.get("timezone") or "(unknown)" for g in nodes)
    continents = Counter(CONTINENTS.get(c, "Other") for c in countries)
    hosting = Counter(
        "hosting" if g.get("hosting") is True else ("not hosting" if g.get("hosting") is False else "unknown")
        for g in nodes
    )
    mobile = sum(1 for g in nodes if g.get("mobile") is True)
    proxy = sum(1 for g in nodes if g.get("proxy") is True)
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
        "asns": len([k for k in asns if k]),
        "whoisOrgs": len([k for k in whois_orgs if k and k != "(no whois org)"]),
        "hostingPct": round(100 * hosting.get("hosting", 0) / max(1, hosting.get("hosting", 0) + hosting.get("not hosting", 0)), 1),
        "hostingUnknown": hosting.get("unknown", 0),
        "mobile": mobile,
        "proxy": proxy,
    }

    data = {
        "generatedAt": doc.get("generatedAt", ""),
        "stats": stats,
        "countries": {"labels": [c for c, _ in countries.most_common(15)],
                      "values": [v for _, v in countries.most_common(15)]},
        "continents": {"labels": [c for c, _ in continents.most_common()],
                       "values": [v for _, v in continents.most_common()]},
        "isps": {"labels": [i for i, _ in isps.most_common(15)],
                 "values": [v for _, v in isps.most_common(15)]},
        "ispByCountry": {"isps": top_isps, "countries": top_countries + ["Other"],
                         "rows": {i: [isp_by_country[i][c] for c in top_countries + ["Other"]] for i in top_isps}},
        "asns": {"labels": [a for a, _ in asns.most_common(12)],
                 "values": [v for _, v in asns.most_common(12)]},
        "whoisOrgs": {"labels": [w for w, _ in whois_orgs.most_common(12)],
                      "values": [v for _, v in whois_orgs.most_common(12)]},
        "timezones": {"labels": [t for t, _ in timezones.most_common(12)],
                      "values": [v for _, v in timezones.most_common(12)]},
        "hosting": {"labels": list(hosting.keys()), "values": list(hosting.values())},
        "types": {"labels": list(types.keys()), "values": list(types.values())},
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

    out = Path(__file__).resolve().parent / "analysis.html"
    html = TEMPLATE.replace("/*__DATA__*/", json.dumps(data))
    out.write_text(html)

    print("analysis.html written to", out)
    print(json.dumps(stats, indent=2))
    print("top countries:", countries.most_common(6))
    print("top ISPs:", isps.most_common(6))
    return 0


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Secret Network Node Analysis</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root { --blue:#1f77ff; --green:#2ecc71; --purple:#7b2ff7; --red:#e74c3c; }
  body { margin:0; font-family:system-ui,sans-serif; background:#0f1420; color:#e6ebf5; }
  header { padding:22px 28px; border-bottom:1px solid #232b3d; display:flex; align-items:baseline; gap:18px; }
  header h1 { margin:0; font-size:20px; }
  header a { color:var(--blue); text-decoration:none; font-size:13px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; padding:22px 28px; }
  .card { background:#171e2e; border:1px solid #232b3d; border-radius:10px; padding:14px 16px; }
  .card .n { font-size:26px; font-weight:700; }
  .card .l { font-size:12px; color:#8b96ad; text-transform:uppercase; letter-spacing:.05em; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(420px,1fr)); gap:16px; padding:0 28px 28px; }
  .panel { background:#171e2e; border:1px solid #232b3d; border-radius:10px; padding:16px; }
  .panel h2 { margin:0 0 10px; font-size:14px; color:#aeb8cc; }
  .panel .chart { position:relative; height:320px; }
  table { border-collapse:collapse; width:100%; font-size:12px; }
  th,td { padding:6px 10px; text-align:left; border-bottom:1px solid #232b3d; white-space:nowrap; }
  th { position:sticky; top:0; background:#171e2e; color:#8b96ad; text-transform:uppercase; font-size:10px; letter-spacing:.05em; }
  .pill { display:inline-block; padding:1px 8px; border-radius:10px; font-size:10px; font-weight:600; }
  .pill.rpc { background:rgba(31,119,255,.2); color:#6ea6ff; }
  .pill.peer { background:rgba(46,204,113,.15); color:#4fe38b; }
  .table-wrap { overflow:auto; max-height:560px; }
  .muted { color:#8b96ad; }
</style>
</head>
<body>
<header>
  <h1>Secret Network node analysis</h1>
  <a href="index.html">&larr; map</a>
  <a href="nodes.csv">download CSV</a>
  <span class="muted" id="gen"></span>
</header>

<div class="cards" id="cards"></div>

<div class="grid">
  <div class="panel"><h2>Top ISPs / hosting providers</h2><div class="chart"><canvas id="isps"></canvas></div></div>
  <div class="panel"><h2>Top countries</h2><div class="chart"><canvas id="countries"></canvas></div></div>
  <div class="panel"><h2>ISP distribution by region (top ISPs)</h2><div class="chart"><canvas id="ispByCountry"></canvas></div></div>
  <div class="panel"><h2>Continents</h2><div class="chart"><canvas id="continents"></canvas></div></div>
  <div class="panel"><h2>Top ASNs</h2><div class="chart"><canvas id="asns"></canvas></div></div>
  <div class="panel"><h2>WHOIS registrant organizations</h2><div class="chart"><canvas id="whoisOrgs"></canvas></div></div>
  <div class="panel"><h2>Timezone distribution</h2><div class="chart"><canvas id="timezones"></canvas></div></div>
  <div class="panel"><h2>Node types &amp; hosting flags</h2><div class="chart"><canvas id="types"></canvas></div></div>
</div>

<div class="grid"><div class="panel" style="grid-column:1/-1">
  <h2>All nodes</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Host / IP</th><th>Type</th><th>Country</th><th>City</th><th>Timezone</th><th>ISP</th><th>ASN</th><th>WHOIS org</th><th>Reverse DNS</th><th>Hosting</th><th>Moniker</th></tr></thead>
    <tbody id="tbody"></tbody>
  </table></div>
</div></div>

<script>
const DATA = /*__DATA__*/;
const D = DATA;

document.getElementById('gen').textContent = 'generated ' + (D.generatedAt || '?');

const s = D.stats;
const cards = document.getElementById('cards');
const defs = [
  ['Total nodes', s.total], ['RPC', s.rpc], ['Peers', s.peers],
  ['Countries', s.countries], ['ISPs', s.isps], ['ASNs', s.asns],
  ['WHOIS orgs', s.whoisOrgs], ['Hosting %', s.hostingPct + '%'],
];
cards.innerHTML = defs.map(([l, n]) =>
  `<div class="card"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

const grid = '#232b3d', panel = '#171e2e', text = '#e6ebf5';
Chart.defaults.color = '#aeb8cc';
Chart.defaults.borderColor = grid;
Chart.defaults.font.family = 'system-ui, sans-serif';

function bar(id, labels, values, color, horizontal) {
  new Chart(document.getElementById(id), {
    type: horizontal ? 'bar' : 'bar',
    data: { labels, datasets: [{ data: values, backgroundColor: color || 'rgba(31,119,255,.75)', borderRadius: 4 }] },
    options: { indexAxis: horizontal ? 'y' : 'x', maintainAspectRatio: false, plugins: { legend: { display: false } } }
  });
}

bar('isps', D.isps.labels, D.isps.values, 'rgba(31,119,255,.75)', true);
bar('countries', D.countries.labels, D.countries.values, 'rgba(46,204,113,.7)', true);
bar('asns', D.asns.labels, D.asns.values, 'rgba(123,47,247,.7)', true);
bar('whoisOrgs', D.whoisOrgs.labels, D.whoisOrgs.values, 'rgba(231,76,60,.65)', true);
bar('timezones', D.timezones.labels, D.timezones.values, 'rgba(241,196,15,.7)', true);

const palette = ['#1f77ff','#2ecc71','#e74c3c','#f39c12','#7b2ff7','#00bcd4','#e91e63'];
new Chart(document.getElementById('continents'), {
  type: 'doughnut',
  data: { labels: D.continents.labels, datasets: [{ data: D.continents.values, backgroundColor: palette }] },
  options: { maintainAspectRatio: false }
});

new Chart(document.getElementById('ispByCountry'), {
  type: 'bar',
  data: {
    labels: D.ispByCountry.isps,
    datasets: D.ispByCountry.countries.map((c, i) => ({
      label: c, data: D.ispByCountry.isps.map(isp => D.ispByCountry.rows[isp][i]),
      backgroundColor: palette[i % palette.length]
    }))
  },
  options: { indexAxis: 'y', maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
});

new Chart(document.getElementById('types'), {
  type: 'doughnut',
  data: {
    labels: [...D.types.labels, ...D.hosting.labels],
    datasets: [{
      data: [...D.types.values, ...D.hosting.values],
      backgroundColor: [...D.types.labels.map(l => l === 'RPC' ? '#1f77ff' : '#2ecc71'),
        '#e74c3c', '#7b2ff7', '#f39c12']
    }]
  },
  options: { maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
});

const tbody = document.getElementById('tbody');
tbody.innerHTML = D.table.map(r =>
  `<tr><td>${esc(r.host)}</td>
   <td><span class="pill ${r.type === 'RPC' ? 'rpc' : 'peer'}">${r.type}</span></td>
   <td>${esc(r.country)}</td><td>${esc(r.city)}</td><td>${esc(r.timezone)}</td>
   <td>${esc(r.isp)}</td><td>${esc(r.asn)}</td><td>${esc(r.whois)}</td>
   <td>${esc(r.hostname)}</td><td>${esc(r.hosting)}</td><td>${esc(r.moniker)}</td></tr>`).join('');

function esc(x) { return String(x ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())