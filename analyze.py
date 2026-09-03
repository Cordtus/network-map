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

    out = Path(__file__).resolve().parent / "insights.html"
    html = TEMPLATE.replace("/*__DATA__*/", json.dumps(data))
    out.write_text(html)

    print("insights.html written to", out)
    print(json.dumps(stats, indent=2))
    print("top countries:", countries.most_common(6))
    print("top ISPs:", isps.most_common(6))
    return 0


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Map Of Nodes — Insights</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg:#f1f3f7; --surface:#ffffff; --surface-2:#f5f6f9; --border:#e2e5ec;
    --text:#171a21; --muted:#5f6b7a; --accent:#1f77ff; --accent-2:#7b2ff7;
    --shadow:0 8px 24px rgba(20,30,55,.10);
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg:#0d1119; --surface:#141a26; --surface-2:#1a2130; --border:#252d3f;
      --text:#e6ebf5; --muted:#8b96ad; --accent:#4c9aff; --accent-2:#a06bff;
      --shadow:0 8px 28px rgba(0,0,0,.45);
    }
  }
  :root[data-theme="dark"] {
    --bg:#0d1119; --surface:#141a26; --surface-2:#1a2130; --border:#252d3f;
    --text:#e6ebf5; --muted:#8b96ad; --accent:#4c9aff; --accent-2:#a06bff;
    --shadow:0 8px 28px rgba(0,0,0,.45);
  }
  :root[data-theme="light"] {
    --bg:#f1f3f7; --surface:#ffffff; --surface-2:#f5f6f9; --border:#e2e5ec;
    --text:#171a21; --muted:#5f6b7a; --accent:#1f77ff; --accent-2:#7b2ff7;
    --shadow:0 8px 24px rgba(20,30,55,.10);
  }
  * { box-sizing: border-box; }
  body { margin:0; font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
         background:var(--bg); color:var(--text); }
  header {
    position:sticky; top:0; z-index:10; display:flex; align-items:center; gap:14px;
    padding:16px 24px; background:var(--surface); border-bottom:1px solid var(--border);
  }
  header .logo { display:flex; align-items:center; gap:10px; font-weight:700; font-size:16px; }
  header .logo svg { width:22px; height:22px; }
  header nav { margin-left:auto; display:flex; align-items:center; gap:10px; }
  header .sub { color:var(--muted); font-size:12px; }
  .btn { display:inline-flex; align-items:center; gap:6px; border:1px solid var(--border);
         cursor:pointer; font-size:13px; font-weight:600; border-radius:8px; padding:8px 14px;
         text-decoration:none; background:transparent; color:var(--text); transition:background .15s; white-space:nowrap; }
  .btn:hover { background:var(--surface-2); }
  .btn.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  .btn.primary:hover { filter:brightness(.94); }
  .btn svg { width:15px; height:15px; }
  .btn-ghost { border-color:transparent; padding:8px 10px; color:var(--muted); }
  .btn-ghost:hover { background:var(--surface-2); color:var(--text); }

  .stats { display:flex; flex-wrap:wrap; gap:28px; align-items:center; padding:4px 2px; }
  .stat .n { font-size:24px; font-weight:700; line-height:1.2; }
  .stat .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }

  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(420px,1fr)); gap:16px; padding:0 24px 28px; }
  .panel { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:16px; box-shadow:var(--shadow); }
  .panel h2 { margin:0 0 10px; font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }
  .panel .chart { position:relative; height:320px; }

  table { border-collapse:collapse; width:100%; font-size:12px; }
  th,td { padding:6px 10px; text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; }
  th { position:sticky; top:0; background:var(--surface); color:var(--muted); text-transform:uppercase; font-size:10px; letter-spacing:.05em; }
  .pill { display:inline-block; padding:1px 8px; border-radius:10px; font-size:10px; font-weight:600; }
  .pill.rpc { background:rgba(31,119,255,.18); color:var(--accent); }
  .pill.peer { background:rgba(46,204,113,.16); color:#16a34a; }
  .table-wrap { overflow:auto; max-height:560px; }
</style>
</head>
<body>
<header>
  <div class="logo">
    <svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="var(--accent)"/><g stroke="#fff" stroke-width="2" stroke-linecap="round"><line x1="16" y1="9" x2="9" y2="21"/><line x1="16" y1="9" x2="23" y2="21"/><line x1="9" y1="21" x2="23" y2="21"/></g><circle cx="16" cy="9" r="3.2" fill="#fff"/><circle cx="9" cy="21" r="3.2" fill="#fff"/><circle cx="23" cy="21" r="3.2" fill="#fff"/></svg>
    Map Of Nodes <span class="sub">/ Insights</span>
  </div>
  <nav>
    <span class="sub" id="gen"></span>
    <a class="btn" href="index.html"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 6v6h6"/><path d="M3 10a9 9 0 1 0 3-7"/></svg>Map</a>
    <a class="btn" href="nodes.csv" download="nodes.csv"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>CSV</a>
    <button class="btn btn-ghost" id="themeToggle" title="Toggle theme"><svg id="iconMoon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg><svg id="iconSun" style="display:none" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg></button>
  </nav>
</header>

<div class="grid">
  <div class="panel" style="grid-column:1/-1">
    <h2>Overview</h2>
    <div class="stats" id="stats"></div>
  </div>
  <div class="panel"><h2>Top ISPs / hosting providers</h2><div class="chart"><canvas id="isps"></canvas></div></div>
  <div class="panel"><h2>Top countries</h2><div class="chart"><canvas id="countries"></canvas></div></div>
  <div class="panel"><h2>ISP distribution by region (top ISPs)</h2><div class="chart"><canvas id="ispByCountry"></canvas></div></div>
  <div class="panel"><h2>Continents</h2><div class="chart"><canvas id="continents"></canvas></div></div>
  <div class="panel"><h2>Top ASNs</h2><div class="chart"><canvas id="asns"></canvas></div></div>
  <div class="panel"><h2>WHOIS registrant organizations</h2><div class="chart"><canvas id="whoisOrgs"></canvas></div></div>
  <div class="panel"><h2>Timezone distribution</h2><div class="chart"><canvas id="timezones"></canvas></div></div>
</div>

<div class="grid"><div class="panel" style="grid-column:1/-1">
  <h2>All nodes</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Host / IP</th><th>Type</th><th>Country</th><th>City</th><th>Timezone</th><th>ISP</th><th>ASN</th><th>WHOIS org</th><th>Reverse DNS</th><th>Hosting</th><th>Moniker</th></tr></thead>
    <tbody id="tbody"></tbody>
  </table></div>
</div></div>

<script>
// ---- theme: default to system, overridable, persisted ----
(function () {
  const stored = localStorage.getItem('map-theme');
  const theme = stored === 'light' || stored === 'dark' ? stored : 'system';
  const moon = document.getElementById('iconMoon'), sun = document.getElementById('iconSun');
  const apply = t => {
    document.documentElement.setAttribute('data-theme', t === 'system' ? '' : t);
    const dark = t === 'dark' || (t === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
    moon.style.display = dark ? 'block' : 'none';
    sun.style.display = dark ? 'none' : 'block';
    localStorage.setItem('map-theme', t);
  };
  apply(theme);
  document.getElementById('themeToggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark'
      : (localStorage.getItem('map-theme') === 'light' ? 'light' : 'system');
    apply(cur === 'system' ? 'light' : cur === 'light' ? 'dark' : 'system');
  });
})();

const DATA = /*__DATA__*/;
const D = DATA;

document.getElementById('gen').textContent = 'generated ' + (D.generatedAt || '?');

const s = D.stats;
const defs = [
  ['Total nodes', s.total], ['Countries', s.countries], ['ISPs', s.isps],
  ['ASNs', s.asns], ['WHOIS orgs', s.whoisOrgs],
];
document.getElementById('stats').innerHTML = defs.map(([l, n]) =>
  `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

const grid = 'transparent';
Chart.defaults.color = '#8b96ad';
Chart.defaults.borderColor = grid;
Chart.defaults.font.family = 'system-ui, sans-serif';

function bar(id, labels, values, color, horizontal) {
  new Chart(document.getElementById(id), {
    type: 'bar',
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