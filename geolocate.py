#!/usr/bin/env python3
"""Geolocate discovered network hosts/IPs and emit map data.

Reads the crawler's output (data/good_ips.json, data/peer_ips.json,
data/rejected_ips.json, data/nodes.json) and resolves each host to lat/lon.

Providers (with fallback):
  1. ipinfo.io   - primary, token optional (env IPINFO_TOKEN, else bundled key)
  2. ip-api.com  - no-key fallback, HTTP only, ~45 req/min (rate-limited)

Results are cached in data/geo_cache.json so re-runs cost nothing. Emits
geolocations.js (map data) and data/nodes_geo.json (enriched node records).
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

VERSION = "1.0.0"
USER_AGENT = f"network-map-geolocator/{VERSION}"

DEFAULT_IPINFO_TOKEN = "d8a32befc88cff"  # bundled legacy token (ipinfo free plan)
IPAPI_MIN_INTERVAL = 1.4  # ip-api.com free tier: 45 req/min
IPAPI_BASE = "http://ip-api.com/json"

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"
RDAP_TIMEOUT = 6
RDAP_MIN_INTERVAL = 0.15  # per-RIR throttle

GEO_CACHE_FILE = "geo_cache.json"
WHOIS_CACHE_FILE = "whois_cache.json"
GEO_CACHE_MAX_AGE = 30 * 24 * 3600  # 30 days

logger_lock = threading.Lock()


def log(msg: str, level: str = "INFO") -> None:
    with logger_lock:
        print(f"[{time.strftime('%H:%M:%S')}] {level} {msg}", flush=True)


def is_public_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    a, b = nums[0], nums[1]
    if a == 0 or a >= 224 or a == 127 or a == 10 or a == 100 and 64 <= b <= 127:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    return True


def resolve_ip(host: str) -> str:
    """Best-effort DNS resolution of a hostname to a public IPv4 (cached)."""
    if is_public_ipv4(host):
        return host
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = info[4][0]
            if is_public_ipv4(ip):
                return ip
    except OSError:
        pass
    return host


class WhoisLookup:
    """Minimal dependency-free WHOIS via RDAP (IANA bootstrap + RIR servers)."""

    def __init__(self) -> None:
        self._bootstrap: dict[tuple, str] = {}
        self._bootstrap_ts = 0.0
        self.lock = threading.Lock()
        self.rdap_last: dict[str, float] = {}
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.session.headers["Accept"] = "application/rdap+json"

    def _rirs(self) -> dict[tuple, str]:
        if self._bootstrap and time.time() - self._bootstrap_ts < 7 * 24 * 3600:
            return self._bootstrap
        try:
            data = self.session.get(RDAP_BOOTSTRAP_URL, timeout=10).json()
            services = {
                tuple(cidrs): urls[0].rstrip("/")
                for cidrs, urls in data.get("services", [])
                if urls
            }
            self._bootstrap = services
            self._bootstrap_ts = time.time()
        except (requests.RequestException, ValueError):
            self._bootstrap = self._bootstrap or {}
        return self._bootstrap

    def _base_for_ip(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for cidrs, base in self._rirs().items():
            for cidr in cidrs:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return base
                except ValueError:
                    continue
        return None

    def _throttle(self, base: str) -> None:
        host = urlparse(base).hostname
        with self.lock:
            last = self.rdap_last.get(host, 0.0)
        wait = last + RDAP_MIN_INTERVAL - time.time()
        if wait > 0:
            time.sleep(wait)
        with self.lock:
            self.rdap_last[host] = max(self.rdap_last.get(host, 0.0), time.time())

    def lookup(self, ip: str) -> dict | None:
        base = self._base_for_ip(ip)
        if not base:
            return None
        self._throttle(base)
        try:
            resp = self.session.get(f"{base}/ip/{ip}", timeout=RDAP_TIMEOUT)
        except requests.RequestException:
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        return self._parse(data)

    @staticmethod
    def _vcard(entity: dict) -> dict:
        props: dict[str, str] = {}
        vc = entity.get("vcardArray") or []
        rows = vc[1] if len(vc) > 1 else []
        for row in rows:
            if len(row) >= 4 and row[0] in ("fn", "org", "email", "tel"):
                props.setdefault(row[0], str(row[3]))
        return props

    @staticmethod
    def _cidr(data: dict) -> str | None:
        sa, ea = data.get("startAddress"), data.get("endAddress")
        if not sa or not ea:
            return None
        try:
            first = ipaddress.ip_address(sa)
            last = ipaddress.ip_address(ea)
        except ValueError:
            return None
        if int(first) > int(last):
            return None
        # Smallest aligned prefix whose network exactly covers first..last.
        for prefix in range(1, 33):
            try:
                net = ipaddress.ip_network(f"{first}/{prefix}", strict=True)
            except ValueError:
                continue
            if net.network_address == first and net.broadcast_address == last:
                return str(net)
        return None

    def _parse(self, data: dict) -> dict | None:
        whois: dict = {
            "netname": data.get("name"),
            "cidr": self._cidr(data),
            "country": data.get("country"),
            "org": None,
            "abuse": None,
        }
        handle = data.get("handle")
        if handle and str(handle).startswith("NET"):
            whois["handle"] = str(handle)
        for ent in data.get("entities") or []:
            props = self._vcard(ent)
            roles = ent.get("roles") or []
            if "abuse" in roles and props.get("email"):
                whois["abuse"] = props["email"]
            if whois["org"] is None and (props.get("org") or props.get("fn")):
                whois["org"] = props.get("org") or props.get("fn")
        if not (whois["netname"] or whois["org"] or whois["cidr"]):
            return None
        return whois


class GeoLocator:
    def __init__(self, cfg: argparse.Namespace) -> None:
        self.cfg = cfg
        self.cache: dict[str, dict] = {}
        self.whois_cache: dict[str, dict] = {}
        self.flags_cache: dict[str, dict] = {}
        self.dns_cache: dict[str, str] = {}
        self.ipapi_lock = threading.Lock()
        self.ipapi_last = 0.0
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.whois = WhoisLookup()

    # ----- cache ----------------------------------------------------------
    def load_cache(self) -> None:
        path = Path(self.cfg.data_dir) / GEO_CACHE_FILE
        if path.exists():
            try:
                self.cache = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                self.cache = {}
        wpath = Path(self.cfg.data_dir) / WHOIS_CACHE_FILE
        if wpath.exists():
            try:
                self.whois_cache = json.loads(wpath.read_text())
            except (json.JSONDecodeError, OSError):
                self.whois_cache = {}
        fpath = Path(self.cfg.data_dir) / "flags_cache.json"
        if fpath.exists():
            try:
                self.flags_cache = json.loads(fpath.read_text())
            except (json.JSONDecodeError, OSError):
                self.flags_cache = {}

    def save_cache(self) -> None:
        (Path(self.cfg.data_dir) / GEO_CACHE_FILE).write_text(json.dumps(self.cache, indent=2))
        (Path(self.cfg.data_dir) / WHOIS_CACHE_FILE).write_text(json.dumps(self.whois_cache, indent=2))
        (Path(self.cfg.data_dir) / "flags_cache.json").write_text(json.dumps(self.flags_cache, indent=2))

    # ----- providers ------------------------------------------------------
    def _ipinfo(self, host: str, ip: str) -> dict | None:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {}
        if self.cfg.ipinfo_token:
            headers["Authorization"] = f"Bearer {self.cfg.ipinfo_token}"
        try:
            resp = self.session.get(url, timeout=10, headers=headers)
        except requests.RequestException as exc:
            log(f"ipinfo failed for {host}: {str(exc)[:100]}", "DEBUG")
            return None
        if resp.status_code == 200:
            data = resp.json()
            loc = (data.get("loc") or "").split(",")
            if len(loc) == 2:
                return {
                    "ip": ip,
                    "latitude": loc[0].strip(),
                    "longitude": loc[1].strip(),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "countryCode": data.get("country"),
                    "org": data.get("org"),  # e.g. "AS16509 Amazon.com, Inc."
                    "asn": (data.get("org") or "").split(" ")[0] if data.get("org", "").startswith("AS") else None,
                    "hostname": data.get("hostname"),  # reverse DNS / PTR
                    "postal": data.get("postal"),
                    "timezone": data.get("timezone"),
                    "provider": "ipinfo",
                }
        if resp.status_code in (401, 403, 429):
            log(f"ipinfo returned {resp.status_code} (token exhausted?) - switching to ip-api", "WARN")
        return None

    def _ipapi_throttle(self) -> None:
        with self.ipapi_lock:
            wait = self.ipapi_last + IPAPI_MIN_INTERVAL - time.time()
            if wait > 0:
                time.sleep(wait)
            self.ipapi_last = time.time()

    def _ipapi(self, host: str, ip: str) -> dict | None:
        if self.cfg.no_fallback:
            return None
        self._ipapi_throttle()
        url = (
            f"{IPAPI_BASE}/{ip}?fields=status,message,country,countryCode,region,regionName,city,"
            "zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
        )
        try:
            resp = self.session.get(url, timeout=10)
        except requests.RequestException as exc:
            log(f"ip-api failed for {host}: {str(exc)[:100]}", "DEBUG")
            return None
        if resp.status_code == 429:
            log("ip-api rate limit hit, waiting 60s", "WARN")
            time.sleep(60)
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if data.get("status") == "success":
            return {
                "ip": data.get("query", ip),
                "latitude": str(data.get("lat")),
                "longitude": str(data.get("lon")),
                "city": data.get("city"),
                "region": data.get("regionName"),
                "country": data.get("country"),
                "countryCode": data.get("countryCode"),
                "org": data.get("org") or data.get("isp"),
                "as": data.get("as"),
                "asn": (data.get("as") or "").split(" ")[0] if (data.get("as") or "").startswith("AS") else None,
                "hostname": data.get("reverse"),
                "postal": data.get("zip"),
                "timezone": data.get("timezone"),
                "mobile": bool(data.get("mobile")),
                "proxy": bool(data.get("proxy")),
                "hosting": bool(data.get("hosting")),
                "provider": "ip-api",
            }
        return None

    def _lookup(self, host: str) -> dict | None:
        ip = self.dns_cache.get(host) or resolve_ip(host)
        self.dns_cache[host] = ip
        geo = self._ipinfo(host, ip)
        if not geo:
            geo = self._ipapi(host, ip)
        if geo:
            geo["host"] = host
        return geo

    # ----- orchestration --------------------------------------------------
    def geolocate(self, hosts: list[str], label: str) -> list[dict]:
        results: list[dict] = []
        pending: list[str] = []
        for host in hosts:
            cached = self.cache.get(host)
            if cached and not self.cfg.force:
                results.append(cached)
            else:
                pending.append(host)

        if not pending:
            log(f"{label}: {len(results)} results (all cached)")
            return results

        log(f"{label}: {len(pending)} lookups ({len(results)} cached)")
        with ThreadPoolExecutor(max_workers=self.cfg.workers) as pool:
            futures = {pool.submit(self._lookup, h): h for h in pending}
            done = 0
            for fut in futures:
                host = futures[fut]
                try:
                    geo = fut.result()
                except Exception as exc:  # noqa: BLE001
                    log(f"lookup error for {host}: {exc}", "WARN")
                    geo = None
                if geo:
                    self.cache[host] = geo
                    results.append(geo)
                done += 1
                if done % 20 == 0:
                    log(f"{label}: {done}/{len(pending)} done")
        return results

    def _enrich_whois(self, geos: list[dict]) -> None:
        """Attach RDAP/WHOIS info to each geo record, keyed by unique IP."""
        unique_ips = {g.get("ip") for g in geos if g.get("ip") and is_public_ipv4(g["ip"])}
        pending = [ip for ip in unique_ips if ip not in self.whois_cache]
        if not pending:
            log(f"whois: {len(unique_ips)} IPs (all cached)")
        else:
            log(f"whois: {len(pending)} lookups ({len(unique_ips) - len(pending)} cached)")
            with ThreadPoolExecutor(max_workers=self.cfg.whois_workers) as pool:
                futures = {pool.submit(self.whois.lookup, ip): ip for ip in pending}
                for fut in futures:
                    ip = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        log(f"whois error for {ip}: {exc}", "WARN")
                        result = None
                    if result:
                        self.whois_cache[ip] = result
        for g in geos:
            g["whois"] = self.whois_cache.get(g.get("ip")) or {}

    def _enrich_flags(self, geos: list[dict]) -> None:
        """One-time ip-api pass to fill hosting/mobile/proxy/reverse/timezone
        on IPs that were resolved by ipinfo (which lacks those fields).
        Rate-limited to ~45/min; results are cached per IP."""
        unique_ips = {g.get("ip") for g in geos if g.get("ip") and is_public_ipv4(g["ip"])}
        pending = [ip for ip in unique_ips if ip not in self.flags_cache]
        if not pending:
            log(f"flags: {len(unique_ips)} IPs (all cached)")
        else:
            log(f"flags: enriching {len(pending)} IPs via ip-api (~{len(pending) // 45 + 1} min)")
            for ip in pending:
                self._ipapi_throttle()
                geo = self._ipapi(ip, ip)
                if geo:
                    self.flags_cache[ip] = {
                        "hosting": geo.get("hosting"),
                        "mobile": geo.get("mobile"),
                        "proxy": geo.get("proxy"),
                        "timezone": geo.get("timezone") or None,
                        "postal": geo.get("postal"),
                        "hostname": geo.get("hostname") or None,
                        "as": geo.get("as"),
                        "asn": geo.get("asn"),
                        "countryCode": geo.get("countryCode"),
                    }
        for g in geos:
            flags = self.flags_cache.get(g.get("ip")) or {}
            for key, val in flags.items():
                if val is not None and g.get(key) in (None, ""):
                    g[key] = val

    def run(self) -> int:
        data_dir = Path(self.cfg.data_dir)
        if not data_dir.exists():
            log(f"Data dir {data_dir} does not exist. Run crawler.py first.", "ERROR")
            return 1

        good = json.loads((data_dir / "good_ips.json").read_text()) if (data_dir / "good_ips.json").exists() else {}
        peers = json.loads((data_dir / "peer_ips.json").read_text()) if (data_dir / "peer_ips.json").exists() else {}
        rejected = json.loads((data_dir / "rejected_ips.json").read_text()) if (data_dir / "rejected_ips.json").exists() else []
        nodes = json.loads((data_dir / "nodes.json").read_text()) if (data_dir / "nodes.json").exists() else {}

        if not isinstance(good, dict):
            good = {h: time.time() for h in good}
        if not isinstance(peers, dict):
            peers = {h: time.time() for h in peers}
        if not isinstance(rejected, list):
            rejected = list(rejected)

        good_hosts = list(good.keys())
        peer_hosts = [h for h in peers if h not in good]

        self.load_cache()
        start = time.time()
        good_geo = self.geolocate(good_hosts, "good")
        peer_geo = self.geolocate(peer_hosts, "peers")
        rejected_geo = self.geolocate(rejected, "rejected") if self.cfg.rejected else []
        self.save_cache()

        # Enrich good entries with node metadata from the crawler
        node_by_host = {}
        for node in nodes.values():
            node_by_host.setdefault(node.get("host"), []).append(node)

        for geo in good_geo:
            meta = node_by_host.get(geo["host"], [])
            if meta:
                m = meta[0]
                geo["moniker"] = m.get("moniker") or ""
                geo["chain"] = m.get("chain") or ""
                geo["chainId"] = m.get("chainId") or ""
                geo["archive"] = bool(m.get("archive"))
                geo["fresh"] = bool(m.get("fresh"))
                geo["rpc"] = m.get("rpc")
                geo["rest"] = m.get("rest")
                geo["earliestBlock"] = m.get("earliestBlock")

        # WHOIS (RDAP) enrichment for every unique public IP
        if not self.cfg.no_whois:
            self._enrich_whois(good_geo + peer_geo)

        # Optional ip-api flag enrichment (hosting/mobile/proxy/etc)
        if self.cfg.ipapi_enrich:
            self._enrich_flags(good_geo + peer_geo)

        self.save_cache()

        counts = {
            "good": len(good_geo),
            "peers": len(peer_geo),
        }

        # Emit geolocations.js
        out = {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "chainId": next(iter(good_geo), {}).get("chainId"),
            "counts": counts,
            "good": good_geo,
            "peers": peer_geo,
        }
        js = (
            "var networkData = "
            + json.dumps(out, indent=2)
            + ";\n"
            + "var goodGeolocations = networkData.good;\n"
        )
        (data_dir / "geolocations.js").write_text(js)

        # Emit CSV export
        self._write_csv(good_geo + peer_geo, data_dir / "nodes.csv")

        # Emit full node dataset (geo + isp + whois) for analysis/mapping
        (data_dir / "all_nodes.json").write_text(
            json.dumps({"generatedAt": out["generatedAt"], "good": good_geo, "peers": peer_geo}, indent=2)
        )

        # Emit enriched node records
        (data_dir / "nodes_geo.json").write_text(json.dumps(good_geo, indent=2))

        elapsed = time.time() - start
        log(f"Done in {elapsed:.1f}s: " + json.dumps(counts))
        return 0

    def _write_csv(self, geos: list[dict], path: Path) -> None:
        columns = [
            "host", "ip", "latitude", "longitude", "city", "region", "country",
            "timezone", "postal", "reverse_dns", "asn",
            "isp_org", "whois_netname", "whois_org", "whois_cidr", "whois_abuse",
            "hosting", "mobile", "proxy",
            "moniker", "chain", "archive", "fresh", "rpc", "rest",
        ]
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for g in geos:
                row = {
                    "host": g.get("host"),
                    "ip": g.get("ip"),
                    "latitude": g.get("latitude"),
                    "longitude": g.get("longitude"),
                    "city": g.get("city"),
                    "region": g.get("region"),
                    "country": g.get("country"),
                    "timezone": g.get("timezone"),
                    "postal": g.get("postal"),
                    "reverse_dns": g.get("hostname"),
                    "asn": g.get("asn"),
                    "isp_org": g.get("org"),
                    "moniker": g.get("moniker"),
                    "chain": g.get("chain"),
                    "archive": "yes" if g.get("archive") else "no",
                    "fresh": "yes" if g.get("fresh") else "no",
                    "rpc": g.get("rpc"),
                    "rest": g.get("rest"),
                    "hosting": "yes" if g.get("hosting") else ("no" if g.get("hosting") is False else ""),
                    "mobile": "yes" if g.get("mobile") else ("no" if g.get("mobile") is False else ""),
                    "proxy": "yes" if g.get("proxy") else ("no" if g.get("proxy") is False else ""),
                }
                whois = g.get("whois") or {}
                row.update(
                    {
                        "whois_netname": whois.get("netname"),
                        "whois_org": whois.get("org"),
                        "whois_cidr": whois.get("cidr"),
                        "whois_abuse": whois.get("abuse"),
                    }
                )
                writer.writerow(row)
        log(f"Wrote {path.name} with {len(geos)} rows")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Geolocate crawled node hosts and emit map data")
    p.add_argument("--data-dir", default=None, help="Crawler data dir (default <script_dir>/data)")
    p.add_argument("--network", default=None, help="Network slug for output paths (default from data-dir basename)")
    p.add_argument("--ipinfo-token", default=None, help="ipinfo.io access token (default: env IPINFO_TOKEN or bundled)")
    p.add_argument("--workers", type=int, default=20, help="Concurrent lookups (default 20)")
    p.add_argument("--force", action="store_true", help="Ignore the geo cache and re-lookup everything")
    p.add_argument("--no-fallback", action="store_true", help="Never use the ip-api.com fallback")
    p.add_argument("--rejected", action="store_true", help="Also geolocate the rejected host list (off by default)")
    p.add_argument("--whois-workers", type=int, default=10, help="Concurrent RDAP lookups (default 10)")
    p.add_argument("--no-whois", action="store_true", help="Skip RDAP/WHOIS enrichment")
    p.add_argument("--ipapi-enrich", action="store_true", help="Fill hosting/mobile/proxy via ip-api (one-time, ~45/min)")
    p.add_argument("--quiet", action="store_true", help="Reduce log output")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.quiet:
        global log
        log = lambda msg, level="INFO": None  # noqa: E731
    if args.data_dir is None:
        args.data_dir = str(Path(__file__).resolve().parent / "data")
    if args.network is None:
        args.network = Path(args.data_dir).name
    args.ipinfo_token = args.ipinfo_token or os_env_token() or DEFAULT_IPINFO_TOKEN
    return GeoLocator(args).run()


def os_env_token() -> str | None:
    import os

    return os.environ.get("IPINFO_TOKEN")


if __name__ == "__main__":
    sys.exit(main())