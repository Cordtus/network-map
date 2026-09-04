#!/usr/bin/env python3
"""CometBFT / Cosmos-SDK network crawler.

Give it a single RPC/REST/gRPC endpoint and it recursively discovers the whole
peer network, validating every node against the expected chain-id, then emits
good/rejected IP lists, discovered ports, per-chain endpoints and node metadata
for downstream geolocation and mapping.

Probing strategy (port-first): instead of hammering one host with every port in
sequence, each probe round sends at most one request per host and sweeps the
host pool once per port, so load is spread evenly across the network and no
single endpoint is ever pounded.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

VERSION = "1.0.0"
USER_AGENT = f"network-map-crawler/{VERSION}"

# Ordered by likelihood; peer hosts are probed in this order. 26656 is the
# p2p port every live node keeps open - a great liveness gate for the sweep.
RPC_PORTS_PRIORITY = [443, 26657, 80, 36657, 26656]

# Ports used to judge whether a host is a live node (TCP connect check).
LIVENESS_PORTS = [26656, 26657, 443]

# Digit variations of the standard Tendermint ports, plus empirically-known
# custom RPC ports (from the lazy-lb and rpc-crawler-1 corpora). Covers
# patterns like 26607/26617/26637, 20667/21667/23667, 16657/36657/46657,
# digit reshuffles (25667, 62567, 75266), reversals, and friends.
def _port_patterns(base: int) -> set[int]:
    s = str(base)
    out: set[int] = set()

    # 1) replace a single digit in any position (26657 -> 26607/26617/26637)
    for i in range(len(s)):
        for d in range(10):
            if str(d) == s[i]:
                continue
            out.add(int(s[:i] + str(d) + s[i + 1 :]))

    # 2) every permutation of the digits (26657 -> 25667/62567/27656/...)
    for perm in set(itertools.permutations(s)):
        out.add(int("".join(perm)))

    # 3) reversal (26657 -> 75662)
    out.add(int(s[::-1]))

    return {p for p in out if 80 <= p <= 65535 and p != base}


def _build_expanded_ports() -> list[int]:
    bases = [26657, 26656, 17157]
    # tens-position variants of 26657; varying those too yields the X06X7 /
    # X16X7 / X36X7 family (e.g. 20667, 21667, 23667) the user asked about.
    family = [26607, 26617, 26627, 26637, 26647, 26667, 26677, 26687, 26697]
    extras = [
        22257, 14657, 58657, 33657, 53657, 37657, 31657, 10157, 27957, 2401,
        15957, 14957, 14917, 8080, 8443, 8000, 9090, 9091, 8545, 8546,
        26658, 26659, 26655, 1317, 46657, 56657, 16657, 26757, 26857, 26957,
        26557, 27657, 28657, 29657, 25657, 9095, 9096, 1318, 1320, 44457,
        75757, 57557, 17157, 18157, 19157, 21157, 22157, 23157, 24157, 25157,
        27157, 28157, 29157, 17257, 17357, 17457, 17557, 17657, 17757, 17857,
        17957, 16257, 16357, 16457, 16557, 16757, 16857, 16957, 12657, 13657,
        15657, 17657, 18657, 19657, 26556, 26756, 26856, 26660, 26670, 26680,
        26690, 26600, 26610, 26620, 26630, 26640, 26650, 26660, 26670, 26680,
        26690, 20656, 21656, 22656, 23656, 24656, 25656, 27656, 28656, 29656,
    ]
    ports: set[int] = set()
    for b in bases:
        ports |= _port_patterns(b)
    for b in family:
        ports |= _port_patterns(b)
    ports |= set(extras)
    # Priority ports are handled in the first sweep; drop them here.
    ports -= set(RPC_PORTS_PRIORITY)

    def score(p: int) -> int:
        s = str(p)
        if s.startswith("266"):
            return 0  # 266xx: closest to the standard port
        if s.startswith("26"):
            return 1  # 26xxx family
        if len(s) == 5 and s.endswith(("56", "57")) and s[0] in "13456789":
            return 2  # x6xxx sibling chains (16657, 36657, 46657...)
        return 3

    return sorted(ports, key=lambda p: (score(p), p))


ALL_EXPANDED_PORTS = _build_expanded_ports()
# Default tier-2 sweep: a focused slice of the highest-likelihood patterns.
# --deep uses the full generated list (including permutations/reversals).
RPC_PORTS_EXPANDED = ALL_EXPANDED_PORTS[:150]
RPC_PORTS_DEEP = ALL_EXPANDED_PORTS

REST_PORTS = [443, 1317, 80, 8080, 8443, 3000]

REST_NODE_INFO_PATH = "/cosmos/base/tendermint/v1beta1/node_info"

NON_ROUTABLE = {"0.0.0.0", "127.0.0.1", "localhost", "::", "::1", ""}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def log(msg: str, level: str = "INFO") -> None:
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
    if a == 0 or a >= 224:
        return False  # 0.x, multicast, reserved
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return False  # private
    if a == 127 or (a == 169 and b == 254):
        return False  # loopback / link-local
    if a == 100 and 64 <= b <= 127:
        return False  # CGNAT
    return True


def is_hostname(host: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$", host)) and "." in host


def protocols_for(host: str, port: int) -> list[str]:
    """Ordered protocol candidates for a host:port.

    Never assume a single scheme: some hosts serve plain HTTP on 443 and TLS on
    80 or custom ports, so both are always attempted (ordered by likelihood).
    """
    if port == 443:
        return ["https", "http"]
    if port == 80:
        return ["http", "https"]
    # Custom ports: plain-IP nodes usually speak HTTP, hostname-terminated
    # nodes usually TLS, but try both either way.
    if is_public_ipv4(host):
        return ["http", "https"]
    return ["https", "http"]


def normalize_url(raw: str) -> str | None:
    url = raw.strip()
    if not url.startswith(("http://", "https://", "grpc://")):
        url = f"https://{url}"
    try:
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            return f"{parsed.scheme}://{parsed.hostname}{parsed.path}".rstrip("/")
    except ValueError:
        return None
    return None


def extract_host(addr: str) -> str | None:
    if not addr:
        return None
    stripped = re.sub(r"^(tcp|http|https|grpc)://", "", addr.strip())
    if stripped.startswith("["):
        return None  # skip IPv6
    if stripped.startswith(":"):
        return None
    stripped = re.sub(r":\d+$", "", stripped)
    stripped = stripped.split("/")[0]
    return stripped or None


def extract_port(addr: str) -> int | None:
    if not addr:
        return None
    m = re.search(r":(\d+)(?:/|$)", addr)
    if m:
        port = int(m.group(1))
        if 0 < port <= 65535:
            return port
    return None


def resolve_host(host: str) -> str:
    """Best-effort DNS resolution of a hostname to a public IPv4."""
    if is_public_ipv4(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        for info in infos:
            ip = info[4][0]
            if is_public_ipv4(ip):
                return ip
    except OSError:
        pass
    return host


class JsonStore:
    def __init__(self, data_dir: Path) -> None:
        self.dir = data_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def load(self, name: str, default):
        path = self.dir / name
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return default

    def save(self, name: str, data) -> None:
        path = self.dir / name
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(path)


# --------------------------------------------------------------------------- #
# Crawler
# --------------------------------------------------------------------------- #
class Crawler:
    def __init__(self, cfg: argparse.Namespace) -> None:
        self.cfg = cfg
        self.store = JsonStore(Path(cfg.data_dir))

        self.lock = threading.RLock()
        self.checked_urls: set[str] = set()
        self.checked_host_keys: set[str] = set()  # "host|chainId"
        self.seen_nodes: set[str] = set()  # "chainId|nodeId"
        self.host_last_req: dict[str, float] = {}
        self.host_failures: dict[str, int] = {}

        # Persistent state
        self.good_ips: dict[str, float] = {}
        self.peer_ips: dict[str, float] = {}
        self.pex_seeds: dict[str, float] = {}
        self.rejected_ips: set[str] = set()
        self.blacklist: list[dict] = []
        self.ports: set[int] = set()
        self.endpoints: dict[str, dict] = {}
        self.nodes: dict[str, dict] = {}

        self.chain_id: str | None = None
        self._local = threading.local()
        self._start = time.time()
        self._pool: ThreadPoolExecutor | None = None
        self._queue: list[dict] = []
        self._pending_hosts: set[str] = set()
        self._pending_rpc: set[tuple[str, int]] = set()
        self._probed_hosts: set[str] = set()
        self.reachable_hosts: set[str] = set()
        self._dark_counts: dict[str, int] = {}
        self._last_save = time.time()

    # ----- state ---------------------------------------------------------
    def load(self) -> None:
        self.good_ips = self.store.load("good_ips.json", {})
        if not isinstance(self.good_ips, dict):
            self.good_ips = {}
        self.peer_ips = self.store.load("peer_ips.json", {})
        if not isinstance(self.peer_ips, dict):
            self.peer_ips = {}
        self.pex_seeds = self.store.load("pex_seeds.json", {})
        if not isinstance(self.pex_seeds, dict):
            self.pex_seeds = {}
        self.rejected_ips = set(self.store.load("rejected_ips.json", []))
        self.blacklist = self.store.load("blacklisted_ips.json", [])
        self.ports = set(self.store.load("ports.json", []))
        self.endpoints = self.store.load("endpoints.json", {})

    def save(self) -> None:
        self.store.save("good_ips.json", self.good_ips)
        self.store.save("peer_ips.json", self.peer_ips)
        self.store.save("pex_seeds.json", self.pex_seeds)
        self.store.save("rejected_ips.json", sorted(self.rejected_ips))
        self.store.save("blacklisted_ips.json", self.blacklist)
        self.store.save("ports.json", sorted(self.ports))
        self.store.save("endpoints.json", self.endpoints)
        self.store.save("nodes.json", self.nodes)

    # ----- plumbing ------------------------------------------------------
    @property
    def over_time(self) -> bool:
        return time.time() - self._start > self.cfg.time

    def session(self) -> requests.Session:
        s = getattr(self._local, "s", None)
        if s is None:
            s = requests.Session()
            self._local.s = s
        return s

    def throttle(self, host: str) -> None:
        if not host:
            return
        with self.lock:
            last = self.host_last_req.get(host, 0.0)
        wait = last + self.cfg.min_interval - time.time()
        if wait > 0:
            time.sleep(wait)
        with self.lock:
            self.host_last_req[host] = max(self.host_last_req.get(host, 0.0), time.time())

    def _mark_reachable(self, host: str) -> None:
        if not host or host in NON_ROUTABLE:
            return
        with self.lock:
            self.reachable_hosts.add(host)

    def fetch(self, url: str, timeout: float | None = None) -> tuple[dict | None, str]:
        """Fetch JSON. Returns (data, status) where status is one of:
        'ok' (200 JSON), 'alive' (host answered but not RPC JSON), 'dark'
        (connect timeout / no response), 'error' (other failures)."""
        try:
            host = urlparse(url).hostname
        except ValueError:
            host = None
        self.throttle(host or "")
        t = timeout if timeout is not None else self.cfg.timeout
        last_err: str | None = None
        for attempt in range(self.cfg.retries + 1):
            try:
                resp = self.session().get(
                    url,
                    timeout=t,
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                )
                # Any HTTP response means the host is alive (may be non-RPC).
                self._mark_reachable(host or "")
                if resp.status_code == 200:
                    try:
                        return resp.json(), "ok"
                    except ValueError:
                        return None, "alive"
                last_err = f"HTTP {resp.status_code}"
                return None, "alive"
            except requests.exceptions.SSLError as exc:
                # TLS handshake failed but TCP connected: host is alive.
                self._mark_reachable(host or "")
                last_err = str(exc)[:120]
                time.sleep(0.4 * (attempt + 1))
            except requests.exceptions.RequestException as exc:
                last_err = str(exc)[:120]
                time.sleep(0.4 * (attempt + 1))
                msg = str(exc).lower()
                if "timed out" in msg and attempt == self.cfg.retries:
                    return None, "dark"
                if "connection refused" in msg:
                    return None, "alive"
        if last_err:
            log(f"Fetch failed: {url} ({last_err})", "DEBUG")
        return None, "error"

    def record_failure(self, host: str) -> None:
        if not host or host in NON_ROUTABLE:
            return
        with self.lock:
            self.host_failures[host] = self.host_failures.get(host, 0) + 1
            entry = next((e for e in self.blacklist if e["ip"] == host), None)
            if entry is None:
                self.blacklist.append({"ip": host, "failureCount": 1, "timestamp": int(time.time())})
            else:
                entry["failureCount"] += 1
                entry["timestamp"] = int(time.time())
            if self.host_failures[host] >= self.cfg.max_failures:
                self.rejected_ips.add(host)
                log(f"Host {host} rejected after {self.cfg.max_failures} failures", "WARN")

    # ----- status / net_info ---------------------------------------------
    def check_status(self, url: str, timeout: float | None = None) -> tuple[dict | None, str]:
        """Fetch /status. Returns (node metadata or None, probe status)."""
        data, status = self.fetch(f"{url}/status", timeout=timeout)
        if not data or not isinstance(data.get("result"), dict):
            return None, status
        res = data["result"]
        ni = res.get("node_info") or {}
        si = res.get("sync_info") or {}
        network = ni.get("network")
        node_id = ni.get("id")
        moniker = ni.get("moniker") or ""
        latest = None
        latest_raw = si.get("latest_block_time") or ""
        try:
            latest = datetime.fromisoformat(latest_raw.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            latest = None
        earliest = si.get("earliest_block_height")
        try:
            earliest = int(earliest)
        except (TypeError, ValueError):
            earliest = None
        fresh = latest is not None and (time.time() - latest) <= self.cfg.freshness
        return (
            {
                "network": network,
                "nodeId": node_id,
                "moniker": moniker,
                "fresh": bool(fresh),
                "earliestBlock": earliest,
                "archive": earliest == 1,
                "latestBlockTime": si.get("latest_block_time"),
            },
            status,
        )

    def fetch_peers(self, url: str) -> tuple[set[str], set[tuple[str, int]], set[int], list[tuple[str, str, int]]]:
        """Extract peer hosts, advertised RPC (host, port) combos, p2p ports
        and PEX seeds (nodeID, host, p2pPort)."""
        data, _ = self.fetch(f"{url}/net_info")
        hosts: set[str] = set()
        advertised: set[tuple[str, int]] = set()
        ports: set[int] = set()
        pex_seeds: list[tuple[str, str, int]] = []
        if not data or not isinstance(data.get("result"), dict):
            return hosts, advertised, ports, pex_seeds
        peers = data["result"].get("peers") or []
        for peer in peers:
            remote_ip = peer.get("remote_ip", "")
            ni = peer.get("node_info") or {}
            listen_addr = ni.get("listen_addr") or ""
            rpc_addr = (ni.get("other") or {}).get("rpc_address") or ""
            node_id = ni.get("id")

            if is_public_ipv4(remote_ip):
                hosts.add(remote_ip)

            # RPC address is the strongest signal: probe it directly.
            rpc_host = extract_host(rpc_addr)
            rpc_port = extract_port(rpc_addr)
            if rpc_host in NON_ROUTABLE:
                rpc_host = remote_ip
            if rpc_host and rpc_port and (is_public_ipv4(rpc_host) or is_hostname(rpc_host)):
                advertised.add((rpc_host, rpc_port))

            # P2P seed for the PEX crawler: nodeID@host:p2pPort
            p2p_port = extract_port(listen_addr)
            p2p_host = extract_host(listen_addr)
            if p2p_host in NON_ROUTABLE:
                p2p_host = remote_ip
            if node_id and p2p_host and p2p_port and (is_public_ipv4(p2p_host) or is_hostname(p2p_host)):
                pex_seeds.append((node_id, p2p_host, p2p_port))

            for addr in (listen_addr, rpc_addr):
                host = extract_host(addr)
                if host:
                    if host in NON_ROUTABLE:
                        host = remote_ip
                    if is_public_ipv4(host) or is_hostname(host):
                        hosts.add(host)
                port = extract_port(addr)
                if port:
                    ports.add(port)
        return hosts, advertised, ports, pex_seeds

    # ----- endpoint checking ---------------------------------------------
    def check_rpc_endpoint(
        self, url: str, expected_chain: str | None, timeout: float | None = None
    ) -> tuple[str | None, dict | None, str]:
        info, status = self.check_status(url, timeout=timeout)
        if not info:
            return None, None, status
        if expected_chain is not None and info["network"] != expected_chain:
            log(f"{url} is on chain {info['network']} != {expected_chain}, skipping", "DEBUG")
            return None, None, "alive"
        return url, info, "ok"

    def check_rest_endpoint(self, url: str, expected_chain: str | None) -> bool:
        self.throttle(urlparse(url).hostname or "")
        data, _ = self.fetch(f"{url}{REST_NODE_INFO_PATH}")
        if not data:
            return False
        for key in ("default_node_info", "node_info"):
            ni = data.get(key)
            if isinstance(ni, dict):
                network = ni.get("network")
                if network and (expected_chain is None or network == expected_chain):
                    return True
                if network:
                    return False
        return False

    def discover_rest(self, rpc_url: str, expected_chain: str | None) -> str | None:
        """Derive a REST endpoint for a known-good RPC host."""
        parsed = urlparse(rpc_url)
        host = parsed.hostname or ""
        candidates: list[str] = []

        # rpc -> rest/lcd/api substitution on the URL
        for sub in ("rpc", "lcd", "api"):
            cand = rpc_url.replace("/rpc/", f"/{sub}/")
            if sub != "rpc":
                cand = cand.replace(f"://rpc.", f"://{sub}.")
                cand = cand.replace(f"://{sub}.", f"://{sub}.", 1)  # no-op guard
            if cand != rpc_url and cand not in candidates:
                candidates.append(cand)
        if "rpc" in host:
            candidates.append(rpc_url.replace(f"://rpc.", "://rest."))
            candidates.append(rpc_url.replace(f"://rpc.", "://api."))
            candidates.append(rpc_url.replace(f"://rpc.", "://lcd."))

        # Port scan on the host
        for port in REST_PORTS:
            for proto in protocols_for(host, port):
                candidates.append(f"{proto}://{host}:{port}")

        for cand in candidates:
            if self.check_rest_endpoint(cand, expected_chain):
                return cand
        return None

    # ----- core crawl -----------------------------------------------------
    def run(self, seeds: list[str]) -> dict:
        log(f"Starting crawl with {len(seeds)} seed(s): {', '.join(seeds)}")
        for seed in seeds:
            parsed = urlparse(seed)
            host = parsed.hostname or ""
            if parsed.scheme == "grpc" or "grpc" in host:
                # gRPC endpoint: no HTTP status endpoint, probe its host for RPC
                self.checked_urls.add(seed)
                self._add_host(host)
            elif host.startswith(("api.", "rest.", "lcd.")):
                # REST endpoint: try rpc substitution on the same host
                rpc_host = re.sub(r"^(api|rest|lcd)\.", "rpc.", host)
                for proto in ("https", "http"):
                    self.enqueue_url(f"{proto}://{rpc_host}")
                self._add_host(host)
            else:
                self.enqueue_url(seed)

        self._pool = ThreadPoolExecutor(max_workers=self.cfg.workers)
        try:
            self._crawl_loop()
        finally:
            self._pool.shutdown(wait=True)

        self.save()
        summary = self.summarize()
        log("Crawl complete: " + json.dumps(summary))
        return summary

    def enqueue_url(self, url: str) -> None:
        with self.lock:
            if url in self.checked_urls:
                return
            self.checked_urls.add(url)
        self._queue.append({"kind": "url", "url": url, "depth": 0})

    def _add_host(self, host: str) -> None:
        with self.lock:
            self._pending_hosts.add(host)

    def _crawl_loop(self) -> None:
        iteration = 0
        while (self._queue or self._pending_hosts or self._pending_rpc) and not self.over_time:
            iteration += 1
            batch, self._queue = self._queue[: self.cfg.batch], self._queue[self.cfg.batch :]
            log(f"--- Iteration {iteration} | urlq={len(self._queue)} hosts={len(self._pending_hosts)} "
                f"advertised={len(self._pending_rpc)} | good={len(self.good_ips)} "
                f"| elapsed={time.time() - self._start:.0f}s")

            results = list(self._pool.map(self._process_item, batch))

            new_hosts: set[str] = set()
            new_combos: set[tuple[str, int]] = set()
            for res in results:
                if not res:
                    continue
                if res.get("ok"):
                    self._record_node(res)
                    new_hosts.update(res.get("peers", ()))
                    new_combos.update(res.get("rpc_combos", ()))
                else:
                    host = res.get("host")
                    if host:
                        self.record_failure(host)

            # Newly-discovered peers and advertised RPC combos join the probe pool
            for host in new_hosts:
                if not self._host_checked(host) and host not in self._probed_hosts:
                    self._add_host(host)
            for combo in new_combos:
                if not self._combo_checked(combo):
                    self._pending_rpc.add(combo)

            # Port-first sweep of the pools
            if self._pending_rpc or self._pending_hosts:
                self._probe_batch(list(self._pending_hosts), list(self._pending_rpc))
                self._pending_hosts = {
                    h
                    for h in self._pending_hosts
                    if not self._host_checked(h) and h not in self._probed_hosts
                }
                self._pending_rpc = {c for c in self._pending_rpc if not self._combo_checked(c)}

            if iteration % 5 == 0:
                self.save()

    def _host_checked(self, host: str) -> bool:
        with self.lock:
            return f"{host}|{self.chain_id or ''}" in self.checked_host_keys

    def _combo_checked(self, combo: tuple[str, int]) -> bool:
        return f"{combo[0]}|{combo[1]}|{self.chain_id or ''}" in self.checked_urls

    def _process_item(self, item: dict) -> dict | None:
        endpoint, info, _ = self.check_rpc_endpoint(item["url"], self.chain_id)
        if not endpoint or not info:
            return {"ok": False, "host": urlparse(item["url"]).hostname}
        return {
            "ok": True,
            "endpoint": endpoint,
            "info": info,
            "depth": item["depth"],
            "peers": set(),
        }

    def _probe_batch(self, hosts: list[str], combos: list[tuple[str, int]]) -> None:
        """Probe pools with the port-first sequence:

        1. advertised RPC combos directly (one request per combo),
        2. sweep priority ports across all hosts, one port at a time (no
           pruning: even a host dark on one port may answer another),
        3. expanded variation ports, but only across hosts that are likely
           live nodes (answered some HTTP, or TCP-open on p2p/rpc ports),
        4. dark-prune within the expanded sweep only, where it saves real time.
        """
        original = set(hosts)
        discovered: set[str] = set()

        # Step 1: advertised combos (strongest signal)
        if combos:
            log(f"  checking {len(combos)} advertised RPC combos")
            results = list(self._pool.map(lambda c: (c, self._try_advertised(c[0], c[1])), combos))
            for combo, res in results:
                if res.get("found"):
                    self._record_node(res["result"])
                    discovered.update(res["result"].get("peers", ()))
                    self._dark_counts.pop(combo[0], None)

        # Step 2: full priority sweep, all ports, no pruning
        pending = {h for h in original if not self._host_checked(h)}
        if pending:
            log(f"  sweeping {len(pending)} hosts across {len(RPC_PORTS_PRIORITY)} ports (port-first)")
            for port in RPC_PORTS_PRIORITY:
                if not pending:
                    break
                pending = self._sweep(pending, port, discovered, prune=False)

            # Step 3: expanded variations only for likely-live hosts
            live = set()
            if not self.cfg.deep:
                expanded = ALL_EXPANDED_PORTS[: self.cfg.expanded_ports]
                live = {h for h in pending if self._is_live(h)}
                if live:
                    log(f"  expanded sweep across {len(live)} live hosts ({len(expanded)} ports)")
                    for port in expanded:
                        if not live:
                            break
                        live = self._sweep(live, port, discovered, prune=True, expanded=True)
                pending = {h for h in pending if not self._host_checked(h)}
            elif pending:
                for port in RPC_PORTS_DEEP:
                    if not pending:
                        break
                    pending = self._sweep(pending, port, discovered, prune=True, expanded=True)

            # Step 4: full 1-65535 TCP scan on live hosts that still have no RPC.
            # These are raw node IPs (not rate-limited API services), so a full
            # port scan is safe; only open ports get an HTTP probe afterwards.
            if self.cfg.scan_all:
                targets = [
                    h
                    for h in (live if not self.cfg.deep else pending)
                    if not self._host_checked(h)
                ]
                if targets:
                    log(f"  full-scanning {len(targets)} hosts (all 65535 ports)")
                    results = self._pool.map(self._full_scan_and_probe, targets)
                    for peers_found in results:
                        for host in peers_found:
                            if not self._host_checked(host) and host not in self._probed_hosts:
                                self._add_host(host)
                pending = {h for h in pending if not self._host_checked(h)}

        # Everything not found is done (not rejected, just not an RPC node).
        self._probed_hosts |= {h for h in original if not self._host_checked(h)}

        # Cascade: peers discovered through probing get probed next round
        for host in discovered:
            if not self._host_checked(host) and host not in self._probed_hosts:
                self._add_host(host)

        self.save()

    def _is_live(self, host: str) -> bool:
        """A host is worth an expensive port sweep if it answered any HTTP or
        has a TCP-open p2p/rpc port - i.e. it is a real, reachable node."""
        if host in self.reachable_hosts:
            return True
        for port in LIVENESS_PORTS:
            if self._tcp_probe(host, port, timeout=self.cfg.probe_timeout) == "open":
                return True
        return False

    def _tcp_probe(self, host: str, port: int, timeout: float = 0.8) -> str:
        """Cheap TCP connect check. Returns 'open', 'closed' or 'dark'."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return "open"
        except socket.timeout:
            return "dark"
        except OSError:
            return "closed"

    def _full_scan_and_probe(self, host: str) -> set[str]:
        """Full 1-65535 TCP scan of a host, then HTTP-probe the open ports."""
        discovered: set[str] = set()
        try:
            open_ports = self._scan_host_ports(host)
        except Exception as exc:  # noqa: BLE001
            log(f"scan of {host} failed: {exc}", "WARN")
            return discovered
        if not open_ports:
            return discovered
        log(f"  {host}: {len(open_ports)} open ports, probing for RPC")
        for port in sorted(open_ports):
            res = self._try_port(host, port, expanded=True)
            if res.get("found"):
                self._record_node(res["result"])
                discovered.update(res["result"].get("peers", ()))
                break
        return discovered

    def _scan_host_ports(self, host: str) -> list[int]:
        """TCP-connect scan of every port. Uses the per-host rate limit only for
        HTTP probes; raw connects are cheap and these are unrate-limited nodes."""
        open_ports: list[int] = []
        concurrency = min(self.cfg.scan_concurrency, 1024)
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            for start in range(1, 65536, concurrency):
                ports = range(start, min(start + concurrency, 65536))
                futures = [ex.submit(self._tcp_probe, host, p, self.cfg.scan_timeout) for p in ports]
                for p, fut in zip(ports, futures):
                    if fut.result() == "open":
                        open_ports.append(p)
                if self.over_time:
                    break
        return open_ports

    def _sweep(
        self, hosts: set[str], port: int, discovered: set[str], prune: bool, expanded: bool = False
    ) -> set[str]:
        """Probe one port across a pool of hosts; returns hosts still unfound."""
        remaining: set[str] = set()
        results = self._pool.map(lambda h: (h, self._try_port(h, port, expanded)), list(hosts))
        for host, res in results:
            if res.get("found"):
                self._record_node(res["result"])
                discovered.update(res["result"].get("peers", ()))
                self._dark_counts.pop(host, None)
            elif prune and res.get("dark"):
                d = self._dark_counts.get(host, 0) + 1
                self._dark_counts[host] = d
                if d < self.cfg.dark_threshold:
                    remaining.add(host)
                # firewalled/dark host: pruned after consecutive timeouts
            else:
                self._dark_counts.pop(host, None)
                remaining.add(host)
        if time.time() - self._last_save > 15:
            self.save()
            self._last_save = time.time()
        return remaining

    def _try_advertised(self, host: str, port: int) -> dict:
        for proto in protocols_for(host, port):
            url = f"{proto}://{host}:{port}"
            with self.lock:
                key = f"{host}|{port}|{self.chain_id or ''}"
                if key in self.checked_urls:
                    return {"found": False, "dark": False}
                self.checked_urls.add(key)
            endpoint, info, status = self.check_rpc_endpoint(
                url, self.chain_id, timeout=self.cfg.probe_timeout
            )
            if endpoint and info:
                return {
                    "found": True,
                    "result": {"ok": True, "endpoint": endpoint, "info": info, "depth": 1, "peers": set()},
                }
        return {"found": False, "dark": False}

    def _try_port(self, host: str, port: int, expanded: bool = False) -> dict:
        # TCP preflight: never send HTTP to a port that isn't open. This keeps
        # the sweep fast and keeps request volume to any single host minimal
        # (no 429s, no blocked endpoints).
        tcp = self._tcp_probe(host, port, timeout=0.8)
        if tcp == "closed":
            return {"found": False, "dark": False}
        if tcp == "dark":
            return {"found": False, "dark": True}

        dark = True
        tried = False
        timeout = self.cfg.expanded_timeout if expanded else self.cfg.probe_timeout
        for proto in protocols_for(host, port):
            url = f"{proto}://{host}:{port}"
            with self.lock:
                if url in self.checked_urls:
                    continue
                self.checked_urls.add(url)
            tried = True
            endpoint, info, status = self.check_rpc_endpoint(url, self.chain_id, timeout=timeout)
            if endpoint and info:
                return {
                    "found": True,
                    "result": {"ok": True, "endpoint": endpoint, "info": info, "depth": 1, "peers": set()},
                }
            if status != "dark":
                dark = False
        if not tried:
            return {"found": False, "dark": False}
        return {"found": False, "dark": dark}

    def _record_node(self, res: dict) -> None:
        endpoint = res["endpoint"]
        info = res["info"]
        chain = info.get("network") or self.chain_id or ""
        parsed = urlparse(endpoint)
        host = parsed.hostname or ""
        key = f"{chain}|{info.get('nodeId')}" if info.get("nodeId") else f"{chain}|{host}"

        # Chain-id lock: once we see the first real chain, all nodes must match
        if self.chain_id is None and chain:
            self.chain_id = chain
            log(f"Detected chain-id: {chain}")
            self.checked_host_keys = {
                k for k in self.checked_host_keys if not k.endswith("|")
            }
        if self.chain_id and chain != self.chain_id:
            return

        with self.lock:
            if info.get("nodeId"):
                if key in self.seen_nodes:
                    return
                self.seen_nodes.add(key)
            self.good_ips[host] = time.time()
            self.checked_host_keys.add(f"{host}|{self.chain_id or ''}")

            existing = self.nodes.get(key) or {}
            record = {
                "id": info.get("nodeId"),
                "host": host,
                "rpc": endpoint,
                "rest": existing.get("rest") if existing else None,
                "moniker": info.get("moniker", ""),
                "chain": chain,
                "chainId": chain,
                "earliestBlock": info.get("earliestBlock"),
                "archive": bool(info.get("archive")),
                "fresh": bool(info.get("fresh")),
                "firstSeen": existing.get("firstSeen", int(time.time())),
                "lastSeen": int(time.time()),
            }
            self.nodes[key] = record

            per_chain = self.endpoints.setdefault(
                chain,
                {"chain_id": chain, "rpc": [], "rest": []},
            )
            if endpoint not in per_chain["rpc"]:
                per_chain["rpc"].append(endpoint)

            if res.get("depth", 0) < self.cfg.depth and (info.get("fresh") or not self.pex_seeds):
                peers, advertised, ports, pex_seeds = self.fetch_peers(endpoint)
                res["peers"] = peers
                res["rpc_combos"] = advertised
                self.ports.update(ports)
                now = time.time()
                for p in peers:
                    self.peer_ips[p] = now
                for node_id, host, p2p_port in pex_seeds:
                    self.pex_seeds[f"{node_id}@{host}:{p2p_port}"] = now

            # REST discovery on this RPC host, once
            if record["rest"] is None:
                rest = self.discover_rest(endpoint, self.chain_id)
                if rest:
                    record["rest"] = rest
                    if rest not in per_chain["rest"]:
                        per_chain["rest"].append(rest)

    def summarize(self) -> dict:
        total_rpc = sum(len(c.get("rpc", [])) for c in self.endpoints.values())
        total_rest = sum(len(c.get("rest", [])) for c in self.endpoints.values())
        return {
            "chainId": self.chain_id,
            "goodIPs": len(self.good_ips),
            "rejectedIPs": len(self.rejected_ips),
            "rpcEndpoints": total_rpc,
            "restEndpoints": total_rest,
            "nodes": len(self.nodes),
            "ports": sorted(self.ports),
            "duration": f"{time.time() - self._start:.1f}s",
        }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CometBFT network crawler")
    p.add_argument("--seed", action="append", default=[], help="Seed endpoint (repeatable)")
    p.add_argument("--chain", action="append", default=[], help="Seed from cosmos/chain-registry (repeatable)")
    p.add_argument("--merge", default=None, help="Merge good_ips.json-style host file as probe targets")
    p.add_argument("--depth", type=int, default=3, help="Max crawl depth (default 3)")
    p.add_argument("--time", type=int, default=300, help="Max crawl time in seconds (default 300)")
    p.add_argument("--workers", type=int, default=50, help="Concurrent requests (default 50)")
    p.add_argument("--batch", type=int, default=30, help="URLs processed per iteration (default 30)")
    p.add_argument("--timeout", type=float, default=3.0, help="Per-request timeout seconds (default 3)")
    p.add_argument("--probe-timeout", type=float, default=2.0, help="Port-probe timeout seconds (default 2)")
    p.add_argument("--dark-threshold", type=int, default=2, help="Consecutive dark ports before a host is pruned (default 2)")
    p.add_argument("--freshness", type=int, default=120, help="Max block age seconds for a healthy node (default 120)")
    p.add_argument("--min-interval", type=float, default=0.1, help="Min seconds between requests to one host (default 0.1)")
    p.add_argument("--retries", type=int, default=2, help="Retries per request (default 2)")
    p.add_argument("--max-failures", type=int, default=10, help="Failures before host is rejected (default 10)")
    p.add_argument("--deep", action="store_true", help="Probe the full RPC port list (permutations/reversals) on peer hosts")
    p.add_argument("--expanded-ports", type=int, default=40, help="Max variation ports swept per live host (default 40)")
    p.add_argument("--expanded-timeout", type=float, default=1.5, help="Probe timeout for the expanded sweep (default 1.5)")
    p.add_argument("--scan-all", action="store_true", help="Full 1-65535 TCP scan of live hosts with no RPC, then probe open ports")
    p.add_argument("--scan-timeout", type=float, default=0.3, help="Per-port connect timeout during full scan (default 0.3)")
    p.add_argument("--scan-concurrency", type=int, default=256, help="Parallel connects during full scan per host (default 256)")
    p.add_argument("--data-dir", default=None, help="Output directory (default <script_dir>/data)")
    p.add_argument("--quiet", action="store_true", help="Reduce log output")
    return p.parse_args(argv)


def seed_from_chain_registry(chain_name: str) -> tuple[list[str], list[str]]:
    """Fetch RPC seeds and known P2P peer hosts from the cosmos chain-registry."""
    seeds: list[str] = []
    peer_hosts: list[str] = []
    url = f"https://raw.githubusercontent.com/cosmos/chain-registry/master/{chain_name}/chain.json"
    try:
        data = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT}).json()
    except (requests.RequestException, ValueError):
        log(f"Could not fetch chain-registry entry for {chain_name}", "ERROR")
        return seeds, peer_hosts
    for api in data.get("apis", {}).get("rpc", []):
        addr = api.get("address")
        if addr and normalize_url(addr):
            seeds.append(normalize_url(addr))
    # Known P2P peers (format: nodeid@host:port) are live nodes - probe them.
    for section in ("seeds", "persistent_peers"):
        for p in data.get("peers", {}).get(section, []):
            addr = p.get("address", "")
            host = addr.split("@")[-1].split(":")[0] if "@" in addr else addr.split(":")[0]
            if host and (is_public_ipv4(host) or is_hostname(host)):
                peer_hosts.append(host)
    return list(dict.fromkeys(seeds)), list(dict.fromkeys(peer_hosts))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.quiet:
        global log
        log = lambda msg, level="INFO": None  # noqa: E731

    if args.data_dir is None:
        args.data_dir = str(Path(__file__).resolve().parent / "data")

    seeds: list[str] = []
    for s in args.seed:
        norm = normalize_url(s)
        if norm:
            seeds.append(norm)
        else:
            seeds.append(s)  # gRPC-style, classify in run()

    for chain in args.chain:
        chain_seeds, chain_peers = seed_from_chain_registry(chain)
        seeds.extend(chain_seeds)
        args.merge_hosts = getattr(args, "merge_hosts", []) + chain_peers
        if chain_peers:
            log(f"Chain {chain}: {len(chain_seeds)} RPC seeds, {len(chain_peers)} known P2P peers")

    if args.merge:
        merge_path = Path(args.merge)
        if merge_path.exists():
            merged = json.loads(merge_path.read_text())
            hosts = list(merged.keys()) if isinstance(merged, dict) else list(merged)
            args.merge_hosts = hosts
            log(f"Merged {len(hosts)} hosts from {args.merge}")

    if not seeds and not getattr(args, "merge_hosts", []):
        log("No seeds given. Pass --seed <endpoint> or --chain <name>.", "ERROR")
        return 1

    crawler = Crawler(args)
    crawler.load()

    for host in getattr(args, "merge_hosts", []):
        crawler._add_host(host)

    crawler.run(seeds)
    return 0


if __name__ == "__main__":
    sys.exit(main())