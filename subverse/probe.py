"""Orchestrator: drive the full resolve -> asn -> scan pipeline.

This is the one function the CLI calls. It is deliberately linear and easy to
read; each stage prints a short progress line so a long nmap pass doesn't look
like a hang.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import sys

from .model import ScanResult, IPResult
from .resolver import Resolver
from .asn import ASNLookup
from .scanner import NmapScanner, nmap_available
from .http_probe import probe_all as http_probe_all
from .dns_posture import PostureLookup
from .classify import classify


def _log(msg: str, quiet: bool = False):
    if not quiet:
        print(f"[*] {msg}", file=sys.stderr, flush=True)


def read_domains(path: str) -> list[tuple[str, str]]:
    """Read a domains file. Returns (host, note) pairs.

    Format: one host per line. '#' starts a comment. An optional note can follow
    the host after whitespace or a tab (handy for carrying status from a report).
    Blank lines and duplicates (case-insensitive) are dropped, order preserved.
    """
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # split host from optional note on whitespace
            parts = line.split(None, 1)
            host = parts[0].rstrip(".").lower()
            note = parts[1].strip() if len(parts) > 1 else ""
            if not host or host in seen:
                continue
            seen.add(host)
            out.append((host, note))
    return out


def run_probe(
    domains: list[tuple[str, str]],
    *,
    resolver_servers: list[str] | None = None,
    ports: list[int] | None = None,
    do_scan: bool = True,
    scan_intensity: str = "light",
    do_http: bool = True,
    do_posture: bool = True,
    http_timeout: float = 6.0,
    timeout: float = 4.0,
    workers: int = 24,
    quiet: bool = False,
) -> ScanResult:
    result = ScanResult()
    hosts = [h for h, _ in domains]
    notes = {h: n for h, n in domains}

    # --- Stage 1: DNS resolution ---------------------------------------------
    _log(f"Resolving {len(hosts)} host(s)...", quiet)
    resolver = Resolver(resolver_servers, timeout=timeout, workers=workers)
    host_results = resolver.resolve_all(hosts)
    for hr in host_results:
        hr.note = notes.get(hr.host, "")
    result.hosts = host_results

    resolved = sum(1 for h in host_results if h.resolvable)
    _log(f"Resolved {resolved}/{len(host_results)} host(s).", quiet)

    # --- Stage 2: collect unique IPs + ASN/provider --------------------------
    unique_ips: list[str] = []
    seen_ip: set[str] = set()
    for hr in host_results:
        for ip in hr.ips:
            if ip not in seen_ip:
                seen_ip.add(ip)
                unique_ips.append(ip)

    _log(f"Identifying hosting providers for {len(unique_ips)} unique IP(s)...", quiet)
    asn = ASNLookup(timeout=timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 16)) as ex:
        ip_info = dict(zip(unique_ips, ex.map(asn.lookup, unique_ips)))
        ptr_map = dict(zip(unique_ips, ex.map(resolver.ptr, unique_ips)))

    for ip in unique_ips:
        info = ip_info.get(ip, {})
        ipr = IPResult(
            ip=ip,
            version=info.get("version", 4),
            asn=info.get("asn", ""),
            provider=info.get("provider", ""),
            country=info.get("country", ""),
            prefix=info.get("prefix", ""),
            ptr=ptr_map.get(ip, ""),
        )
        # A public DNS record that points at a private/reserved address leaks
        # internal topology and usually means a stale/misconfigured entry.
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local \
                    or addr.is_reserved or addr.is_unspecified:
                ipr.notes.append("Private/reserved IP exposed in public DNS "
                                 "(internal-topology leak / stale record)")
        except ValueError:
            pass
        result.ips[ip] = ipr

    # --- Stage 3: service/version probe --------------------------------------
    if do_scan and unique_ips:
        if not nmap_available():
            _log("nmap not found — skipping service probe (install nmap to enable).", quiet)
        else:
            _log(f"Probing services on {len(unique_ips)} IP(s) with nmap -sV "
                 f"(this can take a minute)...", quiet)
            scanner = NmapScanner(ports=ports, intensity=scan_intensity)
            port_map = scanner.scan(unique_ips)
            for ip, ports_found in port_map.items():
                if ip in result.ips:
                    result.ips[ip].ports = ports_found
                    result.ips[ip].scanned = True
            open_total = sum(len(v.open_ports) for v in result.ips.values())
            old_total = sum(1 for v in result.ips.values() for p in v.ports if p.old)
            _log(f"Found {open_total} open port(s); {old_total} flagged as old/risky.", quiet)
    else:
        _log("Service probe skipped.", quiet)

    # --- Stage 4: HTTP / TLS probe (resolvable hosts only) -------------------
    if do_http:
        live = [hr for hr in host_results if hr.resolvable]
        _log(f"Probing HTTP/TLS on {len(live)} reachable host(s)...", quiet)
        http_results = http_probe_all([hr.host for hr in live],
                                      timeout=http_timeout, workers=workers)
        for hr in live:
            r = http_results.get(hr.host, {})
            hr.reachable = r.get("reachable", False)
            hr.http_status = r.get("http_status", 0)
            hr.http_via = r.get("http_via", "")
            hr.http_server = r.get("http_server", "")
            hr.http_final = r.get("http_final", "")
            hr.tls_ok = r.get("tls_ok", None)
            hr.tls_issue = r.get("tls_issue", "")
        up = sum(1 for hr in live if hr.reachable)
        insecure = sum(1 for hr in live if hr.tls_ok is False)
        _log(f"{up} host(s) answered HTTP; {insecure} with insecure/failed TLS.", quiet)

    # --- Stage 5: zone DNS / email posture ----------------------------------
    if do_posture:
        zones = sorted({hr.zone for hr in host_results if hr.zone})
        _log(f"Checking DNS/email posture for {len(zones)} zone(s)...", quiet)
        pl = PostureLookup(timeout=timeout)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 8)) as ex:
            for zone, posture in zip(zones, ex.map(pl.lookup, zones)):
                result.posture[zone] = posture

    # --- Stage 6: classify rows, derive role tags + footnotes ----------------
    classify(result)

    return result
