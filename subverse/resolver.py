"""DNS resolution stage.

For each input hostname we collect the CNAME chain, A/AAAA addresses, MX hosts,
and the authoritative nameservers of its zone. dnspython is synchronous, so we
fan out across a thread pool for throughput.
"""

from __future__ import annotations

import concurrent.futures
from functools import lru_cache

import dns.resolver
import dns.reversename
import dns.exception

from .model import HostResult


# Multi-label public suffixes we care about often enough to special-case.
# Anything not listed falls back to "last two labels", which is correct for the
# vast majority of TLDs (.se, .com, .io, ...).
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "gov.au",
    "co.nz", "co.za", "com.br", "co.jp", "or.jp",
}


def registrable_domain(host: str) -> str:
    """Best-effort zone apex without pulling in the full Public Suffix List."""
    labels = host.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in _MULTI_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else last_two
    # handle e.g. foo.co.uk where co.uk is the suffix
    suffix_two = ".".join(labels[-2:])
    if suffix_two in _MULTI_SUFFIXES:
        return last_three
    return last_two


def _make_resolver(servers: list[str] | None, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=not servers)
    if servers:
        r.nameservers = servers
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def _query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    try:
        ans = resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return []
    if ans.rrset is None:
        return []
    out = []
    for r in ans:
        if rdtype == "MX":
            out.append(str(r.exchange).rstrip("."))
        elif rdtype in ("NS", "CNAME"):
            out.append(str(r.target).rstrip("."))
        else:
            out.append(r.to_text())
    return out


class Resolver:
    def __init__(self, servers: list[str] | None = None, timeout: float = 4.0,
                 workers: int = 24):
        self.servers = servers
        self.timeout = timeout
        self.workers = workers
        self._r = _make_resolver(servers, timeout)

    @lru_cache(maxsize=4096)
    def _zone_ns(self, zone: str) -> tuple[str, ...]:
        return tuple(sorted(_query(self._r, zone, "NS")))

    def resolve_host(self, host: str) -> HostResult:
        host = host.strip().rstrip(".")
        res = HostResult(host=host)
        try:
            cname = _query(self._r, host, "CNAME")
            res.cnames = cname
            res.a = _query(self._r, host, "A")
            res.aaaa = _query(self._r, host, "AAAA")
            res.mx = _query(self._r, host, "MX")
            res.zone = registrable_domain(host)
            res.nameservers = list(self._zone_ns(res.zone))
            res.resolvable = bool(res.a or res.aaaa or res.cnames)
        except Exception as exc:  # defensive: never let one host kill the run
            res.error = f"{type(exc).__name__}: {exc}"
        return res

    def resolve_all(self, hosts: list[str]) -> list[HostResult]:
        results: dict[str, HostResult] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self.resolve_host, h): h for h in hosts}
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                results[r.host] = r
        # preserve input order
        return [results[h.strip().rstrip(".")] for h in hosts
                if h.strip().rstrip(".") in results]

    def ptr(self, ip: str) -> str:
        try:
            rev = dns.reversename.from_address(ip)
            names = _query(self._r, rev.to_text(), "PTR")
            return names[0].rstrip(".") if names else ""
        except Exception:
            return ""
