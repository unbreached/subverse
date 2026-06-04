"""Data model for a Subverse scan.

These dataclasses are the single source of truth that every stage of the
pipeline (resolve -> asn -> scan -> flag) fills in, and that both renderers and
the JSON exporter read from.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class PortResult:
    """One TCP port observed on an IP, as reported by the scanner."""

    port: int
    proto: str = "tcp"
    state: str = "closed"          # open | closed | filtered
    service: str = ""              # nmap service name, e.g. "http"
    product: str = ""              # e.g. "Apache httpd"
    version: str = ""              # e.g. "2.2.15"
    extrainfo: str = ""            # e.g. "(CentOS)"
    tunnel: str = ""               # e.g. "ssl"
    banner: str = ""               # raw-ish banner / scriptline if any
    old: bool = False              # heuristic: outdated/EOL software?
    old_reason: str = ""           # why it was flagged

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    def label(self) -> str:
        """Compact human label, e.g. '443/tcp nginx 1.10.3'."""
        bits = [f"{self.port}/{self.proto}"]
        name = " ".join(p for p in (self.product, self.version) if p) or self.service
        if name:
            bits.append(name)
        if self.tunnel == "ssl" and "ssl" not in name.lower():
            bits.append("(ssl)")
        return " ".join(bits)


@dataclass
class IPResult:
    """A unique IP address, its network owner, and what is listening on it."""

    ip: str
    version: int = 4               # 4 or 6
    asn: str = ""                  # e.g. "16509"
    provider: str = ""             # AS name / hosting provider, e.g. "AMAZON-02"
    country: str = ""              # ISO country code
    prefix: str = ""               # announced BGP prefix
    ptr: str = ""                  # reverse DNS, if any
    ports: list[PortResult] = field(default_factory=list)
    scanned: bool = False          # did the scanner actually run against it?
    notes: list[str] = field(default_factory=list)   # IP-level findings (e.g. private IP)
    role: str = ""                 # derived role tag, e.g. "Reverse-proxy hub"
    footnote: str = ""             # analyst footnote for this card

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open]

    @property
    def has_old(self) -> bool:
        return any(p.old for p in self.ports)

    @property
    def risky(self) -> bool:
        """Any reason to draw attention to this IP: old service or IP-level note."""
        return self.has_old or bool(self.notes)

    def provider_label(self) -> str:
        if self.provider and self.asn:
            return f"{self.provider} (AS{self.asn})"
        return self.provider or (f"AS{self.asn}" if self.asn else "unknown network")


@dataclass
class HostResult:
    """One hostname from the input list and everything we learned about it."""

    host: str
    resolvable: bool = False
    cnames: list[str] = field(default_factory=list)
    a: list[str] = field(default_factory=list)         # IPv4
    aaaa: list[str] = field(default_factory=list)       # IPv6
    mx: list[str] = field(default_factory=list)
    zone: str = ""                                      # registrable/zone name
    nameservers: list[str] = field(default_factory=list)
    error: str = ""                                     # resolution error, if any
    note: str = ""                                       # optional free-text tag from input

    # HTTP / TLS probe results
    reachable: bool = False        # got any HTTP(S) response
    http_status: int = 0           # final HTTP status code (0 = no response)
    http_via: str = ""             # scheme that answered: "https" | "http"
    http_server: str = ""          # Server response header
    http_final: str = ""           # final URL after redirects
    tls_ok: Optional[bool] = None  # None = not tried / not HTTPS
    tls_issue: str = ""            # why TLS was considered insecure

    # derived for the map (set by classify)
    category: str = ""             # active | insecure | error | third-party | misconfig
    annotation: str = ""           # right-aligned record/status label, e.g. "CNAME · 403"

    @property
    def ips(self) -> list[str]:
        return self.a + self.aaaa


@dataclass
class Posture:
    """Zone-level DNS / email security posture."""

    zone: str
    spf: str = ""                  # raw SPF record, if present
    spf_ok: bool = False           # has SPF with a hard/soft fail-all
    dmarc: str = ""                # raw DMARC record
    dmarc_policy: str = ""         # none | quarantine | reject
    dkim: list[str] = field(default_factory=list)   # DKIM selectors found
    caa: list[str] = field(default_factory=list)     # CAA issuers
    wildcard: str = ""             # where a wildcard *.zone resolves, if any


@dataclass
class ScanResult:
    """Top-level container returned by the orchestrator."""

    hosts: list[HostResult] = field(default_factory=list)
    ips: dict[str, IPResult] = field(default_factory=dict)   # ip -> IPResult
    posture: dict[str, Posture] = field(default_factory=dict)  # zone -> Posture
    meta: dict = field(default_factory=dict)

    def ip(self, addr: str) -> Optional[IPResult]:
        return self.ips.get(addr)

    def to_dict(self) -> dict:
        return {
            "meta": self.meta,
            "hosts": [asdict(h) for h in self.hosts],
            "ips": {k: asdict(v) for k, v in self.ips.items()},
            "posture": {k: asdict(v) for k, v in self.posture.items()},
        }
