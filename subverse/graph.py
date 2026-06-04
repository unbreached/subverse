"""Turn a ScanResult into an abstract node/edge graph.

Both renderers consume this so the interactive HTML and the static image always
tell the same story. The mental model:

    zone (example.com)
      └─ subdomain hosts ──> shared IPs ──> hosting providers
                              (dead hosts cluster on their own)
      └─ nameservers

Hosts/IPs running old or risky software get a risk flag; hosts that no longer
resolve get a 'dead' flag — those are the forgotten-subdomain candidates.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import ScanResult, HostResult
from . import style


@dataclass
class Node:
    id: str
    kind: str            # zone | host | ip | provider | ns | cname
    label: str
    color: str
    risk: bool = False
    dead: bool = False
    sublabel: str = ""
    tooltip: list[str] = field(default_factory=list)
    provider: str = ""


@dataclass
class Edge:
    src: str
    dst: str
    kind: str            # subdomain | resolves | hosted | cname | ns
    label: str = ""


@dataclass
class Graph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)   # sorted, for legend


def _reg_domain(host: str) -> str:
    from .resolver import registrable_domain
    return registrable_domain(host)


def _host_tooltip(hr: HostResult, scan: ScanResult) -> list[str]:
    lines = [f"<b>{hr.host}</b>"]
    if hr.note:
        lines.append(f"note: {hr.note}")
    if not hr.resolvable:
        lines.append("⚠ does not resolve (no A/AAAA/CNAME)")
        if hr.error:
            lines.append(hr.error)
        return lines
    if hr.cnames:
        lines.append("CNAME → " + ", ".join(hr.cnames))
    if hr.a:
        lines.append("A: " + ", ".join(hr.a))
    if hr.aaaa:
        lines.append("AAAA: " + ", ".join(hr.aaaa))
    if hr.mx:
        lines.append("MX: " + ", ".join(hr.mx))
    return lines


def _ip_tooltip(ipr) -> list[str]:
    lines = [f"<b>{ipr.ip}</b>", ipr.provider_label()]
    if ipr.country:
        lines.append(f"country: {ipr.country}")
    if ipr.ptr:
        lines.append(f"PTR: {ipr.ptr}")
    for note in ipr.notes:
        lines.append(f"⚠ {note}")
    if ipr.scanned:
        opens = ipr.open_ports
        if opens:
            for p in opens:
                tag = "  ⚠ OLD/RISKY" if p.old else ""
                lines.append(f"{p.label()}{tag}")
                if p.old and p.old_reason:
                    lines.append(f"    └ {p.old_reason}")
        else:
            lines.append("no open ports (of those scanned)")
    return lines


def build_graph(scan: ScanResult) -> Graph:
    g = Graph()

    # Provider ordering for stable colors / legend.
    providers = sorted({ip.provider for ip in scan.ips.values() if ip.provider})
    g.providers = providers

    seen: set[str] = set()

    def add(node: Node):
        if node.id not in seen:
            seen.add(node.id)
            g.nodes.append(node)

    # Zones (anchors)
    zones = {hr.zone or _reg_domain(hr.host) for hr in scan.hosts}
    for z in sorted(zones):
        add(Node(id=f"zone:{z}", kind="zone", label=z, color=style.ACCENT,
                 tooltip=[f"<b>{z}</b>", "root domain / zone apex"]))

    # IPs + providers
    for ip, ipr in scan.ips.items():
        col = style.provider_color(ipr.provider, providers)
        add(Node(
            id=f"ip:{ip}", kind="ip", label=ip,
            sublabel=ipr.provider or (f"AS{ipr.asn}" if ipr.asn else ""),
            color=col, risk=ipr.risky, provider=ipr.provider,
            tooltip=_ip_tooltip(ipr),
        ))
        if ipr.provider:
            pid = f"prov:{ipr.provider}"
            add(Node(id=pid, kind="provider",
                     label=ipr.provider,
                     sublabel=f"AS{ipr.asn}" if ipr.asn else "",
                     color=col, provider=ipr.provider,
                     tooltip=[f"<b>{ipr.provider_label()}</b>", "hosting provider / network"]))
            g.edges.append(Edge(f"ip:{ip}", pid, "hosted"))

    # Hosts
    for hr in scan.hosts:
        zone = hr.zone or _reg_domain(hr.host)
        # a host's "risk" = any flagged IP it resolves to (old service / bad IP)
        host_risk = any(scan.ips[ip].risky for ip in hr.ips if ip in scan.ips)
        # color a resolvable host by its first IP's provider; dead = muted
        prov = ""
        for ip in hr.ips:
            if ip in scan.ips and scan.ips[ip].provider:
                prov = scan.ips[ip].provider
                break
        if not hr.resolvable:
            col = style.MUTED
        else:
            col = style.provider_color(prov, providers) if prov else style.TEAL
        add(Node(
            id=f"host:{hr.host}", kind="host", label=hr.host,
            color=col, risk=host_risk, dead=not hr.resolvable,
            provider=prov, tooltip=_host_tooltip(hr, scan),
        ))
        g.edges.append(Edge(f"zone:{zone}", f"host:{hr.host}", "subdomain"))

        # host -> IPs
        for ip in hr.ips:
            if ip in scan.ips:
                g.edges.append(Edge(f"host:{hr.host}", f"ip:{ip}", "resolves"))

        # external CNAME targets (subdomain-takeover relevant)
        for cn in hr.cnames:
            if _reg_domain(cn) != zone:
                cid = f"cname:{cn}"
                add(Node(id=cid, kind="cname", label=cn, color=style.AMBER,
                         tooltip=[f"<b>{cn}</b>",
                                  "external CNAME target — verify ownership "
                                  "(subdomain-takeover surface)"]))
                g.edges.append(Edge(f"host:{hr.host}", cid, "cname", "CNAME"))

    # Nameservers (per zone)
    for hr in scan.hosts:
        zone = hr.zone or _reg_domain(hr.host)
        for ns in hr.nameservers:
            nid = f"ns:{ns}"
            add(Node(id=nid, kind="ns", label=ns, color=style.TEAL,
                     tooltip=[f"<b>{ns}</b>", f"nameserver for {zone}"]))
            g.edges.append(Edge(f"zone:{zone}", nid, "ns", "NS"))

    # Dedupe edges: many hosts share the same zone/nameservers/IPs, so without
    # this the graph fills with overlapping identical edges (esp. zone->NS).
    seen_edges: set[tuple[str, str, str]] = set()
    unique: list[Edge] = []
    for e in g.edges:
        key = (e.src, e.dst, e.kind)
        if key not in seen_edges:
            seen_edges.add(key)
            unique.append(e)
    g.edges = unique

    return g
