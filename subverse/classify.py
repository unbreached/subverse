"""Derive the human-facing labels for the card map.

Three jobs, all best-effort first passes meant to be hand-refined:
  1. per-host status category + right-aligned annotation (record + http/tls state)
  2. per-IP role tag ("Reverse-proxy hub", "Info leak", "Third-party", ...)
  3. per-IP analyst footnote

Everything here is heuristic — it reads only the data the probe already
collected, never the network.
"""

from __future__ import annotations

import ipaddress
import re

from .model import ScanResult, HostResult, IPResult
from .resolver import registrable_domain

# Hosting/provider keywords that signal a managed third-party (not your server).
_THIRD_PARTY_HINTS = (
    "smtp2go", "sendgrid", "mailgun", "mailchimp", "mandrill", "mailjet",
    "outlook", "office365", "microsoft", "google", "googlehosted", "gslb",
    "cloudflare", "fastly", "akamai", "shopify", "wpengine", "hubspot",
    "zendesk", "github", "herokudns", "azurewebsites", "awsglobal",
)


def _short_target(name: str) -> str:
    """A compact label for a CNAME target ('foo.track.smtp2go.net' -> 'SMTP2GO')."""
    low = name.lower()
    for hint in _THIRD_PARTY_HINTS:
        if hint in low:
            return {
                "smtp2go": "SMTP2GO", "outlook": "Microsoft 365",
                "office365": "Microsoft 365", "microsoft": "Microsoft 365",
                "google": "Google", "googlehosted": "Google",
                "cloudflare": "Cloudflare", "fastly": "Fastly",
                "akamai": "Akamai", "sendgrid": "SendGrid",
            }.get(hint, hint.upper())
    return name


def _is_external_cname(hr: HostResult) -> bool:
    return any(registrable_domain(c) != hr.zone for c in hr.cnames)


def _record_label(hr: HostResult) -> str:
    if hr.host == hr.zone:
        return "apex"
    if hr.cnames:
        if _is_external_cname(hr):
            ext = next(c for c in hr.cnames if registrable_domain(c) != hr.zone)
            return f"CNAME → {_short_target(ext)}"
        return "CNAME"
    if hr.a or hr.aaaa:
        return "A"
    return "—"


def _host_private(hr: HostResult, scan: ScanResult) -> bool:
    for ip in hr.ips:
        ipr = scan.ips.get(ip)
        if ipr and any("Private/reserved" in n for n in ipr.notes):
            return True
    return False


def _classify_host(hr: HostResult, scan: ScanResult) -> None:
    parts = [_record_label(hr)]
    private = _host_private(hr, scan)
    external = _is_external_cname(hr)
    wildcard_ip = False
    posture = scan.posture.get(hr.zone)
    if posture and posture.wildcard:
        wc_ips = {x.strip() for x in posture.wildcard.split(",")}
        wildcard_ip = bool(set(hr.a) & wc_ips)

    # status flags appended to the annotation
    if private:
        parts.append("private A")
    if hr.http_status >= 400:
        parts.append(str(hr.http_status))
    if hr.tls_ok is False and hr.reachable and 0 < hr.http_status < 400:
        parts.append("insecure")
    if not hr.reachable and wildcard_ip:
        parts.append("wildcard")
    # surface old/risky software found by nmap on this host's IP(s)
    for ip in hr.ips:
        ipr = scan.ips.get(ip)
        if ipr:
            for p in ipr.ports:
                if p.old:
                    label = " ".join(x for x in (p.product, p.version) if x) or p.service
                    parts.append(f"⚠ {label}".strip())
                    break

    hr.annotation = " · ".join(p for p in parts if p and p != "—")

    # category (drives the status dot color), in priority order
    if private:
        hr.category = "misconfig"
    elif external:
        hr.category = "third-party"
    elif not hr.reachable:
        hr.category = "misconfig" if wildcard_ip else "error"
    elif hr.http_status >= 400:
        hr.category = "error"
    elif hr.tls_ok is False:
        hr.category = "insecure"
    else:
        hr.category = "active"


def _spf_networks(scan: ScanResult, zone: str) -> list:
    posture = scan.posture.get(zone)
    nets = []
    if posture and posture.spf:
        for tok in re.findall(r"ip4:([0-9./]+)", posture.spf):
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                pass
    return nets


def _ip_in_spf(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _classify_ips(scan: ScanResult) -> None:
    # map ip -> hosts that resolve to it
    hosts_on: dict[str, list[HostResult]] = {}
    for hr in scan.hosts:
        for ip in hr.ips:
            hosts_on.setdefault(ip, []).append(hr)

    busiest = max((len(v) for v in hosts_on.values()), default=0)

    # union of SPF networks across zones (usually one zone)
    all_nets = []
    for zone in {hr.zone for hr in scan.hosts}:
        all_nets += _spf_networks(scan, zone)

    for ip, ipr in scan.ips.items():
        members = hosts_on.get(ip, [])
        n = len(members)
        is_private = any("Private/reserved" in note for note in ipr.notes)
        third_party = any(_is_external_cname(m) for m in members) or \
            any(hint in (ipr.provider or "").lower() for hint in _THIRD_PARTY_HINTS) or \
            any(hint in (ipr.ptr or "").lower() for hint in _THIRD_PARTY_HINTS)
        proxyish = any("haproxy" in (p.product or "").lower() or "proxy" in (p.service or "")
                       for p in ipr.ports)

        apex_here = any(m.host == m.zone for m in members)

        # role (priority order)
        if is_private:
            ipr.role = "Info leak"
        elif third_party:
            ipr.role = "Third-party"
        elif n >= 5 and n == busiest:
            ipr.role = "Reverse-proxy hub"
        elif apex_here:
            ipr.role = "Public website"
        elif _ip_in_spf(ip, all_nets):
            ipr.role = "In SPF range"
        elif n == 1:
            ipr.role = "Standalone"
        else:
            ipr.role = "App host"

        ipr.footnote = _ip_footnote(ipr, members, proxyish)


def _ip_footnote(ipr: IPResult, members: list[HostResult], proxyish: bool) -> str:
    if any("Private/reserved" in note for note in ipr.notes):
        return "Internal IP published in public DNS. Reachable only inside the LAN."
    if ipr.role == "Reverse-proxy hub":
        cname_count = sum(1 for m in members if m.cnames)
        return (f"One host fronts ~{len(members)} names"
                + (f" ({cname_count} via CNAME)" if cname_count else "")
                + ". Most 5xx are backends down behind it, not separate servers.")
    if ipr.role == "Third-party":
        ext = next((m for m in members if m.cnames), None)
        if ext:
            tgt = next((c for c in ext.cnames), "")
            return f"{ext.host} is a live CNAME → {_short_target(tgt)}, not offline."
    # PTR vs served-name mismatch
    if ipr.ptr and members:
        ptr_label = ipr.ptr.split(".")[0].lower()
        served = {m.host.split(".")[0].lower() for m in members}
        if ptr_label not in served and not ptr_label.isdigit() \
                and len(ptr_label) > 2 and any(c.isalpha() for c in ptr_label):
            return (f"PTR says “{ptr_label}”, but serves "
                    f"{', '.join(sorted(served))}. Naming mismatch.")
    return ""


def classify(scan: ScanResult) -> None:
    """Populate host.category/annotation and ip.role/footnote in place."""
    for hr in scan.hosts:
        _classify_host(hr, scan)
    _classify_ips(scan)


def apply_overrides(scan: ScanResult, path: str) -> int:
    """Refine auto-derived role tags / footnotes from a sidecar file.

    Format, one per line ('#' comments allowed):
        <ip>|<role>|<footnote>
    Blank role or footnote keeps the auto-derived value. The IP matches any
    address in a card's IP set. Returns the number of IPs overridden.
    """
    applied = 0
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            cols = [c.strip() for c in line.split("|")]
            ip = cols[0]
            role = cols[1] if len(cols) > 1 else ""
            foot = cols[2] if len(cols) > 2 else ""
            ipr = scan.ips.get(ip)
            if not ipr:
                continue
            if role:
                ipr.role = role
            if foot:
                ipr.footnote = foot
            applied += 1
    return applied
