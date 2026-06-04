"""Zone-level DNS / email security posture.

Looks up the records that drive the badge row on the map: SPF and its fail mode,
DMARC policy, which DKIM selectors publish a key, the CAA issuer allow-list, and
whether a wildcard *.zone resolves (which makes many "dead" subdomains mere
wildcard artifacts rather than real hosts).
"""

from __future__ import annotations

import dns.resolver
import dns.exception

from .model import Posture

# Selectors worth probing — covers M365, Google, and common ESP defaults.
_DKIM_SELECTORS = [
    "selector1", "selector2",            # Microsoft 365
    "google",                            # Google Workspace
    "default", "dkim", "mail", "k1", "k2",
    "s1", "s2", "smtp", "mandrill", "mailjet", "sendgrid",
]


class PostureLookup:
    def __init__(self, timeout: float = 4.0):
        self._r = dns.resolver.Resolver()
        self._r.timeout = timeout
        self._r.lifetime = timeout * 2

    def _txt(self, name: str) -> list[str]:
        try:
            ans = self._r.resolve(name, "TXT", raise_on_no_answer=False)
        except dns.exception.DNSException:
            return []
        if ans.rrset is None:
            return []
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]

    def _exists(self, name: str, rdtype: str) -> bool:
        try:
            ans = self._r.resolve(name, rdtype, raise_on_no_answer=False)
            return ans.rrset is not None
        except dns.exception.DNSException:
            return False

    def lookup(self, zone: str) -> Posture:
        p = Posture(zone=zone)

        # SPF
        for txt in self._txt(zone):
            if txt.lower().startswith("v=spf1"):
                p.spf = txt
                p.spf_ok = ("-all" in txt or "~all" in txt)
                break

        # DMARC
        for txt in self._txt(f"_dmarc.{zone}"):
            if txt.lower().startswith("v=dmarc1"):
                p.dmarc = txt
                for tok in txt.split(";"):
                    tok = tok.strip()
                    if tok.lower().startswith("p="):
                        p.dmarc_policy = tok.split("=", 1)[1].strip().lower()
                break

        # DKIM selectors
        for sel in _DKIM_SELECTORS:
            recs = self._txt(f"{sel}._domainkey.{zone}")
            if any(("v=dkim1" in t.lower()) or ("k=rsa" in t.lower()) or ("p=" in t)
                   for t in recs):
                p.dkim.append(sel)

        # CAA
        try:
            ans = self._r.resolve(zone, "CAA", raise_on_no_answer=False)
            if ans.rrset is not None:
                issuers = []
                for r in ans:
                    if getattr(r, "tag", b"") in (b"issue", b"issuewild", "issue", "issuewild"):
                        val = r.value.decode() if isinstance(r.value, bytes) else str(r.value)
                        val = val.strip().strip('"')
                        if val and val not in issuers:
                            issuers.append(val)
                p.caa = issuers
        except dns.exception.DNSException:
            pass

        # Wildcard: does a guaranteed-nonexistent label still resolve?
        probe = f"dp-wildcard-probe-zzqx.{zone}"
        try:
            ans = self._r.resolve(probe, "A", raise_on_no_answer=False)
            if ans.rrset is not None:
                ips = [r.to_text() for r in ans]
                p.wildcard = ", ".join(ips)
        except dns.exception.DNSException:
            pass

        return p
