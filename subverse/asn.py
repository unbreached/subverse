"""Map IP addresses to their hosting provider / network owner.

Uses Team Cymru's free DNS-based IP-to-ASN service — no API key, no rate-limit
sign-up. Two TXT lookups per IP:

  origin:  <reversed-ip>.origin.asn.cymru.com  -> "ASN | prefix | CC | reg | date"
  as-name: AS<asn>.asn.cymru.com               -> "ASN | CC | reg | date | name"

IPv6 uses the nibble format under origin6.asn.cymru.com. Results are cached so a
shared host hit by 40 subdomains is only looked up once.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

import dns.resolver
import dns.exception


class ASNLookup:
    def __init__(self, timeout: float = 4.0):
        self._r = dns.resolver.Resolver()
        self._r.timeout = timeout
        self._r.lifetime = timeout * 2

    def _txt(self, name: str) -> str:
        try:
            ans = self._r.resolve(name, "TXT", raise_on_no_answer=False)
        except dns.exception.DNSException:
            return ""
        if ans.rrset is None:
            return ""
        for r in ans:
            # strings come back quoted and possibly chunked
            return b"".join(r.strings).decode("utf-8", "replace")
        return ""

    @staticmethod
    def _origin_qname(ip: str) -> tuple[str, int]:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            rev = ".".join(reversed(ip.split(".")))
            return f"{rev}.origin.asn.cymru.com", 4
        # IPv6: expand to nibbles, reversed, dot-separated
        nibbles = addr.exploded.replace(":", "")
        rev = ".".join(reversed(nibbles))
        return f"{rev}.origin6.asn.cymru.com", 6

    @lru_cache(maxsize=8192)
    def lookup(self, ip: str) -> dict:
        """Return {asn, provider, country, prefix, version} for an IP (best-effort)."""
        result = {"asn": "", "provider": "", "country": "", "prefix": "",
                  "version": ipaddress.ip_address(ip).version}
        try:
            qname, ver = self._origin_qname(ip)
        except ValueError:
            return result
        result["version"] = ver

        origin = self._txt(qname)
        if not origin:
            return result
        # "16509 | 52.0.0.0/11 | US | arin | 2010-..."  (first ASN if multiple)
        parts = [p.strip() for p in origin.split("|")]
        if parts:
            result["asn"] = parts[0].split()[0] if parts[0] else ""
        if len(parts) > 1:
            result["prefix"] = parts[1]
        if len(parts) > 2:
            result["country"] = parts[2]

        if result["asn"]:
            asinfo = self._txt(f"AS{result['asn']}.asn.cymru.com")
            # "16509 | US | arin | 2000-.. | AMAZON-02, US"
            ap = [p.strip() for p in asinfo.split("|")]
            if len(ap) >= 5:
                name = ap[4]
                # Cymru appends a ", XX" registration-country tag — drop it.
                if len(name) > 4 and name[-4] == "," and name[-2:].isalpha() \
                        and name[-2:].isupper():
                    name = name[:-4]
                result["provider"] = name.strip()
        return result
