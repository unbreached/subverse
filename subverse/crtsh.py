"""Subdomain enumeration via crt.sh Certificate Transparency search.

crt.sh indexes public CT logs, so querying it for a domain returns every name
that has ever appeared in a certificate for it — including long-expired ones,
which is exactly how forgotten/stale subdomains surface. No API key is needed.

The network fetch (`fetch_subdomains`) is a thin wrapper around the pure parser
(`parse_crtsh_json`); the parser holds all the logic and is unit-tested offline.
Only the Python standard library is used.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from . import __version__

_UA = f"Subverse/{__version__} (+attack-surface map; authorized assessment)"
_FETCH_TIMEOUT = 30.0            # crt.sh is slow; independent of the DNS timeout


class CrtShError(Exception):
    """Raised when crt.sh cannot be reached or returns unusable data."""


def parse_crtsh_json(text: str, domain: str) -> list[str]:
    """Extract the in-scope (sub)domains from a crt.sh JSON response.

    `text` is the raw JSON body; `domain` is the registrable apex. Returns a
    sorted, de-duplicated list of lowercase hostnames that are the apex itself
    or a subdomain of it. The apex is always included. Everything crt.sh mixes
    in — CA/intermediate strings (which contain spaces), subject email
    addresses, `*.` wildcard entries, and look-alike domains that merely
    contain the apex as a substring — is filtered out.

    Raises ValueError (via json.loads) if `text` is not valid JSON.
    """
    data = json.loads(text)

    apex = domain.strip().rstrip(".").lower()
    # a valid name is the apex or <labels>.<apex>, labels being DNS-safe chars
    sub_re = re.compile(r"^(?:[a-z0-9_-]+\.)+" + re.escape(apex) + r"$")

    found: set[str] = {apex}
    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            raw = entry.get(field) or ""
            for name in str(raw).split("\n"):
                name = name.strip()
                if name.startswith("*."):
                    name = name[2:]
                name = name.lower()
                if name == apex or sub_re.match(name):
                    found.add(name)
    return sorted(found)


def merge_targets(existing: list[tuple[str, str]],
                  new: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Merge two (host, note) lists, de-duplicating case-insensitively.

    `existing` entries come first and win on conflict, so a note carried in
    from a hand-maintained domains file is never clobbered by a bare crt.sh
    hit for the same host. Order is otherwise preserved; blank hosts dropped.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for host, note in list(existing) + list(new):
        key = host.strip().rstrip(".").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append((host.strip().rstrip("."), note))
    return out


def fetch_subdomains(domain: str, timeout: float = _FETCH_TIMEOUT) -> list[str]:
    """Query crt.sh for a domain and return its (sub)domains via the parser.

    Raises CrtShError on any network failure, a non-200 response, or a body
    that the parser cannot read as JSON.
    """
    domain = domain.strip().rstrip(".").lower()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": _UA,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise CrtShError(f"crt.sh returned HTTP {exc.code} for {domain}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise CrtShError(f"could not reach crt.sh: {reason}") from exc

    try:
        return parse_crtsh_json(body, domain)
    except ValueError as exc:
        raise CrtShError("crt.sh returned a non-JSON response "
                         "(it is often overloaded; try again)") from exc
