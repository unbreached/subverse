"""Heuristic 'is this software old / risky?' tagging.

This is intentionally conservative and clearly heuristic — it is NOT a CVE
scanner. It flags versions that are well past end-of-life or obviously stale, so
that forgotten hosts running ancient daemons jump out in the visualization. Edit
_MIN_SAFE to tune to your own baseline.
"""

from __future__ import annotations

import re

from .model import PortResult

# product substring -> (minimum "not obviously ancient" version, note)
# Versions below this are flagged. Kept rough on purpose.
_MIN_SAFE: list[tuple[str, tuple[int, ...], str]] = [
    ("openssh", (8, 0), "OpenSSH < 8.0 is past most distro support"),
    ("apache", (2, 4, 50), "Apache httpd < 2.4.50 (2.2.x/2.4 early are EOL)"),
    ("nginx", (1, 20), "nginx < 1.20 is EOL"),
    ("openssl", (1, 1, 1), "OpenSSL < 1.1.1 is EOL"),
    ("exim", (4, 94), "Exim < 4.94 (many RCE CVEs)"),
    ("proftpd", (1, 3, 6), "ProFTPD < 1.3.6"),
    ("vsftpd", (3, 0), "vsftpd < 3.0"),
    ("php", (8, 0), "PHP < 8.0 is EOL"),
    ("microsoft-iis", (10, 0), "IIS < 10 (Server <2016) is dated"),
    ("postfix", (3, 0), "Postfix < 3.0 is old"),
    ("dovecot", (2, 3), "Dovecot < 2.3"),
    ("mysql", (5, 7), "MySQL < 5.7 is EOL"),
    ("pure-ftpd", (1, 0, 49), "Pure-FTPd < 1.0.49"),
]

# Services whose mere exposure on the public internet is worth a second look.
_RISKY_PLAINTEXT = {
    21: "FTP exposed (plaintext credentials)",
    23: "Telnet exposed (plaintext)",
    25: "SMTP exposed (verify it is not an open relay)",
}

_VER_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


def _parse_version(s: str) -> tuple[int, ...]:
    m = _VER_RE.search(s or "")
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def _older_than(found: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    if not found:
        return False
    n = max(len(found), len(minimum))
    f = found + (0,) * (n - len(found))
    m = minimum + (0,) * (n - len(minimum))
    return f < m


def flag_port(p: PortResult) -> PortResult:
    """Mutate and return a PortResult with .old / .old_reason set heuristically.

    Only OPEN ports are ever flagged — a closed/filtered port is not a finding.
    """
    if not p.is_open:
        return p
    haystack = f"{p.product} {p.version} {p.extrainfo}".lower()
    ver = _parse_version(p.version) or _parse_version(p.product) or _parse_version(p.banner)

    for needle, minimum, note in _MIN_SAFE:
        if needle in haystack and _older_than(ver, minimum):
            p.old = True
            p.old_reason = note
            return p

    # Exposed plaintext service with no/old crypto wrapper.
    if p.port in _RISKY_PLAINTEXT and p.tunnel != "ssl":
        p.old = True
        p.old_reason = _RISKY_PLAINTEXT[p.port]
    return p
