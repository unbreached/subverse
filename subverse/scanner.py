"""Service/version probing via nmap -sV.

We scan unique IPs (not hostnames) so a server shared by many subdomains is hit
once. nmap's XML output is parsed back into PortResult objects, then run through
the old-software heuristics.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from .model import PortResult
from .flagging import flag_port

DEFAULT_PORTS = [21, 22, 25, 80, 443]


def nmap_available() -> str | None:
    return shutil.which("nmap")


class NmapScanner:
    def __init__(self, ports: list[int] | None = None, timeout: int = 600,
                 host_timeout: str = "90s", intensity: str = "light",
                 extra_args: list[str] | None = None):
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout
        self.host_timeout = host_timeout
        self.intensity = intensity            # light | normal | aggressive
        self.extra_args = extra_args or []
        self.path = nmap_available()

    def _build_cmd(self, ips: list[str]) -> list[str]:
        cmd = [
            self.path, "-sV", "-Pn", "-n",
            "-p", ",".join(str(p) for p in self.ports),
            "-T4",
            "--host-timeout", self.host_timeout,
            "-oX", "-",
        ]
        if self.intensity == "light":
            cmd.append("--version-light")
        elif self.intensity == "aggressive":
            cmd += ["--version-all", "--script=banner"]
        cmd += self.extra_args
        cmd += ips
        return cmd

    def scan(self, ips: list[str]) -> dict[str, list[PortResult]]:
        """Return {ip: [PortResult, ...]} for the given IPs."""
        if not ips:
            return {}
        if not self.path:
            raise RuntimeError(
                "nmap not found on PATH. Install it (brew install nmap) or run "
                "with --no-scan to skip service probing."
            )
        cmd = self._build_cmd(ips)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            # parse whatever partial XML we got before the timeout
            return self._parse(exc.stdout or "")
        return self._parse(proc.stdout)

    @staticmethod
    def _parse(xml_text: str) -> dict[str, list[PortResult]]:
        out: dict[str, list[PortResult]] = {}
        if not xml_text.strip():
            return out
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return out
        for host in root.findall("host"):
            addr = None
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
                    break
            if not addr:
                continue
            results: list[PortResult] = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    state_el = port.find("state")
                    svc = port.find("service")
                    pr = PortResult(
                        port=int(port.get("portid")),
                        proto=port.get("protocol", "tcp"),
                        state=state_el.get("state") if state_el is not None else "unknown",
                    )
                    if svc is not None:
                        pr.service = svc.get("name", "") or ""
                        pr.product = svc.get("product", "") or ""
                        pr.version = svc.get("version", "") or ""
                        pr.extrainfo = svc.get("extrainfo", "") or ""
                        pr.tunnel = svc.get("tunnel", "") or ""
                    # capture any banner script output
                    for script in port.findall("script"):
                        if script.get("id") == "banner":
                            pr.banner = (script.get("output") or "").strip()
                    flag_port(pr)
                    results.append(pr)
            out[addr] = results
        return out
