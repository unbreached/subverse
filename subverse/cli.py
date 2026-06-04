"""Command-line entry point for Subverse."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .platform_utils import open_path
# NOTE: modules that import dnspython (probe, scanner, ...) are imported lazily
# inside main(), AFTER the dependency bootstrap, so a missing dnspython can be
# auto-installed instead of crashing at import time.

DEFAULT_PORTS = [21, 22, 25, 80, 443]


def _parse_ports(s: str) -> list[int]:
    out = []
    for chunk in s.split(","):
        chunk = chunk.strip()
        if chunk:
            out.append(int(chunk))
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subverse",
        description="Full DNS + service probe of a domain list, rendered as an "
                    "interactive graph and a static evidence image.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("domains", nargs="?",
                   help="Path to a text file: one (sub)domain per line "
                        "('#' comments and trailing notes allowed).")
    p.add_argument("-o", "--output-dir", default="out", help="Where to write outputs.")
    p.add_argument("-n", "--name", default=None,
                   help="Base filename for outputs (default: derived from input).")
    p.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help="Comma-separated TCP ports to probe.")
    p.add_argument("--no-scan", action="store_true",
                   help="Skip the nmap service/version probe (DNS + ASN only).")
    p.add_argument("--no-http", action="store_true",
                   help="Skip the HTTP/TLS probe.")
    p.add_argument("--no-posture", action="store_true",
                   help="Skip the DNS/email posture (SPF/DKIM/DMARC/CAA) checks.")
    p.add_argument("--intensity", choices=["light", "normal", "aggressive"],
                   default="light", help="nmap -sV intensity.")
    p.add_argument("--graph", action="store_true",
                   help="Also emit the node-graph view (HTML + PNG/SVG) "
                        "alongside the default card map.")
    p.add_argument("--no-cards", action="store_true",
                   help="Skip the card map (e.g. when you only want --graph).")
    p.add_argument("--subtitle", default=None, help="Subtitle under the map title.")
    p.add_argument("--labels", default=None,
                   help="Sidecar file (ip|role|footnote per line) to refine the "
                        "auto-derived role tags / footnotes.")
    p.add_argument("--resolver", default=None,
                   help="Comma-separated DNS resolvers to use (default: system).")
    p.add_argument("--timeout", type=float, default=4.0, help="DNS query timeout (s).")
    p.add_argument("--workers", type=int, default=24, help="Concurrent DNS workers.")
    p.add_argument("--no-html", action="store_true", help="Don't write interactive HTML.")
    p.add_argument("--no-image", action="store_true", help="Don't render PNG/SVG.")
    p.add_argument("--json", action="store_true", help="Also write raw results as JSON.")
    p.add_argument("--dpi", type=int, default=160, help="PNG resolution.")
    p.add_argument("--title", default=None, help="Title shown on the visualizations.")
    p.add_argument("--org", default="", help="Organization / client name for the header.")
    p.add_argument("--ref", default="", help="Ticket / advisory reference for the header.")
    p.add_argument("--open", action="store_true",
                   help="Open the generated HTML/PNG when done (macOS 'open').")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output.")
    p.add_argument("--check-deps", action="store_true",
                   help="Report which optional tools (nmap/graphviz/browser) are "
                        "installed, then exit.")
    p.add_argument("--install-deps", action="store_true",
                   help="Auto-install missing optional tools via the OS package "
                        "manager (brew/apt/dnf/pacman/winget/choco), then continue.")
    p.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from . import bootstrap

    want_scan = not args.no_scan
    want_png = not args.no_cards
    want_graph = args.graph

    # --check-deps: just report and exit
    if args.check_deps:
        print("Subverse optional tools:")
        bootstrap.report(want_scan, want_png, want_graph)
        return 0

    # --install-deps: install missing system tools before continuing
    if args.install_deps:
        bootstrap.install(want_scan, want_png, want_graph)

    # make sure the one Python dependency is present (auto-install if missing)
    if not bootstrap.ensure_python_deps(auto=True):
        return 2

    # heavy imports happen now — after dnspython is guaranteed importable
    from .probe import read_domains, run_probe
    from .render_cards import render_cards_image

    if not args.domains:
        print("error: no domains file given. Pass a file, or use --check-deps / "
              "--install-deps.", file=sys.stderr)
        return 2

    in_path = Path(args.domains)
    if not in_path.exists():
        print(f"error: domains file not found: {in_path}", file=sys.stderr)
        return 2

    domains = read_domains(str(in_path))
    if not domains:
        print(f"error: no domains found in {in_path}", file=sys.stderr)
        return 2

    # warn (don't fail) about missing optional tools relevant to this run
    if not args.quiet:
        miss = bootstrap.missing(want_scan, want_png, want_graph)
        if miss:
            print(f"[!] optional tool(s) missing: {', '.join(miss)} — "
                  f"run with --install-deps to auto-install, or --check-deps for "
                  f"instructions.", file=sys.stderr)

    resolver_servers = (
        [s.strip() for s in args.resolver.split(",") if s.strip()]
        if args.resolver else None
    )
    ports = _parse_ports(args.ports)

    scan = run_probe(
        domains,
        resolver_servers=resolver_servers,
        ports=ports,
        do_scan=not args.no_scan,
        scan_intensity=args.intensity,
        do_http=not args.no_http,
        do_posture=not args.no_posture,
        timeout=args.timeout,
        workers=args.workers,
        quiet=args.quiet,
    )

    # optional manual refinement of role tags / footnotes
    if args.labels:
        if Path(args.labels).exists():
            from .classify import apply_overrides
            n = apply_overrides(scan, args.labels)
            if not args.quiet:
                print(f"[*] Applied {n} label override(s) from {args.labels}",
                      file=sys.stderr)
        else:
            print(f"[!] labels file not found: {args.labels}", file=sys.stderr)

    # stats + meta
    n_hosts = len(scan.hosts)
    n_dead = sum(1 for h in scan.hosts if not h.resolvable)
    n_risk = sum(1 for h in scan.hosts
                 if any(scan.ips[ip].risky for ip in h.ips if ip in scan.ips))
    n_ips = len(scan.ips)
    providers = sorted({ip.provider for ip in scan.ips.values() if ip.provider})
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # primary zone = the most-represented zone, used for a sensible default title
    zone_counts: dict[str, int] = {}
    for h in scan.hosts:
        zone_counts[h.zone] = zone_counts.get(h.zone, 0) + 1
    primary_zone = max(zone_counts, key=zone_counts.get) if zone_counts else in_path.stem

    title = args.title or f"{primary_zone} — external attack surface map"
    meta = {
        "title": title, "org": args.org, "ref": args.ref, "timestamp": ts,
        "subtitle": args.subtitle, "tool": f"Subverse {__version__}",
        "stats": {"hosts": n_hosts, "ips": n_ips, "providers": len(providers),
                  "dead": n_dead, "risk": n_risk},
    }
    if not meta["subtitle"]:
        meta.pop("subtitle")
    scan.meta = meta

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = args.name or in_path.stem
    out_base = out_dir / base

    produced: list[str] = []

    # --- default: the card-grid attack-surface map -------------------------
    if not args.no_cards:
        result = render_cards_image(scan, meta, out_base, scale=2)
        for key in ("html", "png"):
            if key in result:
                produced.append(result[key])
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)

    # --- optional: the node-graph view -------------------------------------
    if args.graph:
        from .graph import build_graph
        from .render_html import render_html
        from .render_graphviz import render_images
        g = build_graph(scan)
        graph_base = out_dir / f"{base}-graph"
        if not args.no_html:
            gp = graph_base.with_suffix(".html")
            gp.write_text(render_html(g, meta), encoding="utf-8")
            produced.append(str(gp))
        if not args.no_image:
            gres = render_images(g, meta, graph_base, dpi=args.dpi)
            for key in ("png", "svg", "dot"):
                if key in gres:
                    produced.append(gres[key])
            if "error" in gres:
                print(f"[!] {gres['error']}", file=sys.stderr)

    if args.json:
        json_path = out_base.with_suffix(".json")
        json_path.write_text(json.dumps(scan.to_dict(), indent=2), encoding="utf-8")
        produced.append(str(json_path))

    insecure = sum(1 for h in scan.hosts if h.tls_ok is False)
    errs = sum(1 for h in scan.hosts if h.category == "error")
    print("\n=== Subverse summary ===")
    print(f"  subdomains : {n_hosts}  (active {sum(1 for h in scan.hosts if h.category=='active')}, "
          f"insecure-TLS {insecure}, error/unreachable {errs})")
    print(f"  unique IPs : {n_ips}")
    print(f"  providers  : {len(providers)}" +
          (f"  [{', '.join(providers)}]" if providers else ""))
    print(f"  flagged    : {n_risk} host(s) on risky IPs (old service / private IP)")
    print("  outputs    :")
    for pth in produced:
        print(f"    - {pth}")

    if args.open:
        for pth in produced:
            if pth.endswith((".html", ".png")):
                open_path(pth)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
