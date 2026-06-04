"""Static image renderer via Graphviz.

Emits a DOT file and shells out to `dot` to produce PNG + SVG. Layout is a
left-to-right hierarchy: zone -> subdomains -> shared IPs (clustered by hosting
provider). Dead/unresolved hosts get their own boxed cluster so the
forgotten-subdomain story reads at a glance. Styled to drop straight into a
written report as evidence.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .graph import Graph, Node
from . import style


def dot_available() -> str | None:
    return shutil.which("dot")


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


class _IdMap:
    def __init__(self):
        self._m: dict[str, str] = {}

    def get(self, key: str) -> str:
        if key not in self._m:
            self._m[key] = f"n{len(self._m)}"
        return self._m[key]


def _node_attrs(n: Node) -> str:
    border = n.color
    fill = style.darken(n.color, 0.5)
    fontcolor = style.TEXT
    penwidth = 1.2
    dash = ""
    shape = {
        "zone": "box", "host": "box", "ip": "box",
        "provider": "box", "ns": "box", "cname": "note",
    }.get(n.kind, "box")
    style_attr = "filled,rounded"

    label = _esc(n.label)
    if n.sublabel:
        label = f"{label}\\n{_esc(n.sublabel)}"

    if n.kind == "zone":
        penwidth = 3.0
        label = f"{_esc(n.label)}"
    if n.risk:
        border = style.RED
        penwidth = 3.0
        label = "⚠ " + label
    if n.dead:
        border = style.MUTED
        fill = style.PANEL
        fontcolor = style.MUTED
        dash = "dashed,"
        label = "○ " + label

    return (f'[label="{label}", shape={shape}, style="{dash}{style_attr}", '
            f'fillcolor="{fill}", color="{border}", fontcolor="{fontcolor}", '
            f'penwidth={penwidth}]')


def build_dot(g: Graph, meta: dict) -> str:
    ids = _IdMap()
    lines: list[str] = []
    lines.append("digraph Subverse {")
    lines.append(f'  bgcolor="{style.BG}";')
    lines.append("  rankdir=LR;")
    lines.append("  splines=true; overlap=false; concentrate=true;")
    lines.append("  nodesep=0.22; ranksep=1.5;")
    lines.append('  pad=0.4;')
    lines.append(f'  node [fontname="Menlo,monospace", fontsize=11, margin="0.10,0.045"];')
    lines.append(f'  edge [color="{style.GRID}", arrowsize=0.6, penwidth=1.0];')

    # --- header / title ------------------------------------------------------
    title = _esc(meta.get("title", "Attack Surface Map"))
    org = _esc(meta.get("org", ""))
    ref = _esc(meta.get("ref", ""))
    ts = _esc(meta.get("timestamp", ""))
    stats = meta.get("stats", {})
    statline = (f"{stats.get('hosts',0)} subdomains&#160;&#183;&#160;"
                f"{stats.get('ips',0)} unique IPs&#160;&#183;&#160;"
                f"{stats.get('providers',0)} providers&#160;&#183;&#160;"
                f"<font color='{style.MUTED}'>{stats.get('dead',0)} dead</font>"
                f"&#160;&#183;&#160;"
                f"<font color='{style.RED}'>{stats.get('risk',0)} risk</font>")
    header = (
        '  labelloc="t"; labeljust="l";\n'
        '  label=<<table border="0" cellborder="0" cellspacing="0" cellpadding="2">'
        f'<tr><td align="left"><font color="{style.TEXT}" point-size="11">SUB</font>'
        f'<font color="{style.ACCENT}" point-size="11">VERSE</font>'
        f'<font color="{style.TEXT_DIM}" point-size="9">  ATTACK SURFACE MAP</font></td></tr>'
        f'<tr><td align="left"><font color="{style.TEXT}" point-size="20"><b>{title}</b></font></td></tr>'
        f'<tr><td align="left"><font color="{style.TEXT_DIM}" point-size="10">{org}'
        f'&#160;&#160;|&#160;&#160;{ref}&#160;&#160;|&#160;&#160;{ts}</font></td></tr>'
        f'<tr><td align="left"><font point-size="11">{statline}</font></td></tr>'
        '</table>>;'
    )
    lines.append(header)
    lines.append(f'  fontname="Menlo,monospace"; fontcolor="{style.TEXT}";')

    # index helpers
    nodes_by_kind: dict[str, list[Node]] = {}
    for n in g.nodes:
        nodes_by_kind.setdefault(n.kind, []).append(n)

    # zone + host + cname nodes (top level)
    for n in g.nodes:
        if n.kind in ("zone", "host", "cname"):
            lines.append(f'  {ids.get(n.id)} {_node_attrs(n)};')

    # --- provider clusters wrapping their IPs --------------------------------
    ips_by_provider: dict[str, list[Node]] = {}
    for n in nodes_by_kind.get("ip", []):
        ips_by_provider.setdefault(n.provider or "Unknown network", []).append(n)

    for ci, (prov, ip_nodes) in enumerate(sorted(ips_by_provider.items())):
        col = style.provider_color(prov, g.providers) if prov != "Unknown network" else style.MUTED
        lines.append(f'  subgraph cluster_prov_{ci} {{')
        lines.append(f'    label="{_esc(prov)}"; fontcolor="{col}"; fontsize=11;')
        lines.append(f'    color="{col}"; style="rounded"; penwidth=1.6;')
        lines.append(f'    bgcolor="{style.darken(col, 0.16)}";')
        for n in ip_nodes:
            lines.append(f'    {ids.get(n.id)} {_node_attrs(n)};')
        lines.append("  }")

    # --- dead-host cluster (the headline finding) ----------------------------
    dead_hosts = [n for n in nodes_by_kind.get("host", []) if n.dead]
    if dead_hosts:
        lines.append('  subgraph cluster_dead {')
        lines.append(f'    label="Does not resolve — forgotten / removable candidates";')
        lines.append(f'    fontcolor="{style.MUTED}"; color="{style.MUTED}"; '
                     f'style="dashed,rounded"; penwidth=1.4;')
        for n in dead_hosts:
            lines.append(f'    {ids.get(n.id)};')
        lines.append("  }")

    # --- nameserver cluster --------------------------------------------------
    ns_nodes = nodes_by_kind.get("ns", [])
    if ns_nodes:
        lines.append('  subgraph cluster_ns {')
        lines.append(f'    label="Nameservers"; fontcolor="{style.TEAL}"; '
                     f'color="{style.TEAL}"; style="rounded"; penwidth=1.3;')
        for n in ns_nodes:
            lines.append(f'    {ids.get(n.id)} {_node_attrs(n)};')
        lines.append("  }")

    # provider hub nodes (diamonds) outside clusters
    for n in nodes_by_kind.get("provider", []):
        lines.append(f'  {ids.get(n.id)} {_node_attrs(n)};')

    # --- edges ---------------------------------------------------------------
    edge_color = {
        "subdomain": style.GRID,
        "resolves": "#44444f",
        "hosted": style.MUTED,
        "cname": style.AMBER,
        "ns": style.TEAL,
    }
    for e in g.edges:
        col = edge_color.get(e.kind, style.GRID)
        attrs = [f'color="{col}"']
        if e.label:
            attrs.append(f'label="{_esc(e.label)}", fontcolor="{col}", fontsize=8')
        if e.kind in ("cname", "ns"):
            attrs.append("style=dashed")
        if e.kind == "hosted":
            attrs.append("arrowhead=none, penwidth=0.7")
        lines.append(f'  {ids.get(e.src)} -> {ids.get(e.dst)} [{", ".join(attrs)}];')

    lines.append("}")
    return "\n".join(lines)


def render_images(g: Graph, meta: dict, out_base: Path, dpi: int = 160) -> dict:
    """Write <base>.dot and render PNG + SVG. Returns paths produced."""
    out_base = Path(out_base)
    out_base.parent.mkdir(parents=True, exist_ok=True)
    dot_path = out_base.with_suffix(".dot")
    dot_src = build_dot(g, meta)
    dot_path.write_text(dot_src, encoding="utf-8")

    produced = {"dot": str(dot_path)}
    dot_bin = dot_available()
    if not dot_bin:
        produced["error"] = ("graphviz 'dot' not found — wrote .dot only. "
                             "Install with: brew install graphviz")
        return produced

    for fmt, flag in (("png", f"-Gdpi={dpi}"), ("svg", "")):
        target = out_base.with_suffix(f".{fmt}")
        cmd = [dot_bin, f"-T{fmt}"]
        if flag:
            cmd.append(flag)
        cmd += [str(dot_path), "-o", str(target)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            produced[fmt] = str(target)
        except subprocess.CalledProcessError as exc:
            produced[f"{fmt}_error"] = exc.stderr.strip() or str(exc)
    return produced
