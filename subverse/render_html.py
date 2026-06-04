"""Interactive HTML renderer (vis-network).

Produces a single self-contained .html file: drag/zoom/hover the graph, filter
node types, and toggle 'risk only' to isolate forgotten/vulnerable hosts. The
vis-network library loads from a CDN, so viewing needs internet (the data itself
is embedded inline).
"""

from __future__ import annotations

import html
import json
import re

from .graph import Graph
from . import style

_CDN = "https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"

# vis-network shape + sizing per node kind
_SHAPE = {
    "zone": ("box", 22),
    "host": ("dot", 13),
    "ip": ("box", 16),
    "provider": ("diamond", 20),
    "ns": ("triangle", 14),
    "cname": ("star", 16),
}


def _plain(tooltip: list[str]) -> str:
    txt = "\n".join(tooltip)
    return re.sub(r"</?b>", "", txt)


def _vis_nodes(g: Graph) -> list[dict]:
    out = []
    for n in g.nodes:
        shape, size = _SHAPE.get(n.kind, ("dot", 12))
        border = n.color
        bg = style.darken(n.color, 0.5)
        if n.risk:
            border = style.RED
        if n.dead:
            border = style.MUTED
            bg = style.PANEL
        label = n.label
        if n.risk:
            label = "⚠ " + label
        elif n.dead:
            label = "○ " + label
        node = {
            "id": n.id,
            "label": label,
            "title": _plain(n.tooltip),
            "shape": shape,
            "size": size,
            "group": n.kind,
            "color": {
                "background": bg,
                "border": border,
                "highlight": {"background": n.color, "border": "#ffffff"},
                "hover": {"background": n.color, "border": "#ffffff"},
            },
            "borderWidth": 3 if (n.risk or n.kind in ("zone", "provider")) else 1,
            "borderWidthSelected": 4,
            "font": {
                "color": style.MUTED if n.dead else style.TEXT,
                "size": 18 if n.kind == "zone" else 13,
                "face": "ui-monospace, Menlo, monospace",
                "strokeWidth": 4,
                "strokeColor": style.BG,
            },
            "shapeProperties": {"borderDashes": [5, 4] if n.dead else False},
            "_kind": n.kind,
            "_risk": n.risk,
            "_dead": n.dead,
        }
        if n.kind in ("zone", "ip") and n.sublabel:
            node["label"] = f"{label}\n{n.sublabel}"
        out.append(node)
    return out


def _vis_edges(g: Graph) -> list[dict]:
    color_for = {
        "subdomain": style.GRID,
        "resolves": "#3a3a46",
        "hosted": style.MUTED,
        "cname": style.AMBER,
        "ns": style.TEAL,
    }
    out = []
    for i, e in enumerate(g.edges):
        out.append({
            "id": f"e{i}",
            "from": e.src,
            "to": e.dst,
            "label": e.label,
            "color": {"color": color_for.get(e.kind, style.GRID),
                      "highlight": "#ffffff", "opacity": 0.7},
            "dashes": e.kind in ("cname", "ns"),
            "width": 1.4,
            "arrows": {"to": {"enabled": e.kind in ("resolves", "hosted", "cname"),
                              "scaleFactor": 0.5}},
            "font": {"color": style.TEXT_DIM, "size": 10, "strokeWidth": 3,
                     "strokeColor": style.BG, "align": "middle"},
            "smooth": {"type": "continuous"},
        })
    return out


def render_html(g: Graph, meta: dict) -> str:
    nodes_json = json.dumps(_vis_nodes(g))
    edges_json = json.dumps(_vis_edges(g))

    # counts for the header
    n_hosts = sum(1 for n in g.nodes if n.kind == "host")
    n_dead = sum(1 for n in g.nodes if n.kind == "host" and n.dead)
    n_risk = sum(1 for n in g.nodes if n.kind == "host" and n.risk)
    n_ips = sum(1 for n in g.nodes if n.kind == "ip")
    n_prov = len(g.providers)

    title = html.escape(meta.get("title", "Subverse — Attack Surface Map"))
    org = html.escape(meta.get("org", ""))
    ref = html.escape(meta.get("ref", ""))
    ts = html.escape(meta.get("timestamp", ""))

    # provider legend swatches
    legend_items = []
    for p in g.providers:
        c = style.provider_color(p, g.providers)
        legend_items.append(
            f'<span class="sw" style="background:{c}"></span>{html.escape(p)}')
    provider_legend = "".join(f"<div class='leg'>{x}</div>" for x in legend_items)

    return _TEMPLATE.format(
        title=title, org=org, ref=ref, ts=ts,
        n_hosts=n_hosts, n_dead=n_dead, n_risk=n_risk, n_ips=n_ips, n_prov=n_prov,
        nodes_json=nodes_json, edges_json=edges_json,
        provider_legend=provider_legend, cdn=_CDN,
        BG=style.BG, PANEL=style.PANEL, ACCENT=style.ACCENT, TEAL=style.TEAL,
        RED=style.RED, AMBER=style.AMBER, MUTED=style.MUTED, TEXT=style.TEXT,
        TEXT_DIM=style.TEXT_DIM, GRID=style.GRID,
    )


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<script src="{cdn}"></script>
<style>
  :root {{
    --bg:{BG}; --panel:{PANEL}; --accent:{ACCENT}; --teal:{TEAL};
    --red:{RED}; --amber:{AMBER}; --muted:{MUTED}; --text:{TEXT};
    --dim:{TEXT_DIM}; --grid:{GRID};
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin:0; height:100%; background:var(--bg); color:var(--text);
    font-family: ui-monospace, Menlo, Consolas, monospace; }}
  #bar {{ display:flex; align-items:center; gap:18px; padding:12px 18px;
    background:linear-gradient(180deg,#16161c,#0e0e12);
    border-top:3px solid var(--accent); border-bottom:1px solid var(--grid); }}
  #bar .brand {{ font-weight:700; letter-spacing:3px; color:var(--text);
    font-size:18px; }}
  #bar .brand span {{ color:var(--accent); }}
  #bar .title {{ font-size:14px; color:var(--text); }}
  #bar .meta {{ font-size:11px; color:var(--dim); }}
  #bar .spacer {{ flex:1; }}
  #stats {{ display:flex; gap:14px; }}
  #stats .stat {{ text-align:center; }}
  #stats .num {{ font-size:18px; font-weight:700; }}
  #stats .lbl {{ font-size:10px; color:var(--dim); text-transform:uppercase;
    letter-spacing:1px; }}
  .num.risk {{ color:var(--red); }} .num.dead {{ color:var(--muted); }}
  .num.ip {{ color:var(--teal); }} .num.host {{ color:var(--text); }}
  #wrap {{ display:flex; height:calc(100% - 58px); }}
  #net {{ flex:1; height:100%; }}
  #side {{ width:260px; background:var(--panel); border-left:1px solid var(--grid);
    padding:14px; overflow:auto; font-size:12px; }}
  #side h3 {{ font-size:11px; text-transform:uppercase; letter-spacing:1.5px;
    color:var(--dim); margin:18px 0 8px; }}
  #side h3:first-child {{ margin-top:0; }}
  .row {{ display:flex; align-items:center; gap:8px; margin:5px 0; cursor:pointer; }}
  .sw {{ display:inline-block; width:12px; height:12px; border-radius:3px;
    flex:0 0 auto; }}
  .leg {{ display:flex; align-items:center; gap:8px; margin:4px 0;
    font-size:11px; color:var(--dim); }}
  input[type=checkbox] {{ accent-color: var(--accent); }}
  #search {{ width:100%; padding:6px 8px; background:#0c0c10; border:1px solid var(--grid);
    color:var(--text); border-radius:6px; font-family:inherit; font-size:12px; }}
  .pill {{ display:inline-block; padding:2px 7px; border-radius:10px; font-size:10px;
    border:1px solid currentColor; }}
  .foot {{ font-size:10px; color:var(--dim); margin-top:18px; line-height:1.5; }}
  .shape-note {{ color:var(--dim); font-size:10px; }}
  .inspect {{ font-size:11px; color:var(--dim); line-height:1.5; word-break:break-word; }}
  .ins-title {{ color:var(--text); font-weight:700; margin-bottom:6px; word-break:break-all; }}
  .ins-body {{ white-space:pre-wrap; margin:0 0 8px; color:var(--text);
    font-family:inherit; font-size:11px; }}
  .ins-conn {{ white-space:pre-wrap; color:var(--dim);
    border-top:1px solid var(--grid); padding-top:6px; }}
  .ins-conn b {{ color:var(--teal); }}
</style>
</head>
<body>
  <div id="bar">
    <div class="brand">SUB<span>VERSE</span></div>
    <div>
      <div class="title">{title}</div>
      <div class="meta">{org} &nbsp; {ref} &nbsp; {ts}</div>
    </div>
    <div class="spacer"></div>
    <div id="stats">
      <div class="stat"><div class="num host">{n_hosts}</div><div class="lbl">Subdomains</div></div>
      <div class="stat"><div class="num ip">{n_ips}</div><div class="lbl">Unique IPs</div></div>
      <div class="stat"><div class="num">{n_prov}</div><div class="lbl">Providers</div></div>
      <div class="stat"><div class="num dead">{n_dead}</div><div class="lbl">Dead</div></div>
      <div class="stat"><div class="num risk">{n_risk}</div><div class="lbl">Risk</div></div>
    </div>
  </div>
  <div id="wrap">
    <div id="net"></div>
    <div id="side">
      <h3>Search</h3>
      <input id="search" placeholder="filter by name..." />
      <h3>Inspector</h3>
      <div id="inspect" class="inspect">Click any node for its DNS records, ports, banners &amp; connections.</div>
      <h3>Show node types</h3>
      <label class="row"><input type="checkbox" data-kind="zone" checked> Root domains</label>
      <label class="row"><input type="checkbox" data-kind="host" checked> Subdomains</label>
      <label class="row"><input type="checkbox" data-kind="ip" checked> IP addresses</label>
      <label class="row"><input type="checkbox" data-kind="provider" checked> Providers</label>
      <label class="row"><input type="checkbox" data-kind="ns" checked> Nameservers</label>
      <label class="row"><input type="checkbox" data-kind="cname" checked> External CNAMEs</label>
      <h3>Highlight</h3>
      <label class="row"><input type="checkbox" id="riskonly"> Risk / dead only</label>
      <h3>Node legend</h3>
      <div class="leg"><span class="sw" style="background:{ACCENT}"></span>Root domain (box)</div>
      <div class="leg"><span class="sw" style="background:{TEAL}"></span>Nameserver (△)</div>
      <div class="leg"><span class="sw" style="background:{AMBER}"></span>External CNAME (★)</div>
      <div class="leg"><span class="sw" style="border:2px solid {RED};background:transparent"></span>⚠ old / risky service</div>
      <div class="leg"><span class="sw" style="border:2px dashed {MUTED};background:transparent"></span>○ does not resolve (forgotten?)</div>
      <h3>Hosting providers</h3>
      {provider_legend}
      <div class="foot">
        Hover any node for DNS records, ports &amp; banners.<br/>
        Generated by Subverse.<br/>
        For authorized security assessment only.
      </div>
    </div>
  </div>
<script>
  const RAW_NODES = {nodes_json};
  const RAW_EDGES = {edges_json};
  const nodes = new vis.DataSet(RAW_NODES);
  const edges = new vis.DataSet(RAW_EDGES);
  const container = document.getElementById('net');
  const data = {{ nodes, edges }};
  const options = {{
    layout: {{ improvedLayout: true }},
    interaction: {{ hover:true, tooltipDelay:80, navigationButtons:true, keyboard:true }},
    physics: {{
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {{ gravitationalConstant:-55, springLength:110,
        springConstant:0.05, avoidOverlap:0.6 }},
      stabilization: {{ iterations: 220 }},
    }},
    nodes: {{ shadow:false }},
    edges: {{ shadow:false }},
  }};
  const network = new vis.Network(container, data, options);

  // tooltip styling (vis injects a div.vis-tooltip)
  const st = document.createElement('style');
  st.textContent = '.vis-tooltip{{background:#0c0c10!important;color:#e8e8ec!important;'+
    'border:1px solid #2dd4bf!important;border-radius:6px!important;padding:8px 10px!important;'+
    'font-family:ui-monospace,Menlo,monospace!important;font-size:11px!important;'+
    'white-space:pre!important;box-shadow:0 4px 18px rgba(0,0,0,.6)!important;}}';
  document.head.appendChild(st);

  // --- filtering ---
  const kindEnabled = {{zone:true,host:true,ip:true,provider:true,ns:true,cname:true}};
  let riskOnly = false;
  let term = '';
  function apply() {{
    RAW_NODES.forEach(n => {{
      let vis_ = kindEnabled[n._kind] !== false;
      if (riskOnly && !(n._risk || n._dead)) vis_ = false;
      if (term && !String(n.label).toLowerCase().includes(term)) vis_ = false;
      nodes.update({{id:n.id, hidden: !vis_}});
    }});
  }}
  document.querySelectorAll('input[data-kind]').forEach(cb => {{
    cb.addEventListener('change', () => {{ kindEnabled[cb.dataset.kind]=cb.checked; apply(); }});
  }});
  document.getElementById('riskonly').addEventListener('change', e => {{ riskOnly=e.target.checked; apply(); }});
  document.getElementById('search').addEventListener('input', e => {{ term=e.target.value.toLowerCase(); apply(); }});
  network.once('stabilizationIterationsDone', () => network.setOptions({{physics:false}}));

  // --- click-to-inspect: pin a node's full detail + what it connects to ---
  const NODE_BY_ID = {{}};
  RAW_NODES.forEach(n => {{ NODE_BY_ID[n.id] = n; }});
  const inspectEl = document.getElementById('inspect');
  const INSPECT_HINT = 'Click any node for its DNS records, ports, banners & connections.';
  function esc(s) {{ return String(s).replace(/[&<>]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c])); }}
  function showInspect(id) {{
    const n = NODE_BY_ID[id];
    if (!n) {{ return; }}
    const conn = network.getConnectedNodes(id)
      .map(cid => (NODE_BY_ID[cid] || {{}}).label || cid)
      .map(l => String(l).replace(/\\n/g, '  '));
    let h = '<div class="ins-title">' + esc(String(n.label).replace(/\\n/g, '  ')) + '</div>';
    if (n.title) {{ h += '<pre class="ins-body">' + esc(n.title) + '</pre>'; }}
    if (conn.length) {{ h += '<div class="ins-conn"><b>Connected (' + conn.length + ')</b>\\n' + esc(conn.join('\\n')) + '</div>'; }}
    inspectEl.innerHTML = h;
  }}
  network.on('selectNode', p => showInspect(p.nodes[0]));
  network.on('deselectNode', () => {{ inspectEl.textContent = INSPECT_HINT; }});
</script>
</body>
</html>
"""
