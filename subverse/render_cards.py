"""Card-grid attack-surface map renderer.

Produces the report-style layout: a header + status legend + DNS/email posture
badges, then one card per shared hosting IP. Each card shows the IP, an owner
line, a role tag, the subdomains that resolve there (with a status dot + a
record/HTTP annotation), and an analyst footnote. Renders to a self-contained
HTML file and rasterizes to PNG via headless Chromium.
"""

from __future__ import annotations

import html
from pathlib import Path

from .model import ScanResult, HostResult, IPResult
from . import style
from .platform_utils import find_browser, screenshot_html

CAT_COLOR = {
    "active": style.GREEN,
    "insecure": style.AMBER,
    "error": style.RED,
    "third-party": style.BLUE,
    "misconfig": style.MUTED,
}
CAT_LABEL = {
    "active": "active / reachable",
    "insecure": "insecure TLS",
    "error": "error / unreachable",
    "third-party": "third-party",
    "misconfig": "misconfig / leak",
}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _short(host: str, zone: str) -> str:
    if host == zone:
        return host
    if host.endswith("." + zone):
        return host[: -(len(zone) + 1)]
    return host


# --------------------------------------------------------------------------- #
#  Build an intermediate list of "cards" from the scan
# --------------------------------------------------------------------------- #
class Card:
    def __init__(self):
        self.ips: list[str] = []
        self.label: str | None = None      # overrides IP header (e.g. "Microsoft 365")
        self.role: str = ""
        self.owner: str = ""
        self.category: str = "active"
        self.rows: list[dict] = []
        self.footnote: str = ""
        self.feature: bool = False
        self.count: int = 0


def _owner_line(ipr: IPResult) -> str:
    if not ipr.provider and not ipr.asn:
        if any("Private/reserved" in n for n in ipr.notes):
            return "RFC1918 private · no ASN · non-routable"
        return ipr.ptr or "unknown network"
    bits = [ipr.provider or "unknown"]
    if ipr.asn:
        cc = f" ({ipr.country})" if ipr.country else ""
        bits.append(f"AS{ipr.asn}{cc}")
    bits.append(ipr.ptr or "no PTR")
    return " · ".join(bits)


def _card_category(role: str, row_cats: list[str]) -> str:
    if role == "Info leak":
        return "misconfig"
    if role in ("Third-party", "Mail (MX)"):
        return "third-party"
    if "error" in row_cats:
        return "error"
    if "insecure" in row_cats:
        return "insecure"
    if "active" in row_cats:
        return "active"
    return "misconfig"


def _sort_rows(rows: list[dict], zone: str) -> list[dict]:
    def key(r):
        name = r["name"]
        return (0 if name == zone else 1, name)
    return sorted(rows, key=key)


def build_cards(scan: ScanResult) -> list[Card]:
    # group hosts by the set of IPv4s they resolve to (fallback to IPv6)
    groups: dict[tuple, list[HostResult]] = {}
    for hr in scan.hosts:
        key = tuple(sorted(hr.a)) or tuple(sorted(hr.aaaa)) or ("(unresolved)",)
        groups.setdefault(key, []).append(hr)

    cards: list[Card] = []
    busiest = max((len(v) for v in groups.values()), default=0)

    for key, members in groups.items():
        ips = [k for k in key if k != "(unresolved)"]
        rep = scan.ips.get(ips[0]) if ips else None
        zone = members[0].zone
        card = Card()
        card.ips = ips
        card.count = len(members)
        if rep:
            card.role = rep.role
            card.owner = _owner_line(rep)
            card.footnote = rep.footnote
        rows = [{"name": m.host, "short": _short(m.host, m.zone),
                 "category": m.category, "annotation": m.annotation}
                for m in members]
        card.rows = _sort_rows(rows, zone)
        card.category = _card_category(card.role, [r["category"] for r in rows])
        card.feature = (len(members) == busiest and len(members) >= 5)

        # IPv6 footnote for the apex card
        apex = next((m for m in members if m.host == m.zone), None)
        if apex and apex.aaaa and "IPv6" not in card.footnote:
            extra = f"Apex also has IPv6 {apex.aaaa[0]}."
            card.footnote = (card.footnote + " " + extra).strip() if card.footnote else extra
        cards.append(card)

    # synthetic Mail (MX) card from the apex MX records
    mx_card = _mx_card(scan)
    if mx_card:
        cards.append(mx_card)

    # order: feature first, then by member count desc, then third-party/mail last
    def order_key(c: Card):
        return (0 if c.feature else 1,
                0 if c.role not in ("Third-party", "Mail (MX)") else 1,
                -c.count)
    cards.sort(key=order_key)
    return cards


def _mx_card(scan: ScanResult) -> Card | None:
    apex = next((h for h in scan.hosts if h.host == h.zone and h.mx), None)
    if not apex:
        return None
    card = Card()
    card.role = "Mail (MX)"
    card.category = "third-party"
    low = " ".join(apex.mx).lower()
    if "outlook" in low or "protection.outlook" in low:
        card.label = "Microsoft 365"
        card.owner = "Microsoft · Exchange Online · " + apex.mx[0]
    elif "google" in low or "googlemail" in low or "aspmx" in low:
        card.label = "Google Workspace"
        card.owner = "Google · " + apex.mx[0]
    else:
        card.label = "Mail exchange"
        card.owner = apex.mx[0]
    card.rows = [{"name": mx, "short": mx, "category": "third-party",
                  "annotation": "MX"} for mx in apex.mx]
    post = scan.posture.get(apex.zone)
    if post and post.spf:
        card.footnote = "All inbound mail. SPF authorizes the senders listed above."
    return card


# --------------------------------------------------------------------------- #
#  Posture badges
# --------------------------------------------------------------------------- #
def _badges(scan: ScanResult) -> list[dict]:
    # use the zone with the most hosts (the primary target)
    counts: dict[str, int] = {}
    for h in scan.hosts:
        counts[h.zone] = counts.get(h.zone, 0) + 1
    if not counts:
        return []
    zone = max(counts, key=counts.get)
    p = scan.posture.get(zone)
    out: list[dict] = []
    if not p:
        return out

    # SPF
    if p.spf_ok:
        mode = "-all hardfail" if "-all" in p.spf else "~all softfail"
        out.append({"icon": "✓", "state": "ok", "text": f"SPF {mode}"})
    elif p.spf:
        out.append({"icon": "⚠", "state": "warn", "text": "SPF present (no -all)"})
    else:
        out.append({"icon": "✗", "state": "bad", "text": "SPF missing"})

    # DKIM
    if p.dkim:
        if {"selector1", "selector2"} <= set(p.dkim):
            txt = "DKIM via M365"
        elif "google" in p.dkim:
            txt = "DKIM via Google"
        else:
            txt = "DKIM (" + ", ".join(p.dkim) + ")"
        out.append({"icon": "✓", "state": "ok", "text": txt})
    else:
        out.append({"icon": "⚠", "state": "warn", "text": "DKIM none found"})

    # CAA
    if p.caa:
        n = len(p.caa)
        out.append({"icon": "✓", "state": "ok",
                    "text": f"CAA — {n} CA{'s' if n != 1 else ''} only"})
    else:
        out.append({"icon": "⚠", "state": "warn", "text": "CAA none (any CA can issue)"})

    # DMARC
    if p.dmarc_policy in ("reject", "quarantine"):
        out.append({"icon": "✓", "state": "ok", "text": f"DMARC p={p.dmarc_policy}"})
    elif p.dmarc_policy == "none":
        out.append({"icon": "⚠", "state": "warn", "text": "DMARC p=none (monitor only)"})
    elif p.dmarc:
        out.append({"icon": "⚠", "state": "warn", "text": "DMARC present"})
    else:
        out.append({"icon": "✗", "state": "bad", "text": "DMARC missing"})

    # Wildcard
    if p.wildcard:
        out.append({"icon": "⚠", "state": "warn",
                    "text": f"Wildcard *.{zone} → {p.wildcard}"})
    else:
        out.append({"icon": "✓", "state": "ok", "text": "No wildcard"})
    return out


# --------------------------------------------------------------------------- #
#  HTML rendering
# --------------------------------------------------------------------------- #
def _row_html(r: dict) -> str:
    color = CAT_COLOR.get(r["category"], style.MUTED)
    ann = f'<span class="ann">{_esc(r["annotation"])}</span>' if r["annotation"] else ""
    return (f'<div class="row"><span class="nm">'
            f'<i class="dot" style="background:{color}"></i>{_esc(r["short"])}</span>'
            f'{ann}</div>')


def _card_html(card: Card) -> str:
    border = CAT_COLOR.get(card.category, style.MUTED)
    role_color = CAT_COLOR.get(card.category, style.MUTED)
    header = _esc(card.label) if card.label else _esc(" / ".join(card.ips))
    role = (f'<span class="role" style="color:{role_color};border-color:{role_color}">'
            f'{_esc(card.role)}</span>') if card.role else ""
    rows_cls = "rows grid3" if card.feature else "rows"
    rows = "".join(_row_html(r) for r in card.rows)
    foot = (f'<div class="foot">{_esc(card.footnote)}</div>' if card.footnote else "")
    cls = "card feature" if card.feature else "card"
    return (f'<div class="{cls}" style="border-top-color:{border}">'
            f'<div class="chead"><span class="ip">{header}</span>{role}</div>'
            f'<div class="owner">{_esc(card.owner)}</div>'
            f'<div class="{rows_cls}">{rows}</div>{foot}</div>')


def render_cards_html(scan: ScanResult, meta: dict) -> str:
    cards = build_cards(scan)
    badges = _badges(scan)

    title = _esc(meta.get("title", "external attack surface map"))
    org = _esc(meta.get("org", ""))
    ref = _esc(meta.get("ref", ""))
    ts = _esc(meta.get("timestamp", ""))
    subtitle = _esc(meta.get("subtitle",
                    "Grouped by shared hosting IP & ASN · DNS verified live · "
                    "HTTP status from live scan"))

    # legend
    legend = "".join(
        f'<span class="leg"><i class="dot" style="background:{CAT_COLOR[c]}"></i>'
        f'{_esc(CAT_LABEL[c])}</span>'
        for c in ("active", "insecure", "error", "third-party", "misconfig"))

    # posture badges
    badge_html = "".join(
        f'<span class="badge {b["state"]}">{b["icon"]} {_esc(b["text"])}</span>'
        for b in badges)

    # split feature vs masonry
    feature_cards = [c for c in cards if c.feature]
    rest = [c for c in cards if not c.feature]
    feature_html = "".join(_card_html(c) for c in feature_cards)
    rest_html = "".join(_card_html(c) for c in rest)

    return _PAGE.replace("{{TITLE}}", title) \
        .replace("{{ORG}}", org).replace("{{REF}}", ref).replace("{{TS}}", ts) \
        .replace("{{SUBTITLE}}", subtitle).replace("{{LEGEND}}", legend) \
        .replace("{{BADGES}}", badge_html) \
        .replace("{{FEATURE}}", feature_html).replace("{{REST}}", rest_html) \
        .replace("{{BG}}", style.BG).replace("{{PANEL}}", style.PANEL) \
        .replace("{{GRID}}", style.GRID).replace("{{TEXT}}", style.TEXT) \
        .replace("{{DIM}}", style.TEXT_DIM).replace("{{ACCENT}}", style.ACCENT) \
        .replace("{{GREEN}}", style.GREEN).replace("{{AMBER}}", style.AMBER) \
        .replace("{{RED}}", style.RED).replace("{{BLUE}}", style.BLUE) \
        .replace("{{MUTED}}", style.MUTED)


def _estimate_height(cards: list[Card], badges: int) -> int:
    """Estimate the rendered page height (logical px) so the screenshot captures
    the whole page. Generous on purpose — overflow just blends into the dark bg."""
    # Constants are calibrated (logical px) against rendered output; a full
    # tallest-card buffer + small margin guarantee we never clip a card.
    import math
    h = 230                                   # title + subtitle + meta + legend
    h += 60 if badges else 0                  # posture badge row
    col_total = 0                             # masonry column content
    tallest = 0                               # buffer against column imbalance
    for c in cards:
        rows = len(c.rows)
        if c.feature:
            ch = 90 + math.ceil(rows / 3) * 22 + (40 if c.footnote else 0)
            h += ch + 16
        else:
            ch = 78 + rows * 22 + (40 if c.footnote else 0) + 14
            col_total += ch
            tallest = max(tallest, ch)
    h += (col_total + 1) // 2 + tallest       # two masonry cols + imbalance buffer
    h += 70                                    # footer
    return int(h * 1.04) + 40


def render_cards_image(scan: ScanResult, meta: dict, out_base: Path,
                       width: int = 1240, scale: int = 2) -> dict:
    out_base = Path(out_base)
    out_base.parent.mkdir(parents=True, exist_ok=True)
    html_path = out_base.with_suffix(".html")
    html_path.write_text(render_cards_html(scan, meta), encoding="utf-8")
    produced = {"html": str(html_path)}

    browser = find_browser()
    if not browser:
        produced["error"] = ("no Chrome/Chromium found to rasterize the PNG — "
                             "open the HTML and export, or install a browser.")
        return produced

    cards = build_cards(scan)
    height = _estimate_height(cards, len(_badges(scan)))
    png_path = out_base.with_suffix(".png")
    if screenshot_html(browser, str(html_path), str(png_path),
                       width=width, height=height, scale=scale):
        produced["png"] = str(png_path)
    else:
        produced["error"] = "headless screenshot failed; HTML is still available."
    return produced


# --------------------------------------------------------------------------- #
#  Page template (CSS has no format placeholders; tokens are {{NAME}})
# --------------------------------------------------------------------------- #
_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>{{TITLE}}</title>
<style>
  :root{
    --bg:{{BG}};--panel:{{PANEL}};--grid:{{GRID}};--text:{{TEXT}};--dim:{{DIM}};
    --accent:{{ACCENT}};--green:{{GREEN}};--amber:{{AMBER}};--red:{{RED}};
    --blue:{{BLUE}};--muted:{{MUTED}};
  }
  *{box-sizing:border-box;}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    -webkit-font-smoothing:antialiased;}
  .wrap{max-width:1180px;margin:0 auto;padding:34px 28px 44px;}
  mono,.ip,.nm,.ann,.badge{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
  h1{font-size:26px;margin:0 0 4px;font-weight:800;letter-spacing:-.3px;}
  h1 .brand{color:var(--accent);}
  .sub{color:var(--dim);font-size:13px;margin-bottom:16px;}
  .meta{color:var(--dim);font-size:11px;margin-bottom:18px;
    font-family:ui-monospace,Menlo,monospace;}
  .legend{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:14px;font-size:12px;color:var(--dim);}
  .leg{display:inline-flex;align-items:center;gap:7px;}
  .dot{display:inline-block;width:9px;height:9px;border-radius:50%;flex:0 0 auto;}
  .badges{display:flex;flex-wrap:wrap;gap:9px;margin:6px 0 26px;
    padding-bottom:22px;border-bottom:1px solid var(--grid);}
  .badge{font-size:11.5px;padding:4px 11px;border-radius:20px;border:1px solid var(--muted);
    color:var(--dim);background:rgba(255,255,255,.015);white-space:nowrap;}
  .badge.ok{color:var(--green);border-color:rgba(34,197,94,.5);}
  .badge.warn{color:var(--amber);border-color:rgba(245,158,11,.5);}
  .badge.bad{color:var(--red);border-color:rgba(239,68,68,.5);}
  .card{background:var(--panel);border:1px solid var(--grid);border-top:3px solid var(--muted);
    border-radius:9px;padding:15px 17px;margin:0 0 16px;break-inside:avoid;}
  .feature{margin-bottom:20px;}
  .chead{display:flex;align-items:baseline;justify-content:space-between;gap:12px;}
  .ip{font-size:15px;font-weight:700;color:var(--text);letter-spacing:.2px;}
  .role{font-size:11px;padding:2px 9px;border-radius:20px;border:1px solid currentColor;
    white-space:nowrap;font-family:-apple-system,sans-serif;}
  .owner{color:var(--dim);font-size:11.5px;margin:3px 0 11px;
    font-family:ui-monospace,Menlo,monospace;}
  .rows{display:flex;flex-direction:column;gap:5px;}
  .rows.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:5px 26px;}
  .row{display:flex;align-items:center;justify-content:space-between;gap:10px;
    font-size:13px;line-height:1.45;}
  .nm{display:inline-flex;align-items:center;gap:8px;color:var(--text);overflow:hidden;
    text-overflow:ellipsis;white-space:nowrap;}
  .ann{color:var(--dim);font-size:11px;white-space:nowrap;text-align:right;}
  .foot{margin-top:11px;padding-top:9px;border-top:1px solid var(--grid);
    color:var(--dim);font-size:11.5px;font-style:italic;line-height:1.5;}
  .masonry{columns:2;column-gap:16px;}
  @media(max-width:760px){.masonry{columns:1;}.rows.grid3{grid-template-columns:1fr;}}
  .footer{margin-top:26px;color:var(--dim);font-size:10.5px;line-height:1.5;
    border-top:1px solid var(--grid);padding-top:14px;}
</style></head>
<body><div class="wrap">
  <h1>{{TITLE}}</h1>
  <div class="sub">{{SUBTITLE}}</div>
  <div class="meta">{{ORG}} &nbsp; {{REF}} &nbsp; {{TS}}</div>
  <div class="legend">{{LEGEND}}</div>
  <div class="badges">{{BADGES}}</div>
  {{FEATURE}}
  <div class="masonry">{{REST}}</div>
  <div class="footer">Generated by Subverse — live DNS + HTTP/TLS + nmap probe.
    For authorized security assessment only.</div>
</div></body></html>
"""
