"""Shared visual style.

A dark report palette — near-black canvas, orange accent, teal/red/green
status hues — so exported images read cleanly and drop straight into a
written report. Both renderers import from here.
"""

from __future__ import annotations

import colorsys

# --- dark report palette -----------------------------------------------------
BG = "#0e0e12"          # canvas
PANEL = "#17171d"       # node fill base / panels
GRID = "#23232c"        # subtle lines
ACCENT = "#f1592b"      # orange accent (root domains, titles, rules)
TEAL = "#2dd4bf"        # informational / nameservers
RED = "#ef4444"         # risk / old software / error
AMBER = "#f59e0b"       # warning / insecure TLS
GREEN = "#22c55e"       # healthy / active
BLUE = "#4f9cf9"        # third-party / external service
MUTED = "#6b7280"       # dead/forgotten hosts, secondary text
TEXT = "#e8e8ec"        # primary text
TEXT_DIM = "#9aa0aa"    # secondary text

# Distinct, dark-theme-friendly hues cycled per hosting provider.
PROVIDER_PALETTE = [
    "#4f9cf9", "#a78bfa", "#22c55e", "#eab308", "#ec4899",
    "#06b6d4", "#f97316", "#84cc16", "#e879f9", "#38bdf8",
    "#fb7185", "#34d399", "#c084fc", "#facc15", "#2dd4bf",
]


def provider_color(provider: str, order: list[str]) -> str:
    """Stable color for a provider based on its position in a sorted list."""
    if not provider:
        return MUTED
    try:
        idx = order.index(provider)
    except ValueError:
        idx = abs(hash(provider))
    return PROVIDER_PALETTE[idx % len(PROVIDER_PALETTE)]


def _hex_to_rgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore


def _rgb_to_hex(rgb) -> str:
    return "#" + "".join(f"{int(round(c * 255)):02x}" for c in rgb)


def darken(hex_color: str, factor: float = 0.45) -> str:
    """Return a darkened version of a color (for node fills behind a bright border)."""
    r, g, b = _hex_to_rgb(hex_color)
    h, l, s = colorsys.rgb_to_hls(r, g, b)
    return _rgb_to_hex(colorsys.hls_to_rgb(h, max(0.0, l * factor), s))
