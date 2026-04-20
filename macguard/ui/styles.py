"""
MacGuard Analyzer — UI styles, colors, and theme constants.
"""

from __future__ import annotations

# ── Status colors ─────────────────────────────────────────────────────────────

STATUS_COLORS = {
    "critical": "#E53935",
    "warning":  "#FB8C00",
    "ok":       "#43A047",
    "info":     "#1E88E5",
}

STATUS_BG_COLORS = {
    "critical": "#3D1010",
    "warning":  "#3D2200",
    "ok":       "#0F2D10",
    "info":     "#0D1E3D",
}

STATUS_ICONS = {
    "critical": "🔴",
    "warning":  "🟡",
    "ok":       "🟢",
    "info":     "🔵",
}

STATUS_LABELS = {
    "critical": "Critico",
    "warning":  "Attenzione",
    "ok":       "OK",
    "info":     "Info",
}

# ── Category ──────────────────────────────────────────────────────────────────

CATEGORY_ICONS = {
    "security":    "🔒",
    "storage":     "💾",
    "performance": "⚡",
    "privacy":     "👁",
}

CATEGORY_NAMES = {
    "security":    "Sicurezza",
    "storage":     "Spazio Disco",
    "performance": "Performance",
    "privacy":     "Privacy",
}

CATEGORY_DESCRIPTIONS = {
    "security":    "Firewall, FileVault, SIP, porte aperte, LaunchAgents",
    "storage":     "Cache, log, Cestino, file grandi, backup iOS",
    "performance": "CPU, RAM, swap, batteria, uptime",
    "privacy":     "Accessi app, cronologia, dati diagnostici",
}

CATEGORY_COLORS = {
    "security":    "#E53935",
    "storage":     "#FB8C00",
    "performance": "#1E88E5",
    "privacy":     "#43A047",
}

# ── Typography ────────────────────────────────────────────────────────────────

FONT_TITLE   = ("SF Pro Display", 28, "bold")
FONT_HEADING = ("SF Pro Display", 16, "bold")
FONT_BODY    = ("SF Pro Text",    13, "normal")
FONT_SMALL   = ("SF Pro Text",    11, "normal")
FONT_MONO    = ("SF Mono",        11, "normal")

# Fallback fonts if SF Pro not available
FONT_TITLE_FB   = ("Helvetica Neue", 28, "bold")
FONT_HEADING_FB = ("Helvetica Neue", 16, "bold")
FONT_BODY_FB    = ("Helvetica Neue", 13, "normal")
FONT_SMALL_FB   = ("Helvetica Neue", 11, "normal")
FONT_MONO_FB    = ("Courier",        11, "normal")

# ── Dimensions ────────────────────────────────────────────────────────────────

WINDOW_WIDTH  = 960
WINDOW_HEIGHT = 720
MIN_WIDTH     = 800
MIN_HEIGHT    = 600

CARD_CORNER   = 8
CARD_PADDING  = 12

# ── Theme ─────────────────────────────────────────────────────────────────────

APP_NAME    = "MacGuard Analyzer"
APP_VERSION = "1.0.0"
