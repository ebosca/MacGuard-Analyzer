#!/usr/bin/env python3
"""
MacGuard Analyzer — Entry point.

Launches the GUI application after setting up logging and verifying dependencies.
"""

from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path

# ── Ensure project root is on sys.path ───────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Setup logging early (before any imports that use it) ─────────────────────
from utils.cleaner import setup_logging
setup_logging()

import logging
LOG = logging.getLogger("macguard.main")
LOG.info("MacGuard Analyzer avviato")


# ── Auto-install customtkinter if missing ─────────────────────────────────────

def _try_install(package: str) -> bool:
    """Attempt to install a pip package. Returns True on success."""
    try:
        print(f"Installazione {package}...", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package, "--quiet"],
            timeout=120,
            check=False,
        )
        return result.returncode == 0
    except Exception as exc:
        print(f"Impossibile installare {package}: {exc}", flush=True)
        return False


def _ensure_dependencies():
    """Check and install required packages."""
    required = {
        "customtkinter": "customtkinter",
        "darkdetect":    "darkdetect",
        "psutil":        "psutil",
    }
    optional = {
        "reportlab":     "reportlab",
    }

    missing = []
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append((module, package))

    if missing:
        print("Alcune dipendenze necessarie non sono installate.")
        for module, package in missing:
            ok = _try_install(package)
            if not ok:
                print(f"ERRORE: impossibile installare '{package}'.")
                print(f"Installa manualmente con: pip install {package}")
                sys.exit(1)

    # Optional — install silently
    for module, package in optional.items():
        try:
            __import__(module)
        except ImportError:
            _try_install(package)


# ── Disclaimer dialog ─────────────────────────────────────────────────────────

def _show_disclaimer(root) -> bool:
    """Show startup disclaimer. Returns True if user accepts."""
    from tkinter import messagebox
    from utils import lang as _L

    result = messagebox.askyesno(
        _L.t("disclaimer_popup_title"),
        _L.t("disclaimer_popup_body"),
        icon="warning",
    )
    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Check dependencies
    _ensure_dependencies()

    # Import CTk after ensuring it's installed
    import customtkinter as ctk
    from ui.main_window import MainWindow

    # Set appearance (will respect system setting)
    ctk.set_appearance_mode("system")
    ctk.set_default_color_theme("blue")

    # Create temporary root for disclaimer
    root = ctk.CTk()
    root.withdraw()  # Hide main window during disclaimer

    if not _show_disclaimer(root):
        LOG.info("Utente ha rifiutato il disclaimer. Uscita.")
        root.destroy()
        sys.exit(0)

    root.destroy()

    # Launch main window
    LOG.info("Apertura finestra principale")
    app = MainWindow()
    app.mainloop()
    LOG.info("MacGuard Analyzer chiuso")


if __name__ == "__main__":
    main()
