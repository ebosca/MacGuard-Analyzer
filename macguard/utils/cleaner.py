"""
MacGuard Analyzer — Safe cleanup utilities.

SAFETY RULES:
- Files are MOVED TO TRASH (recoverable), never permanently deleted
- Every operation is logged to ~/Library/Logs/MacGuard/macguard.log
- Dry-run mode simulates all operations without executing them
- Absolute paths are validated before any action
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Tuple

from analyzer import CheckResult
from utils import commands as cmd

LOG = logging.getLogger("macguard.cleaner")

LOG_DIR = Path.home() / "Library/Logs/MacGuard"


def setup_logging() -> None:
    """Create log directory and configure rotating file logger."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "macguard.log"

    # File handler with rotation
    from logging.handlers import RotatingFileHandler
    handler = RotatingFileHandler(
        str(log_file),
        maxBytes=5 * 1024 * 1024,   # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    handler.setLevel(logging.DEBUG)

    root_logger = logging.getLogger("macguard")
    root_logger.setLevel(logging.DEBUG)
    if not any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
        root_logger.addHandler(handler)


def _validate_path(path: str) -> Tuple[bool, str]:
    """
    Validate that a path is safe to clean:
    - Must be absolute
    - Must not be a system directory
    - Must exist
    """
    if not path.startswith("/"):
        return False, f"Percorso non assoluto: {path}"

    p = Path(path)

    # Block critical system paths
    forbidden = {
        "/", "/System", "/usr", "/bin", "/sbin", "/etc",
        "/Library/Preferences", "/private/etc",
        str(Path.home() / "Library/Preferences"),
        str(Path.home() / "Library/Keychains"),
    }
    if str(p) in forbidden or any(str(p).startswith(f) for f in ["/System/", "/usr/bin/", "/sbin/"]):
        return False, f"Percorso di sistema protetto: {path}"

    if not p.exists():
        return False, f"Percorso non trovato: {path}"

    return True, "ok"


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def clean_selected(
    results: List[CheckResult],
    selected_ids: List[str],
    dry_run: bool = True,
) -> List[str]:
    """
    Clean selected items by check_id.

    Args:
        results: All analysis results
        selected_ids: check_ids of items to clean
        dry_run: If True, simulate without executing

    Returns:
        List of action descriptions (planned or completed)
    """
    actions: List[str] = []
    mode = "[DRY RUN]" if dry_run else "[ESECUZIONE]"

    for result in results:
        if result.check_id not in selected_ids:
            continue
        if not result.cleanable:
            continue

        LOG.info("%s Pulizia: %s", mode, result.name)

        # Handle special cleanup commands
        if result.clean_command == "empty_trash":
            action = "Svuota il Cestino"
            actions.append(action)
            LOG.info("%s %s", mode, action)
            if not dry_run:
                rc, out, err = cmd.empty_trash_osascript()
                if rc != 0:
                    LOG.error("Errore svuotamento Cestino: %s", err)
                    actions.append(f"  ERRORE: {err}")
                else:
                    LOG.info("Cestino svuotato con successo.")
            continue

        if result.clean_command == "brew_cleanup":
            action = "Esegui: brew cleanup (rimuove formule e bottiglie obsolete)"
            actions.append(action)
            LOG.info("%s %s", mode, action)
            if not dry_run:
                rc, out, err = cmd.brew_cleanup_run()
                if rc != 0:
                    LOG.error("Errore brew cleanup: %s", err)
                    actions.append(f"  ERRORE: {err}")
                else:
                    LOG.info("Brew cleanup completato.")
            continue

        # Handle path-based cleanup
        for path in result.clean_paths:
            ok, reason = _validate_path(path)
            if not ok:
                action = f"SALTATO ({reason}): {path}"
                LOG.warning("Validazione fallita: %s", reason)
                actions.append(action)
                continue

            p = Path(path)
            try:
                size = p.stat().st_size if p.is_file() else _get_dir_size(path)
                size_str = _fmt_size(size) if size else "?"
            except Exception:
                size_str = "?"

            action = f"Sposta nel Cestino: {path} ({size_str})"
            actions.append(action)
            LOG.info("%s %s", mode, action)

            if not dry_run:
                rc, out, err = cmd.move_to_trash_osascript(path)
                if rc != 0:
                    LOG.error("Errore spostamento nel Cestino (%s): %s", path, err)
                    actions.append(f"  ERRORE: {err}")
                else:
                    LOG.info("Spostato nel Cestino: %s", path)

    if not actions:
        actions.append("Nessun elemento selezionato per la pulizia.")

    return actions


def _get_dir_size(path: str) -> int:
    """Fast directory size estimate."""
    total = 0
    try:
        for entry in os.scandir(path):
            try:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += _get_dir_size(entry.path)
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass
    return total


def get_cleanable_summary(results: List[CheckResult]) -> str:
    """Return a human-readable summary of what can be cleaned."""
    cleanable = [r for r in results if r.cleanable]
    if not cleanable:
        return "Nessun elemento pulibile trovato."

    total_bytes = sum(r.size_bytes for r in cleanable if r.size_bytes)
    lines = [f"Elementi pulibili: {len(cleanable)}"]
    if total_bytes:
        lines.append(f"Spazio recuperabile: {_fmt_size(total_bytes)}")
    for r in cleanable:
        sz = _fmt_size(r.size_bytes) if r.size_bytes else "?"
        lines.append(f"  • {r.name}: {sz}")
    return "\n".join(lines)
