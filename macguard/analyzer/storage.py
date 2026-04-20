"""
MacGuard Analyzer — Storage / disk cleanup analysis module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from analyzer import CheckEntry, CheckResult
from utils import commands as cmd


def _parse_du_kb(out: str) -> Optional[int]:
    """Parse 'du -sk' output → bytes. Extracts the last numeric line (total)."""
    # du -sk output may have multiple lines if there are sub-errors;
    # the last non-empty line contains the total.
    for line in reversed(out.strip().splitlines()):
        match = re.match(r"(\d+)", line.strip())
        if match:
            return int(match.group(1)) * 1024
    return None


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


# ── Checks ───────────────────────────────────────────────────────────────────

def check_user_caches() -> CheckResult:
    cache_path = str(Path.home() / "Library/Caches")
    rc, out, _ = cmd.get_dir_size_kb(cache_path)
    # rc may be non-zero due to permission errors on sub-dirs, but output still has total
    size = _parse_du_kb(out) if out.strip() else None
    size_str = _fmt_size(size) if size else "sconosciuta"

    threshold_warn = 500 * 1024 * 1024   # 500 MB
    threshold_crit = 2 * 1024 * 1024 * 1024  # 2 GB

    if size and size >= threshold_crit:
        status = "warning"
    elif size and size >= threshold_warn:
        status = "warning"
    else:
        status = "ok"

    cleanable = size is not None and size > threshold_warn
    return CheckResult(
        check_id="user_caches",
        name="Cache utente",
        status=status,
        description=f"La cartella ~/Library/Caches occupa {size_str}.",
        impact="Le cache non rimosse accumulano spazio disco nel tempo.",
        recommendation="Svuota le cache delle app non in uso. Le app le rigenereranno automaticamente.",
        category="storage",
        cleanable=cleanable,
        size_bytes=size,
        clean_paths=[cache_path] if cleanable else [],
        details=[f"Percorso: {cache_path}", f"Dimensione: {size_str}"],
    )


def check_system_temp() -> CheckResult:
    paths = ["/tmp", "/private/var/tmp"]
    total = 0
    details: List[str] = []
    for p in paths:
        rc, out, _ = cmd.get_dir_size_kb(p)
        size = _parse_du_kb(out) if out.strip() else None
        if size:
            total += size
            details.append(f"{p}: {_fmt_size(size)}")

    status = "warning" if total > 100 * 1024 * 1024 else "ok"
    return CheckResult(
        check_id="system_temp",
        name="File temporanei di sistema",
        status=status,
        description=f"File temporanei in /tmp e /private/var/tmp: {_fmt_size(total)}.",
        impact="I file temporanei occupano spazio disco e vengono rimossi al riavvio.",
        recommendation="Riavvia il Mac per pulire i file temporanei automaticamente.",
        category="storage",
        cleanable=total > 50 * 1024 * 1024,
        size_bytes=total if total > 0 else None,
        details=details,
    )


def check_old_logs() -> CheckResult:
    paths = [
        str(Path.home() / "Library/Logs"),
        "/var/log",
    ]
    total = 0
    details: List[str] = []
    for p in paths:
        if Path(p).exists():
            rc, out, _ = cmd.get_dir_size_kb(p)
            size = _parse_du_kb(out) if out.strip() else None
            if size:
                total += size
                details.append(f"{p}: {_fmt_size(size)}")

    status = "warning" if total > 200 * 1024 * 1024 else "ok"
    log_path = str(Path.home() / "Library/Logs")
    return CheckResult(
        check_id="old_logs",
        name="Log di sistema e applicazioni",
        status=status,
        description=f"Log totali: {_fmt_size(total)}.",
        impact="I log vecchi occupano spazio senza fornire valore.",
        recommendation="Rimuovi i log più vecchi di 30 giorni.",
        category="storage",
        cleanable=total > 100 * 1024 * 1024,
        size_bytes=total if total > 0 else None,
        clean_paths=[log_path] if total > 100 * 1024 * 1024 else [],
        details=details,
    )


def check_trash() -> CheckResult:
    rc, out, _ = cmd.get_trash_size()
    size = _parse_du_kb(out) if out.strip() else None
    size_str = _fmt_size(size) if size else "sconosciuta"
    empty = size is None or size < 1024

    if empty:
        return CheckResult(
            check_id="trash",
            name="Cestino",
            status="ok",
            description="Il Cestino è vuoto.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )
    return CheckResult(
        check_id="trash",
        name="Cestino",
        status="warning",
        description=f"Il Cestino contiene {size_str} di file da eliminare definitivamente.",
        impact="I file nel Cestino occupano spazio disco finché non viene svuotato.",
        recommendation="Svuota il Cestino per recuperare spazio.",
        category="storage",
        cleanable=True,
        size_bytes=size,
        clean_command="empty_trash",
        details=[f"Dimensione Cestino: {size_str}"],
    )


def check_ds_store() -> CheckResult:
    home = str(Path.home())
    rc, out, err = cmd.find_ds_store(home)
    # rc may be non-zero due to permissions or timeout — still use what we got
    if rc != 0 and not out.strip():
        return CheckResult(
            check_id="ds_store",
            name="File .DS_Store",
            status="info",
            description="Ricerca .DS_Store non completata (timeout o permessi insufficienti).",
            impact="Nessuno.",
            recommendation="Puoi cercarli manualmente con: find ~ -maxdepth 3 -name .DS_Store",
            category="storage",
        )

    files = [f.strip() for f in out.strip().splitlines() if f.strip()]
    if not files:
        return CheckResult(
            check_id="ds_store",
            name="File .DS_Store",
            status="ok",
            description="Nessun file .DS_Store trovato.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    return CheckResult(
        check_id="ds_store",
        name="File .DS_Store",
        status="info",
        description=f"Trovati {len(files)} file .DS_Store nella home.",
        impact="I file .DS_Store sono metadati macOS. Occupano poco spazio ma possono esporre informazioni sulle cartelle.",
        recommendation="Puoi eliminarli in sicurezza. Verranno ricreati da macOS quando apri le cartelle.",
        category="storage",
        cleanable=True,
        size_bytes=len(files) * 6 * 1024,  # ~6 KB each
        clean_paths=files[:50],  # limit to 50 for safety
        details=files[:20],
    )


def check_large_downloads() -> CheckResult:
    downloads = str(Path.home() / "Downloads")
    rc, out, _ = cmd.find_large_files(downloads, min_size_mb=500)
    if rc != 0 or not out.strip():
        return CheckResult(
            check_id="large_downloads",
            name="File grandi nei Download",
            status="ok",
            description="Nessun file >500 MB trovato in ~/Downloads.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    files = [f.strip() for f in out.strip().splitlines() if f.strip()]
    total = 0
    details: List[str] = []
    for f in files[:20]:
        try:
            sz = Path(f).stat().st_size
            total += sz
            details.append(f"{Path(f).name}: {_fmt_size(sz)}")
        except Exception:
            details.append(Path(f).name)

    return CheckResult(
        check_id="large_downloads",
        name="File grandi nei Download",
        status="warning",
        description=f"Trovati {len(files)} file >500 MB in ~/Downloads ({_fmt_size(total)} totali).",
        impact="I file grandi occupano spazio SSD prezioso.",
        recommendation="Rimuovi o archivia i file di Download non più necessari.",
        category="storage",
        cleanable=False,  # user must decide
        size_bytes=total,
        details=details,
    )


def check_ios_backups() -> CheckResult:
    rc, out, _ = cmd.check_ios_backups()
    size = _parse_du_kb(out) if out.strip() else None

    if size is None or size < 1024:
        return CheckResult(
            check_id="ios_backups",
            name="Backup iOS (iTunes/Finder)",
            status="ok",
            description="Nessun backup iOS trovato.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    backup_path = str(Path.home() / "Library/Application Support/MobileSync/Backup")
    return CheckResult(
        check_id="ios_backups",
        name="Backup iOS (iTunes/Finder)",
        status="warning",
        description=f"Backup iOS trovati: {_fmt_size(size)}.",
        impact="I backup iOS obsoleti occupano molto spazio.",
        recommendation="Gestisci i backup in Finder → il tuo dispositivo → Gestisci backup.",
        category="storage",
        cleanable=True,
        size_bytes=size,
        clean_paths=[backup_path],
        details=[f"Percorso: {backup_path}", f"Dimensione: {_fmt_size(size)}"],
    )


def check_mounted_dmgs() -> CheckResult:
    rc, out, _ = cmd.get_mounted_dmgs()
    if rc != 0 or not out.strip():
        return CheckResult(
            check_id="mounted_dmgs",
            name="Immagini disco .dmg montate",
            status="ok",
            description="Nessuna immagine disco montata.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    # Count non-system disk images
    images = re.findall(r"image-path\s+:\s+(.+\.dmg)", out, re.IGNORECASE)
    if not images:
        return CheckResult(
            check_id="mounted_dmgs",
            name="Immagini disco .dmg montate",
            status="ok",
            description="Nessuna immagine .dmg montata trovata.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    return CheckResult(
        check_id="mounted_dmgs",
        name="Immagini disco .dmg montate",
        status="info",
        description=f"Trovate {len(images)} immagini disco montate.",
        impact="Le DMG montate occupano spazio virtuale e possono contenere app da installare.",
        recommendation="Espelli le immagini disco non necessarie.",
        category="storage",
        details=[Path(img).name for img in images],
    )


def check_brew_cache() -> CheckResult:
    if not cmd.check_brew_available():
        return CheckResult(
            check_id="brew_cache",
            name="Cache Homebrew",
            status="info",
            description="Homebrew non è installato.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    rc, out, _ = cmd.brew_cleanup_dry_run()
    size: Optional[int] = None

    # Parse freed space from brew dry-run output
    match = re.search(r"(\d+(?:\.\d+)?)\s*(MB|GB|KB)", out, re.IGNORECASE)
    if match:
        val = float(match.group(1))
        unit = match.group(2).upper()
        if unit == "GB":
            size = int(val * 1024 * 1024 * 1024)
        elif unit == "MB":
            size = int(val * 1024 * 1024)
        elif unit == "KB":
            size = int(val * 1024)

    if size is None or size < 1024:
        # Try du on cache dir
        rc2, out2, _ = cmd.get_brew_cache_size()
        size = _parse_du_kb(out2) if out2.strip() else None

    if not size or size < 10 * 1024 * 1024:
        return CheckResult(
            check_id="brew_cache",
            name="Cache Homebrew",
            status="ok",
            description="La cache Homebrew è piccola o già pulita.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
            size_bytes=size,
        )

    return CheckResult(
        check_id="brew_cache",
        name="Cache Homebrew",
        status="warning",
        description=f"La cache Homebrew occupa circa {_fmt_size(size)}.",
        impact="La cache delle formule e bottiglie scaricate occupa spazio disco.",
        recommendation="Esegui: brew cleanup",
        category="storage",
        cleanable=True,
        size_bytes=size,
        clean_command="brew_cleanup",
    )


def check_npm_cache() -> CheckResult:
    npm_cache = Path.home() / ".npm"
    if not npm_cache.exists():
        return CheckResult(
            check_id="npm_cache",
            name="Cache npm",
            status="info",
            description="npm non è installato o non ha cache.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    rc, out, _ = cmd.get_dir_size_kb(str(npm_cache))
    size = _parse_du_kb(out) if out.strip() else None
    size_str = _fmt_size(size) if size else "sconosciuta"

    if not size or size < 100 * 1024 * 1024:
        return CheckResult(
            check_id="npm_cache",
            name="Cache npm",
            status="ok",
            description=f"Cache npm: {size_str}.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
            size_bytes=size,
        )

    return CheckResult(
        check_id="npm_cache",
        name="Cache npm",
        status="warning",
        description=f"La cache npm occupa {size_str}.",
        impact="La cache npm accumula pacchetti scaricati.",
        recommendation="Esegui: npm cache clean --force",
        category="storage",
        cleanable=True,
        size_bytes=size,
        clean_paths=[str(npm_cache)],
    )


def check_pip_cache() -> CheckResult:
    pip_cache = Path.home() / "Library/Caches/pip"
    if not pip_cache.exists():
        return CheckResult(
            check_id="pip_cache",
            name="Cache pip",
            status="info",
            description="pip non ha cache o non è installato.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    rc, out, _ = cmd.get_dir_size_kb(str(pip_cache))
    size = _parse_du_kb(out) if out.strip() else None
    size_str = _fmt_size(size) if size else "sconosciuta"

    if not size or size < 50 * 1024 * 1024:
        return CheckResult(
            check_id="pip_cache",
            name="Cache pip",
            status="ok",
            description=f"Cache pip: {size_str}.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
            size_bytes=size,
        )

    return CheckResult(
        check_id="pip_cache",
        name="Cache pip",
        status="warning",
        description=f"La cache pip occupa {size_str}.",
        impact="La cache pip accumula pacchetti Python scaricati.",
        recommendation="Esegui: pip cache purge",
        category="storage",
        cleanable=True,
        size_bytes=size,
        clean_paths=[str(pip_cache)],
    )


def check_xcode_derived_data() -> CheckResult:
    xcode_data = Path.home() / "Library/Developer/Xcode/DerivedData"
    if not xcode_data.exists():
        return CheckResult(
            check_id="xcode_derived",
            name="Xcode DerivedData",
            status="info",
            description="Xcode non è installato o non ha DerivedData.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
        )

    rc, out, _ = cmd.check_xcode_derived_data()
    size = _parse_du_kb(out) if out.strip() else None
    size_str = _fmt_size(size) if size else "sconosciuta"

    if not size or size < 500 * 1024 * 1024:
        return CheckResult(
            check_id="xcode_derived",
            name="Xcode DerivedData",
            status="ok",
            description=f"Xcode DerivedData: {size_str}.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="storage",
            size_bytes=size,
        )

    return CheckResult(
        check_id="xcode_derived",
        name="Xcode DerivedData",
        status="warning",
        description=f"Xcode DerivedData occupa {size_str}.",
        impact="I dati derivati di Xcode si accumulano con ogni build.",
        recommendation="In Xcode: Preferences → Locations → DerivedData → Delete.",
        category="storage",
        cleanable=True,
        size_bytes=size,
        clean_paths=[str(xcode_data)],
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def get_all_checks() -> List[CheckEntry]:
    return [
        (check_user_caches,        "Cache utente"),
        (check_system_temp,        "File temporanei di sistema"),
        (check_old_logs,           "Log di sistema"),
        (check_trash,              "Cestino"),
        (check_ds_store,           "File .DS_Store"),
        (check_large_downloads,    "File grandi nei Download"),
        (check_ios_backups,        "Backup iOS"),
        (check_mounted_dmgs,       "Immagini disco montate"),
        (check_brew_cache,         "Cache Homebrew"),
        (check_npm_cache,          "Cache npm"),
        (check_pip_cache,          "Cache pip"),
        (check_xcode_derived_data, "Xcode DerivedData"),
    ]
