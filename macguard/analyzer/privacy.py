"""
MacGuard Analyzer — Privacy analysis module.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from analyzer import CheckEntry, CheckResult
from utils import commands as cmd


TCC_SERVICES: Dict[str, str] = {
    "kTCCServiceLocation":     "Posizione",
    "kTCCServiceContactsFull": "Contatti",
    "kTCCServiceCalendar":     "Calendario",
    "kTCCServiceMicrophone":   "Microfono",
    "kTCCServiceCamera":       "Fotocamera",
    "kTCCServicePhotos":       "Foto",
    "kTCCServiceReminders":    "Promemoria",
}


def _query_tcc(service: str) -> List[str]:
    """Query TCC DB with graceful fallback."""
    rc, out, _ = cmd.query_tcc_db(service)
    if rc == 0 and out.strip():
        return [a.strip() for a in out.strip().splitlines() if a.strip()]
    return []


def _get_apps_from_privacy_report() -> Dict[str, List[str]]:
    """
    Parse system_profiler SPPrivacyDataType JSON output as fallback
    when TCC DB is not accessible.
    Returns dict mapping service_name → list of app names.
    """
    rc, out, _ = cmd.get_privacy_report()
    if rc != 0 or not out.strip():
        return {}

    try:
        data = json.loads(out)
        result: Dict[str, List[str]] = {}
        privacy_data = data.get("SPPrivacyDataType", [])
        for item in privacy_data:
            stype = item.get("_name", "")
            apps = item.get("spprivacy_apps", [])
            app_names = []
            for app in apps:
                if isinstance(app, dict):
                    name = app.get("_name") or app.get("spprivacy_app_name", "")
                    if name:
                        app_names.append(name)
                elif isinstance(app, str):
                    app_names.append(app)
            if app_names:
                result[stype] = app_names
        return result
    except (json.JSONDecodeError, KeyError, TypeError):
        return {}


def _check_tcc_service(service: str, label: str) -> Optional[List[str]]:
    """Try TCC DB first, then system_profiler fallback."""
    apps = _query_tcc(service)
    return apps if apps else None


# ── Checks ───────────────────────────────────────────────────────────────────

def check_location_access() -> CheckResult:
    apps = _check_tcc_service("kTCCServiceLocation", "Posizione")

    if apps is None:
        return CheckResult(
            check_id="location_access",
            name="App con accesso alla posizione",
            status="info",
            description="Impossibile leggere il DB TCC (protetto da SIP). Verifica manualmente.",
            impact="Nessuno.",
            recommendation="Vai in Impostazioni di Sistema → Privacy → Localizzazione.",
            category="privacy",
        )

    if not apps:
        return CheckResult(
            check_id="location_access",
            name="App con accesso alla posizione",
            status="ok",
            description="Nessuna app ha accesso alla posizione.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="privacy",
        )

    return CheckResult(
        check_id="location_access",
        name="App con accesso alla posizione",
        status="info",
        description=f"{len(apps)} app ha/hanno accesso ai dati di localizzazione.",
        impact="Queste app conoscono la tua posizione geografica.",
        recommendation="Rimuovi l'accesso alle app non necessarie in Impostazioni → Privacy → Localizzazione.",
        category="privacy",
        details=apps,
    )


def check_contacts_access() -> CheckResult:
    apps = _check_tcc_service("kTCCServiceContactsFull", "Contatti")

    if apps is None:
        return CheckResult(
            check_id="contacts_access",
            name="App con accesso ai contatti",
            status="info",
            description="Impossibile leggere il DB TCC (protetto da SIP). Verifica manualmente.",
            impact="Nessuno.",
            recommendation="Vai in Impostazioni di Sistema → Privacy → Contatti.",
            category="privacy",
        )

    if not apps:
        return CheckResult(
            check_id="contacts_access",
            name="App con accesso ai contatti",
            status="ok",
            description="Nessuna app ha accesso ai contatti.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="privacy",
        )

    return CheckResult(
        check_id="contacts_access",
        name="App con accesso ai contatti",
        status="info",
        description=f"{len(apps)} app ha/hanno accesso alla rubrica contatti.",
        impact="Queste app possono leggere nomi, email e numeri dei tuoi contatti.",
        recommendation="Verifica le app elencate in Impostazioni → Privacy → Contatti.",
        category="privacy",
        details=apps,
    )


def check_calendar_access() -> CheckResult:
    apps = _check_tcc_service("kTCCServiceCalendar", "Calendario")

    if apps is None:
        return CheckResult(
            check_id="calendar_access",
            name="App con accesso al calendario",
            status="info",
            description="Impossibile leggere il DB TCC (protetto da SIP). Verifica manualmente.",
            impact="Nessuno.",
            recommendation="Vai in Impostazioni di Sistema → Privacy → Calendari.",
            category="privacy",
        )

    if not apps:
        return CheckResult(
            check_id="calendar_access",
            name="App con accesso al calendario",
            status="ok",
            description="Nessuna app ha accesso al calendario.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="privacy",
        )

    return CheckResult(
        check_id="calendar_access",
        name="App con accesso al calendario",
        status="info",
        description=f"{len(apps)} app ha/hanno accesso agli eventi del calendario.",
        impact="Queste app conoscono i tuoi appuntamenti e impegni.",
        recommendation="Verifica le app elencate in Impostazioni → Privacy → Calendari.",
        category="privacy",
        details=apps,
    )


def check_recent_items() -> CheckResult:
    rc, out, _ = cmd.get_recent_items()
    if rc != 0 or not out.strip():
        return CheckResult(
            check_id="recent_items",
            name="Elementi recenti",
            status="info",
            description="Nessun dato sugli elementi recenti disponibile.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="privacy",
        )

    # Count mentions of 'CustomListItems' groups
    items_count = out.count("BookmarkData") + out.count("Title")
    items_count = min(items_count // 2, 50)

    if items_count == 0:
        return CheckResult(
            check_id="recent_items",
            name="Elementi recenti",
            status="ok",
            description="La cronologia elementi recenti è vuota.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="privacy",
        )

    return CheckResult(
        check_id="recent_items",
        name="Elementi recenti",
        status="info",
        description=f"macOS mantiene una cronologia di circa {items_count} elementi recenti.",
        impact="Chiunque acceda al Mac può vedere i file e le app usate di recente.",
        recommendation="Cancella la cronologia in Impostazioni → Generali → Elementi recenti → Nessuno.",
        category="privacy",
    )


def check_diagnostic_reports() -> CheckResult:
    rc, out, _ = cmd.get_diagnostics_size()

    size_bytes: Optional[int] = None
    if rc == 0 and out.strip():
        match = re.match(r"(\d+)", out.strip())
        if match:
            size_bytes = int(match.group(1)) * 1024

    diag_path = str(Path.home() / "Library/Logs/DiagnosticReports")
    path_obj = Path(diag_path)

    if not path_obj.exists() or (size_bytes is not None and size_bytes < 1024):
        return CheckResult(
            check_id="diagnostic_reports",
            name="Report diagnostici",
            status="ok",
            description="Nessun report diagnostico trovato.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="privacy",
        )

    # Count files
    try:
        report_files = list(path_obj.glob("*.ips")) + list(path_obj.glob("*.crash"))
        count = len(report_files)
    except Exception:
        count = 0

    size_str = f"{size_bytes // 1024:.0f} KB" if size_bytes else "sconosciuta"

    return CheckResult(
        check_id="diagnostic_reports",
        name="Report diagnostici",
        status="info",
        description=f"Trovati {count} report diagnostici ({size_str}).",
        impact="I report diagnostici contengono informazioni dettagliate sul sistema e possono essere inviati ad Apple.",
        recommendation="Puoi eliminarli in Impostazioni → Privacy → Analisi e miglioramenti.",
        category="privacy",
        cleanable=count > 0,
        size_bytes=size_bytes,
        clean_paths=[diag_path] if count > 0 else [],
        details=[f"Report in ~/Library/Logs/DiagnosticReports: {count}", f"Dimensione: {size_str}"],
    )


def check_siri_data() -> CheckResult:
    rc, out, _ = cmd.check_siri_data_sharing()
    if rc != 0:
        return CheckResult(
            check_id="siri_data",
            name="Condivisione dati Siri",
            status="info",
            description="Impossibile verificare le impostazioni di condivisione dati Siri.",
            impact="Nessuno.",
            recommendation="Verifica in Impostazioni → Privacy → Analisi e miglioramenti.",
            category="privacy",
        )

    opt_in = out.strip() == "1"
    return CheckResult(
        check_id="siri_data",
        name="Condivisione dati Siri",
        status="info" if not opt_in else "warning",
        description=(
            "La condivisione dei dati Siri con Apple è ATTIVA."
            if opt_in else
            "La condivisione dei dati Siri con Apple è disattivata."
        ),
        impact="I dati Siri condivisi includono interazioni vocali e personali.",
        recommendation="Disattiva in Impostazioni → Privacy e sicurezza → Analisi e miglioramenti.",
        category="privacy",
    )


def check_privacy_summary() -> CheckResult:
    """
    Summary check using system_profiler as a catch-all when TCC DB is inaccessible.
    """
    report = _get_apps_from_privacy_report()
    if not report:
        return CheckResult(
            check_id="privacy_summary",
            name="Riepilogo accessi Privacy",
            status="info",
            description="Impossibile ottenere il riepilogo privacy dal sistema.",
            impact="Nessuno.",
            recommendation="Verifica manualmente in Impostazioni di Sistema → Privacy e sicurezza.",
            category="privacy",
        )

    all_apps: List[str] = []
    for service, apps in report.items():
        for app in apps:
            all_apps.append(f"{service}: {app}")

    return CheckResult(
        check_id="privacy_summary",
        name="Riepilogo accessi Privacy",
        status="info",
        description=f"Trovati {len(all_apps)} accessi privacy nelle impostazioni di sistema.",
        impact="Le app con accessi privacy possono leggere dati sensibili.",
        recommendation="Rivedi gli accessi in Impostazioni di Sistema → Privacy e sicurezza.",
        category="privacy",
        details=all_apps[:30],
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def get_all_checks() -> List[CheckEntry]:
    return [
        (check_location_access,   "Accesso posizione"),
        (check_contacts_access,   "Accesso contatti"),
        (check_calendar_access,   "Accesso calendario"),
        (check_recent_items,      "Elementi recenti"),
        (check_diagnostic_reports,"Report diagnostici"),
        (check_siri_data,         "Condivisione dati Siri"),
        (check_privacy_summary,   "Riepilogo Privacy"),
    ]
