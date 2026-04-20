"""
MacGuard Analyzer — Security analysis module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from analyzer import CheckEntry, CheckResult
from utils import commands as cmd

# Apple-signed prefixes that are considered trusted for LaunchAgents/Daemons
APPLE_PREFIXES = (
    "com.apple.", "com.openssh.", "com.cups.", "com.citrix.",
    "com.microsoft.", "com.adobe.", "com.google.", "com.dropbox.",
)

# Well-known safe listening ports (AirPlay, mDNS, etc.)
SAFE_PORTS = {
    7000, 5000, 49152, 49153, 49154, 49155,
    2049, 111, 88, 445, 139, 548,
}


# ── Individual checks ────────────────────────────────────────────────────────

def check_firewall() -> CheckResult:
    rc, out, _ = cmd.check_firewall()
    enabled = rc == 0 and "enabled" in out.lower()
    if enabled:
        return CheckResult(
            check_id="firewall",
            name="Firewall applicazioni",
            status="ok",
            description="Il firewall applicazioni macOS è attivo.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )
    return CheckResult(
        check_id="firewall",
        name="Firewall applicazioni",
        status="critical",
        description="Il firewall applicazioni macOS è DISATTIVATO.",
        impact="Il Mac accetta connessioni di rete in entrata non filtrate.",
        recommendation="Vai in Impostazioni di Sistema → Network → Firewall → Attiva.",
        category="security",
    )


def check_filevault() -> CheckResult:
    rc, out, _ = cmd.check_filevault()
    on = rc == 0 and "on" in out.lower()
    if on:
        return CheckResult(
            check_id="filevault",
            name="FileVault (cifratura disco)",
            status="ok",
            description="FileVault è attivo. Il disco è cifrato.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )
    return CheckResult(
        check_id="filevault",
        name="FileVault (cifratura disco)",
        status="critical",
        description="FileVault è DISATTIVATO. I dati sul disco non sono cifrati.",
        impact="Chiunque abbia accesso fisico al Mac può leggere tutti i file.",
        recommendation="Vai in Impostazioni di Sistema → Privacy e sicurezza → FileVault → Attiva.",
        category="security",
    )


def check_gatekeeper() -> CheckResult:
    rc, out, _ = cmd.check_gatekeeper()
    enabled = rc == 0 and "enabled" in out.lower()
    if enabled:
        return CheckResult(
            check_id="gatekeeper",
            name="Gatekeeper",
            status="ok",
            description="Gatekeeper è attivo. Solo app verificate possono essere eseguite.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )
    return CheckResult(
        check_id="gatekeeper",
        name="Gatekeeper",
        status="critical",
        description="Gatekeeper è DISATTIVATO.",
        impact="Qualsiasi app non firmata può essere eseguita senza avvisi.",
        recommendation="Esegui nel Terminale: sudo spctl --master-enable",
        category="security",
    )


def check_sip() -> CheckResult:
    rc, out, _ = cmd.check_sip()
    enabled = rc == 0 and "enabled" in out.lower()
    if enabled:
        return CheckResult(
            check_id="sip",
            name="System Integrity Protection (SIP)",
            status="ok",
            description="SIP è attivo. I file di sistema sono protetti.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )
    return CheckResult(
        check_id="sip",
        name="System Integrity Protection (SIP)",
        status="warning",
        description="SIP è DISATTIVATO.",
        impact="I file e i processi di sistema non sono protetti da modifiche non autorizzate.",
        recommendation="Riattiva SIP dal Recovery Mode: csrutil enable",
        category="security",
    )


def check_ssh() -> CheckResult:
    rc, _, _ = cmd.check_ssh_running()
    ssh_running = rc == 0

    # Check for authorized_keys
    authorized_keys = Path.home() / ".ssh" / "authorized_keys"
    has_auth_keys = authorized_keys.exists() and authorized_keys.stat().st_size > 0

    if not ssh_running:
        return CheckResult(
            check_id="ssh",
            name="SSH remoto",
            status="ok",
            description="Il server SSH non è in esecuzione.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )

    status = "critical" if has_auth_keys else "warning"
    details = ["Il server SSH è attivo e accetta connessioni."]
    if has_auth_keys:
        details.append("Trovato ~/.ssh/authorized_keys — accesso con chiave pubblica configurato.")

    return CheckResult(
        check_id="ssh",
        name="SSH remoto",
        status=status,
        description="Il server SSH è in esecuzione e accetta connessioni remote.",
        impact="Chiunque sulla rete può tentare di accedere al Mac via SSH.",
        recommendation="Disattiva SSH se non necessario: Impostazioni → Generali → Condivisione → Accesso remoto.",
        category="security",
        details=details,
    )


def check_open_ports() -> List[CheckResult]:
    rc, out, _ = cmd.get_open_ports()
    results: List[CheckResult] = []
    if rc != 0 or not out.strip():
        results.append(CheckResult(
            check_id="open_ports",
            name="Porte di rete aperte",
            status="ok",
            description="Nessuna porta TCP in ascolto rilevata.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        ))
        return results

    # Parse lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    suspicious: List[str] = []
    seen_ports: set = set()
    for line in out.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue
        command = parts[0]
        pid = parts[1]
        name_field = parts[-1]  # e.g. *:8080 or 127.0.0.1:5000
        # Extract port
        port_match = re.search(r":(\d+)$", name_field)
        if not port_match:
            continue
        port = int(port_match.group(1))
        if port in seen_ports:
            continue
        seen_ports.add(port)
        # Only flag non-localhost listeners on non-safe ports
        if name_field.startswith("*:") and port not in SAFE_PORTS:
            suspicious.append(f"Porta {port} — processo: {command} (PID {pid})")

    if not suspicious:
        results.append(CheckResult(
            check_id="open_ports",
            name="Porte di rete aperte",
            status="ok",
            description=f"Trovate {len(seen_ports)} porte in ascolto, tutte conosciute o locali.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
            details=[f"Porte totali in ascolto: {len(seen_ports)}"],
        ))
    else:
        results.append(CheckResult(
            check_id="open_ports",
            name="Porte di rete aperte",
            status="warning",
            description=f"Trovate {len(suspicious)} porte aperte a tutte le interfacce di rete.",
            impact="Processi in ascolto su tutte le interfacce sono accessibili dalla rete locale.",
            recommendation="Verifica che ciascun processo sia legittimo. Usa il Firewall per limitare l'accesso.",
            category="security",
            details=suspicious,
        ))
    return results


def check_login_items() -> CheckResult:
    rc, out, _ = cmd.get_login_items_osascript()
    if rc != 0 or not out.strip():
        return CheckResult(
            check_id="login_items",
            name="Elementi di login",
            status="info",
            description="Nessun elemento di login trovato o accesso non disponibile.",
            impact="Nessuno.",
            recommendation="Verifica manualmente in Impostazioni di Sistema → Generali → Elementi di login.",
            category="security",
        )
    items = [i.strip() for i in out.strip().split(",") if i.strip()]
    return CheckResult(
        check_id="login_items",
        name="Elementi di login",
        status="info",
        description=f"Trovati {len(items)} elementi che si avviano al login.",
        impact="Ogni elemento rallenta il boot e consuma risorse in background.",
        recommendation="Rimuovi gli elementi non necessari da Impostazioni di Sistema → Generali → Elementi di login.",
        category="security",
        details=items,
    )


def check_launch_agents() -> List[CheckResult]:
    plists = cmd.get_launch_agents_list()
    if not plists:
        return [CheckResult(
            check_id="launch_agents",
            name="LaunchAgents / LaunchDaemons",
            status="ok",
            description="Nessun LaunchAgent o LaunchDaemon di terze parti trovato.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )]

    third_party: List[str] = []
    for p in plists:
        name = p.stem
        if not any(name.startswith(prefix) for prefix in APPLE_PREFIXES):
            third_party.append(f"{p.name} ({p.parent})")

    if not third_party:
        return [CheckResult(
            check_id="launch_agents",
            name="LaunchAgents / LaunchDaemons",
            status="ok",
            description=f"Trovati {len(plists)} agenti, tutti di Apple o software noto.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
            details=[p.name for p in plists[:10]],
        )]

    return [CheckResult(
        check_id="launch_agents",
        name="LaunchAgents / LaunchDaemons di terze parti",
        status="warning",
        description=f"Trovati {len(third_party)} agenti di avvio non Apple.",
        impact="Questi processi vengono avviati automaticamente e operano in background.",
        recommendation="Verifica ogni elemento. Rimuovi quelli di app disinstallate.",
        category="security",
        details=third_party,
    )]


def check_pending_updates() -> CheckResult:
    rc, out, _ = cmd.get_pending_updates()
    if rc == -1:  # timeout or command not found
        return CheckResult(
            check_id="pending_updates",
            name="Aggiornamenti di sicurezza",
            status="info",
            description="Impossibile verificare gli aggiornamenti (timeout o comando non disponibile).",
            impact="Sconosciuto.",
            recommendation="Verifica manualmente in Impostazioni di Sistema → Generali → Aggiornamento Software.",
            category="security",
        )

    lines = out + _ if _ else out
    no_updates = "no new software available" in lines.lower()
    has_security = "security" in lines.lower() or "recommended" in lines.lower()

    if no_updates:
        return CheckResult(
            check_id="pending_updates",
            name="Aggiornamenti di sicurezza",
            status="ok",
            description="Il sistema è aggiornato. Nessun aggiornamento disponibile.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )

    update_lines = [l.strip() for l in lines.splitlines() if "*" in l or "-" in l][:10]
    status = "critical" if has_security else "warning"
    return CheckResult(
        check_id="pending_updates",
        name="Aggiornamenti di sicurezza",
        status=status,
        description=f"Aggiornamenti disponibili {'(inclusi aggiornamenti di sicurezza)' if has_security else ''}.",
        impact="Sistema vulnerabile a exploit noti se non aggiornato.",
        recommendation="Aggiorna subito in Impostazioni di Sistema → Generali → Aggiornamento Software.",
        category="security",
        details=update_lines,
    )


def check_folder_permissions() -> CheckResult:
    sensitive = [
        str(Path.home() / "Documents"),
        str(Path.home() / "Desktop"),
        str(Path.home() / "Downloads"),
    ]
    issues: List[str] = []
    for folder in sensitive:
        rc, out, _ = cmd.get_folder_permissions(folder)
        if rc == 0 and out.strip():
            perms = out.strip().split()[0] if out.strip() else ""
            # World-writable = danger (drwxrwxrwx)
            if len(perms) >= 10 and perms[7] == "w":
                issues.append(f"{folder}: {perms} — scrittura pubblica!")

    if not issues:
        return CheckResult(
            check_id="folder_perms",
            name="Permessi cartelle sensibili",
            status="ok",
            description="I permessi di Documenti, Desktop e Download sono corretti.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="security",
        )
    return CheckResult(
        check_id="folder_perms",
        name="Permessi cartelle sensibili",
        status="warning",
        description="Alcune cartelle sensibili hanno permessi troppo aperti.",
        impact="Altri utenti del sistema possono leggere o modificare i tuoi file.",
        recommendation="Correggi i permessi con: chmod 700 ~/Documents ~/Desktop ~/Downloads",
        category="security",
        details=issues,
    )


def check_camera_mic_access() -> CheckResult:
    services = {
        "kTCCServiceCamera": "Fotocamera",
        "kTCCServiceMicrophone": "Microfono",
    }
    details: List[str] = []
    for service, label in services.items():
        rc, out, _ = cmd.query_tcc_db(service)
        if rc == 0 and out.strip():
            apps = [a.strip() for a in out.strip().splitlines() if a.strip()]
            for app in apps:
                details.append(f"{label}: {app}")

    if not details:
        return CheckResult(
            check_id="camera_mic",
            name="Accesso fotocamera e microfono",
            status="info",
            description="Nessuna app con accesso a fotocamera/microfono trovata (o permessi DB non disponibili).",
            impact="Nessuno.",
            recommendation="Verifica in Impostazioni di Sistema → Privacy e sicurezza.",
            category="security",
        )
    return CheckResult(
        check_id="camera_mic",
        name="Accesso fotocamera e microfono",
        status="info",
        description=f"Trovate {len(details)} app con accesso a fotocamera o microfono.",
        impact="Le app elencate possono accedere alla fotocamera o al microfono.",
        recommendation="Rimuovi l'accesso alle app non necessarie in Impostazioni di Sistema → Privacy.",
        category="security",
        details=details,
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def get_all_checks() -> List[CheckEntry]:
    return [
        (check_firewall,          "Controllo Firewall"),
        (check_filevault,         "Controllo FileVault"),
        (check_gatekeeper,        "Controllo Gatekeeper"),
        (check_sip,               "Controllo SIP"),
        (check_ssh,               "Controllo SSH"),
        (check_open_ports,        "Porte di rete aperte"),
        (check_login_items,       "Elementi di login"),
        (check_launch_agents,     "LaunchAgents e LaunchDaemons"),
        (check_pending_updates,   "Aggiornamenti di sicurezza"),
        (check_folder_permissions,"Permessi cartelle sensibili"),
        (check_camera_mic_access, "Accesso fotocamera/microfono"),
    ]
