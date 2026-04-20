"""
MacGuard Analyzer — Localisation module (IT / EN).

Usage:
    from utils import lang
    lang.set_lang("EN")
    label = lang.t("btn_start")          # plain string
    text  = lang.t("status_done", n=12, c=2, w=4)  # with format vars
"""

from __future__ import annotations

_lang: str = "IT"


def get_lang() -> str:
    return _lang


def set_lang(code: str) -> None:
    global _lang
    _lang = code


def t(key: str, **kwargs) -> str:
    """Return translated string for *key* in the active language."""
    text = _S.get(_lang, _S["IT"]).get(key) or _S["IT"].get(key) or key
    return text.format(**kwargs) if kwargs else text


# ── Check-result translations (EN only — IT is the source in the analyzers) ──

def translate_result(r):
    """Return r with English strings applied when lang is EN. IT → no-op."""
    if _lang != "EN":
        return r
    tr = _CHECKS_EN.get(r.check_id)
    if not tr:
        return r
    from dataclasses import replace as _dc_replace
    kwargs: dict = {}
    if "name" in tr:
        kwargs["name"] = tr["name"]
    # description: prefer status-specific key, then generic, then keep original
    desc_key = f"desc_{r.status}" if f"desc_{r.status}" in tr else "desc"
    if desc_key in tr:
        tmpl = tr[desc_key]
        size_str = _fmt_r_size(r.size_bytes) if r.size_bytes else "—"
        n = len(r.details) if r.details else 0
        kwargs["description"] = tmpl.format(size=size_str, n=n)
    if "impact" in tr:
        kwargs["impact"] = tr.get(f"impact_{r.status}", tr["impact"])
    else:
        ok_key, bad_key = "impact_ok", "impact_bad"
        if r.status == "ok" and ok_key in tr:
            kwargs["impact"] = tr[ok_key]
        elif r.status != "ok" and bad_key in tr:
            kwargs["impact"] = tr[bad_key]
    if "recommendation" in tr:
        kwargs["recommendation"] = tr.get(f"rec_{r.status}", tr["recommendation"])
    else:
        ok_key, bad_key = "rec_ok", "rec_bad"
        if r.status == "ok" and ok_key in tr:
            kwargs["recommendation"] = tr[ok_key]
        elif r.status != "ok" and bad_key in tr:
            kwargs["recommendation"] = tr[bad_key]
    return _dc_replace(r, **kwargs) if kwargs else r


def _fmt_r_size(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f} GB"
    if b >= 1_048_576:     return f"{b/1_048_576:.1f} MB"
    if b >= 1024:          return f"{b/1024:.1f} KB"
    return f"{b} B"


_CHECKS_EN: dict = {
    # ── Security ─────────────────────────────────────────────────────────────
    "firewall": {
        "name":       "Application Firewall",
        "desc_ok":    "The macOS application firewall is enabled.",
        "desc_critical": "The macOS application firewall is DISABLED.",
        "impact_ok":  "None.",
        "impact_bad": "Your Mac accepts unfiltered incoming network connections.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Go to System Settings → Network → Firewall → Enable.",
    },
    "filevault": {
        "name":       "FileVault (disk encryption)",
        "desc_ok":    "FileVault is enabled. The disk is encrypted.",
        "desc_critical": "FileVault is DISABLED. Data on disk is not encrypted.",
        "impact_ok":  "None.",
        "impact_bad": "Anyone with physical access to your Mac can read all your files.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Go to System Settings → Privacy & Security → FileVault → Enable.",
    },
    "gatekeeper": {
        "name":       "Gatekeeper",
        "desc_ok":    "Gatekeeper is enabled. Only verified apps can run.",
        "desc_critical": "Gatekeeper is DISABLED.",
        "impact_ok":  "None.",
        "impact_bad": "Any unsigned app can run without warnings.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Run in Terminal: sudo spctl --master-enable",
    },
    "sip": {
        "name":       "System Integrity Protection (SIP)",
        "desc_ok":    "SIP is enabled. System files are protected.",
        "desc_warning": "SIP is DISABLED.",
        "impact_ok":  "None.",
        "impact_bad": "System files and processes are not protected from unauthorised changes.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Re-enable SIP from Recovery Mode: csrutil enable",
    },
    "ssh": {
        "name":       "Remote SSH",
        "desc_ok":    "The SSH server is not running.",
        "desc_warning": "The SSH server is running and accepting remote connections.",
        "desc_critical": "The SSH server is running and accepting remote connections.",
        "impact_ok":  "None.",
        "impact_bad": "Anyone on the network can attempt to access your Mac via SSH.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Disable SSH if not needed: Settings → General → Sharing → Remote Login.",
    },
    "open_ports": {
        "name":       "Open network ports",
        "desc_ok":    "No TCP ports listening on all interfaces detected.",
        "desc_warning": "Found {n} ports open on all network interfaces.",
        "impact_ok":  "None.",
        "impact_bad": "Processes listening on all interfaces are reachable from the local network.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Verify each process is legitimate. Use the Firewall to restrict access.",
    },
    "login_items": {
        "name":       "Login Items",
        "desc_ok":    "No login items found or access unavailable.",
        "desc_info":  "Found {n} items that launch at login.",
        "impact_ok":  "None.",
        "impact_bad": "Each item slows boot and consumes background resources.",
        "rec_ok":     "Check manually in System Settings → General → Login Items.",
        "rec_bad":    "Remove unneeded items in System Settings → General → Login Items.",
    },
    "launch_agents": {
        "name":       "LaunchAgents / LaunchDaemons",
        "desc_ok":    "No third-party LaunchAgents or LaunchDaemons found.",
        "desc_warning": "Found {n} third-party startup agents.",
        "impact_ok":  "None.",
        "impact_bad": "These processes start automatically and run in the background.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Verify each item. Remove any belonging to uninstalled apps.",
    },
    "pending_updates": {
        "name":       "Security updates",
        "desc_ok":    "System is up to date. No updates available.",
        "desc_warning": "Updates available.",
        "desc_critical": "Updates available (including security updates).",
        "desc_info":  "Unable to check updates (timeout or command unavailable).",
        "impact_ok":  "None.",
        "impact_bad": "System is vulnerable to known exploits if not updated.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Update now in System Settings → General → Software Update.",
    },
    "folder_perms": {
        "name":       "Sensitive folder permissions",
        "desc_ok":    "Permissions on Documents, Desktop, and Downloads are correct.",
        "desc_warning": "Some sensitive folders have overly open permissions.",
        "impact_ok":  "None.",
        "impact_bad": "Other system users can read or modify your files.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Fix permissions with: chmod 700 ~/Documents ~/Desktop ~/Downloads",
    },
    "camera_mic": {
        "name":       "Camera & Microphone access",
        "desc_ok":    "No apps with camera/microphone access found (or TCC DB unavailable).",
        "desc_info":  "Found {n} apps with camera or microphone access.",
        "impact_ok":  "None.",
        "impact_bad": "Listed apps can access your camera or microphone.",
        "rec_ok":     "Check in System Settings → Privacy & Security.",
        "rec_bad":    "Remove access for unused apps in System Settings → Privacy.",
    },
    # ── Storage ──────────────────────────────────────────────────────────────
    "user_caches": {
        "name":       "User caches",
        "desc":       "The ~/Library/Caches folder uses {size}.",
        "impact_ok":  "None.",
        "impact_bad": "Uncleared caches accumulate disk space over time.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Clear caches for unused apps. Apps will regenerate them automatically.",
    },
    "system_temp": {
        "name":       "System temporary files",
        "desc":       "Temporary files in /tmp and /private/var/tmp: {size}.",
        "impact_ok":  "None.",
        "impact_bad": "Temporary files consume disk space and are removed on reboot.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Restart your Mac to clear temporary files automatically.",
    },
    "old_logs": {
        "name":       "System & application logs",
        "desc":       "Total logs: {size}.",
        "impact_ok":  "None.",
        "impact_bad": "Old logs take up space without providing value.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Remove logs older than 30 days.",
    },
    "trash": {
        "name":       "Trash",
        "desc_ok":    "The Trash is empty.",
        "desc_warning": "The Trash contains {size} of files to permanently delete.",
        "impact_ok":  "None.",
        "impact_bad": "Files in the Trash occupy disk space until it is emptied.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Empty the Trash to reclaim space.",
    },
    "ds_store": {
        "name":       ".DS_Store files",
        "desc_ok":    "No .DS_Store files found.",
        "desc_info":  "Found {n} .DS_Store files in the home folder.",
        "desc_warning": ".DS_Store search not completed (timeout or insufficient permissions).",
        "impact_ok":  "None.",
        "impact_bad": ".DS_Store files are macOS metadata. They use little space but may expose folder structure information.",
        "rec_ok":     "No action required.",
        "rec_bad":    "You can safely delete them. macOS will recreate them when you open folders.",
    },
    "large_downloads": {
        "name":       "Large files in Downloads",
        "desc_ok":    "No files >500 MB found in ~/Downloads.",
        "desc_warning": "Found {n} files >500 MB in ~/Downloads ({size} total).",
        "impact_ok":  "None.",
        "impact_bad": "Large files consume valuable SSD space.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Remove or archive Downloads files you no longer need.",
    },
    "ios_backups": {
        "name":       "iOS backups (iTunes/Finder)",
        "desc_ok":    "No iOS backups found.",
        "desc_warning": "iOS backups found: {size}.",
        "impact_ok":  "None.",
        "impact_bad": "Outdated iOS backups take up a lot of space.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Manage backups in Finder → your device → Manage Backups.",
    },
    "mounted_dmgs": {
        "name":       "Mounted .dmg disk images",
        "desc_ok":    "No disk images mounted.",
        "desc_info":  "Found {n} mounted disk images.",
        "impact_ok":  "None.",
        "impact_bad": "Mounted DMGs occupy virtual space and may contain apps to install.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Eject disk images you no longer need.",
    },
    "brew_cache": {
        "name":       "Homebrew cache",
        "desc_ok":    "Homebrew cache is small or already clean.",
        "desc_info":  "Homebrew is not installed.",
        "desc_warning": "The Homebrew cache uses approximately {size}.",
        "impact_ok":  "None.",
        "impact_bad": "Cached formula and bottle downloads take up disk space.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Run: brew cleanup",
    },
    "npm_cache": {
        "name":       "npm cache",
        "desc_ok":    "npm cache: {size}.",
        "desc_info":  "npm is not installed or has no cache.",
        "desc_warning": "The npm cache uses {size}.",
        "impact_ok":  "None.",
        "impact_bad": "The npm cache accumulates downloaded packages.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Run: npm cache clean --force",
    },
    "pip_cache": {
        "name":       "pip cache",
        "desc_ok":    "pip cache: {size}.",
        "desc_info":  "pip has no cache or is not installed.",
        "desc_warning": "The pip cache uses {size}.",
        "impact_ok":  "None.",
        "impact_bad": "The pip cache accumulates downloaded Python packages.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Run: pip cache purge",
    },
    "xcode_derived": {
        "name":       "Xcode DerivedData",
        "desc_ok":    "Xcode DerivedData: {size}.",
        "desc_info":  "Xcode is not installed or has no DerivedData.",
        "desc_warning": "Xcode DerivedData uses {size}.",
        "impact_ok":  "None.",
        "impact_bad": "Xcode derived data accumulates with each build.",
        "rec_ok":     "No action required.",
        "rec_bad":    "In Xcode: Settings → Locations → DerivedData → Delete.",
    },
    # ── Performance ──────────────────────────────────────────────────────────
    "cpu_processes": {
        "name":       "High CPU processes",
        "desc_ok":    "No processes with abnormally high CPU usage detected.",
        "desc_warning": "Processes detected with high CPU usage.",
        "desc_critical": "Processes detected with very high CPU usage.",
        "impact_ok":  "None.",
        "impact_bad": "High CPU processes may overheat your Mac and drain the battery.",
        "rec_ok":     "Monitor with Activity Monitor if you notice slowdowns.",
        "rec_bad":    "Check processes in Activity Monitor. Quit unnecessary ones.",
    },
    "memory_usage": {
        "name":       "RAM memory usage",
        "desc_ok":    "RAM usage is normal.",
        "desc_warning": "RAM usage is high.",
        "desc_critical": "RAM is nearly exhausted.",
        "impact_ok":  "None.",
        "impact_bad": "Exhausted RAM causes disk swapping, slowing down the system.",
        "rec_ok":     "Use Activity Monitor to keep an eye on RAM.",
        "rec_bad":    "Close unused apps. Consider a RAM upgrade.",
    },
    "swap": {
        "name":       "Swap usage (virtual memory)",
        "desc_ok":    "Swap usage is minimal or zero.",
        "desc_warning": "Swap is in use.",
        "desc_critical": "High swap usage detected.",
        "impact_ok":  "None.",
        "impact_bad": "High swap usage indicates insufficient RAM and causes slowdowns.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Close memory-hungry apps. Restart your Mac.",
    },
    "disk_space": {
        "name":       "Available SSD space",
        "desc_ok":    "SSD space is adequate.",
        "desc_warning": "SSD space is getting low.",
        "desc_critical": "SSD space is critically low.",
        "impact_ok":  "None.",
        "impact_bad": "Insufficient SSD space causes system instability.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Free up space by removing unnecessary files.",
    },
    "battery": {
        "name":       "Battery health",
        "desc_ok":    "Battery is in good condition.",
        "desc_warning": "Battery health is degraded.",
        "desc_critical": "Battery health is poor.",
        "impact_ok":  "None.",
        "impact_bad": "Reduced battery life. Your Mac may shut down unexpectedly.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Contact Apple Support for a replacement.",
    },
    "uptime": {
        "name":       "System uptime",
        "desc_ok":    "System uptime is normal.",
        "desc_warning": "System has been running for a long time without a restart.",
        "impact_ok":  "None.",
        "impact_bad": "Extended uptime can cause memory leaks and slowdowns.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Restart your Mac periodically (every 7–14 days).",
    },
    # ── Privacy ──────────────────────────────────────────────────────────────
    "location_access": {
        "name":       "Apps with Location access",
        "desc_ok":    "No apps with location access found.",
        "desc_info":  "Found {n} apps with location access.",
        "impact_ok":  "None.",
        "impact_bad": "These apps know your geographic location.",
        "rec_ok":     "Go to System Settings → Privacy → Location Services.",
        "rec_bad":    "Remove access for unnecessary apps in Settings → Privacy → Location Services.",
    },
    "contacts_access": {
        "name":       "Apps with Contacts access",
        "desc_ok":    "No apps with contacts access found.",
        "desc_info":  "Found {n} apps with contacts access.",
        "impact_ok":  "None.",
        "impact_bad": "These apps can read your contacts' names, emails, and phone numbers.",
        "rec_ok":     "Go to System Settings → Privacy → Contacts.",
        "rec_bad":    "Review the listed apps in Settings → Privacy → Contacts.",
    },
    "calendar_access": {
        "name":       "Apps with Calendar access",
        "desc_ok":    "No apps with calendar access found.",
        "desc_info":  "Found {n} apps with calendar access.",
        "impact_ok":  "None.",
        "impact_bad": "These apps know your appointments and commitments.",
        "rec_ok":     "Go to System Settings → Privacy → Calendars.",
        "rec_bad":    "Review the listed apps in Settings → Privacy → Calendars.",
    },
    "recent_items": {
        "name":       "Recent items",
        "desc_ok":    "No recent items found or feature is disabled.",
        "desc_info":  "Found {n} recent items (apps, documents, servers).",
        "impact_ok":  "None.",
        "impact_bad": "Anyone accessing your Mac can see recently used files and apps.",
        "rec_ok":     "No action required.",
        "rec_bad":    "Clear history in Settings → General → Recent Items → None.",
    },
    "diagnostic_reports": {
        "name":       "Diagnostic reports",
        "desc_ok":    "No diagnostic reports found.",
        "desc_info":  "Found {n} diagnostic report(s).",
        "impact_ok":  "None.",
        "impact_bad": "Diagnostic reports contain detailed system information and may be sent to Apple.",
        "rec_ok":     "No action required.",
        "rec_bad":    "You can delete them in Settings → Privacy → Analytics & Improvements.",
    },
    "siri_data": {
        "name":       "Siri data sharing",
        "desc_ok":    "Siri data sharing is disabled or not configured.",
        "desc_info":  "Siri data sharing is enabled.",
        "impact_ok":  "None.",
        "impact_bad": "Shared Siri data includes voice interactions and personal information.",
        "rec_ok":     "Check in Settings → Privacy → Analytics & Improvements.",
        "rec_bad":    "Disable in Settings → Privacy & Security → Analytics & Improvements.",
    },
    "privacy_summary": {
        "name":       "Privacy access summary",
        "desc_ok":    "No significant privacy accesses detected.",
        "desc_info":  "Found {n} app(s) with privacy access permissions.",
        "impact_ok":  "None.",
        "impact_bad": "Apps with privacy access may read sensitive data.",
        "rec_ok":     "Check manually in System Settings → Privacy & Security.",
        "rec_bad":    "Review access in System Settings → Privacy & Security.",
    },
}

# ── String tables ─────────────────────────────────────────────────────────────

_S: dict[str, dict[str, str]] = {
    "IT": {
        # Header
        "app_subtitle":         "Analisi sicurezza, spazio, performance e privacy del tuo Mac",
        "lang_btn":             "🇬🇧 EN",
        # Disclaimer banner
        "disclaimer_banner":    (
            "⚠  MacGuard Analyzer non modifica nulla senza la tua conferma. "
            "Si consiglia di fare un backup prima di qualsiasi pulizia. "
            "Tutte le operazioni vengono registrate in ~/Library/Logs/MacGuard/"
        ),
        # Categories
        "cat_select_label":     "Seleziona le categorie da analizzare:",
        "cat_security":         "Sicurezza",
        "cat_storage":          "Spazio Disco",
        "cat_performance":      "Performance",
        "cat_privacy":          "Privacy",
        "cat_security_desc":    "Firewall, FileVault, SIP, porte aperte, LaunchAgents",
        "cat_storage_desc":     "Cache, log, Cestino, file grandi, backup iOS",
        "cat_performance_desc": "CPU, RAM, swap, batteria, uptime",
        "cat_privacy_desc":     "Accessi app, cronologia, dati diagnostici",
        # Action bar
        "btn_start":            "▶  Avvia Analisi",
        "btn_stop":             "⏹ Ferma",
        "status_ready":         "Pronto",
        "status_starting":      "Avvio analisi...",
        "status_stopped":       "Analisi interrotta.",
        "status_done":          "✓ Analisi completata — {n} controlli | {c} critici | {w} avvisi",
        # Toolbar
        "btn_export":           "📄 Esporta Report",
        "btn_clean":            "🗑 Pulisci Selezionati",
        "selected_count":       "{n} elemento/i selezionato/i",
        # Filter bar
        "filter_label":         "Filtro:",
        "filter_all":           "Tutti",
        "filter_critical":      "🔴 Critici",
        "filter_warning":       "🟡 Attenzione",
        "filter_ok":            "🟢 OK",
        # Score widget
        "score_label":          "/100\nScore Sicurezza",
        "space_recoverable":    "recuperabili",
        "space_optimal":        "✓ Spazio ottimale",
        # Result cards (UI chrome only — check content stays in scan language)
        "card_select":          "Seleziona",
        "card_impact_prefix":   "⚠ Impatto: ",
        "card_rec_skip":        "Nessuna azione richiesta.",
        "card_impact_skip":     "Nessuno.",
        "card_details":         "▶ Dettagli ({n})",
        "card_details_open":    "▼ Dettagli ({n})",
        "card_details_more":    "  ... e altri {n} elementi",
        # Empty / scanning states
        "empty_msg":            "Seleziona le categorie e avvia l'analisi.",
        "scanning_msg":         "Analisi in corso...",
        # Status badge labels
        "status_critical":      "Critico",
        "status_warning":       "Attenzione",
        "status_ok":            "OK",
        "status_info":          "Info",
        # Dialogs — no category
        "dlg_no_cat_title":     "Nessuna categoria",
        "dlg_no_cat_msg":       "Seleziona almeno una categoria per avviare l'analisi.",
        # Dialogs — no report
        "dlg_no_rep_title":     "Nessun report",
        "dlg_no_rep_msg":       "Avvia prima un'analisi.",
        # Dialogs — export
        "dlg_export_title":     "Esporta Report",
        "dlg_export_ok_title":  "Report esportato",
        "dlg_export_ok_msg":    "Report salvato in:\n{path}\n\nAprirlo ora?",
        "dlg_export_err_title": "Errore esportazione",
        "ft_html":              "HTML (consigliato)",
        "ft_txt":               "Testo",
        "ft_pdf":               "PDF",
        "ft_all":               "Tutti i file",
        # Dialogs — cleanup
        "dlg_no_sel_title":     "Nessuna selezione",
        "dlg_no_sel_msg":       "Seleziona almeno un elemento da pulire.",
        "dlg_clean_confirm_title": "Conferma pulizia",
        "dlg_clean_confirm_msg": (
            "Verranno eseguite le seguenti operazioni:\n\n"
            "{actions}\n\n"
            "⚠ I file verranno spostati nel Cestino (recuperabili).\n\n"
            "Vuoi procedere?"
        ),
        "dlg_clean_done_title": "Pulizia completata",
        "dlg_clean_done_msg":   (
            "Operazioni eseguite:\n\n"
            "{actions}\n\n"
            "Log salvato in ~/Library/Logs/MacGuard/macguard.log"
        ),
        "dlg_clean_err_title":  "Errore durante la pulizia",
        # Startup disclaimer popup
        "disclaimer_popup_title": "MacGuard Analyzer — Disclaimer",
        "disclaimer_popup_body": (
            "⚠  AVVISO IMPORTANTE\n\n"
            "MacGuard Analyzer è fornito 'COSÌ COM'È' senza garanzie.\n"
            "L'autore NON è responsabile per perdita di dati, danni al sistema\n"
            "o conseguenze indesiderate derivanti dall'uso di questo software.\n\n"
            "PRIMA DI QUALSIASI PULIZIA:\n"
            "• Fai sempre un backup dei dati (Time Machine consigliato)\n"
            "• I file vengono spostati nel Cestino — NON eliminati definitivamente\n"
            "• Viene mostrata un'anteprima prima di qualsiasi operazione\n"
            "• Non sono richieste password root/admin per l'analisi\n"
            "• Tutte le operazioni vengono registrate in:\n"
            "  ~/Library/Logs/MacGuard/macguard.log\n\n"
            "Uso a proprio rischio e pericolo.\n"
            "Cliccando Sì accetti questi termini.\n\n"
            "© Emanuele Riccardo Boscaglia — emanuele.boscaglia@gmail.com\n\n"
            "Vuoi procedere?"
        ),
        # Report strings
        "report_title":         "MacGuard Analyzer — Report Analisi Sistema",
        "report_score_lbl":     "SCORE SICUREZZA",
        "report_recoverable_lbl": "SPAZIO RECUPERABILE",
        "report_critical_lbl":  "Critici",
        "report_warning_lbl":   "Attenzione",
        "report_ok_lbl":        "OK",
        "report_impact_lbl":    "Impatto",
        "report_rec_lbl":       "Raccomandazione",
        "report_size_lbl":      "Dimensione",
        "report_footer":        "Report generato da MacGuard Analyzer v1.0.0",
        "report_score_good":    "Ottimo",
        "report_score_mid":     "Migliorabile",
        "report_score_bad":     "Critico",
        "report_space_lbl":     "spazio recuperabile",
        "report_cat_labels": {
            "security":    ("SICUREZZA",    "Sicurezza",    "🔒"),
            "storage":     ("SPAZIO DISCO", "Spazio Disco", "💾"),
            "performance": ("PERFORMANCE",  "Performance",  "⚡"),
            "privacy":     ("PRIVACY",      "Privacy",      "👁"),
        },
        "report_status_long": {
            "critical": "[CRITICO]   ",
            "warning":  "[ATTENZIONE]",
            "ok":       "[OK]        ",
            "info":     "[INFO]      ",
        },
        "report_status_short": {
            "critical": "Critico",
            "warning":  "Attenzione",
            "ok":       "OK",
            "info":     "Info",
        },
        "report_details_more":  "... e altri {n} elementi",
        "report_rec_skip":      "Nessuna azione richiesta.",
        "report_impact_skip":   "Nessuno.",
    },

    "EN": {
        # Header
        "app_subtitle":         "Security, disk space, performance & privacy analysis for your Mac",
        "lang_btn":             "🇮🇹 IT",
        # Disclaimer banner
        "disclaimer_banner":    (
            "⚠  MacGuard Analyzer makes no changes without your confirmation. "
            "Always back up your data before any cleanup. "
            "All actions are logged to ~/Library/Logs/MacGuard/"
        ),
        # Categories
        "cat_select_label":     "Select categories to analyze:",
        "cat_security":         "Security",
        "cat_storage":          "Disk Space",
        "cat_performance":      "Performance",
        "cat_privacy":          "Privacy",
        "cat_security_desc":    "Firewall, FileVault, SIP, open ports, LaunchAgents",
        "cat_storage_desc":     "Caches, logs, Trash, large files, iOS backups",
        "cat_performance_desc": "CPU, RAM, swap, battery, uptime",
        "cat_privacy_desc":     "App access, history, diagnostic data",
        # Action bar
        "btn_start":            "▶  Start Analysis",
        "btn_stop":             "⏹ Stop",
        "status_ready":         "Ready",
        "status_starting":      "Starting analysis...",
        "status_stopped":       "Analysis stopped.",
        "status_done":          "✓ Analysis complete — {n} checks | {c} critical | {w} warnings",
        # Toolbar
        "btn_export":           "📄 Export Report",
        "btn_clean":            "🗑 Clean Selected",
        "selected_count":       "{n} item(s) selected",
        # Filter bar
        "filter_label":         "Filter:",
        "filter_all":           "All",
        "filter_critical":      "🔴 Critical",
        "filter_warning":       "🟡 Warning",
        "filter_ok":            "🟢 OK",
        # Score widget
        "score_label":          "/100\nSecurity Score",
        "space_recoverable":    "recoverable",
        "space_optimal":        "✓ Storage optimal",
        # Result cards
        "card_select":          "Select",
        "card_impact_prefix":   "⚠ Impact: ",
        "card_rec_skip":        "Nessuna azione richiesta.",
        "card_impact_skip":     "Nessuno.",
        "card_details":         "▶ Details ({n})",
        "card_details_open":    "▼ Details ({n})",
        "card_details_more":    "  ... and {n} more items",
        # Empty / scanning states
        "empty_msg":            "Select categories and start the analysis.",
        "scanning_msg":         "Scanning in progress...",
        # Status badge labels
        "status_critical":      "Critical",
        "status_warning":       "Warning",
        "status_ok":            "OK",
        "status_info":          "Info",
        # Dialogs — no category
        "dlg_no_cat_title":     "No category selected",
        "dlg_no_cat_msg":       "Select at least one category to start the analysis.",
        # Dialogs — no report
        "dlg_no_rep_title":     "No report",
        "dlg_no_rep_msg":       "Run an analysis first.",
        # Dialogs — export
        "dlg_export_title":     "Export Report",
        "dlg_export_ok_title":  "Report exported",
        "dlg_export_ok_msg":    "Report saved to:\n{path}\n\nOpen it now?",
        "dlg_export_err_title": "Export error",
        "ft_html":              "HTML (recommended)",
        "ft_txt":               "Text",
        "ft_pdf":               "PDF",
        "ft_all":               "All files",
        # Dialogs — cleanup
        "dlg_no_sel_title":     "Nothing selected",
        "dlg_no_sel_msg":       "Select at least one item to clean.",
        "dlg_clean_confirm_title": "Confirm cleanup",
        "dlg_clean_confirm_msg": (
            "The following operations will be performed:\n\n"
            "{actions}\n\n"
            "⚠ Files will be moved to the Trash (recoverable).\n\n"
            "Do you want to proceed?"
        ),
        "dlg_clean_done_title": "Cleanup complete",
        "dlg_clean_done_msg":   (
            "Operations completed:\n\n"
            "{actions}\n\n"
            "Log saved to ~/Library/Logs/MacGuard/macguard.log"
        ),
        "dlg_clean_err_title":  "Error during cleanup",
        # Startup disclaimer popup
        "disclaimer_popup_title": "MacGuard Analyzer — Disclaimer",
        "disclaimer_popup_body": (
            "⚠  IMPORTANT DISCLAIMER\n\n"
            "MacGuard Analyzer is provided 'AS IS' without any warranty.\n"
            "The author is NOT responsible for data loss, system damage,\n"
            "or unintended consequences arising from use of this software.\n\n"
            "BEFORE ANY CLEANUP OPERATION:\n"
            "• Always back up your data (Time Machine recommended)\n"
            "• Files are moved to the Trash — NOT permanently deleted\n"
            "• A preview is shown before any action is taken\n"
            "• No root/admin password is required for analysis\n"
            "• All operations are logged at:\n"
            "  ~/Library/Logs/MacGuard/macguard.log\n\n"
            "Use entirely at your own risk.\n"
            "By clicking Yes you accept these terms.\n\n"
            "© Emanuele Riccardo Boscaglia — emanuele.boscaglia@gmail.com\n\n"
            "Do you want to proceed?"
        ),
        # Report strings
        "report_title":         "MacGuard Analyzer — System Analysis Report",
        "report_score_lbl":     "SECURITY SCORE",
        "report_recoverable_lbl": "RECOVERABLE SPACE",
        "report_critical_lbl":  "Critical",
        "report_warning_lbl":   "Warning",
        "report_ok_lbl":        "OK",
        "report_impact_lbl":    "Impact",
        "report_rec_lbl":       "Recommendation",
        "report_size_lbl":      "Size",
        "report_footer":        "Report generated by MacGuard Analyzer v1.0.0",
        "report_score_good":    "Good",
        "report_score_mid":     "Fair",
        "report_score_bad":     "Critical",
        "report_space_lbl":     "recoverable space",
        "report_cat_labels": {
            "security":    ("SECURITY",    "Security",    "🔒"),
            "storage":     ("DISK SPACE",  "Disk Space",  "💾"),
            "performance": ("PERFORMANCE", "Performance", "⚡"),
            "privacy":     ("PRIVACY",     "Privacy",     "👁"),
        },
        "report_status_long": {
            "critical": "[CRITICAL] ",
            "warning":  "[WARNING]  ",
            "ok":       "[OK]       ",
            "info":     "[INFO]     ",
        },
        "report_status_short": {
            "critical": "Critical",
            "warning":  "Warning",
            "ok":       "OK",
            "info":     "Info",
        },
        "report_details_more":  "... and {n} more items",
        "report_rec_skip":      "Nessuna azione richiesta.",
        "report_impact_skip":   "Nessuno.",
    },
}