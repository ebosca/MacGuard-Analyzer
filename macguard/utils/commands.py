"""
MacGuard Analyzer — Safe shell command wrappers.

SECURITY RULES:
- NEVER use shell=True
- ALWAYS use argument lists
- NEVER pass user-supplied strings directly as command arguments
- All subprocess calls must go through run()
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import List, Tuple

LOG = logging.getLogger("macguard.commands")

# ── Core wrapper ─────────────────────────────────────────────────────────────

def run(args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    """
    Single entry point for all subprocess calls.
    Returns (returncode, stdout, stderr).
    Never raises — all exceptions are caught and returned as rc=-1.
    """
    LOG.debug("run: %s", args)
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        LOG.warning("timeout (%ds): %s", timeout, args)
        return -1, "", f"timeout dopo {timeout}s"
    except FileNotFoundError:
        LOG.debug("command not found: %s", args[0])
        return -1, "", f"comando non trovato: {args[0]}"
    except Exception as exc:
        LOG.error("run error %s: %s", args, exc)
        return -1, "", str(exc)


# ── Security checks ──────────────────────────────────────────────────────────

def check_firewall() -> Tuple[int, str, str]:
    return run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])


def check_filevault() -> Tuple[int, str, str]:
    return run(["/usr/bin/fdesetup", "status"])


def check_sip() -> Tuple[int, str, str]:
    return run(["/usr/bin/csrutil", "status"])


def check_gatekeeper() -> Tuple[int, str, str]:
    return run(["/usr/sbin/spctl", "--status"])


def check_ssh_running() -> Tuple[int, str, str]:
    return run(["/bin/launchctl", "list", "com.openssh.sshd"])


def get_open_ports() -> Tuple[int, str, str]:
    return run(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20)


def get_login_items_osascript() -> Tuple[int, str, str]:
    script = 'tell application "System Events" to get name of every login item'
    return run(["/usr/bin/osascript", "-e", script])


def get_pending_updates() -> Tuple[int, str, str]:
    return run(["/usr/sbin/softwareupdate", "-l"], timeout=60)


def get_folder_permissions(path: str) -> Tuple[int, str, str]:
    return run(["/usr/bin/stat", "-f", "%Sp %Su %Sg", path])


def query_tcc_db(service: str) -> Tuple[int, str, str]:
    """Query user-level TCC database. May fail silently on modern macOS (SIP-protected)."""
    db = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")
    sql = f"SELECT client FROM access WHERE service='{service}' AND auth_value=2"
    return run(["/usr/bin/sqlite3", db, sql])


def get_privacy_report() -> Tuple[int, str, str]:
    """Fallback: system_profiler for privacy info (no root needed)."""
    return run(["/usr/sbin/system_profiler", "SPPrivacyDataType", "-json"], timeout=30)


def get_launch_agents_list() -> List[Path]:
    """Return list of LaunchAgent/LaunchDaemon plist paths."""
    dirs = [
        Path.home() / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    plists: List[Path] = []
    for d in dirs:
        if d.exists():
            plists.extend(d.glob("*.plist"))
    return plists


# ── Storage checks ───────────────────────────────────────────────────────────

def get_dir_size_kb(path: str) -> Tuple[int, str, str]:
    return run(["/usr/bin/du", "-sk", path], timeout=30)


def get_trash_size() -> Tuple[int, str, str]:
    return run(["/usr/bin/du", "-sk", str(Path.home() / ".Trash")], timeout=20)


def find_ds_store(directory: str) -> Tuple[int, str, str]:
    return run(
        ["/usr/bin/find", directory, "-maxdepth", "3", "-name", ".DS_Store", "-type", "f"],
        timeout=15,
    )


def find_large_files(directory: str, min_size_mb: int = 500) -> Tuple[int, str, str]:
    """Find files larger than min_size_mb MB (up to depth 3)."""
    size_bytes = min_size_mb * 1024 * 1024
    return run(
        [
            "/usr/bin/find", directory,
            "-maxdepth", "3",
            "-type", "f",
            "-size", f"+{size_bytes}c",
        ],
        timeout=30,
    )


def get_mounted_dmgs() -> Tuple[int, str, str]:
    return run(["/usr/bin/hdiutil", "info"])


def check_brew_available() -> bool:
    for path in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
        if Path(path).exists():
            return True
    return False


def get_brew_path() -> str:
    for path in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
        if Path(path).exists():
            return path
    return "brew"


def brew_cleanup_dry_run() -> Tuple[int, str, str]:
    return run([get_brew_path(), "cleanup", "--dry-run"], timeout=60)


def get_brew_cache_size() -> Tuple[int, str, str]:
    rc, path, _ = run([get_brew_path(), "--cache"])
    if rc == 0 and path.strip():
        return run(["/usr/bin/du", "-sk", path.strip()], timeout=20)
    return -1, "", "brew cache non trovata"


def check_xcode_derived_data() -> Tuple[int, str, str]:
    path = str(Path.home() / "Library/Developer/Xcode/DerivedData")
    return run(["/usr/bin/du", "-sk", path], timeout=30)


def check_ios_backups() -> Tuple[int, str, str]:
    path = str(Path.home() / "Library/Application Support/MobileSync/Backup")
    return run(["/usr/bin/du", "-sk", path], timeout=30)


# ── Performance checks ───────────────────────────────────────────────────────

def get_vm_stat() -> Tuple[int, str, str]:
    return run(["/usr/bin/vm_stat"])


def get_swap_usage() -> Tuple[int, str, str]:
    return run(["/usr/sbin/sysctl", "vm.swapusage"])


def get_disk_usage() -> Tuple[int, str, str]:
    return run(["/bin/df", "-k", "/"])


def get_battery_info() -> Tuple[int, str, str]:
    return run(["/usr/bin/pmset", "-g", "batt"])


def get_ioreg_battery() -> Tuple[int, str, str]:
    return run(["/usr/sbin/ioreg", "-rn", "AppleSmartBattery"], timeout=10)


def get_uptime() -> Tuple[int, str, str]:
    return run(["/usr/bin/uptime"])


def get_memory_pressure() -> Tuple[int, str, str]:
    return run(["/usr/bin/memory_pressure"])


def get_top_processes() -> Tuple[int, str, str]:
    """Get process list sorted by CPU."""
    return run(["/bin/ps", "-arcwwwxo", "pid,pcpu,pmem,comm"], timeout=10)


# ── Privacy checks ───────────────────────────────────────────────────────────

def get_recent_items() -> Tuple[int, str, str]:
    return run(
        ["/usr/bin/defaults", "read", "com.apple.recentitems"],
        timeout=10,
    )


def get_diagnostics_size() -> Tuple[int, str, str]:
    path = str(Path.home() / "Library/Logs/DiagnosticReports")
    return run(["/usr/bin/du", "-sk", path], timeout=15)


def check_siri_data_sharing() -> Tuple[int, str, str]:
    return run(
        ["/usr/bin/defaults", "read", "com.apple.assistant.support",
         "Siri Data Sharing Opt-In Status"],
        timeout=5,
    )


def check_diagnostic_reports_opt_in() -> Tuple[int, str, str]:
    return run(
        ["/usr/bin/defaults", "read", "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist",
         "AutoSubmit"],
        timeout=5,
    )


# ── Cleanup ──────────────────────────────────────────────────────────────────

def move_to_trash_osascript(path: str) -> Tuple[int, str, str]:
    """
    Move a file/directory to Trash via Finder (recoverable).
    path must be absolute.
    """
    if not path.startswith("/"):
        raise ValueError(f"Il percorso deve essere assoluto: {path}")
    script = f'tell application "Finder" to move POSIX file "{path}" to trash'
    return run(["/usr/bin/osascript", "-e", script], timeout=30)


def empty_trash_osascript() -> Tuple[int, str, str]:
    script = 'tell application "Finder" to empty trash'
    return run(["/usr/bin/osascript", "-e", script], timeout=60)


def brew_cleanup_run() -> Tuple[int, str, str]:
    return run([get_brew_path(), "cleanup"], timeout=120)
