"""
MacGuard Analyzer — Performance analysis module.
"""

from __future__ import annotations

import re
from typing import List, Optional

from analyzer import CheckEntry, CheckResult
from utils import commands as cmd

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


# ── Checks ───────────────────────────────────────────────────────────────────

def check_cpu_processes() -> CheckResult:
    details: List[str] = []

    if HAS_PSUTIL:
        try:
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent"]):
                try:
                    procs.append(p.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            # Sort by CPU
            procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
            top5 = procs[:5]
            details = [
                f"{p['name']} (PID {p['pid']}): {p.get('cpu_percent', 0):.1f}% CPU"
                for p in top5
            ]
            high_cpu = [p for p in top5 if (p.get("cpu_percent") or 0) > 50]

            if high_cpu:
                return CheckResult(
                    check_id="cpu_processes",
                    name="Processi con alto consumo CPU",
                    status="warning",
                    description=f"{len(high_cpu)} processo/i con CPU >50%.",
                    impact="Processi ad alto consumo CPU possono surriscaldare il Mac e scaricare la batteria.",
                    recommendation="Verifica i processi in Activity Monitor. Termina quelli non necessari.",
                    category="performance",
                    details=details,
                )
        except Exception:
            pass  # fall through to ps-based check
    else:
        # Fallback: parse ps output
        rc, out, _ = cmd.get_top_processes()
        if rc == 0 and out:
            lines = out.strip().splitlines()
            for line in lines[1:6]:  # skip header, top 5
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    details.append(f"{parts[3].strip()}: {parts[1]}% CPU")

    return CheckResult(
        check_id="cpu_processes",
        name="Processi con alto consumo CPU",
        status="ok",
        description="Nessun processo con CPU eccessivo rilevato.",
        impact="Nessuno.",
        recommendation="Monitora con Activity Monitor se noti rallentamenti.",
        category="performance",
        details=details[:5],
    )


def check_memory_usage() -> CheckResult:
    details: List[str] = []

    if HAS_PSUTIL:
        try:
            mem = psutil.virtual_memory()
            used_pct = mem.percent
            total_str = _fmt_size(mem.total)
            used_str = _fmt_size(mem.used)
            avail_str = _fmt_size(mem.available)
            details = [
                f"Totale: {total_str}",
                f"Utilizzata: {used_str} ({used_pct:.0f}%)",
                f"Disponibile: {avail_str}",
            ]

            if used_pct > 90:
                status = "critical"
                desc = f"RAM al {used_pct:.0f}%: il sistema sta usando swap pesantemente."
            elif used_pct > 75:
                status = "warning"
                desc = f"RAM al {used_pct:.0f}%: possibile rallentamento."
            else:
                status = "ok"
                desc = f"RAM al {used_pct:.0f}%: utilizzo normale."

            # Top RAM consumers
            procs = []
            for p in psutil.process_iter(["pid", "name", "memory_percent"]):
                try:
                    procs.append(p.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            procs.sort(key=lambda x: x.get("memory_percent") or 0, reverse=True)
            for p in procs[:3]:
                details.append(
                    f"{p['name']} (PID {p['pid']}): {p.get('memory_percent', 0):.1f}% RAM"
                )

            return CheckResult(
                check_id="memory_usage",
                name="Utilizzo memoria RAM",
                status=status,
                description=desc,
                impact="RAM esaurita causa swap su disco, rallentando il sistema.",
                recommendation="Chiudi le app non in uso. Considera un upgrade della RAM.",
                category="performance",
                details=details,
            )
        except Exception:
            pass

    # Fallback: vm_stat
    rc, out, _ = cmd.get_vm_stat()
    if rc == 0:
        details = [line.strip() for line in out.splitlines()[:8]]

    return CheckResult(
        check_id="memory_usage",
        name="Utilizzo memoria RAM",
        status="info",
        description="Dati memoria disponibili tramite vm_stat.",
        impact="Nessuno.",
        recommendation="Usa Activity Monitor per monitorare la RAM.",
        category="performance",
        details=details[:6],
    )


def check_swap_usage() -> CheckResult:
    rc, out, _ = cmd.get_swap_usage()
    if rc != 0:
        return CheckResult(
            check_id="swap",
            name="Utilizzo swap",
            status="info",
            description="Impossibile leggere l'utilizzo swap.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="performance",
        )

    # Parse: vm.swapusage: total = 1024.00M  used = 512.00M  free = 512.00M
    match = re.search(r"used\s*=\s*([\d.]+)([MG])", out)
    if not match:
        return CheckResult(
            check_id="swap",
            name="Utilizzo swap",
            status="ok",
            description="Swap non in uso.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="performance",
        )

    val = float(match.group(1))
    unit = match.group(2)
    swap_bytes = int(val * (1024**3 if unit == "G" else 1024**2))
    swap_str = _fmt_size(swap_bytes)

    if HAS_PSUTIL:
        try:
            swap = psutil.swap_memory()
            swap_bytes = swap.used
            swap_str = _fmt_size(swap_bytes)
        except Exception:
            pass

    if swap_bytes > 4 * 1024**3:
        status = "warning"
    elif swap_bytes > 1 * 1024**3:
        status = "warning"
    else:
        status = "ok"

    return CheckResult(
        check_id="swap",
        name="Utilizzo swap (memoria virtuale)",
        status=status,
        description=f"Swap in uso: {swap_str}.",
        impact="Alto utilizzo swap indica RAM insufficiente e causa rallentamenti.",
        recommendation="Chiudi le app che consumano più memoria. Riavvia il Mac.",
        category="performance",
        details=[f"Swap utilizzato: {swap_str}", out.strip()],
    )


def check_disk_space() -> CheckResult:
    rc, out, _ = cmd.get_disk_usage()
    if rc != 0:
        return CheckResult(
            check_id="disk_space",
            name="Spazio SSD disponibile",
            status="info",
            description="Impossibile leggere lo spazio disco.",
            impact="Sconosciuto.",
            recommendation="Verifica con: df -h /",
            category="performance",
        )

    lines = out.strip().splitlines()
    if len(lines) < 2:
        return CheckResult(
            check_id="disk_space",
            name="Spazio SSD disponibile",
            status="info",
            description="Impossibile parsare i dati disco.",
            impact="Sconosciuto.",
            recommendation="Verifica con: df -h /",
            category="performance",
        )

    parts = lines[1].split()
    # Format: Filesystem 1K-blocks Used Available Use% Mounted
    if len(parts) >= 5:
        try:
            total_kb = int(parts[1])
            used_kb = int(parts[2])
            avail_kb = int(parts[3])
            use_pct = int(parts[4].strip("%"))
            free_pct = 100 - use_pct

            total_str = _fmt_size(total_kb * 1024)
            avail_str = _fmt_size(avail_kb * 1024)
            used_str = _fmt_size(used_kb * 1024)

            if free_pct < 5:
                status = "critical"
                desc = f"Spazio SSD CRITICO: solo {avail_str} liberi ({free_pct}%)!"
            elif free_pct < 10:
                status = "critical"
                desc = f"Spazio SSD molto basso: {avail_str} liberi ({free_pct}%)."
            elif free_pct < 20:
                status = "warning"
                desc = f"Spazio SSD in esaurimento: {avail_str} liberi ({free_pct}%)."
            else:
                status = "ok"
                desc = f"Spazio SSD: {avail_str} liberi su {total_str} ({free_pct}% disponibile)."

            return CheckResult(
                check_id="disk_space",
                name="Spazio SSD disponibile",
                status=status,
                description=desc,
                impact="Spazio SSD insufficiente causa instabilità del sistema.",
                recommendation="Libera spazio eliminando file non necessari.",
                category="performance",
                details=[
                    f"Totale: {total_str}",
                    f"Utilizzato: {used_str} ({use_pct}%)",
                    f"Disponibile: {avail_str} ({free_pct}%)",
                ],
            )
        except (ValueError, IndexError):
            pass

    return CheckResult(
        check_id="disk_space",
        name="Spazio SSD disponibile",
        status="info",
        description="Dati disco non parsabili.",
        impact="Sconosciuto.",
        recommendation="Verifica con: df -h /",
        category="performance",
    )


def _get_battery_from_system_profiler() -> Optional[dict]:
    """
    Parse battery info from system_profiler SPPowerDataType -json.
    Returns dict with keys: health_pct, cycle_count, charge_pct, condition, max_mah, design_mah
    Returns None if unavailable.
    """
    import json as _json
    rc, out, _ = cmd.run(
        ["/usr/sbin/system_profiler", "SPPowerDataType", "-json"],
        timeout=15,
    )
    if rc != 0 or not out.strip():
        return None
    try:
        data = _json.loads(out)
        entries = data.get("SPPowerDataType", [])
        if not entries:
            return None
        entry = entries[0]

        result: dict = {}

        # Health percentage (the reliable field on all architectures)
        health_info = entry.get("sppower_battery_health_info", {})
        if "sppower_battery_health_percent" in health_info:
            result["health_pct"] = int(health_info["sppower_battery_health_percent"])
        if "sppower_battery_cycle_count" in health_info:
            result["cycle_count"] = int(health_info["sppower_battery_cycle_count"])
        if "sppower_battery_health" in health_info:
            result["condition"] = health_info["sppower_battery_health"]  # "Good", "Fair", "Poor"

        # Current charge
        charge_info = entry.get("sppower_battery_charge_info", {})
        if "sppower_battery_charge_percent" in charge_info:
            result["charge_pct"] = int(charge_info["sppower_battery_charge_percent"])

        # Capacities (may not be present on all models)
        if "sppower_battery_max_capacity" in entry:
            result["max_mah"] = entry["sppower_battery_max_capacity"]
        if "sppower_battery_design_capacity" in entry:
            result["design_mah"] = entry["sppower_battery_design_capacity"]

        return result if result else None
    except Exception:
        return None


def _get_battery_from_ioreg() -> Optional[dict]:
    """
    Parse battery info from ioreg AppleSmartBattery.
    Uses AppleRawMaxCapacity (mAh) instead of MaxCapacity (which may be %).
    Returns dict with health_pct, cycle_count, charge_pct.
    """
    rc, out, _ = cmd.get_ioreg_battery()
    if rc != 0 or not out:
        return None

    result: dict = {}

    # CycleCount
    m = re.search(r'"CycleCount"\s*=\s*(\d+)', out)
    if m:
        result["cycle_count"] = int(m.group(1))

    # AppleRawMaxCapacity and DesignCapacity — both in mAh on Intel & Apple Silicon
    raw_max = re.search(r'"AppleRawMaxCapacity"\s*=\s*(\d+)', out)
    design  = re.search(r'"DesignCapacity"\s*=\s*(\d+)', out)
    if raw_max and design:
        max_mah    = int(raw_max.group(1))
        design_mah = int(design.group(1))
        if design_mah > 0:
            result["health_pct"] = round(max_mah / design_mah * 100)
            result["max_mah"]    = max_mah
            result["design_mah"] = design_mah

    # NOTE: CurrentCapacity in ioreg is a percentage (0-100) on Apple Silicon,
    # but mAh on Intel — do NOT compute charge_pct here to avoid unit mismatch.
    # Charge % is always read from pmset in check_battery().

    return result if result else None


def check_battery() -> CheckResult:
    # Quick check: does the Mac have a battery at all?
    rc, pmset_out, _ = cmd.get_battery_info()
    no_battery = (
        rc != 0
        or "no battery" in pmset_out.lower()
        or "not installed" in pmset_out.lower()
        or "battery" not in pmset_out.lower()
    )
    if no_battery:
        return CheckResult(
            check_id="battery",
            name="Stato batteria",
            status="info",
            description="Nessuna batteria rilevata (Mac desktop o non applicabile).",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="performance",
        )

    # Try system_profiler first (most reliable on Apple Silicon)
    info = _get_battery_from_system_profiler()

    # Fall back to ioreg if system_profiler gave nothing useful
    if not info or "health_pct" not in info:
        info = _get_battery_from_ioreg() or {}

    # Also pull charge % from pmset if not yet found
    if "charge_pct" not in info:
        m = re.search(r"(\d+)%", pmset_out)
        if m:
            info["charge_pct"] = int(m.group(1))

    # Build detail lines
    details: List[str] = []
    if "charge_pct" in info:
        details.append(f"Carica attuale: {info['charge_pct']}%")
    if "health_pct" in info:
        details.append(f"Salute batteria: {info['health_pct']}%")
    if "condition" in info:
        details.append(f"Condizione: {info['condition']}")
    if "cycle_count" in info:
        details.append(f"Cicli di ricarica: {info['cycle_count']}")
    if "max_mah" in info and "design_mah" in info:
        details.append(f"Capacità attuale: {info['max_mah']} mAh / {info['design_mah']} mAh (design)")

    health_pct  = info.get("health_pct")
    cycle_count = info.get("cycle_count")

    # ── Evaluate health ────────────────────────────────────────────────────
    if health_pct is not None:
        if health_pct < 60:
            return CheckResult(
                check_id="battery",
                name="Stato batteria",
                status="critical",
                description=f"Salute batteria al {health_pct}%. Sostituzione consigliata.",
                impact="Autonomia molto ridotta. Il Mac potrebbe spegnersi inaspettatamente.",
                recommendation="Contatta l'assistenza Apple per la sostituzione.",
                category="performance",
                details=details,
            )
        if health_pct < 80:
            return CheckResult(
                check_id="battery",
                name="Stato batteria",
                status="warning",
                description=f"Salute batteria al {health_pct}%. L'autonomia è ridotta.",
                impact="Autonomia inferiore rispetto al nuovo.",
                recommendation="Monitora la salute in Impostazioni → Batteria → Salute batteria.",
                category="performance",
                details=details,
            )
        return CheckResult(
            check_id="battery",
            name="Stato batteria",
            status="ok",
            description=f"Batteria in ottimo stato ({health_pct}% di salute).",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="performance",
            details=details,
        )

    # ── No health data — fall back to cycle count ──────────────────────────
    if cycle_count is not None:
        if cycle_count > 1000:
            status, desc = "warning", f"{cycle_count} cicli di ricarica (limite Apple: ~1000)."
        elif cycle_count > 800:
            status, desc = "warning", f"{cycle_count} cicli — inizia a monitorare la salute."
        else:
            status, desc = "ok", f"Batteria con {cycle_count} cicli, in buono stato."
        return CheckResult(
            check_id="battery",
            name="Stato batteria",
            status=status,
            description=desc,
            impact="Cicli elevati riducono progressivamente l'autonomia.",
            recommendation="Verifica la salute in Impostazioni di Sistema → Batteria → Salute batteria.",
            category="performance",
            details=details,
        )

    # ── No data at all ─────────────────────────────────────────────────────
    return CheckResult(
        check_id="battery",
        name="Stato batteria",
        status="info",
        description="Dati batteria non disponibili.",
        impact="Nessuno.",
        recommendation="Verifica in Impostazioni di Sistema → Batteria → Salute batteria.",
        category="performance",
        details=details,
    )


def check_uptime() -> CheckResult:
    rc, out, _ = cmd.get_uptime()
    if rc != 0:
        return CheckResult(
            check_id="uptime",
            name="Uptime sistema",
            status="info",
            description="Impossibile leggere l'uptime.",
            impact="Nessuno.",
            recommendation="Nessuna azione richiesta.",
            category="performance",
        )

    # Parse days from uptime output: "up X days, ..."
    days_match = re.search(r"up\s+(\d+)\s+day", out)
    days = int(days_match.group(1)) if days_match else 0

    # Also check hours
    if not days_match:
        hrs_match = re.search(r"up\s+(\d+):(\d+)", out)
        if hrs_match:
            days = 0  # less than a day

    if days > 14:
        status = "warning"
        desc = f"Mac acceso da {days} giorni. Un riavvio periodico è consigliato."
    elif days > 7:
        status = "info"
        desc = f"Mac acceso da {days} giorni."
    else:
        status = "ok"
        desc = f"Uptime normale: {out.strip().split(',')[0].strip()}."

    return CheckResult(
        check_id="uptime",
        name="Uptime sistema",
        status=status,
        description=desc,
        impact="Uptime prolungato può causare perdite di memoria e rallentamenti.",
        recommendation="Riavvia periodicamente il Mac (ogni 7-14 giorni).",
        category="performance",
        details=[out.strip()],
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def get_all_checks() -> List[CheckEntry]:
    return [
        (check_cpu_processes, "Processi CPU"),
        (check_memory_usage,  "Utilizzo RAM"),
        (check_swap_usage,    "Utilizzo Swap"),
        (check_disk_space,    "Spazio SSD"),
        (check_battery,       "Stato Batteria"),
        (check_uptime,        "Uptime sistema"),
    ]
