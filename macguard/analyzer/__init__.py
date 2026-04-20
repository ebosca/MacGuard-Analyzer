"""
MacGuard Analyzer — Data model shared by all analyzer modules.
"""

from __future__ import annotations

import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Literal, Optional, Tuple

StatusType = Literal["critical", "warning", "ok", "info"]


@dataclass
class CheckResult:
    check_id: str
    name: str
    status: StatusType
    description: str
    impact: str
    recommendation: str
    category: str = ""          # "security" | "storage" | "performance" | "privacy"
    cleanable: bool = False
    size_bytes: Optional[int] = None
    details: List[str] = field(default_factory=list)
    clean_paths: List[str] = field(default_factory=list)
    clean_command: Optional[str] = None   # e.g. "brew_cleanup", "empty_trash"


@dataclass
class AnalysisReport:
    results: List[CheckResult] = field(default_factory=list)
    security_score: int = 100
    recoverable_bytes: int = 0
    timestamp: str = ""
    macos_version: str = ""
    hostname: str = ""


def compute_security_score(results: List[CheckResult]) -> int:
    score = 100
    for r in results:
        if r.category == "security":
            if r.status == "critical":
                score -= 15
            elif r.status == "warning":
                score -= 5
    return max(0, score)


def compute_recoverable_bytes(results: List[CheckResult]) -> int:
    return sum(r.size_bytes for r in results if r.cleanable and r.size_bytes)


def build_report(results: List[CheckResult]) -> AnalysisReport:
    ver = platform.mac_ver()[0] or "sconosciuta"
    return AnalysisReport(
        results=results,
        security_score=compute_security_score(results),
        recoverable_bytes=compute_recoverable_bytes(results),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        macos_version=ver,
        hostname=socket.gethostname(),
    )


# Type alias for check list entries
CheckEntry = Tuple[Callable[[], "CheckResult | List[CheckResult]"], str]
