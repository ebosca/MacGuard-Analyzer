"""
MacGuard Analyzer — Scrollable results view with check result cards.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from typing import Callable, Dict, List, Optional

import customtkinter as ctk

from analyzer import AnalysisReport, CheckResult
from ui.styles import (
    STATUS_COLORS, STATUS_BG_COLORS, STATUS_ICONS, STATUS_LABELS,
    CATEGORY_ICONS, CATEGORY_NAMES, CATEGORY_COLORS,
    FONT_HEADING_FB, FONT_BODY_FB, FONT_SMALL_FB,
    CARD_CORNER, CARD_PADDING,
)
from utils import lang as _L


class ResultCard(ctk.CTkFrame):
    """A single result card for one CheckResult."""

    def __init__(
        self,
        parent,
        result: CheckResult,
        on_select_change: Optional[Callable] = None,
        **kwargs,
    ):
        super().__init__(
            parent,
            corner_radius=CARD_CORNER,
            border_width=2,
            border_color=STATUS_COLORS.get(result.status, "#555555"),
            fg_color=STATUS_BG_COLORS.get(result.status, "#1a1a2e"),
            **kwargs,
        )

        self.result = result
        self.on_select_change = on_select_change
        self.selected_var = tk.BooleanVar(value=False)
        self._select_cb: Optional[ctk.CTkCheckBox] = None

        self._build()

    def _build(self):
        r = _L.translate_result(self.result)
        status_color = STATUS_COLORS.get(r.status, "#888888")

        # ── Top row: icon + name + status badge ──────────────────────────
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(fill="x", padx=CARD_PADDING, pady=(CARD_PADDING, 4))

        status_icon = STATUS_ICONS.get(r.status, "⚪")
        ctk.CTkLabel(
            top_frame,
            text=status_icon,
            font=ctk.CTkFont(size=18),
            width=28,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkLabel(
            top_frame,
            text=r.name,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="white",
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        # Status badge
        badge_text = _L.t(f"status_{r.status}") or STATUS_LABELS.get(r.status, r.status.upper())
        ctk.CTkLabel(
            top_frame,
            text=badge_text,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=status_color,
            fg_color=("#1a1a1a", "#111111"),
            corner_radius=4,
            padx=6,
            pady=2,
        ).pack(side="right", padx=(4, 0))

        # Checkbox for cleanable items
        if r.cleanable:
            self._select_cb = ctk.CTkCheckBox(
                top_frame,
                text=_L.t("card_select"),
                variable=self.selected_var,
                command=self._on_checkbox,
                font=ctk.CTkFont(size=10),
                checkbox_width=14,
                checkbox_height=14,
                fg_color=status_color,
                hover_color=status_color,
            )
            self._select_cb.pack(side="right", padx=(4, 8))

        # ── Description ───────────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text=r.description,
            font=ctk.CTkFont(size=12),
            text_color=("#e0e0e0", "#dddddd"),
            wraplength=600,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=CARD_PADDING + 34, pady=(0, 4))

        # ── Impact ────────────────────────────────────────────────────────
        impact_skip = _L.t("card_impact_skip")
        if r.impact and r.impact not in (impact_skip, "Nessuno.", ""):
            ctk.CTkLabel(
                self,
                text=f"{_L.t('card_impact_prefix')}{r.impact}",
                font=ctk.CTkFont(size=11),
                text_color=("#aaaaaa", "#999999"),
                wraplength=600,
                justify="left",
                anchor="w",
            ).pack(fill="x", padx=CARD_PADDING + 34, pady=(0, 2))

        # ── Recommendation ────────────────────────────────────────────────
        rec_skip = _L.t("card_rec_skip")
        if r.recommendation and r.recommendation not in (rec_skip, "Nessuna azione richiesta.", ""):
            ctk.CTkLabel(
                self,
                text=f"→ {r.recommendation}",
                font=ctk.CTkFont(size=11),
                text_color=(status_color, status_color),
                wraplength=600,
                justify="left",
                anchor="w",
            ).pack(fill="x", padx=CARD_PADDING + 34, pady=(0, 4))

        # ── Size badge ────────────────────────────────────────────────────
        if r.size_bytes and r.size_bytes > 0:
            ctk.CTkLabel(
                self,
                text=f"💾 {_fmt_size(r.size_bytes)}",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=("#FB8C00", "#FFA726"),
                anchor="w",
            ).pack(fill="x", padx=CARD_PADDING + 34, pady=(0, 4))

        # ── Collapsible details ───────────────────────────────────────────
        if r.details:
            self._collapsed = True
            self._details_frame: Optional[ctk.CTkFrame] = None

            self._toggle_btn = ctk.CTkButton(
                self,
                text=_L.t("card_details", n=len(r.details)),
                font=ctk.CTkFont(size=10),
                fg_color="transparent",
                hover_color=("#2a2a3e", "#2a2a3e"),
                text_color=("#888888", "#888888"),
                anchor="w",
                height=20,
                command=self._toggle_details,
            )
            self._toggle_btn.pack(fill="x", padx=CARD_PADDING + 28, pady=(0, CARD_PADDING))
        else:
            ctk.CTkLabel(self, text="", height=4).pack()

    def _toggle_details(self):
        n = len(self.result.details)
        if self._collapsed:
            self._details_frame = ctk.CTkFrame(self, fg_color=("#111111", "#0d0d1a"), corner_radius=4)
            self._details_frame.pack(fill="x", padx=CARD_PADDING + 28, pady=(0, CARD_PADDING))
            for detail in self.result.details[:20]:
                ctk.CTkLabel(
                    self._details_frame,
                    text=f"  · {detail}",
                    font=ctk.CTkFont(size=10, family="Courier"),
                    text_color=("#cccccc", "#bbbbbb"),
                    anchor="w",
                    wraplength=560,
                    justify="left",
                ).pack(fill="x", padx=4, pady=1)
            if n > 20:
                ctk.CTkLabel(
                    self._details_frame,
                    text=_L.t("card_details_more", n=n - 20),
                    font=ctk.CTkFont(size=10),
                    text_color="#666666",
                    anchor="w",
                ).pack(fill="x", padx=4, pady=1)
            self._toggle_btn.configure(text=_L.t("card_details_open", n=n))
            self._collapsed = False
        else:
            if self._details_frame:
                self._details_frame.destroy()
                self._details_frame = None
            self._toggle_btn.configure(text=_L.t("card_details", n=n))
            self._collapsed = True

    def refresh_texts(self):
        """Update UI-chrome strings after a language change."""
        if self._select_cb is not None:
            self._select_cb.configure(text=_L.t("card_select"))
        if hasattr(self, "_toggle_btn"):
            n = len(self.result.details)
            key = "card_details_open" if not self._collapsed else "card_details"
            self._toggle_btn.configure(text=_L.t(key, n=n))

    def _on_checkbox(self):
        if self.on_select_change:
            self.on_select_change()

    def is_selected(self) -> bool:
        return self.selected_var.get()


class ScoreWidget(ctk.CTkFrame):
    """Displays security score and recoverable space."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, corner_radius=12, fg_color=("#1a1a2e", "#0d1117"), **kwargs)
        self._build()

    def _build(self):
        self._score_label = ctk.CTkLabel(
            self,
            text="—",
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color="#1E88E5",
        )
        self._score_label.pack(side="left", padx=20, pady=12)

        self._score_text_label = ctk.CTkLabel(
            self,
            text=_L.t("score_label"),
            font=ctk.CTkFont(size=11),
            text_color="#888888",
            justify="left",
        )
        self._score_text_label.pack(side="left", padx=(0, 20))

        self._space_label = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(size=13),
            text_color="#FB8C00",
        )
        self._space_label.pack(side="right", padx=20)

    def update_score(self, score: int, recoverable_bytes: int):
        color = "#43A047" if score >= 80 else ("#FB8C00" if score >= 60 else "#E53935")
        self._score_label.configure(text=str(score), text_color=color)
        if recoverable_bytes > 0:
            self._space_label.configure(
                text=f"💾 {_fmt_size(recoverable_bytes)}\n{_L.t('space_recoverable')}"
            )
        else:
            self._space_label.configure(text=_L.t("space_optimal"))

    def refresh_texts(self):
        self._score_text_label.configure(text=_L.t("score_label"))
        # Re-render space label with updated language if a score is showing
        current = self._score_label.cget("text")
        if current not in ("—", "0"):
            if "💾" in self._space_label.cget("text"):
                # Keep the size portion, just re-translate the label
                size_part = self._space_label.cget("text").split("\n")[0]
                self._space_label.configure(text=f"{size_part}\n{_L.t('space_recoverable')}")
            elif self._space_label.cget("text"):
                self._space_label.configure(text=_L.t("space_optimal"))


class ResultsView(ctk.CTkFrame):
    """Main results panel — scrollable list of result cards with summary."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)

        self._cards: List[ResultCard] = []
        self._report: Optional[AnalysisReport] = None
        self._filter_btns: List[ctk.CTkRadioButton] = []
        self._filter_labels_keys = ["filter_all", "filter_critical", "filter_warning", "filter_ok"]
        self._filter_values = ["tutti", "critical", "warning", "ok"]

        self._build()

    def _build(self):
        self._score_widget = ScoreWidget(self)
        self._score_widget.pack(fill="x", padx=8, pady=(8, 4))

        # Filter bar
        filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        filter_frame.pack(fill="x", padx=8, pady=(4, 4))

        self._filter_lbl = ctk.CTkLabel(
            filter_frame, text=_L.t("filter_label"),
            font=ctk.CTkFont(size=11), text_color="#888888"
        )
        self._filter_lbl.pack(side="left", padx=(0, 4))

        self._filter_var = tk.StringVar(value="tutti")
        self._filter_btns = []
        for key, value in zip(self._filter_labels_keys, self._filter_values):
            btn = ctk.CTkRadioButton(
                filter_frame,
                text=_L.t(key),
                value=value,
                variable=self._filter_var,
                command=self._apply_filter,
                font=ctk.CTkFont(size=11),
                radiobutton_width=14,
                radiobutton_height=14,
            )
            btn.pack(side="left", padx=6)
            self._filter_btns.append(btn)

        # Scrollable cards
        self._scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=("#0d0d1a", "#0d0d1a"),
            corner_radius=8,
        )
        self._scroll.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        self._empty_label = ctk.CTkLabel(
            self._scroll,
            text=_L.t("empty_msg"),
            font=ctk.CTkFont(size=14),
            text_color="#555555",
        )
        self._empty_label.pack(pady=60)

    def add_result(self, result: CheckResult):
        """Add a single result card (called from UI thread during analysis)."""
        if self._empty_label.winfo_exists():
            self._empty_label.pack_forget()

        card = ResultCard(
            self._scroll,
            result,
            on_select_change=self._on_selection_changed,
        )
        card.pack(fill="x", padx=4, pady=4)
        self._cards.append(card)

        self._scroll._parent_canvas.after(50, lambda: self._scroll._parent_canvas.yview_moveto(1.0))

    def update_report(self, report: AnalysisReport):
        """Update score display after analysis completes."""
        self._report = report
        self._score_widget.update_score(report.security_score, report.recoverable_bytes)

    def clear(self):
        """Clear all cards for a new analysis."""
        for card in self._cards:
            card.destroy()
        self._cards.clear()
        self._report = None
        self._score_widget.update_score(0, 0)
        self._score_widget._score_label.configure(text="—", text_color="#1E88E5")
        self._score_widget._space_label.configure(text="")

        self._empty_label = ctk.CTkLabel(
            self._scroll,
            text=_L.t("scanning_msg"),
            font=ctk.CTkFont(size=14),
            text_color="#555555",
        )
        self._empty_label.pack(pady=60)

    def refresh_texts(self):
        """Rebuild all cards and update UI-chrome strings after a language change."""
        self._filter_lbl.configure(text=_L.t("filter_label"))
        for btn, key in zip(self._filter_btns, self._filter_labels_keys):
            btn.configure(text=_L.t(key))
        self._score_widget.refresh_texts()
        # Rebuild every card so translated check content is applied
        results = [card.result for card in self._cards]
        for card in self._cards:
            card.destroy()
        self._cards.clear()
        for result in results:
            card = ResultCard(
                self._scroll,
                result,
                on_select_change=self._on_selection_changed,
            )
            card.pack(fill="x", padx=4, pady=4)
            self._cards.append(card)
        self._apply_filter()

    def get_selected_ids(self) -> List[str]:
        """Return check_ids of all selected (checked) items."""
        return [card.result.check_id for card in self._cards if card.is_selected()]

    def get_all_results(self):
        return [card.result for card in self._cards]

    def _apply_filter(self):
        filt = self._filter_var.get()
        for card in self._cards:
            if filt == "tutti" or card.result.status == filt:
                card.pack(fill="x", padx=4, pady=4)
            else:
                card.pack_forget()

    def _on_selection_changed(self):
        selected = self.get_selected_ids()
        if hasattr(self, "on_selection_changed"):
            self.on_selection_changed(selected)


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"
