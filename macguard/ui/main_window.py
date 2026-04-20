"""
MacGuard Analyzer — Main application window.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Callable, Dict, List, Optional, Tuple

import customtkinter as ctk

from analyzer import AnalysisReport, CheckResult, build_report
from ui.results_view import ResultsView
from ui.styles import (
    APP_NAME, APP_VERSION,
    CATEGORY_COLORS, CATEGORY_ICONS,
    WINDOW_WIDTH, WINDOW_HEIGHT, MIN_WIDTH, MIN_HEIGHT,
)
from utils import cleaner, reporter
from utils import lang as _L


# ── Analysis thread ──────────────────────────────────────────────────────────

class AnalysisThread(threading.Thread):
    def __init__(self, categories: List[str], result_queue: queue.Queue):
        super().__init__(daemon=True)
        self.categories = categories
        self.result_queue = result_queue
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def emit(self, msg_type: str, payload):
        self.result_queue.put((msg_type, payload))

    def run(self):
        all_checks = self._build_check_list()
        total = len(all_checks)
        results: List[CheckResult] = []

        for i, (check_fn, label) in enumerate(all_checks):
            if self._stop_event.is_set():
                break

            self.emit("progress", {"step": i, "total": total, "label": label})

            try:
                result = check_fn()
                if isinstance(result, list):
                    for r in result:
                        self.emit("result", r)
                        results.append(r)
                elif result is not None:
                    self.emit("result", result)
                    results.append(result)
            except Exception as exc:
                import logging
                logging.getLogger("macguard.thread").error("Check error [%s]: %s", label, exc)

        self.emit("progress", {"step": total, "total": total, "label": _L.t("status_starting")})
        report = build_report(results)
        self.emit("done", report)

    def _build_check_list(self):
        checks = []
        if "security" in self.categories:
            from analyzer.security import get_all_checks
            checks.extend(get_all_checks())
        if "storage" in self.categories:
            from analyzer.storage import get_all_checks
            checks.extend(get_all_checks())
        if "performance" in self.categories:
            from analyzer.performance import get_all_checks
            checks.extend(get_all_checks())
        if "privacy" in self.categories:
            from analyzer.privacy import get_all_checks
            checks.extend(get_all_checks())
        return checks


# ── Main window ──────────────────────────────────────────────────────────────

class MainWindow(ctk.CTk):

    def __init__(self):
        super().__init__()

        self._analysis_thread: Optional[AnalysisThread] = None
        self._result_queue: queue.Queue = queue.Queue()
        self._current_report: Optional[AnalysisReport] = None
        self._poll_job: Optional[str] = None
        self._last_report_stats: Optional[Tuple[int, int, int]] = None  # (total, critical, warnings)

        self._setup_window()
        self._build_ui()

    # ── Window setup ──────────────────────────────────────────────────────

    def _setup_window(self):
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.minsize(MIN_WIDTH, MIN_HEIGHT)

        self.update_idletasks()
        x = (self.winfo_screenwidth() - WINDOW_WIDTH) // 2
        y = (self.winfo_screenheight() - WINDOW_HEIGHT) // 2
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")

        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

    # ── Logo loader ───────────────────────────────────────────────────────

    def _load_logo(self, size: int = 52) -> Optional[ctk.CTkImage]:
        """Load logo.png as CTkImage. Returns None if PIL is unavailable."""
        try:
            from PIL import Image as PILImage
            logo_path = Path(__file__).parent.parent.parent / "img" / "logo.png"
            if logo_path.exists():
                pil = PILImage.open(logo_path)
                return ctk.CTkImage(light_image=pil, dark_image=pil, size=(size, size))
        except Exception:
            pass
        return None

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_rowconfigure(0, weight=0)    # header
        self.grid_rowconfigure(1, weight=0)    # disclaimer
        self.grid_rowconfigure(2, weight=0)    # categories
        self.grid_rowconfigure(3, weight=0)    # action bar
        self.grid_rowconfigure(4, weight=1)    # results (expands)
        self.grid_rowconfigure(5, weight=0)    # bottom toolbar
        self.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_disclaimer()
        self._build_categories()
        self._build_action_bar()
        self._build_results()
        self._build_toolbar()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=("#1565C0", "#0d1b4b"), corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        # Logo
        logo_img = self._load_logo(52)
        if logo_img:
            ctk.CTkLabel(header, image=logo_img, text="").grid(
                row=0, column=0, rowspan=2, padx=(16, 4), pady=10, sticky="w"
            )
            title_padx = (4, 20)
        else:
            title_padx = (20, 20)

        ctk.CTkLabel(
            header,
            text="MacGuard Analyzer",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="white",
        ).grid(row=0, column=1, pady=(14, 4), padx=title_padx, sticky="w")

        self._subtitle_label = ctk.CTkLabel(
            header,
            text=_L.t("app_subtitle"),
            font=ctk.CTkFont(size=12),
            text_color=("#aaccff", "#8ab4f8"),
        )
        self._subtitle_label.grid(row=1, column=1, pady=(0, 12), padx=title_padx, sticky="w")

        # Button group: theme toggle + language toggle
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.grid(row=0, column=2, rowspan=2, padx=16, sticky="e")

        ctk.CTkButton(
            btn_frame,
            text="☀ / 🌙",
            width=64,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="transparent",
            hover_color=("#1976D2", "#1a2a5e"),
            command=self._toggle_theme,
        ).pack(pady=(8, 3))

        self._lang_btn = ctk.CTkButton(
            btn_frame,
            text=_L.t("lang_btn"),
            width=64,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="transparent",
            hover_color=("#1976D2", "#1a2a5e"),
            command=self._toggle_lang,
        )
        self._lang_btn.pack(pady=(3, 8))

    def _build_disclaimer(self):
        disc = ctk.CTkFrame(self, fg_color=("#fff3cd", "#3d2e00"), corner_radius=0)
        disc.grid(row=1, column=0, sticky="ew")

        self._disclaimer_label = ctk.CTkLabel(
            disc,
            text=_L.t("disclaimer_banner"),
            font=ctk.CTkFont(size=11),
            text_color=("#7d5a00", "#f5c842"),
            wraplength=860,
            justify="left",
        )
        self._disclaimer_label.pack(padx=16, pady=8, anchor="w")

    def _build_categories(self):
        cat_frame = ctk.CTkFrame(self, fg_color=("#f0f4ff", "#111827"), corner_radius=0)
        cat_frame.grid(row=2, column=0, sticky="ew")
        cat_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._cat_select_label = ctk.CTkLabel(
            cat_frame,
            text=_L.t("cat_select_label"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#333333", "#cccccc"),
        )
        self._cat_select_label.grid(row=0, column=0, columnspan=4, padx=16, pady=(12, 8), sticky="w")

        self._category_vars: Dict[str, tk.BooleanVar] = {}
        self._cat_checkboxes: Dict[str, ctk.CTkCheckBox] = {}
        self._cat_desc_labels: Dict[str, ctk.CTkLabel] = {}
        categories = ["security", "storage", "performance", "privacy"]

        for col, cat in enumerate(categories):
            var = tk.BooleanVar(value=True)
            self._category_vars[cat] = var
            color = CATEGORY_COLORS[cat]

            card = ctk.CTkFrame(cat_frame, corner_radius=8, fg_color=("#ffffff", "#1a1f2e"),
                                border_width=2, border_color=color)
            card.grid(row=1, column=col, padx=8, pady=(0, 12), sticky="ew")

            cb = ctk.CTkCheckBox(
                card,
                text=f"{CATEGORY_ICONS[cat]}  {_L.t('cat_' + cat)}",
                variable=var,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=color,
                fg_color=color,
                hover_color=color,
                checkmark_color="white",
            )
            cb.pack(padx=10, pady=(10, 4), anchor="w")
            self._cat_checkboxes[cat] = cb

            desc = ctk.CTkLabel(
                card,
                text=_L.t(f"cat_{cat}_desc"),
                font=ctk.CTkFont(size=10),
                text_color=("#666666", "#888888"),
                wraplength=180,
                justify="left",
            )
            desc.pack(padx=10, pady=(0, 10), anchor="w")
            self._cat_desc_labels[cat] = desc

    def _build_action_bar(self):
        action = ctk.CTkFrame(self, fg_color=("#e8f0fe", "#0d1117"), corner_radius=0)
        action.grid(row=3, column=0, sticky="ew")
        action.grid_columnconfigure(2, weight=1)

        self._start_btn = ctk.CTkButton(
            action,
            text=_L.t("btn_start"),
            font=ctk.CTkFont(size=15, weight="bold"),
            height=44,
            width=180,
            fg_color=("#1565C0", "#1E88E5"),
            hover_color=("#0d47a1", "#1565C0"),
            command=self._start_analysis,
        )
        self._start_btn.grid(row=0, column=0, padx=16, pady=10)

        self._stop_btn = ctk.CTkButton(
            action,
            text=_L.t("btn_stop"),
            font=ctk.CTkFont(size=12),
            height=44,
            width=100,
            fg_color=("#c62828", "#b71c1c"),
            hover_color=("#b71c1c", "#7f0000"),
            command=self._stop_analysis,
            state="disabled",
        )
        self._stop_btn.grid(row=0, column=1, padx=(0, 8), pady=10, sticky="w")

        progress_frame = ctk.CTkFrame(action, fg_color="transparent")
        progress_frame.grid(row=0, column=2, padx=8, pady=10, sticky="ew")

        self._progress_bar = ctk.CTkProgressBar(
            progress_frame,
            height=12,
            corner_radius=6,
            progress_color="#1E88E5",
            fg_color=("#ccddff", "#1a1f2e"),
        )
        self._progress_bar.pack(fill="x", padx=0, pady=(0, 4))
        self._progress_bar.set(0)

        self._status_label = ctk.CTkLabel(
            progress_frame,
            text=_L.t("status_ready"),
            font=ctk.CTkFont(size=11),
            text_color=("#555555", "#888888"),
            anchor="w",
        )
        self._status_label.pack(fill="x")

    def _build_results(self):
        self._results_view = ResultsView(self)
        self._results_view.grid(row=4, column=0, sticky="nsew", padx=8, pady=4)
        self._results_view.on_selection_changed = self._on_selection_changed

    def _build_toolbar(self):
        toolbar = ctk.CTkFrame(self, fg_color=("#e8f0fe", "#0d1117"), corner_radius=0)
        toolbar.grid(row=5, column=0, sticky="ew")

        self._export_btn = ctk.CTkButton(
            toolbar,
            text=_L.t("btn_export"),
            font=ctk.CTkFont(size=12),
            height=36,
            width=160,
            fg_color=("#43A047", "#388E3C"),
            hover_color=("#388E3C", "#2E7D32"),
            command=self._export_report,
            state="disabled",
        )
        self._export_btn.pack(side="left", padx=12, pady=8)

        self._clean_btn = ctk.CTkButton(
            toolbar,
            text=_L.t("btn_clean"),
            font=ctk.CTkFont(size=12),
            height=36,
            width=180,
            fg_color=("#E53935", "#c62828"),
            hover_color=("#c62828", "#7f0000"),
            command=self._clean_selected,
            state="disabled",
        )
        self._clean_btn.pack(side="left", padx=(0, 12), pady=8)

        self._clean_count_label = ctk.CTkLabel(
            toolbar,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=("#555555", "#888888"),
        )
        self._clean_count_label.pack(side="left", padx=4)

        ctk.CTkLabel(
            toolbar,
            text=f"MacGuard v{APP_VERSION}",
            font=ctk.CTkFont(size=10),
            text_color=("#aaaaaa", "#555555"),
        ).pack(side="right", padx=12)

    # ── Analysis control ──────────────────────────────────────────────────

    def _start_analysis(self):
        selected = [cat for cat, var in self._category_vars.items() if var.get()]
        if not selected:
            messagebox.showwarning(_L.t("dlg_no_cat_title"), _L.t("dlg_no_cat_msg"))
            return

        self._results_view.clear()
        self._current_report = None
        self._last_report_stats = None
        self._progress_bar.set(0)
        self._status_label.configure(text=_L.t("status_starting"))
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._export_btn.configure(state="disabled")
        self._clean_btn.configure(state="disabled")
        self._clean_count_label.configure(text="")

        self._result_queue = queue.Queue()
        self._analysis_thread = AnalysisThread(selected, self._result_queue)
        self._analysis_thread.start()
        self._poll_queue()

    def _stop_analysis(self):
        if self._analysis_thread and self._analysis_thread.is_alive():
            self._analysis_thread.stop()
        self._status_label.configure(text=_L.t("status_stopped"))
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                msg_type, payload = self._result_queue.get_nowait()

                if msg_type == "progress":
                    step  = payload["step"]
                    total = payload["total"]
                    label = payload["label"]
                    self._progress_bar.set(step / total if total > 0 else 0)
                    self._status_label.configure(text=f"{label} ({step}/{total})")

                elif msg_type == "result":
                    self._results_view.add_result(payload)

                elif msg_type == "done":
                    self._on_analysis_done(payload)
                    return

        except queue.Empty:
            pass

        self._poll_job = self.after(50, self._poll_queue)

    def _on_analysis_done(self, report: AnalysisReport):
        self._current_report = report
        self._results_view.update_report(report)

        self._progress_bar.set(1.0)
        n = len(report.results)
        c = sum(1 for r in report.results if r.status == "critical")
        w = sum(1 for r in report.results if r.status == "warning")
        self._last_report_stats = (n, c, w)
        self._status_label.configure(text=_L.t("status_done", n=n, c=c, w=w))

        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._export_btn.configure(state="normal")

    def _on_selection_changed(self, selected_ids: List[str]):
        if selected_ids:
            self._clean_btn.configure(state="normal")
            self._clean_count_label.configure(text=_L.t("selected_count", n=len(selected_ids)))
        else:
            self._clean_btn.configure(state="disabled")
            self._clean_count_label.configure(text="")

    # ── Export ────────────────────────────────────────────────────────────

    def _export_report(self):
        if not self._current_report:
            messagebox.showinfo(_L.t("dlg_no_rep_title"), _L.t("dlg_no_rep_msg"))
            return

        path = filedialog.asksaveasfilename(
            title=_L.t("dlg_export_title"),
            defaultextension=".html",
            filetypes=[
                (_L.t("ft_html"), "*.html"),
                (_L.t("ft_txt"),  "*.txt"),
                (_L.t("ft_pdf"),  "*.pdf"),
                (_L.t("ft_all"),  "*.*"),
            ],
            initialfile="MacGuard_Report.html",
        )
        if not path:
            return

        try:
            if path.endswith(".pdf"):
                actual_path = reporter.export_pdf(self._current_report, path)
            elif path.endswith(".txt"):
                reporter.export_txt(self._current_report, path)
                actual_path = path
            else:
                if not path.endswith(".html"):
                    path += ".html"
                reporter.export_html(self._current_report, path)
                actual_path = path

            open_now = messagebox.askyesno(
                _L.t("dlg_export_ok_title"),
                _L.t("dlg_export_ok_msg", path=actual_path),
            )
            if open_now:
                import subprocess
                subprocess.run(["/usr/bin/open", actual_path], check=False)

        except Exception as exc:
            messagebox.showerror(_L.t("dlg_export_err_title"), str(exc))

    # ── Cleanup ───────────────────────────────────────────────────────────

    def _clean_selected(self):
        selected_ids = self._results_view.get_selected_ids()
        if not selected_ids:
            messagebox.showinfo(_L.t("dlg_no_sel_title"), _L.t("dlg_no_sel_msg"))
            return

        all_results = self._results_view.get_all_results()
        actions = cleaner.clean_selected(all_results, selected_ids, dry_run=True)
        action_text = "\n".join(f"  • {a}" for a in actions)

        confirm = messagebox.askyesno(
            _L.t("dlg_clean_confirm_title"),
            _L.t("dlg_clean_confirm_msg", actions=action_text),
        )
        if not confirm:
            return

        try:
            done_actions = cleaner.clean_selected(all_results, selected_ids, dry_run=False)
            done_text = "\n".join(f"  ✓ {a}" for a in done_actions[:20])
            if len(done_actions) > 20:
                done_text += "\n..."
            messagebox.showinfo(
                _L.t("dlg_clean_done_title"),
                _L.t("dlg_clean_done_msg", actions=done_text),
            )
        except Exception as exc:
            messagebox.showerror(_L.t("dlg_clean_err_title"), str(exc))

    # ── Theme toggle ──────────────────────────────────────────────────────

    def _toggle_theme(self):
        current = ctk.get_appearance_mode()
        ctk.set_appearance_mode("Light" if current == "Dark" else "Dark")

    # ── Language toggle ───────────────────────────────────────────────────

    def _toggle_lang(self):
        _L.set_lang("EN" if _L.get_lang() == "IT" else "IT")
        self._refresh_texts()

    def _refresh_texts(self):
        """Update all text-bearing widgets after a language change."""
        # Header
        self._subtitle_label.configure(text=_L.t("app_subtitle"))
        self._lang_btn.configure(text=_L.t("lang_btn"))
        # Disclaimer banner
        self._disclaimer_label.configure(text=_L.t("disclaimer_banner"))
        # Category section
        self._cat_select_label.configure(text=_L.t("cat_select_label"))
        for cat in ["security", "storage", "performance", "privacy"]:
            self._cat_checkboxes[cat].configure(
                text=f"{CATEGORY_ICONS[cat]}  {_L.t('cat_' + cat)}"
            )
            self._cat_desc_labels[cat].configure(text=_L.t(f"cat_{cat}_desc"))
        # Action bar
        self._start_btn.configure(text=_L.t("btn_start"))
        self._stop_btn.configure(text=_L.t("btn_stop"))
        # Status label — restore meaningful text based on current state
        if self._last_report_stats:
            n, c, w = self._last_report_stats
            self._status_label.configure(text=_L.t("status_done", n=n, c=c, w=w))
        elif not (self._analysis_thread and self._analysis_thread.is_alive()):
            self._status_label.configure(text=_L.t("status_ready"))
        # Toolbar
        self._export_btn.configure(text=_L.t("btn_export"))
        self._clean_btn.configure(text=_L.t("btn_clean"))
        sel = self._results_view.get_selected_ids()
        if sel:
            self._clean_count_label.configure(text=_L.t("selected_count", n=len(sel)))
        # Results view
        self._results_view.refresh_texts()
