"""
MacGuard Analyzer — Report generation (HTML, TXT, optional PDF).
"""

from __future__ import annotations

import base64
import html
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from analyzer import AnalysisReport, CheckResult
from utils import lang as _L

LOG = logging.getLogger("macguard.reporter")

SEPARATOR = "─" * 60

_LOGO_PATH = Path(__file__).parent.parent.parent / "img" / "logo.png"


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _logo_b64() -> str:
    """Return logo2.png as a base64 data URI, or '' if unavailable."""
    try:
        if _LOGO_PATH.exists():
            return "data:image/png;base64," + base64.b64encode(_LOGO_PATH.read_bytes()).decode("ascii")
    except Exception:
        pass
    return ""


def _build_txt_lines(report: AnalysisReport) -> List[str]:
    lines: List[str] = []
    sl = _L.t("report_status_long")
    cat_map = _L.t("report_cat_labels")

    lines.append("=" * 60)
    lines.append(f"  MacGuard Analyzer — {_L.t('report_title').split('— ', 1)[-1]}")
    lines.append("=" * 60)
    lines.append(f"  {report.timestamp}")
    lines.append(f"  macOS {report.macos_version}  |  {report.hostname}")
    lines.append("")

    score = report.security_score
    score_bar = "█" * (score // 10) + "░" * (10 - score // 10)
    lines.append(f"  {_L.t('report_score_lbl')}:  {score}/100  [{score_bar}]")

    if report.recoverable_bytes:
        lines.append(f"  {_L.t('report_recoverable_lbl')}: {_fmt_size(report.recoverable_bytes)}")

    critical = sum(1 for r in report.results if r.status == "critical")
    warnings  = sum(1 for r in report.results if r.status == "warning")
    ok_count  = sum(1 for r in report.results if r.status == "ok")
    lines.append(
        f"  {_L.t('report_critical_lbl')}: {critical}  |  "
        f"{_L.t('report_warning_lbl')}: {warnings}  |  "
        f"{_L.t('report_ok_lbl')}: {ok_count}"
    )
    lines.append("")
    lines.append(SEPARATOR)

    order = {"critical": 0, "warning": 1, "ok": 2, "info": 3}
    for cat in ["security", "storage", "performance", "privacy"]:
        cat_results = [r for r in report.results if r.category == cat]
        if not cat_results:
            continue

        txt_label, _, _ = cat_map.get(cat, (cat.upper(), cat.title(), ""))
        lines.append("")
        lines.append(f"  {txt_label}")
        lines.append(SEPARATOR)
        cat_results.sort(key=lambda r: order.get(r.status, 4))

        imp_skip = _L.t("report_impact_skip")
        rec_skip = _L.t("report_rec_skip")

        for _r in cat_results:
            result = _L.translate_result(_r)
            label = sl.get(result.status, "[?]        ")
            lines.append(f"  {label}  {result.name}")
            lines.append(f"            {result.description}")
            if result.impact and result.impact not in (imp_skip, "Nessuno."):
                lines.append(f"            {_L.t('report_impact_lbl')}: {result.impact}")
            if result.recommendation and result.recommendation not in (rec_skip, "Nessuna azione richiesta."):
                lines.append(f"            {_L.t('report_rec_lbl')}: {result.recommendation}")
            if result.size_bytes:
                lines.append(f"            {_L.t('report_size_lbl')}: {_fmt_size(result.size_bytes)}")
            if result.details:
                for detail in result.details[:5]:
                    lines.append(f"            · {detail}")
            lines.append("")

    lines.append(SEPARATOR)
    lines.append(f"  {_L.t('report_footer')}")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    return lines


def export_txt(report: AnalysisReport, path: str) -> None:
    """Export report to a UTF-8 text file."""
    lines = _build_txt_lines(report)
    content = "\n".join(lines)
    output_path = Path(path)
    output_path.write_text(content, encoding="utf-8")
    LOG.info("Report TXT esportato: %s", path)


def export_html(report: AnalysisReport, path: str) -> None:
    """Export report to a self-contained HTML file (no external dependencies)."""

    STATUS_COLORS_HTML = {
        "critical": "#E53935",
        "warning":  "#FB8C00",
        "ok":       "#43A047",
        "info":     "#1E88E5",
    }
    STATUS_BG_HTML = {
        "critical": "#3d1010",
        "warning":  "#3d2200",
        "ok":       "#0f2d10",
        "info":     "#0d1e3d",
    }
    STATUS_ICONS_HTML = {
        "critical": "🔴",
        "warning":  "🟡",
        "ok":       "🟢",
        "info":     "🔵",
    }

    _ss = _L.t("report_status_short")
    _cat = _L.t("report_cat_labels")

    STATUS_LABELS_HTML = {k: _ss.get(k, k) for k in ("critical", "warning", "ok", "info")}
    CATEGORY_NAMES_HTML = {
        cat: (_cat[cat][2], _cat[cat][1], c)
        for cat, c in [
            ("security", "#E53935"), ("storage", "#FB8C00"),
            ("performance", "#1E88E5"), ("privacy", "#43A047"),
        ]
    }

    score = report.security_score
    score_color = "#43A047" if score >= 80 else ("#FB8C00" if score >= 60 else "#E53935")
    score_pct = score  # 0–100, used for the progress arc

    critical = sum(1 for r in report.results if r.status == "critical")
    warnings  = sum(1 for r in report.results if r.status == "warning")
    ok_count  = sum(1 for r in report.results if r.status == "ok")
    info_count = sum(1 for r in report.results if r.status == "info")

    recoverable = _fmt_size(report.recoverable_bytes) if report.recoverable_bytes else "—"

    order = {"critical": 0, "warning": 1, "ok": 2, "info": 3}

    # ── Build category sections ───────────────────────────────────────────────
    cat_sections = ""
    for cat in ["security", "storage", "performance", "privacy"]:
        cat_results = sorted(
            [r for r in report.results if r.category == cat],
            key=lambda r: order.get(r.status, 4),
        )
        if not cat_results:
            continue

        icon, label, color = CATEGORY_NAMES_HTML[cat]
        items_html = ""
        for _r in cat_results:
            r = _L.translate_result(_r)
            sc = STATUS_COLORS_HTML.get(r.status, "#888")
            bg = STATUS_BG_HTML.get(r.status, "#1a1a1a")
            si = STATUS_ICONS_HTML.get(r.status, "⚪")
            sl = STATUS_LABELS_HTML.get(r.status, r.status)
            esc_name = html.escape(r.name)
            esc_desc = html.escape(r.description)
            _rec_skip = _L.t("report_rec_skip")
            _imp_skip = _L.t("report_impact_skip")
            esc_rec  = html.escape(r.recommendation) if r.recommendation and r.recommendation not in (_rec_skip, "Nessuna azione richiesta.") else ""
            esc_imp  = html.escape(r.impact) if r.impact and r.impact not in (_imp_skip, "Nessuno.") else ""

            size_badge = ""
            if r.size_bytes:
                size_badge = f'<span class="size-badge">💾 {html.escape(_fmt_size(r.size_bytes))}</span>'

            details_html = ""
            if r.details:
                detail_items = "".join(
                    f"<li>{html.escape(str(d))}</li>" for d in r.details[:20]
                )
                more = f"<li><em>{_L.t('report_details_more', n=len(r.details)-20)}</em></li>" if len(r.details) > 20 else ""
                details_html = f"""
                <details class="details-block">
                  <summary>Details / Dettagli ({len(r.details)})</summary>
                  <ul>{detail_items}{more}</ul>
                </details>"""

            rec_html = f'<p class="rec">→ {esc_rec}</p>' if esc_rec else ""
            imp_html = f'<p class="impact">⚠ Impatto: {esc_imp}</p>' if esc_imp else ""

            items_html += f"""
        <div class="card" style="border-left:4px solid {sc}; background:{bg};">
          <div class="card-header">
            <span class="status-icon">{si}</span>
            <span class="card-name">{esc_name}</span>
            <span class="badge" style="color:{sc}; border-color:{sc};">{sl}</span>
          </div>
          <p class="desc">{esc_desc}</p>
          {imp_html}
          {rec_html}
          {size_badge}
          {details_html}
        </div>"""

        cat_sections += f"""
      <section class="category">
        <h2 class="cat-title" style="border-left:4px solid {color};">
          {icon} {label}
        </h2>
        {items_html}
      </section>"""

    # ── Full HTML document ────────────────────────────────────────────────────
    logo_src = _logo_b64()
    logo_html = f'<img src="{logo_src}" alt="MacGuard Logo" style="height:56px;margin-right:16px;vertical-align:middle;border-radius:8px;">' if logo_src else "🛡"
    lang_code = "en" if _L.get_lang() == "EN" else "it"

    doc = f"""<!DOCTYPE html>
<html lang="{lang_code}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MacGuard Analyzer — Report</title>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --surface2: #21262d;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --score-color: {score_color};
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 0 0 40px 0;
    }}

    /* Header */
    .header {{
      background: linear-gradient(135deg, #0d1b4b 0%, #1565C0 100%);
      padding: 32px 40px 28px;
      border-bottom: 1px solid #1E88E5;
    }}
    .header h1 {{ font-size: 28px; font-weight: 700; color: #fff; margin-bottom: 4px; }}
    .header .meta {{ color: #8ab4f8; font-size: 13px; }}

    /* Summary bar */
    .summary {{
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      align-items: center;
      background: var(--surface);
      padding: 24px 40px;
      border-bottom: 1px solid var(--border);
    }}
    .score-block {{
      display: flex;
      align-items: center;
      gap: 16px;
    }}
    .score-ring {{
      position: relative;
      width: 90px;
      height: 90px;
    }}
    .score-ring svg {{
      transform: rotate(-90deg);
    }}
    .score-ring .bg-circle {{
      fill: none;
      stroke: var(--surface2);
      stroke-width: 8;
    }}
    .score-ring .fg-circle {{
      fill: none;
      stroke: {score_color};
      stroke-width: 8;
      stroke-linecap: round;
      stroke-dasharray: 251.2;
      stroke-dashoffset: {251.2 - (score_pct / 100 * 251.2):.1f};
      transition: stroke-dashoffset 1s ease;
    }}
    .score-number {{
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      font-weight: 700;
      color: {score_color};
      line-height: 1;
    }}
    .score-number small {{ font-size: 11px; color: var(--muted); font-weight: 400; }}
    .score-label {{ font-size: 14px; color: var(--muted); }}
    .score-label strong {{ display: block; font-size: 16px; color: var(--text); }}

    .stat-pills {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .pill {{
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      border: 1px solid;
    }}
    .pill-critical {{ color: #E53935; border-color: #E53935; background: #3d1010; }}
    .pill-warning  {{ color: #FB8C00; border-color: #FB8C00; background: #3d2200; }}
    .pill-ok       {{ color: #43A047; border-color: #43A047; background: #0f2d10; }}
    .pill-info     {{ color: #1E88E5; border-color: #1E88E5; background: #0d1e3d; }}

    .space-block {{
      margin-left: auto;
      text-align: right;
    }}
    .space-block .space-val {{
      font-size: 22px;
      font-weight: 700;
      color: #FB8C00;
    }}
    .space-block small {{ color: var(--muted); font-size: 12px; }}

    /* Main content */
    .content {{ max-width: 900px; margin: 0 auto; padding: 24px 40px; }}

    /* Category */
    .category {{ margin-bottom: 36px; }}
    .cat-title {{
      font-size: 18px;
      font-weight: 700;
      padding: 10px 16px;
      margin-bottom: 12px;
      background: var(--surface);
      border-radius: 6px;
      padding-left: 20px;
    }}

    /* Card */
    .card {{
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 10px;
      border: 1px solid rgba(255,255,255,0.06);
    }}
    .card-header {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
    }}
    .status-icon {{ font-size: 16px; flex-shrink: 0; }}
    .card-name {{ font-size: 14px; font-weight: 600; flex: 1; }}
    .badge {{
      font-size: 10px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid;
      white-space: nowrap;
    }}
    .desc {{ font-size: 13px; color: var(--text); margin-bottom: 4px; padding-left: 26px; }}
    .impact {{ font-size: 12px; color: var(--muted); padding-left: 26px; margin-bottom: 2px; }}
    .rec {{ font-size: 12px; padding-left: 26px; margin-top: 4px; font-style: italic; }}
    .size-badge {{
      display: inline-block;
      margin-left: 26px;
      margin-top: 6px;
      font-size: 12px;
      font-weight: 600;
      color: #FB8C00;
      background: #3d2200;
      padding: 2px 8px;
      border-radius: 4px;
    }}

    /* Details */
    .details-block {{
      margin-top: 8px;
      margin-left: 26px;
    }}
    .details-block summary {{
      font-size: 11px;
      color: var(--muted);
      cursor: pointer;
      user-select: none;
      padding: 2px 0;
    }}
    .details-block summary:hover {{ color: var(--text); }}
    .details-block ul {{
      margin-top: 6px;
      padding-left: 16px;
      font-size: 11px;
      color: var(--muted);
      font-family: "SF Mono", "Courier New", monospace;
      list-style: disc;
      line-height: 1.8;
    }}

    /* Footer */
    .footer {{
      text-align: center;
      color: var(--muted);
      font-size: 11px;
      padding: 20px;
      border-top: 1px solid var(--border);
      margin-top: 20px;
    }}

    @media print {{
      body {{ background: #fff; color: #111; }}
      .header {{ background: #1565C0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .card {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>

  <header class="header">
    <h1>{logo_html} MacGuard Analyzer</h1>
    <div class="meta">
      {html.escape(report.hostname)} &nbsp;·&nbsp;
      macOS {html.escape(report.macos_version)} &nbsp;·&nbsp;
      {html.escape(report.timestamp)}
    </div>
  </header>

  <div class="summary">
    <div class="score-block">
      <div class="score-ring">
        <svg width="90" height="90" viewBox="0 0 90 90">
          <circle class="bg-circle" cx="45" cy="45" r="40"/>
          <circle class="fg-circle" cx="45" cy="45" r="40"/>
        </svg>
        <div class="score-number">
          {score}<br><small>/100</small>
        </div>
      </div>
      <div class="score-label">
        <strong>{_L.t("report_score_lbl").title()}</strong>
        {_L.t("report_score_good") if score >= 80 else (_L.t("report_score_mid") if score >= 60 else _L.t("report_score_bad"))}
      </div>
    </div>

    <div class="stat-pills">
      <span class="pill pill-critical">🔴 {critical} {_L.t("report_critical_lbl")}</span>
      <span class="pill pill-warning">🟡 {warnings} {_L.t("report_warning_lbl")}</span>
      <span class="pill pill-ok">🟢 {ok_count} {_L.t("report_ok_lbl")}</span>
      <span class="pill pill-info">🔵 {info_count} Info</span>
    </div>

    <div class="space-block">
      <div class="space-val">{html.escape(recoverable)}</div>
      <small>{_L.t("report_space_lbl")}</small>
    </div>
  </div>

  <main class="content">
    {cat_sections}
  </main>

  <footer class="footer">
    {_L.t("report_footer")} — {html.escape(report.timestamp)}
  </footer>

</body>
</html>"""

    Path(path).write_text(doc, encoding="utf-8")
    LOG.info("Report HTML esportato: %s", path)


def export_pdf(report: AnalysisReport, path: str) -> str:
    """
    Export report to PDF using reportlab.
    Falls back to TXT export if reportlab is not installed.
    Returns the actual path of the exported file.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        STATUS_COLORS_PDF = {
            "critical": colors.HexColor("#E53935"),
            "warning":  colors.HexColor("#FB8C00"),
            "ok":       colors.HexColor("#43A047"),
            "info":     colors.HexColor("#1E88E5"),
        }

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )
        styles = getSampleStyleSheet()
        story = []

        # Logo
        if _LOGO_PATH.exists():
            try:
                from reportlab.platypus import Image as RLImage
                logo = RLImage(str(_LOGO_PATH), width=28 * mm, height=28 * mm)
                story.append(logo)
                story.append(Spacer(1, 3 * mm))
            except Exception:
                pass

        # Title
        title_style = ParagraphStyle(
            "title",
            parent=styles["Title"],
            fontSize=22,
            spaceAfter=4 * mm,
            textColor=colors.HexColor("#1565C0"),
        )
        story.append(Paragraph(f"MacGuard Analyzer — {_L.t('report_title').split('— ', 1)[-1]}", title_style))

        # Meta
        meta_style = ParagraphStyle("meta", parent=styles["Normal"], fontSize=10, spaceAfter=2 * mm)
        story.append(Paragraph(
            f"{report.timestamp} | macOS {report.macos_version} | {report.hostname}", meta_style
        ))

        # Score
        score_color = colors.HexColor("#43A047") if report.security_score >= 80 else (
            colors.HexColor("#FB8C00") if report.security_score >= 60 else colors.HexColor("#E53935")
        )
        score_style = ParagraphStyle("score", parent=styles["Normal"], fontSize=14, spaceAfter=4 * mm,
                                     textColor=score_color)
        story.append(Paragraph(f"{_L.t('report_score_lbl')}: {report.security_score}/100", score_style))

        if report.recoverable_bytes:
            story.append(Paragraph(
                f"{_L.t('report_recoverable_lbl')}: {_fmt_size(report.recoverable_bytes)}", meta_style
            ))

        story.append(Spacer(1, 6 * mm))

        # Results by category
        cat_style = ParagraphStyle("cat", parent=styles["Heading2"], fontSize=14, spaceAfter=2 * mm,
                                   textColor=colors.HexColor("#333333"))
        item_style = ParagraphStyle("item", parent=styles["Normal"], fontSize=10, leading=14,
                                    spaceAfter=2 * mm)

        order = {"critical": 0, "warning": 1, "ok": 2, "info": 3}
        cat_map = _L.t("report_cat_labels")
        ss = _L.t("report_status_short")
        rec_skip = _L.t("report_rec_skip")

        for cat in ["security", "storage", "performance", "privacy"]:
            cat_results = sorted(
                [r for r in report.results if r.category == cat],
                key=lambda r: order.get(r.status, 4),
            )
            if not cat_results:
                continue

            _, heading, _ = cat_map.get(cat, (cat.upper(), cat.title(), ""))
            story.append(Paragraph(heading, cat_style))

            for _r in cat_results:
                result = _L.translate_result(_r)
                color = STATUS_COLORS_PDF.get(result.status, colors.black)
                label = ss.get(result.status, result.status.upper())
                text = (
                    f'<font color="#{color.hexval()[2:]}"><b>[{label}]</b></font>  '
                    f'<b>{result.name}</b><br/>'
                    f'{result.description}'
                )
                if result.recommendation and result.recommendation not in (rec_skip, "Nessuna azione richiesta."):
                    text += f'<br/><i>→ {result.recommendation}</i>'
                story.append(Paragraph(text, item_style))

            story.append(Spacer(1, 4 * mm))

        # Footer
        footer_style = ParagraphStyle("footer", parent=styles["Normal"], fontSize=8,
                                      textColor=colors.grey)
        story.append(Paragraph(_L.t("report_footer"), footer_style))

        doc.build(story)
        LOG.info("Report PDF esportato: %s", path)
        return path

    except ImportError:
        # Fallback to TXT
        txt_path = path.replace(".pdf", ".txt")
        export_txt(report, txt_path)
        LOG.warning("reportlab non disponibile — esportato come TXT: %s", txt_path)
        return txt_path
    except Exception as exc:
        LOG.error("Errore esportazione PDF: %s", exc)
        txt_path = path.replace(".pdf", ".txt")
        export_txt(report, txt_path)
        return txt_path
