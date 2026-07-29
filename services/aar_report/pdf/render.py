"""
AAR PDF Renderer (27번 문서 1.5절)
=====================================
WeasyPrint(시스템 라이브러리 cairo/pango 필요) 대신 reportlab을 사용한다.
순수 파이썬이라 배포 이미지에 시스템 패키지를 추가할 필요가 없다는 장점이 있다.
"""
from __future__ import annotations
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

# reportlab 기본 폰트(Helvetica)는 한글을 지원하지 않아 그대로 쓰면 깨진다(■■■■로 표시됨).
# reportlab이 내장 지원하는 한글 CID 폰트(외부 폰트파일 불필요, PDF 리더가 대체)를 등록한다.
KOREAN_FONT = "HYSMyeongJo-Medium"
pdfmetrics.registerFont(UnicodeCIDFont(KOREAN_FONT))


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1Custom", fontName=KOREAN_FONT, fontSize=18, leading=22,
                              spaceAfter=12, textColor=colors.HexColor("#1a1a2e")))
    styles.add(ParagraphStyle(name="H2Custom", fontName=KOREAN_FONT, fontSize=13, leading=16,
                              spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#16213e")))
    styles.add(ParagraphStyle(name="BodyCustom", fontName=KOREAN_FONT, fontSize=10, leading=14))
    return styles


def _metric_table(rows: list[tuple[str, str]]) -> Table:
    data = [["지표", "값"]] + [[k, v] for k, v in rows]
    t = Table(data, colWidths=[80 * mm, 80 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), KOREAN_FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def render_pdf(report: dict, output_path: str) -> None:
    """AAR API(services/aar_report/main.py의 /report/aar)가 반환한 dict를 받아 PDF로 렌더링."""
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            topMargin=20 * mm, bottomMargin=20 * mm,
                            leftMargin=20 * mm, rightMargin=20 * mm)
    styles = _styles()
    story = []

    summary = report.get("summary", {})
    story.append(Paragraph("After-Action Review", styles["H1Custom"]))
    story.append(Paragraph(
        f"시나리오: {summary.get('scenario_id', '-')} · "
        f"생성일시: {datetime.fromtimestamp(summary.get('generated_at', 0)).strftime('%Y-%m-%d %H:%M')}",
        styles["BodyCustom"],
    ))
    story.append(Spacer(1, 8))

    # 최종 점수
    story.append(Paragraph("최종 점수", styles["H2Custom"]))
    score_rows = []
    for team, scores in summary.get("final_scores", {}).items():
        score_rows.append((f"{team} (Red)", str(scores.get("red", 0))))
        score_rows.append((f"{team} (Blue)", str(scores.get("blue", 0))))
    if score_rows:
        story.append(_metric_table(score_rows))
    else:
        story.append(Paragraph("점수 데이터 없음", styles["BodyCustom"]))

    # Red 성과
    story.append(Paragraph("Red 팀 성과", styles["H2Custom"]))
    red = report.get("red_performance", {})
    story.append(_metric_table([
        ("완료한 킬체인 단계 수", str(red.get("stages_completed", 0))),
        ("획득 플래그 수", str(red.get("flags_obtained", 0))),
        ("은신 보너스 합계", str(red.get("stealth_bonus_total", 0))),
    ]))

    # Blue 성과
    story.append(Paragraph("Blue 팀 성과", styles["H2Custom"]))
    blue = report.get("blue_performance", {})

    def _fmt(v, suffix=""):
        return f"{v:.1f}{suffix}" if v is not None else "N/A"

    story.append(_metric_table([
        ("평균 탐지시간 (MTTD)", _fmt(blue.get("mttd_sec"), "초")),
        ("평균 복구시간 (MTTR)", _fmt(blue.get("mttr_sec"), "초")),
        ("탐지율", _fmt((blue.get("detection_rate") or 0) * 100 if blue.get("detection_rate") is not None else None, "%")),
        ("오탐률", _fmt((blue.get("false_positive_rate") or 0) * 100 if blue.get("false_positive_rate") is not None else None, "%")),
    ]))

    # ATT&CK 갭
    story.append(Paragraph("ATT&CK 커버리지 갭", styles["H2Custom"]))
    gaps = report.get("uncovered_techniques", [])
    if gaps:
        story.append(Paragraph(f"탐지되지 않은 기술: {', '.join(gaps)}", styles["BodyCustom"]))
    else:
        story.append(Paragraph("전 기술 탐지 커버리지 확보", styles["BodyCustom"]))

    # ICS 자산 공방 라이프사이클(실 Modbus) — ics_lifecycle 섹션이 있을 때만
    ics = report.get("ics_lifecycle") or {}
    ics_assets = ics.get("assets") or {}
    if ics_assets:
        story.append(Spacer(1, 8))
        story.append(Paragraph("ICS 자산 공방 (실 Modbus)", styles["H2Custom"]))
        t = ics.get("totals", {})
        story.append(Paragraph(
            f"ICS 공격 {t.get('ics_attacks', 0)}건 · 침해 자산 {t.get('compromised_assets', 0)} · "
            f"복구 자산 {t.get('recovered_assets', 0)} · 평균 MTTR "
            f"{_fmt(t.get('avg_mttr_sec'), 's')}", styles["BodyCustom"]))
        header = ("자산", "공격", "침해", "방어", "복구", "MTTR(s)", "기법")
        data = [header]
        for name, v in sorted(ics_assets.items()):
            data.append((name, str(v["attacks"]), str(v["compromised"]), str(v["blocks"]),
                         str(v["recovered"]), _fmt(v["mttr_sec"]), ", ".join(v["techniques"]) or "-"))
        tbl = Table(data, colWidths=[34 * mm, 14 * mm, 14 * mm, 14 * mm, 14 * mm, 20 * mm, 40 * mm])
        tbl.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), KOREAN_FONT), ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E2A3F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(tbl)

    # 개선 권고
    story.append(Spacer(1, 8))
    story.append(Paragraph("개선 권고", styles["H2Custom"]))
    for tip in report.get("recommendations", []):
        story.append(Paragraph(f"• {tip}", styles["BodyCustom"]))

    doc.build(story)
