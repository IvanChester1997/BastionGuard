from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PDFReportGenerator:
    @staticmethod
    def generate(report: dict, output_path: str) -> None:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=20,
            spaceAfter=8 * mm,
        )

        section_style = ParagraphStyle(
            "SectionTitle",
            parent=styles["Heading2"],
            fontSize=13,
            spaceBefore=6 * mm,
            spaceAfter=3 * mm,
        )

        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
        )

        small_style = ParagraphStyle(
            "Small",
            parent=body_style,
            fontSize=8,
            leading=10,
        )

        story = []

        host = str(report.get("host", "Unknown"))
        risk = report.get("risk", {})

        score = risk.get("score", 0)
        level = str(risk.get("level", "UNKNOWN")).upper()

        story.append(Paragraph("BastionGuard Security Report", title_style))
        story.append(Paragraph(f"<b>Host:</b> {host}", body_style))
        story.append(Spacer(1, 3 * mm))

        risk_data = [
            [
                Paragraph("<b>Risk Score</b>", body_style),
                Paragraph("<b>Risk Level</b>", body_style),
            ],
            [
                Paragraph(str(score), body_style),
                Paragraph(level, body_style),
            ],
        ]

        risk_table = Table(risk_data, colWidths=[80 * mm, 80 * mm])
        risk_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        story.append(risk_table)

        story.append(Paragraph("Scanner Summary", section_style))

        scanner_rows = [
            [
                Paragraph("<b>Scanner</b>", small_style),
                Paragraph("<b>Findings</b>", small_style),
            ]
        ]

        for scanner_name, result in report.items():
            if scanner_name in {"host", "risk"}:
                continue

            findings_count = 0

            if isinstance(result, dict):
                findings = result.get("findings", [])
                if isinstance(findings, list):
                    findings_count = len(findings)

            scanner_rows.append(
                [
                    Paragraph(str(scanner_name), small_style),
                    Paragraph(str(findings_count), small_style),
                ]
            )

        scanner_table = Table(
            scanner_rows,
            colWidths=[110 * mm, 50 * mm],
            repeatRows=1,
        )

        scanner_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        story.append(scanner_table)

        story.append(Paragraph("Security Findings", section_style))

        findings_rows = [
            [
                Paragraph("<b>Scanner</b>", small_style),
                Paragraph("<b>Severity</b>", small_style),
                Paragraph("<b>Finding</b>", small_style),
                Paragraph("<b>Remediation</b>", small_style),
            ]
        ]

        for scanner_name, result in report.items():
            if scanner_name in {"host", "risk"}:
                continue

            if not isinstance(result, dict):
                continue

            findings = result.get("findings", [])

            if not isinstance(findings, list):
                continue

            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                severity = str(finding.get("severity", "UNKNOWN"))
                title = str(
                    finding.get(
                        "title",
                        finding.get("description", "Unknown finding"),
                    )
                )
                remediation = str(
                    finding.get(
                        "remediation",
                        finding.get("recommendation", "N/A"),
                    )
                )

                findings_rows.append(
                    [
                        Paragraph(str(scanner_name), small_style),
                        Paragraph(severity, small_style),
                        Paragraph(title, small_style),
                        Paragraph(remediation, small_style),
                    ]
                )

        if len(findings_rows) == 1:
            findings_rows.append(
                [
                    Paragraph("—", small_style),
                    Paragraph("—", small_style),
                    Paragraph("No security findings", small_style),
                    Paragraph("No remediation required", small_style),
                ]
            )

        findings_table = Table(
            findings_rows,
            colWidths=[30 * mm, 25 * mm, 55 * mm, 50 * mm],
            repeatRows=1,
        )

        findings_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        story.append(findings_table)
        story.append(Spacer(1, 8 * mm))
        story.append(
            Paragraph(
                "Generated by BastionGuard",
                small_style,
            )
        )

        doc.build(story)
