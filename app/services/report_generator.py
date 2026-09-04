from html import escape


class ReportGenerator:
    @staticmethod
    def generate_html(report: dict) -> str:
        risk = report.get("risk", {})
        score = risk.get("score", 0)
        level = str(risk.get("level", "UNKNOWN")).upper()

        level_class = {
            "LOW": "low",
            "MEDIUM": "medium",
            "HIGH": "high",
            "CRITICAL": "critical",
        }.get(level, "unknown")

        scanners = []
        findings = []

        for section_name, section_data in report.items():
            if section_name in ("host", "risk"):
                continue

            if not isinstance(section_data, dict):
                continue

            scanner_findings = section_data.get("findings", [])

            scanners.append(
                {
                    "name": section_name,
                    "findings": len(scanner_findings),
                }
            )

            for finding in scanner_findings:
                findings.append(
                    {
                        "scanner": section_name,
                        "severity": str(
                            finding.get("severity", "unknown")
                        ).upper(),
                        "title": finding.get("title", ""),
                        "description": finding.get("description", ""),
                        "remediation": finding.get("remediation", ""),
                    }
                )

        scanner_rows = ""

        for scanner in scanners:
            scanner_rows += f"""
                <tr>
                    <td>{escape(scanner["name"])}</td>
                    <td>{scanner["findings"]}</td>
                </tr>
            """

        finding_rows = ""

        for finding in findings:
            severity = finding["severity"]

            finding_rows += f"""
                <tr>
                    <td>
                        <span class="severity severity-{severity.lower()}">
                            {escape(severity)}
                        </span>
                    </td>
                    <td>{escape(finding["scanner"])}</td>
                    <td>
                        <strong>{escape(str(finding["title"]))}</strong>
                        <div class="description">
                            {escape(str(finding["description"]))}
                        </div>
                    </td>
                    <td>{escape(str(finding["remediation"]))}</td>
                </tr>
            """

        if not finding_rows:
            finding_rows = """
                <tr>
                    <td colspan="4" class="no-findings">
                        No security findings detected.
                    </td>
                </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BastionGuard Security Report</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 40px;
    background: #f4f6f8;
    color: #1f2937;
    font-family: Arial, Helvetica, sans-serif;
}}

.container {{
    max-width: 1400px;
    margin: 0 auto;
}}

.header {{
    margin-bottom: 30px;
}}

.header h1 {{
    margin: 0 0 8px;
    font-size: 32px;
}}

.header p {{
    margin: 0;
    color: #6b7280;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
    margin-bottom: 30px;
}}

.card {{
    background: white;
    border-radius: 12px;
    padding: 24px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}}

.card-label {{
    font-size: 13px;
    text-transform: uppercase;
    color: #6b7280;
    margin-bottom: 10px;
}}

.card-value {{
    font-size: 28px;
    font-weight: bold;
}}

.risk-badge {{
    display: inline-block;
    padding: 7px 14px;
    border-radius: 999px;
    font-size: 14px;
    font-weight: bold;
}}

.low {{
    background: #dcfce7;
    color: #166534;
}}

.medium {{
    background: #fef3c7;
    color: #92400e;
}}

.high {{
    background: #fee2e2;
    color: #991b1b;
}}

.critical {{
    background: #450a0a;
    color: white;
}}

.unknown {{
    background: #e5e7eb;
    color: #374151;
}}

.section {{
    background: white;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 25px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}}

.section h2 {{
    margin-top: 0;
    margin-bottom: 20px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    text-align: left;
    background: #f9fafb;
    padding: 12px;
    font-size: 13px;
    text-transform: uppercase;
    color: #6b7280;
}}

td {{
    padding: 14px 12px;
    border-top: 1px solid #e5e7eb;
    vertical-align: top;
}}

.severity {{
    display: inline-block;
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: bold;
}}

.severity-low {{
    background: #dcfce7;
    color: #166534;
}}

.severity-medium {{
    background: #fef3c7;
    color: #92400e;
}}

.severity-high {{
    background: #fee2e2;
    color: #991b1b;
}}

.severity-critical {{
    background: #450a0a;
    color: white;
}}

.severity-unknown {{
    background: #e5e7eb;
    color: #374151;
}}

.description {{
    margin-top: 6px;
    color: #6b7280;
    line-height: 1.5;
}}

.no-findings {{
    text-align: center;
    color: #166534;
    padding: 30px;
}}

.footer {{
    text-align: center;
    color: #9ca3af;
    font-size: 13px;
    margin-top: 30px;
}}

@media (max-width: 900px) {{
    body {{
        padding: 20px;
    }}

    .cards {{
        grid-template-columns: 1fr;
    }}

    .section {{
        overflow-x: auto;
    }}

    table {{
        min-width: 800px;
    }}
}}
</style>
</head>

<body>
<div class="container">

<div class="header">
    <h1>BastionGuard Security Report</h1>
    <p>Automated Linux security audit</p>
</div>

<div class="cards">

    <div class="card">
        <div class="card-label">Host</div>
        <div class="card-value">{escape(str(report.get("host", "unknown")))}</div>
    </div>

    <div class="card">
        <div class="card-label">Risk Score</div>
        <div class="card-value">{escape(str(score))}</div>
    </div>

    <div class="card">
        <div class="card-label">Risk Level</div>
        <div class="card-value">
            <span class="risk-badge {level_class}">
                {escape(level)}
            </span>
        </div>
    </div>

</div>

<div class="section">
    <h2>Scanner Summary</h2>

    <table>
        <thead>
            <tr>
                <th>Scanner</th>
                <th>Findings</th>
            </tr>
        </thead>
        <tbody>
            {scanner_rows}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>Security Findings</h2>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Scanner</th>
                <th>Finding</th>
                <th>Remediation</th>
            </tr>
        </thead>

        <tbody>
            {finding_rows}
        </tbody>
    </table>
</div>

<div class="footer">
    Generated by BastionGuard
</div>

</div>
</body>
</html>
"""

        return html
