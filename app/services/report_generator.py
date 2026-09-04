class ReportGenerator:
    @staticmethod
    def generate_html(report: dict) -> str:
        risk = report.get("risk", {})

        html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>BastionGuard Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
}}

h1 {{
    color: #222;
}}

.section {{
    margin-top: 25px;
    padding: 15px;
    border: 1px solid #ddd;
}}

.finding {{
    margin-top: 10px;
    padding: 10px;
    background: #f5f5f5;
}}

.severity {{
    font-weight: bold;
}}
</style>
</head>
<body>

<h1>BastionGuard Security Report</h1>

<p><strong>Host:</strong> {report.get("host", "unknown")}</p>
<p><strong>Risk Score:</strong> {risk.get("score", 0)}</p>
<p><strong>Risk Level:</strong> {risk.get("level", "UNKNOWN")}</p>
"""

        for section_name, section_data in report.items():
            if section_name in ("host", "risk"):
                continue

            if not isinstance(section_data, dict):
                continue

            findings = section_data.get("findings", [])

            html += f"""
<div class="section">
<h2>{section_name}</h2>
"""

            for finding in findings:
                html += f"""
<div class="finding">
<div class="severity">
Severity: {finding.get("severity", "unknown")}
</div>

<div>
{finding.get("title", "")}
</div>

<div>
{finding.get("description", "")}
</div>

<div>
<strong>Remediation:</strong>
{finding.get("remediation", "")}
</div>
</div>
"""

            html += "</div>"

        html += """
</body>
</html>
"""

        return html
