from app.services.report_generator import ReportGenerator


def test_generate_html_contains_host():
    report = {
        "host": "192.168.1.40",
        "risk": {
            "score": 35,
            "level": "HIGH",
        },
    }

    html = ReportGenerator.generate_html(report)

    assert "192.168.1.40" in html
    assert "HIGH" in html
    assert "35" in html


def test_generate_html_contains_findings():
    report = {
        "host": "test-host",
        "risk": {
            "score": 10,
            "level": "LOW",
        },
        "ssh": {
            "findings": [
                {
                    "severity": "high",
                    "title": "Root Login Enabled",
                    "description": "Root login is enabled",
                    "remediation": "Disable PermitRootLogin",
                }
            ]
        },
    }

    html = ReportGenerator.generate_html(report)

    assert "Root Login Enabled" in html
    assert "Disable PermitRootLogin" in html
    assert "HIGH" in html


def test_generate_html_contains_risk_badge():
    report = {
        "host": "test-host",
        "risk": {
            "score": 85,
            "level": "CRITICAL",
        },
    }

    html = ReportGenerator.generate_html(report)

    assert "risk-badge critical" in html
    assert "CRITICAL" in html


def test_generate_html_contains_scanner_summary():
    report = {
        "host": "test-host",
        "risk": {
            "score": 20,
            "level": "MEDIUM",
        },
        "ssh": {
            "findings": [
                {
                    "severity": "medium",
                    "title": "Weak SSH Configuration",
                    "description": "SSH configuration requires review",
                    "remediation": "Harden SSH configuration",
                }
            ]
        },
        "users": {
            "findings": [],
        },
    }

    html = ReportGenerator.generate_html(report)

    assert "Scanner Summary" in html
    assert "ssh" in html
    assert "users" in html


def test_generate_html_contains_findings_table():
    report = {
        "host": "test-host",
        "risk": {
            "score": 60,
            "level": "HIGH",
        },
        "ssh": {
            "findings": [
                {
                    "severity": "high",
                    "title": "Root Login Enabled",
                    "description": "Root login is enabled",
                    "remediation": "Disable PermitRootLogin",
                }
            ]
        },
    }

    html = ReportGenerator.generate_html(report)

    assert "Security Findings" in html
    assert "Severity" in html
    assert "Scanner" in html
    assert "Finding" in html
    assert "Remediation" in html


def test_generate_html_escapes_html():
    report = {
        "host": "<script>alert('xss')</script>",
        "risk": {
            "score": 10,
            "level": "LOW",
        },
        "ssh": {
            "findings": [
                {
                    "severity": "low",
                    "title": "<script>bad()</script>",
                    "description": "<b>unsafe</b>",
                    "remediation": "<img src=x>",
                }
            ]
        },
    }

    html = ReportGenerator.generate_html(report)

    assert "<script>alert('xss')</script>" not in html
    assert "<script>bad()</script>" not in html
    assert "<b>unsafe</b>" not in html
    assert "<img src=x>" not in html
    assert "&lt;script&gt;" in html

def test_generate_pdf_creates_file(tmp_path):
    from app.services.pdf_report_generator import PDFReportGenerator

    report = {
        "host": "test-host",
        "risk": {
            "score": 35,
            "level": "HIGH",
        },
    }

    output_path = tmp_path / "report.pdf"

    PDFReportGenerator.generate(report, str(output_path))

    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_generate_pdf_contains_report_data(tmp_path):
    from app.services.pdf_report_generator import PDFReportGenerator
    from pypdf import PdfReader

    report = {
        "host": "test-host",
        "risk": {
            "score": 85,
            "level": "CRITICAL",
        },
        "ssh": {
            "findings": [
                {
                    "severity": "high",
                    "title": "Root Login Enabled",
                    "description": "Root login is enabled",
                    "remediation": "Disable PermitRootLogin",
                }
            ]
        },
    }

    output_path = tmp_path / "report.pdf"

    PDFReportGenerator.generate(report, str(output_path))

    reader = PdfReader(str(output_path))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert "BastionGuard Security Report" in text
    assert "test-host" in text
    assert "85" in text
    assert "CRITICAL" in text
    assert "Root Login Enabled" in text
    assert "Disable PermitRootLogin" in text
