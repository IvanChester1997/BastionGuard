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
    assert "high" in html
