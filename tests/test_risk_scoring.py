from app.services.risk_scoring import RiskScoring


def test_risk_score_high():

    report = {
        "ssh": {
            "findings": [
                {
                    "severity": "high",
                    "title": "test",
                    "description": "test",
                }
            ]
        },
        "users": {
            "findings": [
                {
                    "severity": "medium",
                    "title": "test",
                    "description": "test",
                }
            ]
        },
        "network": {
            "findings": [
                {
                    "severity": "low",
                    "title": "test",
                    "description": "test",
                }
            ]
        },
    }

    result = RiskScoring.calculate(report)

    assert result["score"] == 16
    assert result["level"] == "MEDIUM"


def test_risk_score_critical():

    report = {
        "scanner": {
            "findings": [
                {"severity": "critical"},
                {"severity": "critical"},
                {"severity": "critical"},
            ]
        }
    }

    result = RiskScoring.calculate(report)

    assert result["score"] == 60
    assert result["level"] == "CRITICAL"
