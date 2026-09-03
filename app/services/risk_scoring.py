class RiskScoring:

    WEIGHTS = {
        "critical": 20,
        "high": 10,
        "medium": 5,
        "low": 1,
    }

    @classmethod
    def calculate(cls, report):

        score = 0

        for section in report.values():

            if not isinstance(section, dict):
                continue

            findings = section.get("findings", [])

            for finding in findings:

                severity = finding.get(
                    "severity",
                    "",
                ).lower()

                score += cls.WEIGHTS.get(
                    severity,
                    0,
                )

        if score >= 50:
            level = "CRITICAL"
        elif score >= 25:
            level = "HIGH"
        elif score >= 10:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": score,
            "level": level,
        }
