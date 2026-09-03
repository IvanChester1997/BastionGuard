class Finding:

    def __init__(
        self,
        severity: str,
        title: str,
        description: str,
        remediation: str | None = None
    ):
        self.severity = severity
        self.title = title
        self.description = description
        self.remediation = remediation

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation
        }
