class Finding:

    def __init__(
        self,
        severity: str,
        title: str,
        description: str
    ):
        self.severity = severity
        self.title = title
        self.description = description

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description
        }
