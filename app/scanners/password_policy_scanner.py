from app.models.finding import Finding


class PasswordPolicyScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def _extract_value(self, content, key):

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            if parts[0] == key:
                return parts[1]

        return None

    def scan(self):

        findings = []

        login_defs = self.ssh_client.execute(
            "cat /etc/login.defs 2>/dev/null"
        )["output"]

        sshd_config = self.ssh_client.execute(
            "cat /etc/ssh/sshd_config 2>/dev/null"
        )["output"]

        pass_max_days = self._extract_value(
            login_defs,
            "PASS_MAX_DAYS",
        )

        pass_min_days = self._extract_value(
            login_defs,
            "PASS_MIN_DAYS",
        )

        pass_warn_age = self._extract_value(
            login_defs,
            "PASS_WARN_AGE",
        )

        pass_min_len = self._extract_value(
            login_defs,
            "PASS_MIN_LEN",
        )

        permit_root_login = self._extract_value(
            sshd_config,
            "PermitRootLogin",
        )

        if pass_max_days and int(pass_max_days) > 365:

            findings.append(
                Finding(
                    severity="medium",
                    title="Password expiration period is too long",
                    description=(
                        f"PASS_MAX_DAYS is set to "
                        f"{pass_max_days}. "
                        "Consider reducing it to 365 "
                        "days or less."
                    ),
                ).to_dict()
            )

        if pass_min_len and int(pass_min_len) < 12:

            findings.append(
                Finding(
                    severity="medium",
                    title="Minimum password length is weak",
                    description=(
                        f"PASS_MIN_LEN is set to "
                        f"{pass_min_len}. "
                        "Consider using at least 12."
                    ),
                ).to_dict()
            )

        if pass_warn_age and int(pass_warn_age) < 7:

            findings.append(
                Finding(
                    severity="low",
                    title="Password expiration warning is too short",
                    description=(
                        f"PASS_WARN_AGE is set to "
                        f"{pass_warn_age}. "
                        "Consider using at least 7 days."
                    ),
                ).to_dict()
            )

        if permit_root_login and permit_root_login.lower() == "yes":

            findings.append(
                Finding(
                    severity="high",
                    title="Root SSH login enabled",
                    description=(
                        "PermitRootLogin is enabled. "
                        "Disable direct root SSH access."
                    ),
                ).to_dict()
            )

        return {
            "pass_max_days": pass_max_days,
            "pass_min_days": pass_min_days,
            "pass_warn_age": pass_warn_age,
            "pass_min_len": pass_min_len,
            "permit_root_login": permit_root_login,
            "findings": findings,
        }
