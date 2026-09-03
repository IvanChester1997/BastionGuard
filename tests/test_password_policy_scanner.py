from app.scanners.password_policy_scanner import PasswordPolicyScanner


class MockSSHClient:

    def execute(self, command):

        if "/etc/login.defs" in command:

            return {
                "output": """
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 3
PASS_MIN_LEN 8
"""
            }

        if "/etc/ssh/sshd_config" in command:

            return {
                "output": """
PermitRootLogin yes
"""
            }

        return {"output": ""}


def test_password_policy_scanner():

    scanner = PasswordPolicyScanner(
        MockSSHClient()
    )

    result = scanner.scan()

    assert result["pass_max_days"] == "99999"
    assert result["pass_min_len"] == "8"
    assert result["permit_root_login"] == "yes"

    assert len(result["findings"]) == 4
