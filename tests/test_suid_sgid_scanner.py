from app.scanners.suid_sgid_scanner import SUIDSGIDScanner


class FakeSSHClient:
    def __init__(self, output):
        self.output = output
        self.commands = []

    def execute(self, command):
        self.commands.append(command)
        return {
            "output": self.output,
            "error": "",
        }


def test_suid_and_sgid_are_detected():
    client = FakeSSHClient(
        "\n".join(
            [
                "4755|root|root|/usr/bin/passwd",
                "2755|root|shadow|/usr/bin/chage",
                "755|root|root|/usr/bin/normal",
            ]
        )
    )

    result = SUIDSGIDScanner(client).scan()

    assert result["total"] == 2
    assert result["suid"] == 1
    assert result["sgid"] == 1
    assert len(result["files"]) == 2


def test_expected_system_paths_are_not_findings():
    client = FakeSSHClient(
        "\n".join(
            [
                "4755|root|root|/usr/bin/passwd",
                "4755|root|root|/usr/bin/sudo",
                "2755|root|shadow|/usr/bin/chage",
                "4755|root|root|/bin/su",
            ]
        )
    )

    result = SUIDSGIDScanner(client).scan()

    assert result["total"] == 4
    assert result["findings"] == []


def test_non_system_suid_file_is_finding():
    client = FakeSSHClient(
        "4755|root|root|/opt/suspicious/helper"
    )

    result = SUIDSGIDScanner(client).scan()

    assert result["total"] == 1
    assert result["suid"] == 1
    assert result["sgid"] == 0
    assert len(result["findings"]) == 1
    assert result["findings"][0]["path"] == "/opt/suspicious/helper"


def test_non_system_sgid_file_is_finding():
    client = FakeSSHClient(
        "2755|root|users|/opt/custom/tool"
    )

    result = SUIDSGIDScanner(client).scan()

    assert result["total"] == 1
    assert result["suid"] == 0
    assert result["sgid"] == 1
    assert len(result["findings"]) == 1


def test_invalid_lines_are_ignored():
    client = FakeSSHClient(
        "\n".join(
            [
                "invalid",
                "",
                "not|enough|fields",
                "4755|root|root|/opt/tool",
            ]
        )
    )

    result = SUIDSGIDScanner(client).scan()

    assert result["total"] == 1
    assert result["findings"][0]["path"] == "/opt/tool"


def test_invalid_mode_is_ignored():
    client = FakeSSHClient(
        "\n".join(
            [
                "invalid|root|root|/opt/tool",
                "4755|root|root|/opt/valid",
            ]
        )
    )

    result = SUIDSGIDScanner(client).scan()

    assert result["total"] == 1
    assert result["findings"][0]["path"] == "/opt/valid"


def test_find_command_scans_root_and_privileged_bits():
    client = FakeSSHClient("")

    SUIDSGIDScanner(client).scan()

    assert len(client.commands) == 1

    command = client.commands[0]

    assert "find /" in command
    assert "-perm -4000" in command
    assert "-perm -2000" in command
