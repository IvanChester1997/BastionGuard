from app.scanners.hardening_scanner import HardeningScanner


class FakeSSHClient:

    def __init__(self, output):
        self.output = output

    def execute(self, command):

        assert command == (
            "find / -xdev \\( -perm -4000 -o -perm -2000 \\) "
            "-type f -exec stat -c '%A|%a|%U|%G|%n' {} \\; "
            "2>/dev/null"
        )

        return {
            "output": self.output,
            "error": "",
        }


def test_hardening_scanner_parses_suid_and_sgid():

    scanner = HardeningScanner(
        FakeSSHClient("""\
-rwsr-xr-x|4755|root|root|/usr/bin/passwd
-rwxr-sr-x|2755|root|shadow|/usr/bin/chage
-rwsr-xr-x|4755|root|root|/usr/bin/sudo
""")
    )

    result = scanner.scan()

    assert result["total"] == 3
    assert result["suid_count"] == 2
    assert result["sgid_count"] == 1

    assert result["entries"][0] == {
        "path": "/usr/bin/passwd",
        "permissions": "-rwsr-xr-x",
        "mode": "4755",
        "owner": "root",
        "group": "root",
        "suid": True,
        "sgid": False,
    }

    assert result["entries"][1]["suid"] is False
    assert result["entries"][1]["sgid"] is True


def test_hardening_scanner_detects_non_root_owner():

    scanner = HardeningScanner(
        FakeSSHClient("""\
-rwsr-xr-x|4755|root|root|/usr/bin/passwd
-rwsr-xr-x|4755|ivan|ivan|/usr/local/bin/custom-tool
""")
    )

    result = scanner.scan()

    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["severity"] == "high"
    assert finding["title"] == "SUID/SGID file has non-root owner"
    assert "/usr/local/bin/custom-tool" in finding["description"]
    assert "ivan:ivan" in finding["description"]


def test_hardening_scanner_handles_empty_output():

    scanner = HardeningScanner(
        FakeSSHClient("")
    )

    result = scanner.scan()

    assert result["total"] == 0
    assert result["suid_count"] == 0
    assert result["sgid_count"] == 0
    assert result["entries"] == []
    assert result["findings"] == []
