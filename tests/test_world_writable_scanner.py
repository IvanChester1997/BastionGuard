from app.scanners.world_writable_scanner import WorldWritableScanner


class FakeSSHClient:

    def __init__(self, output):
        self.output = output

    def execute(self, command):

        assert command == (
            "find / -xdev \\( -type f -o -type d \\) "
            "-perm -0002 "
            "-exec stat -c '%A|%a|%U|%G|%n' {} \\; "
            "2>/dev/null"
        )

        return {
            "output": self.output,
            "error": "",
        }


def test_world_writable_scanner_parses_files_and_directories():

    scanner = WorldWritableScanner(
        FakeSSHClient("""\
-rwxrwxrwx|0777|root|root|/opt/test-file
drwxrwxrwt|1777|root|root|/tmp
drwxrwxrwx|0777|root|root|/opt/test-dir
""")
    )

    result = scanner.scan()

    assert result["total"] == 3
    assert result["files"] == 1
    assert result["directories"] == 2

    assert result["entries"][0]["file"] is True
    assert result["entries"][0]["world_writable"] is True

    assert result["entries"][1]["directory"] is True
    assert result["entries"][1]["sticky"] is True


def test_world_writable_file_creates_high_finding():

    scanner = WorldWritableScanner(
        FakeSSHClient("""\
-rwxrwxrwx|0777|root|root|/opt/test-file
""")
    )

    result = scanner.scan()

    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["severity"] == "high"
    assert finding["title"] == "World-writable file detected"
    assert "/opt/test-file" in finding["description"]


def test_world_writable_directory_without_sticky_creates_finding():

    scanner = WorldWritableScanner(
        FakeSSHClient("""\
drwxrwxrwx|0777|root|root|/opt/test-dir
""")
    )

    result = scanner.scan()

    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["severity"] == "high"
    assert finding["title"] == (
        "World-writable directory without sticky bit"
    )
    assert "/opt/test-dir" in finding["description"]


def test_sticky_directory_does_not_create_finding():

    scanner = WorldWritableScanner(
        FakeSSHClient("""\
drwxrwxrwt|1777|root|root|/tmp
""")
    )

    result = scanner.scan()

    assert result["findings"] == []
    assert result["world_writable_directories_without_sticky"] == 0


def test_wsl_mount_is_recorded_but_not_flagged():

    scanner = WorldWritableScanner(
        FakeSSHClient("""\
drwxrwxrwx|0777|ivan|ivan|/mnt/c
""")
    )

    result = scanner.scan()

    assert result["total"] == 1
    assert result["entries"][0]["wsl_mount"] is True
    assert result["findings"] == []


def test_empty_output():

    scanner = WorldWritableScanner(
        FakeSSHClient("")
    )

    result = scanner.scan()

    assert result["total"] == 0
    assert result["files"] == 0
    assert result["directories"] == 0
    assert result["findings"] == []


def test_x11_socket_directory_is_not_flagged():

    scanner = WorldWritableScanner(
        FakeSSHClient("""\
drwxrwxrwx|0777|root|root|/tmp/.X11-unix
""")
    )

    result = scanner.scan()

    assert result["total"] == 1
    assert result["directories"] == 1
    assert result["world_writable_directories_without_sticky"] == 0
    assert result["findings"] == []
