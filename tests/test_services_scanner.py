from app.scanners.services_scanner import ServicesScanner


class FakeSSHClient:

    def __init__(self, output=None):

        self.output = output or """\
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096       0.0.0.0:22         0.0.0.0:*      users:(("sshd",pid=1199,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:6379     0.0.0.0:*      users:(("redis-server",pid=500,fd=6))
tcp   LISTEN 0      4096       127.0.0.1:8080     0.0.0.0:*      users:(("nginx",pid=600,fd=7))
"""

    def execute(self, command):

        assert command == "ss -tulpn"

        return {"output": self.output}


def test_services_scanner():

    scanner = ServicesScanner(FakeSSHClient())

    result = scanner.scan()

    print(result)

    assert "listeners" in result
    assert "findings" in result

    assert len(result["listeners"]) == 3


def test_external_service_exposure():

    scanner = ServicesScanner(FakeSSHClient("""\
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096       0.0.0.0:22         0.0.0.0:*      users:(("sshd",pid=1199,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:6379     0.0.0.0:*      users:(("redis-server",pid=500,fd=6))
tcp   LISTEN 0      4096       [::]:443           [::]:*         users:(("nginx",pid=600,fd=7))
"""))

    result = scanner.scan()

    exposure_findings = [
        finding
        for finding in result["findings"]
        if finding["title"] == "External service exposure"
    ]

    assert len(exposure_findings) == 2

    descriptions = [finding["description"] for finding in exposure_findings]

    assert any("0.0.0.0:22" in description for description in descriptions)

    assert any("[::]:443" in description for description in descriptions)


def test_localhost_is_not_external():

    scanner = ServicesScanner(FakeSSHClient("""\
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096       127.0.0.1:11434     0.0.0.0:*      users:(("ollama",pid=500,fd=6))
tcp   LISTEN 0      4096       [::1]:8080           [::]:*         users:(("nginx",pid=600,fd=7))
"""))

    result = scanner.scan()

    exposure_findings = [
        finding
        for finding in result["findings"]
        if finding["title"] == "External service exposure"
    ]

    assert exposure_findings == []


def test_unknown_process_does_not_break_exposure_detection():

    scanner = ServicesScanner(FakeSSHClient("""\
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096       192.168.1.40:8080    0.0.0.0:*
"""))

    result = scanner.scan()

    exposure_findings = [
        finding
        for finding in result["findings"]
        if finding["title"] == "External service exposure"
    ]

    assert len(exposure_findings) == 1

    assert "unknown" in exposure_findings[0]["description"]
