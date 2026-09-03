from app.scanners.services_scanner import ServicesScanner


class FakeSSHClient:

    def execute(self, command):

        assert command == "ss -tulpn"

        return {
            "output": """\
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096       0.0.0.0:22         0.0.0.0:*      users:(("sshd",pid=1199,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:6379     0.0.0.0:*      users:(("redis-server",pid=500,fd=6))
tcp   LISTEN 0      4096       127.0.0.1:8080     0.0.0.0:*      users:(("nginx",pid=600,fd=7))
"""
        }


def test_services_scanner():

    scanner = ServicesScanner(
        FakeSSHClient()
    )

    result = scanner.scan()

    print(result)

    assert "listeners" in result
    assert "findings" in result

    assert len(result["listeners"]) == 3
