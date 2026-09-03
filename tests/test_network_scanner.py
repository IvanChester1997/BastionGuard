from app.scanners.network_scanner import NetworkScanner


class FakeSSHClient:

    def execute(self, command):

        if command == "ip -br addr":
            return {"output": """\
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth1             UP             192.168.1.40/24
"""}

        if command == "ip route":
            return {"output": """\
default via 192.168.1.1 dev eth1 metric 25
192.168.1.0/24 dev eth1 scope link metric 281
"""}

        if command == "ip -br link":
            return {"output": """\
lo               UNKNOWN        00:00:00:00:00:00
eth1             UP             9c:6b:00:24:de:bf
eth2             DOWN           0a:00:27:00:00:0d
"""}

        raise AssertionError(f"Unexpected command: {command}")


def test_network_scanner():

    scanner = NetworkScanner(FakeSSHClient())

    result = scanner.scan()

    assert "interfaces" in result
    assert "routes" in result
    assert "links" in result
    assert "findings" in result

    assert len(result["interfaces"]) == 2
    assert len(result["routes"]) == 2
    assert len(result["links"]) == 3

    assert result["interfaces"][1]["name"] == "eth1"
    assert result["interfaces"][1]["state"] == "UP"

    assert result["interfaces"][1]["addresses"] == ["192.168.1.40/24"]

    assert result["routes"][0]["destination"] == "default"
    assert result["routes"][0]["gateway"] == "192.168.1.1"
    assert result["routes"][0]["interface"] == "eth1"
    assert result["routes"][0]["metric"] == 25

    assert result["links"][1]["name"] == "eth1"
    assert result["links"][1]["state"] == "UP"
    assert result["links"][1]["mac"] == "9c:6b:00:24:de:bf"

    assert result["findings"] == []


def test_network_scanner_detects_missing_default_route():

    class NoDefaultRouteSSHClient(FakeSSHClient):

        def execute(self, command):

            if command == "ip route":
                return {"output": """\
192.168.1.0/24 dev eth1 scope link metric 281
"""}

            return super().execute(command)

    scanner = NetworkScanner(NoDefaultRouteSSHClient())

    result = scanner.scan()

    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["severity"] == "medium"
    assert finding["title"] == "Default route missing"
