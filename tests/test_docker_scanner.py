from app.scanners.docker_scanner import DockerScanner


class MockSSHClient:

    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    def execute(self, command):
        self.commands.append(command)

        for key, response in self.responses.items():
            if key in command:
                return {
                    "output": response,
                }

        return {
            "output": "",
        }


def test_docker_not_installed():

    client = MockSSHClient(
        {
            "command -v docker": "",
        }
    )

    result = DockerScanner(client).scan()

    assert result["installed"] is False
    assert result["available"] is False
    assert result["findings"] == []


def test_docker_daemon_unavailable():

    client = MockSSHClient(
        {
            "command -v docker": "/usr/bin/docker",
            "docker version": "",
        }
    )

    result = DockerScanner(client).scan()

    assert result["installed"] is True
    assert result["available"] is False
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"


def test_docker_normal_container():

    client = MockSSHClient(
        {
            "command -v docker": "/usr/bin/docker",
            "docker version": "28.0.0",
            "docker ps -aq": "abc123",
            "docker inspect": (
                "/web|appuser|false|bridge||"
            ),
        }
    )

    result = DockerScanner(client).scan()

    assert result["installed"] is True
    assert result["available"] is True
    assert result["container_count"] == 1
    assert result["containers"][0]["name"] == "web"
    assert result["containers"][0]["privileged"] is False


def test_privileged_container():

    client = MockSSHClient(
        {
            "command -v docker": "/usr/bin/docker",
            "docker version": "28.0.0",
            "docker ps -aq": "abc123",
            "docker inspect": (
                "/danger|appuser|true|bridge||"
            ),
        }
    )

    result = DockerScanner(client).scan()

    findings = result["findings"]

    assert any(
        finding["severity"] == "critical"
        and "Privileged" in finding["title"]
        for finding in findings
    )


def test_host_network_and_pid():

    client = MockSSHClient(
        {
            "command -v docker": "/usr/bin/docker",
            "docker version": "28.0.0",
            "docker ps -aq": "abc123",
            "docker inspect": (
                "/network|appuser|false|host|host|"
            ),
        }
    )

    result = DockerScanner(client).scan()

    titles = {
        finding["title"]
        for finding in result["findings"]
    }

    assert "Docker container uses host network" in titles
    assert "Docker container uses host PID namespace" in titles


def test_root_container():

    client = MockSSHClient(
        {
            "command -v docker": "/usr/bin/docker",
            "docker version": "28.0.0",
            "docker ps -aq": "abc123",
            "docker inspect": (
                "/root-container|root|false|bridge||"
            ),
        }
    )

    result = DockerScanner(client).scan()

    assert any(
        finding["severity"] == "medium"
        and finding["title"] == "Docker container runs as root"
        for finding in result["findings"]
    )


def test_docker_socket_mount():

    client = MockSSHClient(
        {
            "command -v docker": "/usr/bin/docker",
            "docker version": "28.0.0",
            "docker ps -aq": "abc123",
            "docker inspect": (
                "/docker-control|appuser|false|bridge||"
                "bind:/var/run/docker.sock:/var/run/docker.sock;"
            ),
        }
    )

    result = DockerScanner(client).scan()

    assert any(
        finding["severity"] == "critical"
        and finding["title"] == "Docker socket mounted into container"
        for finding in result["findings"]
    )


def test_sensitive_host_mount():

    client = MockSSHClient(
        {
            "command -v docker": "/usr/bin/docker",
            "docker version": "28.0.0",
            "docker ps -aq": "abc123",
            "docker inspect": (
                "/sensitive|appuser|false|bridge||"
                "bind:/etc:/host-etc;"
            ),
        }
    )

    result = DockerScanner(client).scan()

    assert any(
        finding["severity"] == "high"
        and finding["title"]
        == "Sensitive host path mounted into container"
        for finding in result["findings"]
    )
