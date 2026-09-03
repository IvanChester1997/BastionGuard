from app.models.finding import Finding


class DockerScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        docker_check = self.ssh_client.execute(
            "command -v docker"
        )

        docker_path = docker_check["output"].strip()

        if not docker_path:
            return {
                "installed": False,
                "available": False,
                "docker_path": None,
                "containers": [],
                "findings": [],
            }

        version_result = self.ssh_client.execute(
            "docker version --format '{{.Server.Version}}' "
            "2>/dev/null"
        )

        docker_version = version_result["output"].strip()

        if not docker_version:
            return {
                "installed": True,
                "available": False,
                "docker_path": docker_path,
                "docker_version": None,
                "containers": [],
                "findings": [
                    Finding(
                        severity="high",
                        title="Docker daemon unavailable",
                        description=(
                            "Docker is installed, but the Docker daemon "
                            "is not available. Verify Docker service status "
                            "and daemon configuration."
                        ),
                    ).to_dict()
                ],
            }

        containers_result = self.ssh_client.execute(
            "docker ps -a --format "
            "'{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}'"
        )

        inspect_result = self.ssh_client.execute(
            "docker ps -aq"
        )

        container_ids = [
            container_id.strip()
            for container_id in inspect_result["output"].splitlines()
            if container_id.strip()
        ]

        containers = []
        findings = []

        for container_id in container_ids:

            inspect = self.ssh_client.execute(
                "docker inspect "
                "--format "
                "'{{.Name}}|"
                "{{.Config.User}}|"
                "{{.HostConfig.Privileged}}|"
                "{{.HostConfig.NetworkMode}}|"
                "{{.HostConfig.PidMode}}|"
                "{{range .Mounts}}"
                "{{.Type}}:{{.Source}}:{{.Destination}};"
                "{{end}}' "
                f"{container_id}"
            )

            line = inspect["output"].strip()

            if not line:
                continue

            parts = line.split("|", 5)

            if len(parts) != 6:
                continue

            (
                name,
                user,
                privileged,
                network_mode,
                pid_mode,
                mounts_raw,
            ) = parts

            name = name.lstrip("/")

            container = {
                "id": container_id,
                "name": name,
                "user": user or "default",
                "privileged": privileged.lower() == "true",
                "network_mode": network_mode,
                "pid_mode": pid_mode,
                "mounts": [],
            }

            for mount in mounts_raw.split(";"):

                if not mount:
                    continue

                mount_parts = mount.split(":", 2)

                if len(mount_parts) != 3:
                    continue

                mount_type, source, destination = mount_parts

                container["mounts"].append(
                    {
                        "type": mount_type,
                        "source": source,
                        "destination": destination,
                    }
                )

            containers.append(container)

            if container["privileged"]:

                findings.append(
                    Finding(
                        severity="critical",
                        title="Privileged Docker container",
                        description=(
                            f"Container {name} runs with privileged "
                            "mode enabled. This significantly weakens "
                            "container isolation and may allow access "
                            "to host resources."
                        ),
                    ).to_dict()
                )

            if container["network_mode"] == "host":

                findings.append(
                    Finding(
                        severity="high",
                        title="Docker container uses host network",
                        description=(
                            f"Container {name} uses the host network "
                            "namespace. Network isolation from the host "
                            "is disabled."
                        ),
                    ).to_dict()
                )

            if container["pid_mode"] == "host":

                findings.append(
                    Finding(
                        severity="high",
                        title="Docker container uses host PID namespace",
                        description=(
                            f"Container {name} uses the host PID "
                            "namespace. Processes on the host may become "
                            "visible from the container."
                        ),
                    ).to_dict()
                )

            if user in ("", "root", "0"):

                findings.append(
                    Finding(
                        severity="medium",
                        title="Docker container runs as root",
                        description=(
                            f"Container {name} runs as root or does not "
                            "define a non-root container user. Prefer "
                            "a dedicated unprivileged user when possible."
                        ),
                    ).to_dict()
                )

            for mount in container["mounts"]:

                source = mount["source"]

                if source == "/var/run/docker.sock":

                    findings.append(
                        Finding(
                            severity="critical",
                            title="Docker socket mounted into container",
                            description=(
                                f"Container {name} has access to the "
                                "Docker socket. Control over the Docker "
                                "daemon can effectively provide host-level "
                                "control."
                            ),
                        ).to_dict()
                    )

                elif source in (
                    "/",
                    "/etc",
                    "/root",
                    "/boot",
                    "/proc",
                    "/sys",
                ):

                    findings.append(
                        Finding(
                            severity="high",
                            title="Sensitive host path mounted into container",
                            description=(
                                f"Container {name} mounts sensitive host "
                                f"path {source}. Review whether this "
                                "mount is required."
                            ),
                        ).to_dict()
                    )

        return {
            "installed": True,
            "available": True,
            "docker_path": docker_path,
            "docker_version": docker_version,
            "container_count": len(containers),
            "containers": containers,
            "findings": findings,
        }
