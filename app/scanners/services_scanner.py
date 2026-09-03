import re

from app.models.finding import Finding


class ServicesScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        result = self.ssh_client.execute("ss -tulpn")

        output = result["output"]

        listeners = []
        findings = []

        dangerous_services = {
            "telnet": "high",
            "vsftpd": "high",
            "redis": "high",
            "mongodb": "high",
            "mysql": "medium",
            "postgres": "medium",
        }

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            protocol = parts[0]
            state = parts[1]
            local_address = parts[4]

            if state not in ("LISTEN", "UNCONN"):
                continue

            process = None

            process_match = re.search(r'users:\(\("([^"]+)"', line)

            if process_match:
                process = process_match.group(1)

            address = local_address
            port = None

            if ":" in local_address:

                address, port = local_address.rsplit(":", 1)

                try:
                    port = int(port)

                except ValueError:
                    port = None

            listener = {
                "protocol": protocol,
                "state": state,
                "address": address,
                "port": port,
                "process": process,
            }

            listeners.append(listener)

            if process:

                process_lower = process.lower()

                for service, severity in dangerous_services.items():

                    if service in process_lower:

                        findings.append(
                            Finding(
                                severity=severity,
                                title=f"{service} detected",
                                description=(
                                    f"{service} is listening on "
                                    f"{address}:{port}. "
                                    "Verify authentication and "
                                    "network exposure."
                                ),
                            ).to_dict()
                        )

        return {
            "listeners": listeners,
            "findings": findings,
        }
