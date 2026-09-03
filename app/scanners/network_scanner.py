import re

from app.models.finding import Finding


class NetworkScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        interfaces_result = self.ssh_client.execute("ip -br addr")

        routes_result = self.ssh_client.execute("ip route")

        links_result = self.ssh_client.execute("ip -br link")

        interfaces = self._parse_interfaces(interfaces_result["output"])

        routes = self._parse_routes(routes_result["output"])

        links = self._parse_links(links_result["output"])

        findings = []

        default_route = any(route["destination"] == "default" for route in routes)

        if not default_route:

            findings.append(
                Finding(
                    severity="medium",
                    title="Default route missing",
                    description=("No default network route was detected."),
                ).to_dict()
            )

        return {
            "interfaces": interfaces,
            "routes": routes,
            "links": links,
            "findings": findings,
        }

    def _parse_interfaces(self, output):

        interfaces = []

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            name = parts[0]
            state = parts[1]

            addresses = parts[2:]

            interfaces.append(
                {
                    "name": name,
                    "state": state,
                    "addresses": addresses,
                }
            )

        return interfaces

    def _parse_routes(self, output):

        routes = []

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            route = {
                "destination": parts[0],
                "gateway": None,
                "interface": None,
                "metric": None,
            }

            if "via" in parts:
                via_index = parts.index("via")

                if via_index + 1 < len(parts):
                    route["gateway"] = parts[via_index + 1]

            if "dev" in parts:
                dev_index = parts.index("dev")

                if dev_index + 1 < len(parts):
                    route["interface"] = parts[dev_index + 1]

            if "metric" in parts:
                metric_index = parts.index("metric")

                if metric_index + 1 < len(parts):

                    try:
                        route["metric"] = int(parts[metric_index + 1])
                    except ValueError:
                        pass

            routes.append(route)

        return routes

    def _parse_links(self, output):

        links = []

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            name = parts[0]
            state = parts[1]

            mac = None

            for part in parts[2:]:

                if re.fullmatch(
                    r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}",
                    part,
                ):
                    mac = part
                    break

            links.append(
                {
                    "name": name,
                    "state": state,
                    "mac": mac,
                }
            )

        return links
