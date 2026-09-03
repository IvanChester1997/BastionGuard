class UpdatesScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        result = self.ssh_client.execute(
            "apt list --upgradable 2>/dev/null"
        )

        output = result["output"]

        packages = []

        security_updates = []

        for line in output.splitlines():

            if (
                not line.strip()
                or line.startswith("Listing")
            ):
                continue

            packages.append(line)

            if "security" in line.lower():
                security_updates.append(line)

        return {
            "total_updates": len(packages),
            "security_updates": len(security_updates),
            "packages": packages[:10],
        }
