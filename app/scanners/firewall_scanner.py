from app.models.finding import Finding


class FirewallScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        findings = []

        ufw_status = self.ssh_client.execute(
            "sudo ufw status"
        )["output"]

        nft_rules = self.ssh_client.execute(
            "sudo nft list ruleset"
        )["output"]

        enabled = False

        if "Status: active" in ufw_status:
            enabled = True

        if not enabled:

            findings.append(
                Finding(
                    severity="high",
                    title="Firewall disabled",
                    description="UFW firewall is not active",
                ).to_dict()
            )

        return {
            "enabled": enabled,
            "findings": findings,
            "rules_length": len(nft_rules),
        }
