from app.core.config_parser import parse_sshd_config
from app.models.finding import Finding


class SSHScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        findings = []
        score = 100

        result = self.ssh_client.execute("cat /etc/ssh/sshd_config")

        raw_config = result["output"]

        config = parse_sshd_config(raw_config)

        if config.get("PermitRootLogin") == "yes":

            findings.append(
                Finding(
                    severity="critical",
                    title="Root login enabled",
                    description="Root can login via SSH",
                ).to_dict()
            )

            score -= 30

        if config.get("PasswordAuthentication") == "yes":

            findings.append(
                Finding(
                    severity="high",
                    title="Password authentication enabled",
                    description="SSH password login enabled",
                ).to_dict()
            )

            score -= 20

        if config.get("PubkeyAuthentication") == "no":

            findings.append(
                Finding(
                    severity="medium",
                    title="Public key auth disabled",
                    description="SSH keys are disabled",
                ).to_dict()
            )

            score -= 10

        return {"score": score, "findings": findings}
