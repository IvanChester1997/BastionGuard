import os
import sys
import json

from dotenv import load_dotenv

from app.services.ssh_client import SSHClient, SSHConnectionError
from app.services.risk_scoring import RiskScoring
from app.scanners.ssh_scanner import SSHScanner
from app.scanners.users_scanner import UsersScanner
from app.scanners.updates_scanner import UpdatesScanner
from app.scanners.services_scanner import ServicesScanner
from app.scanners.network_scanner import NetworkScanner
from app.scanners.hardening_scanner import HardeningScanner
from app.scanners.world_writable_scanner import WorldWritableScanner
from app.scanners.suid_sgid_scanner import SUIDSGIDScanner
from app.scanners.cron_timers_scanner import CronTimersScanner
from app.scanners.firewall_scanner import FirewallScanner
from app.scanners.password_policy_scanner import PasswordPolicyScanner
from app.scanners.docker_scanner import DockerScanner

load_dotenv()


def build_client():
    return SSHClient(
        host=os.getenv("SSH_HOST"),
        username=os.getenv("SSH_USER"),
        key_path=os.getenv("SSH_KEY"),
        port=int(os.getenv("SSH_PORT")),
    )


# Порядок важен: секции добавляются в отчёт в этом же порядке.
SCANNERS = [
    ("ssh", SSHScanner),
    ("users", UsersScanner),
    ("updates", UpdatesScanner),
    ("services", ServicesScanner),
    ("network", NetworkScanner),
    ("hardening", HardeningScanner),
    ("world_writable", WorldWritableScanner),
    ("suid_sgid", SUIDSGIDScanner),
    ("cron_timers", CronTimersScanner),
    ("firewall", FirewallScanner),
    ("password_policy", PasswordPolicyScanner),
    ("docker", DockerScanner),
]


def run():
    client = build_client()
    report = {"host": os.getenv("SSH_HOST")}

    for section_name, scanner_cls in SCANNERS:
        try:
            report[section_name] = scanner_cls(client).scan()
        except SSHConnectionError as exc:
            print(
                f"[FATAL] Scanner '{section_name}' failed due to an SSH "
                f"error: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)
        except Exception as exc:
            print(
                f"[FATAL] Scanner '{section_name}' raised an unexpected "
                f"error: {exc}",
                file=sys.stderr,
            )
            raise

    risk_result = RiskScoring.calculate(report)
    report["risk"] = risk_result

    report_json = json.dumps(report, indent=4, ensure_ascii=False)

    print(report_json)

    with open("reports/latest_report.json", "w", encoding="utf-8") as f:
        f.write(report_json)


if __name__ == "__main__":
    run()
