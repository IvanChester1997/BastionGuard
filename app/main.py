import os
import json

from dotenv import load_dotenv

from app.services.ssh_client import SSHClient
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

load_dotenv()


def build_client():

    return SSHClient(
        host=os.getenv("SSH_HOST"),
        username=os.getenv("SSH_USER"),
        key_path=os.getenv("SSH_KEY"),
        port=int(os.getenv("SSH_PORT")),
    )


def run():

    client = build_client()

    ssh_result = SSHScanner(client).scan()

    users_result = UsersScanner(client).scan()
    updates_result = UpdatesScanner(client).scan()
    services_result = ServicesScanner(client).scan()
    network_result = NetworkScanner(client).scan()
    hardening_result = HardeningScanner(client).scan()
    world_writable_result = WorldWritableScanner(client).scan()
    suid_sgid_result = SUIDSGIDScanner(client).scan()
    cron_timers_result = CronTimersScanner(client).scan()
    firewall_result = FirewallScanner(client).scan()
    password_policy_result = PasswordPolicyScanner(client).scan()

    report = {
        "host": os.getenv("SSH_HOST"),
        "ssh": ssh_result,
        "users": users_result,
        "updates": updates_result,
        "services": services_result,
        "network": network_result,
        "hardening": hardening_result,
        "world_writable": world_writable_result,
        "suid_sgid": suid_sgid_result,
        "cron_timers": cron_timers_result,
        "firewall": firewall_result,
        "password_policy": password_policy_result,
    }

    risk_result = RiskScoring.calculate(report)
    report["risk"] = risk_result

    report_json = json.dumps(report, indent=4, ensure_ascii=False)

    print(report_json)

    with open("reports/latest_report.json", "w", encoding="utf-8") as f:
        f.write(report_json)


if __name__ == "__main__":
    run()
