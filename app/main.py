import argparse
import json
import os
import sys

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


def parse_args():
    parser = argparse.ArgumentParser(description="BastionGuard Linux Security Auditor")

    parser.add_argument("--host")
    parser.add_argument("--user")
    parser.add_argument("--key")
    parser.add_argument("--password")
    parser.add_argument("--port", type=int)

    return parser.parse_args()


def build_client(args):
    key_path = args.key
    password = args.password

    if password is None:
        key_path = key_path or os.getenv("SSH_KEY")

    return SSHClient(
        host=args.host or os.getenv("SSH_HOST"),
        username=args.user or os.getenv("SSH_USER"),
        key_path=key_path,
        password=password,
        port=args.port or int(os.getenv("SSH_PORT")),
    )


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


def run(args):
    client = build_client(args)

    report = {
        "host": args.host or os.getenv("SSH_HOST"),
    }

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

    report_json = json.dumps(
        report,
        indent=4,
        ensure_ascii=False,
    )

    print(report_json)

    with open(
        "reports/latest_report.json",
        "w",
        encoding="utf-8",
    ) as f:
        f.write(report_json)


if __name__ == "__main__":
    run(parse_args())
