import argparse
import getpass
import json
from datetime import datetime
import os
import sys

from dotenv import load_dotenv

from app.services.ssh_client import SSHClient, SSHConnectionError
from app.services.risk_scoring import RiskScoring
from app.services.report_generator import ReportGenerator
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
    parser.add_argument(
        "--interactive",
        action="store_true",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON report to stdout",
    )

    return parser.parse_args()


def prompt_for_missing_args(args):
    print("\nBastionGuard Security Auditor\n")

    if not args.host:
        args.host = input("Host: ").strip()

    if not args.user:
        args.user = input("User: ").strip()

    if not args.port:
        port = input("Port [22]: ").strip()
        args.port = int(port) if port else 22

    print("\nAuthentication:")
    print("1) SSH Key")
    print("2) Password")

    auth_type = input("Select [1/2]: ").strip()

    if auth_type == "2":
        args.password = getpass.getpass("Password: ")
        args.key = None
    else:
        args.key = input("SSH Key Path [/root/.ssh/id_ed25519]: ").strip()

        if not args.key:
            args.key = "/root/.ssh/id_ed25519"

    return args


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
            if not args.json:
                print(f"[+] Running {section_name} scanner...")
            report[section_name] = scanner_cls(client).scan()
        except SSHConnectionError as exc:
            print(
                f"[FATAL] Scanner '{section_name}' failed due to an SSH error: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)
        except Exception as exc:
            print(
                f"[FATAL] Scanner '{section_name}' raised an unexpected error: {exc}",
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

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    history_json_path = f"reports/{timestamp}.json"
    history_html_path = f"reports/{timestamp}.html"

    with open(
        history_json_path,
        "w",
        encoding="utf-8",
    ) as f:
        f.write(report_json)

    html_report = ReportGenerator.generate_html(report)

    with open(
        history_html_path,
        "w",
        encoding="utf-8",
    ) as f:
        f.write(html_report)

    report_path = "reports/latest_report.json"

    with open(
        report_path,
        "w",
        encoding="utf-8",
    ) as f:
        f.write(report_json)

    with open(
        "reports/latest_report.html",
        "w",
        encoding="utf-8",
    ) as f:
        f.write(html_report)

    if args.json:
        print(report_json)
    else:
        print()
        print("=" * 40)
        print(f"Host       : {report['host']}")
        print(f"Risk Score : {risk_result['score']}")
        print(f"Risk Level : {risk_result['level']}")
        print(f"Report     : {report_path}")
        print("HTML Report: reports/latest_report.html")
        print("=" * 40)


if __name__ == "__main__":
    args = parse_args()

    if args.interactive:
        args = prompt_for_missing_args(args)

    run(args)
