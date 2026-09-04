# BastionGuard

BastionGuard is a Linux security auditing tool for authorized SSH-based security assessments.

## Features

- SSH security auditing
- User and update checks
- Service and network auditing
- Linux hardening checks
- World-writable file detection
- SUID/SGID auditing
- Cron and systemd timer checks
- Firewall auditing
- Password policy checks
- Docker auditing
- Risk scoring
- JSON, HTML and PDF reports
- Single-host and multi-host scanning
- Automated tests

## Requirements

- Linux / WSL
- Python 3.13+
- SSH access to the target host

## Installation

```bash
git clone git@github.com:IvanChester1997/BastionGuard.git
cd BastionGuard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Single host:

```bash
python -m app.main --host 192.168.1.10 --user root --key /root/.ssh/id_ed25519
```

JSON output:

```bash
python -m app.main --host 192.168.1.10 --user root --key /root/.ssh/id_ed25519 --json
```

Multi-host:

Create a hosts file with one host per line:

```text
192.168.1.10
192.168.1.11
# comments and empty lines are ignored
```

Then run:

```bash
python -m app.main --hosts-file hosts.txt --user root --key /root/.ssh/id_ed25519
```

## Reports

Reports are generated in the `reports/` directory.

Single-host scans generate JSON, HTML and PDF reports. Multi-host scans additionally generate an aggregate JSON report.

## Risk Scoring

Findings are converted into an overall security risk level: LOW, MEDIUM, HIGH or CRITICAL.

## Testing

```bash
.venv/bin/python -m pytest -q
```

## Security

BastionGuard is intended for authorized security auditing and defensive administration. Only scan systems you own or have explicit permission to audit.

## License

License information will be added separately.
