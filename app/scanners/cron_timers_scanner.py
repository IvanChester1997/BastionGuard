import json


class CronTimersScanner:
    """
    Scanner for cron jobs and systemd timers on a remote Linux host.
    """

    SUSPICIOUS_PATHS = (
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/home/",
        "/mnt/",
    )

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def _find_suspicious_cron_entries(self, cron_output):
        findings = []

        for line in cron_output.splitlines():
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split()

            if len(parts) < 7:
                continue

            if parts[5] != "root":
                continue

            command = " ".join(parts[6:])

            if any(path in command for path in self.SUSPICIOUS_PATHS):
                findings.append(
                    {
                        "severity": "high",
                        "title": "Suspicious root cron command path",
                        "description": (
                            f"Root cron job executes a command from a "
                            f"potentially user-writable path: {command}"
                        ),
                    }
                )

        return findings

    def scan(self):
        cron_result = self.ssh_client.execute(
            "printf '%s\\n' '--- /etc/crontab ---'; "
            "cat /etc/crontab 2>/dev/null || true; "
            "printf '%s\\n' '--- /etc/cron.d ---'; "
            "find /etc/cron.d -maxdepth 1 -type f -readable "
            "-print -exec sh -c 'echo \"--- $1 ---\"; cat \"$1\"' _ {} \\; "
            "2>/dev/null || true; "
            "printf '%s\\n' '--- user crontab ---'; "
            "crontab -l 2>/dev/null || true"
        )

        timer_result = self.ssh_client.execute(
            "systemctl list-timers --all --no-legend --no-pager -o json "
            "2>/dev/null || true"
        )

        try:
            timers = json.loads(timer_result["output"])
        except (json.JSONDecodeError, TypeError):
            timers = []

        findings = self._find_suspicious_cron_entries(
            cron_result["output"]
        )

        return {
            "cron": {
                "output": cron_result["output"],
                "error": cron_result["error"],
            },
            "timers": {
                "items": timers,
                "error": timer_result["error"],
            },
            "findings": findings,
        }
