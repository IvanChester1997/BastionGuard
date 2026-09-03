from app.scanners.cron_timers_scanner import CronTimersScanner


class FakeSSHClient:

    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    def execute(self, command):
        self.commands.append(command)

        for expected, response in self.responses:
            if expected in command:
                return response

        return {
            "output": "",
            "error": "",
        }


def test_cron_timers_scanner_collects_cron_and_timers():
    client = FakeSSHClient(
        [
            (
                "/etc/crontab",
                {
                    "output": (
                        "--- /etc/crontab ---\n"
                        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
                    ),
                    "error": "",
                },
            ),
            (
                "systemctl list-timers",
                {
                    "output": (
                        '[{"unit":"apt-daily.timer",'
                        '"activates":"apt-daily.service"}]'
                    ),
                    "error": "",
                },
            ),
        ]
    )

    result = CronTimersScanner(client).scan()

    assert result["cron"]["output"]
    assert len(result["timers"]["items"]) == 1
    assert result["timers"]["items"][0]["unit"] == "apt-daily.timer"
    assert result["timers"]["items"][0]["activates"] == "apt-daily.service"
    assert result["findings"] == []


def test_cron_timers_scanner_handles_invalid_timer_json():
    client = FakeSSHClient(
        [
            (
                "systemctl list-timers",
                {
                    "output": "not valid json",
                    "error": "",
                },
            ),
        ]
    )

    result = CronTimersScanner(client).scan()

    assert result["timers"]["items"] == []


def test_cron_timers_scanner_collects_cron_d():
    client = FakeSSHClient(
        [
            (
                "/etc/crontab",
                {
                    "output": (
                        "--- /etc/crontab ---\n"
                        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
                        "--- /etc/cron.d ---\n"
                        "--- /etc/cron.d/test_job ---\n"
                        "30 3 * * * root /usr/local/bin/test_job\n"
                    ),
                    "error": "",
                },
            ),
            (
                "systemctl list-timers",
                {
                    "output": "[]",
                    "error": "",
                },
            ),
        ]
    )

    result = CronTimersScanner(client).scan()

    assert "/etc/cron.d/test_job" in result["cron"]["output"]
    assert "/usr/local/bin/test_job" in result["cron"]["output"]


def test_cron_timers_scanner_detects_suspicious_root_path():
    client = FakeSSHClient(
        [
            (
                "/etc/crontab",
                {
                    "output": (
                        "--- /etc/crontab ---\n"
                        "30 3 * * * root /tmp/backup.sh\n"
                    ),
                    "error": "",
                },
            ),
            (
                "systemctl list-timers",
                {
                    "output": "[]",
                    "error": "",
                },
            ),
        ]
    )

    result = CronTimersScanner(client).scan()

    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"
    assert "Suspicious root cron command path" in result["findings"][0]["title"]
    assert "/tmp/backup.sh" in result["findings"][0]["description"]


def test_cron_timers_scanner_ignores_standard_system_jobs():
    client = FakeSSHClient(
        [
            (
                "/etc/crontab",
                {
                    "output": (
                        "# /etc/crontab\n"
                        "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
                        "25 6    * * *   root    test -x /usr/sbin/anacron || "
                        "{ cd / && run-parts --report /etc/cron.daily; }\n"
                        "47 6    * * 7   root    test -x /usr/sbin/anacron || "
                        "{ cd / && run-parts --report /etc/cron.weekly; }\n"
                        "52 6    1 * *   root    test -x /usr/sbin/anacron || "
                        "{ cd / && run-parts --report /etc/cron.monthly; }\n"
                        "30 3 * * 0 root test -e /run/systemd/system || "
                        "SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n"
                        "10 3 * * * root test -e /run/systemd/system || "
                        "SERVICE_MODE=1 /sbin/e2scrub_all -A -r\n"
                    ),
                    "error": "",
                },
            ),
            (
                "systemctl list-timers",
                {
                    "output": "[]",
                    "error": "",
                },
            ),
        ]
    )

    result = CronTimersScanner(client).scan()

    assert result["findings"] == []
