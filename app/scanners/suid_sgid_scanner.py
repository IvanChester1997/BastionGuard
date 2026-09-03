import shlex


class SUIDSGIDScanner:
    """
    Scanner for SUID/SGID files on a remote Linux host.

    The scanner inventories privileged executables and reports
    potentially suspicious files separately from the inventory.
    """

    DEFAULT_EXCLUDED_PATHS = (
        "/proc",
        "/sys",
        "/dev",
        "/run",
    )

    EXPECTED_SYSTEM_PREFIXES = (
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/lib/",
        "/lib32/",
        "/lib64/",
        "/snap/",
    )

    def __init__(self, client):
        self.client = client

    def _build_find_command(self):
        excluded = " ".join(
            f"-path {shlex.quote(path)} -prune -o"
            for path in self.DEFAULT_EXCLUDED_PATHS
        )

        return (
            "find / -xdev "
            f"{excluded} "
            r"\( -type f -o -type l \) "
            r"\( -perm -4000 -o -perm -2000 \) "
            "-printf '%m|%u|%g|%p\\n' "
            "2>/dev/null"
        )

    def _is_suspicious(self, path, mode, owner, group):
        if not path:
            return False

        if any(path.startswith(prefix) for prefix in self.EXPECTED_SYSTEM_PREFIXES):
            return False

        if mode & 0o6000 == 0:
            return False

        return True

    def scan(self):
        command = self._build_find_command()

        result = self.client.execute(command)
        output = result["output"]

        entries = []
        findings = []

        for line in output.splitlines():
            line = line.strip()

            if not line:
                continue

            parts = line.split("|", 3)

            if len(parts) != 4:
                continue

            mode_str, owner, group, path = parts

            try:
                mode = int(mode_str, 8)
            except ValueError:
                continue

            suid = bool(mode & 0o4000)
            sgid = bool(mode & 0o2000)

            # Be defensive: the remote command is expected to return only
            # SUID/SGID entries, but never trust command output blindly.
            if not (suid or sgid):
                continue

            entry = {
                "path": path,
                "mode": mode_str,
                "owner": owner,
                "group": group,
                "suid": suid,
                "sgid": sgid,
            }

            entries.append(entry)

            if self._is_suspicious(path, mode, owner, group):
                findings.append(entry)

        return {
            "total": len(entries),
            "suid": sum(1 for entry in entries if entry["suid"]),
            "sgid": sum(1 for entry in entries if entry["sgid"]),
            "files": entries,
            "findings": findings,
        }
