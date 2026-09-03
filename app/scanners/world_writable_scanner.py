from app.models.finding import Finding


class WorldWritableScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        result = self.ssh_client.execute(
            "find / -xdev \\( -type f -o -type d \\) "
            "-perm -0002 "
            "-exec stat -c '%A|%a|%U|%G|%n' {} \\; "
            "2>/dev/null"
        )

        output = result["output"]

        entries = []
        findings = []

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split("|", 4)

            if len(parts) != 5:
                continue

            permissions, mode, owner, group, path = parts

            mode_value = int(mode, 8)

            is_directory = permissions.startswith("d")
            is_file = permissions.startswith("-")

            world_writable = bool(mode_value & 0o0002)
            sticky = bool(mode_value & 0o1000)
            sgid = bool(mode_value & 0o2000)

            is_wsl_mount = path.startswith("/mnt/")
            is_known_system_directory = path == "/tmp/.X11-unix"

            entry = {
                "path": path,
                "permissions": permissions,
                "mode": mode,
                "owner": owner,
                "group": group,
                "file": is_file,
                "directory": is_directory,
                "world_writable": world_writable,
                "sticky": sticky,
                "sgid": sgid,
                "wsl_mount": is_wsl_mount,
            }

            entries.append(entry)

            if is_wsl_mount or is_known_system_directory:
                continue

            if is_file:

                findings.append(
                    Finding(
                        severity="high",
                        title="World-writable file detected",
                        description=(
                            f"File {path} is writable by all users "
                            f"({permissions}, mode {mode}). "
                            f"Owner: {owner}:{group}. "
                            "Review whether world-write access is required."
                        ),
                    ).to_dict()
                )

            elif is_directory and not sticky:

                findings.append(
                    Finding(
                        severity="high",
                        title="World-writable directory without sticky bit",
                        description=(
                            f"Directory {path} is writable by all users "
                            f"without the sticky bit "
                            f"({permissions}, mode {mode}). "
                            f"Owner: {owner}:{group}. "
                            "Review directory permissions."
                        ),
                    ).to_dict()
                )

        file_entries = [
            entry
            for entry in entries
            if entry["file"]
        ]

        directory_entries = [
            entry
            for entry in entries
            if entry["directory"]
        ]

        suspicious_files = [
            entry
            for entry in file_entries
            if not entry["wsl_mount"]
            and entry["path"] != "/tmp/.X11-unix"
        ]

        suspicious_directories = [
            entry
            for entry in directory_entries
            if not entry["sticky"]
            and not entry["wsl_mount"]
            and entry["path"] != "/tmp/.X11-unix"
        ]

        return {
            "total": len(entries),
            "files": len(file_entries),
            "directories": len(directory_entries),
            "world_writable_files": len(suspicious_files),
            "world_writable_directories_without_sticky": (
                len(suspicious_directories)
            ),
            "entries": entries,
            "findings": findings,
        }
