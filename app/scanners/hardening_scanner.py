from app.models.finding import Finding


class HardeningScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        result = self.ssh_client.execute(
            "find / -xdev \\( -perm -4000 -o -perm -2000 \\) "
            "-type f -exec stat -c '%A|%a|%U|%G|%n' {} \\; "
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

            is_suid = bool(mode_value & 0o4000)
            is_sgid = bool(mode_value & 0o2000)

            entry = {
                "path": path,
                "permissions": permissions,
                "mode": mode,
                "owner": owner,
                "group": group,
                "suid": is_suid,
                "sgid": is_sgid,
            }

            entries.append(entry)

        suid_entries = [entry for entry in entries if entry["suid"]]

        sgid_entries = [entry for entry in entries if entry["sgid"]]

        suspicious_entries = [entry for entry in entries if entry["owner"] != "root"]

        if suspicious_entries:

            for entry in suspicious_entries:

                findings.append(
                    Finding(
                        severity="high",
                        title="SUID/SGID file has non-root owner",
                        description=(
                            f"Privileged SUID/SGID file "
                            f"{entry['path']} is owned by "
                            f"{entry['owner']}:{entry['group']}. "
                            "Review its ownership and permissions."
                        ),
                    ).to_dict()
                )

        return {
            "total": len(entries),
            "suid_count": len(suid_entries),
            "sgid_count": len(sgid_entries),
            "entries": entries,
            "findings": findings,
        }
