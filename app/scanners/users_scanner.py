class UsersScanner:

    def __init__(self, ssh_client):
        self.ssh_client = ssh_client

    def scan(self):

        passwd_data = self.ssh_client.execute(
            "cat /etc/passwd"
        )["output"]

        sudo_data = self.ssh_client.execute(
            "getent group sudo"
        )["output"]

        uid0_users = []
        interactive_users = []
        sudo_users = []

        for line in passwd_data.splitlines():

            parts = line.split(":")

            if len(parts) < 7:
                continue

            username = parts[0]
            uid = parts[2]
            shell = parts[6]

            if uid == "0":
                uid0_users.append(username)

            if shell.endswith("bash") or shell.endswith("sh"):
                interactive_users.append(username)

        if sudo_data:

            parts = sudo_data.split(":")

            if len(parts) >= 4:

                members = parts[3]

                if members.strip():

                    sudo_users = [
                        user.strip()
                        for user in members.split(",")
                    ]

        return {
            "uid0_users": uid0_users,
            "sudo_users": sudo_users,
            "interactive_users": interactive_users,
        }
