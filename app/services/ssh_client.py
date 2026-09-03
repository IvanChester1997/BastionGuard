import paramiko


class SSHClient:

    def __init__(
        self,
        host: str,
        username: str,
        key_path: str,
        port: int = 22,
    ):
        self.host = host
        self.username = username
        self.key_path = key_path
        self.port = port

    def execute(self, command: str):

        key = paramiko.Ed25519Key.from_private_key_file(
            self.key_path
        )

        client = paramiko.SSHClient()

        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        client.connect(
            hostname=self.host,
            username=self.username,
            pkey=key,
            port=self.port,
        )

        stdin, stdout, stderr = client.exec_command(
            command
        )

        output = stdout.read().decode()

        error = stderr.read().decode()

        client.close()

        return {
            "output": output.strip(),
            "error": error.strip()
        }
