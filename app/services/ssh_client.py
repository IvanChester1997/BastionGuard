import socket
import paramiko


class SSHConnectionError(Exception):
    """Raised when the SSH connection to the target host cannot be
    established, or when a command fails to execute over that connection."""
    pass


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
        self._client = None
        self._key = None

    def _load_key(self):
        if self._key is None:
            try:
                self._key = paramiko.Ed25519Key.from_private_key_file(
                    self.key_path
                )
            except FileNotFoundError as exc:
                raise SSHConnectionError(
                    f"SSH key not found at '{self.key_path}' "
                    f"for host '{self.host}'"
                ) from exc
            except paramiko.SSHException as exc:
                raise SSHConnectionError(
                    f"Invalid SSH key at '{self.key_path}': {exc}"
                ) from exc
        return self._key

    def _connect(self):
        if self._client is not None:
            return self._client

        key = self._load_key()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                username=self.username,
                pkey=key,
                port=self.port,
            )
        except paramiko.AuthenticationException as exc:
            raise SSHConnectionError(
                f"Authentication failed for "
                f"{self.username}@{self.host}:{self.port}"
            ) from exc
        except (paramiko.SSHException, socket.error, OSError) as exc:
            raise SSHConnectionError(
                f"Could not connect to {self.host}:{self.port} — {exc}"
            ) from exc

        self._client = client
        return client

    def execute(self, command: str):
        client = self._connect()

        try:
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
        except (paramiko.SSHException, socket.error, OSError) as exc:
            raise SSHConnectionError(
                f"Failed to execute '{command}' on {self.host}: {exc}"
            ) from exc

        return {
            "output": output.strip(),
            "error": error.strip(),
        }

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None
