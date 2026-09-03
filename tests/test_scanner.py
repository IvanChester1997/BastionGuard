import os

from dotenv import load_dotenv

from app.services.ssh_client import SSHClient
from app.scanners.ssh_scanner import SSHScanner


load_dotenv()


client = SSHClient(
    host=os.getenv("SSH_HOST"),
    username=os.getenv("SSH_USER"),
    key_path=os.getenv("SSH_KEY"),
    port=int(os.getenv("SSH_PORT")),
)

scanner = SSHScanner(client)

result = scanner.scan()

print(result)
