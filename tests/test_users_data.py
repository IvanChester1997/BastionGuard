import os

from dotenv import load_dotenv

from app.services.ssh_client import SSHClient


load_dotenv()

client = SSHClient(
    host=os.getenv("SSH_HOST"),
    username=os.getenv("SSH_USER"),
    key_path=os.getenv("SSH_KEY"),
    port=int(os.getenv("SSH_PORT")),
)

print("=== PASSWD ===")
print(client.execute("cat /etc/passwd")["output"])

print("\n=== SUDO ===")
print(client.execute("getent group sudo")["output"])
