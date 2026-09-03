from app.core.config_parser import parse_sshd_config

sample = """
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
"""

print(parse_sshd_config(sample))
