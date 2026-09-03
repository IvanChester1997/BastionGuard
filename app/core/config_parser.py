def parse_sshd_config(config_text: str) -> dict:
    config = {}

    for line in config_text.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        key = parts[0]
        value = " ".join(parts[1:])

        config[key] = value

    return config
