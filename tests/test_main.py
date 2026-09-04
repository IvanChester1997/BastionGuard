from argparse import Namespace

from app.main import build_client


def test_build_client_uses_cli_arguments():
    args = Namespace(
        host="10.0.0.1",
        user="testuser",
        key="/tmp/test_key",
        port=2222,
    )

    client = build_client(args)

    assert client.host == "10.0.0.1"
    assert client.username == "testuser"
    assert client.key_path == "/tmp/test_key"
    assert client.port == 2222
