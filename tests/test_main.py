from argparse import Namespace

from app.main import build_client


def test_build_client_uses_cli_arguments():
    args = Namespace(
        host="10.0.0.1",
        user="testuser",
        key="/tmp/test_key",
        password=None,
        port=2222,
        json=False,
    )

    client = build_client(args)

    assert client.host == "10.0.0.1"
    assert client.username == "testuser"
    assert client.key_path == "/tmp/test_key"
    assert client.password is None
    assert client.port == 2222


def test_build_client_uses_password():
    args = Namespace(
        host="10.0.0.1",
        user="testuser",
        key=None,
        password="secret123",
        port=22,
        json=False,
    )

    client = build_client(args)

    assert client.host == "10.0.0.1"
    assert client.username == "testuser"
    assert client.key_path is None
    assert client.password == "secret123"
    assert client.port == 22
