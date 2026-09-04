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


def test_load_hosts_ignores_comments_empty_lines_and_duplicates(tmp_path):
    from app.main import load_hosts

    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text(
        "# production\n"
        "\n"
        "10.0.0.1\n"
        "10.0.0.2\n"
        "10.0.0.1\n",
        encoding="utf-8",
    )

    assert load_hosts(str(hosts_file)) == [
        "10.0.0.1",
        "10.0.0.2",
    ]


def test_load_hosts_rejects_empty_file(tmp_path):
    from app.main import load_hosts
    import pytest

    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("# no hosts\n\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_hosts(str(hosts_file))
