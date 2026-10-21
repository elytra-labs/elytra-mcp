import json

import pytest

from mirage_mcp.sdk import RuntimeClient


class Wire:
    """Stands in for the loopback socket: records what the SDK sends, answers with a fixed JSON body."""

    def __init__(self):
        self.sent = []

    def __call__(self, address, timeout):
        wire = self

        class Connection:
            replied = False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def sendall(self, data):
                wire.sent.append(data)

            def recv(self, size):
                if self.replied:
                    return b""
                self.replied = True
                return b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"

        return Connection()

    def request(self, index=0):
        head, _, body = self.sent[index].partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        headers = dict(line.split(": ", 1) for line in lines[1:])
        return lines[0], headers, body


def test_scoped_sdk_never_keeps_or_sends_owner_token(monkeypatch):
    wire = Wire()
    monkeypatch.setattr("mirage_mcp.sdk.socket.create_connection", wire)
    owner = RuntimeClient(token="owner-secret")
    scoped = owner.for_run("run-1", "scoped-secret")
    scoped.evaluate("github", "read", {}, "read-1")
    line, headers, body = wire.request()
    assert line.startswith("POST /api/v1/runtime/evaluate ")
    assert headers["Authorization"] == "Bearer scoped-secret"
    assert json.loads(body)["run_id"] == "run-1"
    assert b"owner-secret" not in wire.sent[0]
    assert "owner-secret" not in repr(vars(scoped))
    for action in (lambda: scoped.create_run("Other"), lambda: scoped.list_tools(), lambda: scoped.classify_tool("s", "t", "hash", "SOURCE_TRUSTED"), lambda: scoped.resolve_approval("a", "APPROVED")):
        with pytest.raises(ValueError):
            action()


def test_owner_sdk_does_not_run_without_explicit_run_credentials():
    owner = RuntimeClient(token="owner-secret")
    with pytest.raises(ValueError):
        owner.evaluate("github", "read", {})
    with pytest.raises(ValueError):
        owner.proxy("github", ["python", "server.py"])


@pytest.mark.parametrize("url", ["http://example.com", "https://example.com", "http://127.0.0.1@evil.test", "http://127.0.0.1/?token=secret", "file:///etc/passwd"])
def test_sdk_is_loopback_only_and_rejects_credential_urls(url):
    with pytest.raises(ValueError):
        RuntimeClient(url, token="owner-secret")


def test_sdk_token_file_and_operator_route(tmp_path, monkeypatch):
    wire = Wire()
    monkeypatch.setattr("mirage_mcp.sdk.socket.create_connection", wire)
    token_file = tmp_path / "control-plane.token"
    token_file.write_text("operator-secret\n")
    client = RuntimeClient(token_file=token_file)
    client.list_tools()
    line, headers, _ = wire.request()
    assert line.startswith("GET /api/v1/tools ")
    assert headers["Authorization"] == "Bearer operator-secret"
