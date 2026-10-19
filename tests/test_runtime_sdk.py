import json

import pytest

from mirage_mcp.sdk import RuntimeClient


class Response:
    status = 200
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return None
    def read(self, size):
        return b'{"ok":true}'


class Opener:
    def __init__(self):
        self.requests = []
    def open(self, request, timeout):
        self.requests.append(request)
        return Response()


def test_scoped_sdk_never_keeps_or_sends_owner_token():
    owner = RuntimeClient(token="owner-secret")
    owner._opener = Opener()
    scoped = owner.for_run("run-1", "scoped-secret")
    scoped.evaluate("github", "read", {}, "read-1")
    request = scoped._opener.requests[0]
    assert request.get_header("Authorization") == "Bearer scoped-secret"
    assert json.loads(request.data)["run_id"] == "run-1"
    assert b"owner-secret" not in request.data
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


def test_sdk_token_file_and_operator_route(tmp_path):
    token_file = tmp_path / "control-plane.token"
    token_file.write_text("operator-secret\n")
    client = RuntimeClient(token_file=token_file)
    client._opener = Opener()
    client.list_tools()
    assert client._opener.requests[0].full_url.endswith("/api/v1/tools")
    assert client._opener.requests[0].get_header("Authorization") == "Bearer operator-secret"
