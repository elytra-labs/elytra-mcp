"""Personal link: decisions from the account resolve only the exact held action, and never widen anything."""
import base64
import json
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from mirage_mcp.cloud.client import CloudError
from mirage_mcp.cloud.linked import LinkedConnector
from mirage_mcp.runtime import RuntimeService


def encoded(value): return base64.urlsafe_b64encode(value).decode().rstrip('=')


@pytest.fixture
def signing():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    credentials = {'device_id': 'device-one', 'workspace_id': 'workspace-one', 'device_secret': 'x' * 43, 'origin': 'https://elytra.example',
                   'signing_keys': [{'kid': 'alpha-1', 'jwk': {'kty': 'OKP', 'crv': 'Ed25519', 'x': encoded(public)}}]}
    def sign(payload):
        raw = json.dumps(payload).encode()
        return {'kid': 'alpha-1', 'payload': encoded(raw), 'signature': encoded(private.sign(raw))}
    return credentials, sign


@pytest.fixture
def runtime(tmp_path):
    service = RuntimeService(tmp_path / 'live.db')
    try: yield service
    finally: service.close()


def hold(runtime, arguments=None):
    run = runtime.create_run('Publish a release')
    row = runtime.register_tools(run['run_id'], run['run_token'], 'shell', [{'name': 'run', 'description': 'Run a command', 'inputSchema': {'type': 'object'}}])[0]
    runtime.acknowledge_schema('shell', 'run', row['observed_sha256_hash'], 'SINK_PRIVILEGED_WRITE')
    arguments = arguments or {'command': 'npm publish'}
    assert runtime.evaluate(run['run_id'], run['run_token'], 'shell', 'run', arguments, 'call-one')['status'] == 'PENDING'
    return run, runtime.list_approvals('PENDING')[0], arguments


def decision(approval, **changes):
    now = time.time()
    payload = {'kind': 'approval', 'workspace_id': 'workspace-one', 'device_id': 'device-one', 'epoch': 1, 'policy_revision': 0,
               'issued_at': now, 'expires_at': now + 60, 'command_id': 'c0ffee00-0000-4000-8000-000000000001', 'approval_id': approval['approval_id'], 'decision': 'APPROVED',
               **{key: approval[key] for key in RuntimeService.LINK_BINDING}}
    return {**payload, **changes}


class FakeCloud:
    def __init__(self, decisions=(), fail=False):
        self.decisions, self.fail, self.sent = list(decisions), fail, []
    def request(self, route, body=None):
        if self.fail: raise CloudError('Cloud is unavailable or returned an invalid response')
        assert route == '/devices/link-sync'
        self.sent.append(body)
        return {'decisions': self.decisions}


def connector(runtime, credentials, cloud):
    link = LinkedConnector(runtime, credentials)
    link.client = cloud
    return link


def test_snapshot_sends_redacted_summaries_only(runtime):
    secret = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
    _, approval, _ = hold(runtime, {'command': 'git push', 'token': secret})
    [summary] = runtime.link_snapshot()
    assert summary['local_approval_id'] == approval['approval_id']
    assert summary['binding']['arguments_hash'] == approval['arguments_hash']
    text = json.dumps(summary)
    assert secret not in text
    assert set(summary) == {'local_approval_id', 'binding', 'summary'}


def test_signed_remote_approval_releases_only_the_held_action(runtime, signing):
    credentials, sign = signing
    run, approval, arguments = hold(runtime)
    envelope = sign(decision(approval))
    link = connector(runtime, credentials, FakeCloud([envelope]))
    link.sync_once()
    assert runtime.list_approvals()[0]['status'] == 'APPROVED'
    allowed = runtime.evaluate(run['run_id'], run['run_token'], 'shell', 'run', arguments, 'call-one')
    runtime.claim_execution(run['run_id'], run['run_token'], 'call-one', allowed['permit'], arguments)
    # Redelivery of the same decision cannot release anything again.
    link.sync_once()
    with pytest.raises(RuntimeError):
        runtime.claim_execution(run['run_id'], run['run_token'], 'call-one', allowed['permit'], arguments)


@pytest.mark.parametrize('change', [
    {'arguments_hash': 'f' * 64},          # different arguments
    {'policy_version': 999},              # policy changed since the action was held
    {'tool_name': 'other'},               # another tool
    {'device_id': 'device-two'},          # another machine
    {'workspace_id': 'workspace-two'},    # another account
    {'expires_at': time.time() - 1},      # expired
    {'expires_at': time.time() + 3600},   # outlives the 120 second decision window
])
def test_mismatched_or_foreign_decisions_leave_the_action_held(runtime, signing, change):
    credentials, sign = signing
    _, approval, _ = hold(runtime)
    link = connector(runtime, credentials, FakeCloud([sign(decision(approval, **change))]))
    link.sync_once()
    assert runtime.list_approvals()[0]['status'] == 'PENDING'


def test_unsigned_or_tampered_envelopes_are_rejected(runtime, signing):
    credentials, sign = signing
    _, approval, _ = hold(runtime)
    envelope = sign(decision(approval))
    forged = {**envelope, 'payload': encoded(json.dumps(decision(approval, decision='APPROVED', tool_name='run')).encode()[:-1] + b' }')}
    link = connector(runtime, credentials, FakeCloud([forged, {'kid': 'unknown', 'payload': envelope['payload'], 'signature': envelope['signature']}]))
    link.sync_once()
    assert link.rejected == 2
    assert runtime.list_approvals()[0]['status'] == 'PENDING'


def test_first_decision_wins_and_remote_denial_blocks(runtime, signing):
    credentials, sign = signing
    _, approval, _ = hold(runtime)
    runtime.resolve_approval(approval['approval_id'], 'DENIED')
    connector(runtime, credentials, FakeCloud([sign(decision(approval))])).sync_once()
    assert runtime.list_approvals()[0]['status'] == 'DENIED'

    _, second, _ = hold(runtime, {'command': 'npm publish --tag next'})
    connector(runtime, credentials, FakeCloud([sign(decision(second, decision='DENIED', command_id='c0ffee00-0000-4000-8000-000000000002'))])).sync_once()
    assert next(a for a in runtime.list_approvals() if a['approval_id'] == second['approval_id'])['status'] == 'DENIED'


def test_losing_the_link_never_allows_anything(runtime, signing):
    credentials, _ = signing
    run, _, arguments = hold(runtime)
    link = connector(runtime, credentials, FakeCloud(fail=True))
    with pytest.raises(CloudError):
        link.sync_once()
    assert runtime.list_approvals()[0]['status'] == 'PENDING'
    assert runtime.evaluate(run['run_id'], run['run_token'], 'shell', 'run', arguments, 'call-one')['status'] == 'PENDING'


def test_an_unusable_link_does_not_stop_local_protection(tmp_path):
    from mirage_mcp.server.control_plane import ControlPlaneServer
    broken = {'device_id': 'd', 'workspace_id': 'w', 'device_secret': 'x' * 43, 'origin': 'https://elytra.example', 'signing_keys': [{'kid': 'k', 'jwk': {'kty': 'RSA'}}]}
    server = ControlPlaneServer(port=0, db_path=tmp_path / 'live.db', token_file=tmp_path / 'token', link_credentials=broken)
    try:
        assert server.link_connector is None
        assert server.runtime is not None
    finally:
        server.stop()


def test_link_refuses_a_closed_deployment_and_managed_machines(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from mirage_mcp.cloud import cli
    managed = tmp_path / 'cloud-device.json'
    args = SimpleNamespace(credential_file=str(tmp_path / 'cloud-link.json'), managed_credential_file=str(managed), cloud_url='https://elytra.example',
                           device_name='Laptop', code=True, gateway='http://127.0.0.1:1', token_file=str(tmp_path / 'token'))
    monkeypatch.setattr(cli.CloudClient, 'request', lambda self, route, body=None: {'enrollment_enabled': False, 'signing_keys': []})
    with pytest.raises(CloudError, match='not open yet'):
        cli.link(args)
    managed.write_text('{}')
    with pytest.raises(CloudError, match='managed by a team'):
        cli.link(args)
    assert not (tmp_path / 'cloud-link.json').exists()
