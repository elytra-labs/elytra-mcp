"""Managed execution boundary checks with signed, scoped cloud fixtures."""
import base64
import json
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from mirage_mcp.cloud.client import EnvelopeVerifier, CloudError, load_credentials, save_credentials, CloudClient
from mirage_mcp.cloud.runtime import ManagedRuntimeService
from mirage_mcp.cloud.connector import CloudConnector


def encoded(value): return base64.urlsafe_b64encode(value).decode().rstrip('=')

@pytest.fixture
def signing():
    private=Ed25519PrivateKey.generate()
    public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    credentials={'device_id':'device-one','workspace_id':'workspace-one','device_secret':'x'*43,'origin':'https://elytra.example','signing_keys':[{'kid':'alpha-1','jwk':{'kty':'OKP','crv':'Ed25519','x':encoded(public)}}]}
    def sign(payload):
        raw=json.dumps(payload).encode()
        return {'kid':'alpha-1','payload':encoded(raw),'signature':encoded(private.sign(raw))}
    return credentials,sign

@pytest.fixture
def managed(signing,tmp_path):
    credentials,sign=signing
    runtime=ManagedRuntimeService(tmp_path/'managed.db',credentials)
    run=runtime.create_run('Save a harmless fixture')
    definition={'name':'save','description':'Write a fixture','inputSchema':{'type':'object'}}
    row=runtime.register_tools(run['run_id'],run['run_token'],'fixture',[definition])[0]
    def lease(revision=1,category='SINK_PRIVILEGED_WRITE',**extra):
        now=time.time()
        return {'kind':'lease','workspace_id':'workspace-one','device_id':'device-one','issued_at':now,'expires_at':now+300,'epoch':1,'policy_revision':0,'management_revision':revision,'policies':[],
                'classifications':[{'server_id':'fixture','tool_name':'save','schema_hash':row['observed_sha256_hash'],'category':category}],**extra}
    runtime.apply_cloud_lease(lease())
    try: yield runtime,run,lease
    finally: runtime.close()


def decision(runtime,run):
    result=runtime.evaluate(run['run_id'],run['run_token'],'fixture','save',{'summary':'safe'},'call-one')
    assert result['status']=='PENDING'
    approval=runtime.list_approvals()[0]
    now=time.time()
    return {'kind':'approval','workspace_id':'workspace-one','device_id':'device-one','epoch':1,'policy_revision':0,'management_revision':1,'issued_at':now,'expires_at':min(now+120,approval['expires_at_epoch']),
      'approval_id':'cloud-approval','command_id':'cloud-command','decision':'APPROVED','run_id':run['run_id'],'call_id':'call-one','server_id':'fixture','tool_name':'save',
      'arguments_hash':approval['arguments_hash'],'schema_hash':approval['schema_hash'],'local_policy_version':approval['policy_version']}


def test_signed_exact_approval_claim_once_and_durable_outcome(managed,signing):
    runtime,run,_=managed
    credentials,sign=signing
    verifier=EnvelopeVerifier(credentials['signing_keys'],'workspace-one','device-one')
    payload=decision(runtime,run)
    runtime.apply_cloud_decision(verifier.verify(sign(payload),'approval'))
    # Re-signed redelivery is idempotent and cannot add dispatches.
    runtime.apply_cloud_decision({**payload,'issued_at':payload['issued_at']+1})
    allowed=runtime.evaluate(run['run_id'],run['run_token'],'fixture','save',{'summary':'safe'},'call-one')
    runtime.claim_execution(run['run_id'],run['run_token'],'call-one',allowed['permit'],{'summary':'safe'})
    with pytest.raises(RuntimeError): runtime.claim_execution(run['run_id'],run['run_token'],'call-one',allowed['permit'],{'summary':'safe'})
    runtime.complete_execution(run['run_id'],run['run_token'],'call-one',{'ok':True})
    assert runtime.cloud_acknowledgements()==[{'command_id':'cloud-command','outcome':{'status':'COMPLETED'}}]
    runtime.mark_cloud_acknowledged(runtime.cloud_acknowledgements())
    assert runtime.cloud_acknowledgements()==[]


def test_managed_owner_cannot_self_grant_classify_or_approve(managed):
    runtime,run,_=managed
    for action in (lambda:runtime.create_run('Self grant',[{'server_id':'fixture','tool_name':'save','arguments':{}}]),
      lambda:runtime.acknowledge_schema('fixture','save','a'*64,'SOURCE_TRUSTED'),
      lambda:runtime.save_policy({'action':'AUDIT_ONLY'}), lambda:runtime.resolve_approval('anything','APPROVED'),
      lambda:runtime.register_tools(run['run_id'],run['run_token'],'other',[{'name':'x'}],{'x':'SOURCE_TRUSTED'})):
        with pytest.raises(PermissionError): action()


def test_expired_management_lease_prevents_dispatch(managed):
    runtime,run,_=managed
    payload=decision(runtime,run);runtime.apply_cloud_decision(payload)
    ready=runtime.evaluate(run['run_id'],run['run_token'],'fixture','save',{'summary':'safe'},'call-one')
    with runtime._lock: runtime._put('meta','cloud_lease',{'expires_at':0,'epoch':1})
    with pytest.raises(RuntimeError): runtime.claim_execution(run['run_id'],run['run_token'],'call-one',ready['permit'],{'summary':'safe'})


def test_scope_signature_tamper_expiry_and_wrong_key_rejected(signing):
    credentials,sign=signing
    verifier=EnvelopeVerifier(credentials['signing_keys'],'workspace-one','device-one')
    issued=time.time()
    payload={'kind':'lease','workspace_id':'workspace-one','device_id':'device-one','epoch':1,'policy_revision':0,'issued_at':issued,'expires_at':issued+300}
    assert verifier.verify(sign(payload),'lease')['epoch']==1
    for modified in ({**payload,'device_id':'other'}, {**payload,'workspace_id':'other'}, {**payload,'expires_at':0}, {**payload,'expires_at':time.time()+1000}):
        with pytest.raises(CloudError): verifier.verify(sign(modified),'lease')
    envelope=sign(payload); envelope['payload']=encoded(b'{}')
    with pytest.raises(CloudError): verifier.verify(envelope,'lease')


def test_management_revision_classification_change_invalidates_pending(managed):
    runtime,run,lease=managed
    payload=decision(runtime,run)
    runtime.apply_cloud_lease(lease(2,'UNKNOWN'))
    with pytest.raises(RuntimeError): runtime.apply_cloud_decision(payload)
    assert runtime.list_approvals()[0]['status']=='INVALIDATED'
    with pytest.raises(RuntimeError): runtime.apply_cloud_lease(lease(1))


def test_cloud_client_rejects_non_https_credentials_and_redirects():
    for url in ('http://example.com','https://u:p@example.com','https://example.com/path','https://example.com?secret=1'):
        with pytest.raises(ValueError): CloudClient(url)


def test_private_credential_storage(signing,tmp_path):
    credentials,_=signing
    path=tmp_path/'device.json'; save_credentials(credentials,path)
    assert load_credentials(path)==credentials
    assert path.stat().st_mode&0o777==0o600
    path.chmod(0o644)
    with pytest.raises(CloudError): load_credentials(path)


def test_connector_prioritizes_latest_run_and_keeps_approval_run_together(managed,signing):
    runtime,_,_=managed
    credentials,_=signing
    for index in range(35):
        run=runtime.create_run('Task '+str(index))
    runtime.evaluate(run['run_id'],run['run_token'],'fixture','save',{'summary':'newest'},'newest-call')
    connector=CloudConnector(runtime,credentials)
    body=connector._request_body()
    assert run['run_id'] in {r['run_id'] for r in body['runs']}
    assert any(a['binding']['run_id']==run['run_id'] for a in body['approvals'])
    assert all(a['binding']['run_id'] in {r['run_id'] for r in body['runs']} for a in body['approvals'])
    assert all({'type','summary','occurred_at'}<=set(event) for event in body['events'])


def test_dangling_enrollment_symlink_never_silently_uses_standalone(tmp_path):
    path=tmp_path/'device.json';path.symlink_to(tmp_path/'missing')
    with pytest.raises((OSError,CloudError)):load_credentials(path)


def test_lease_monotonic_deadline_and_cancelled_receipt(managed):
    runtime,run,_=managed
    payload=decision(runtime,run);runtime.apply_cloud_decision(payload)
    runtime.cancel_call(run['run_id'],run['run_token'],'call-one')
    assert runtime.cloud_acknowledgements()[0]['outcome']['status']=='INVALIDATED'
    runtime._lease_deadline=time.monotonic()-1
    assert not runtime.cloud_status()['lease_valid']


def test_disconnect_invalidates_authority_and_rejects_inflight_lease(managed):
    runtime,run,lease=managed
    payload=decision(runtime,run);runtime.apply_cloud_decision(payload)
    assert runtime.disconnect_cloud()['lease_valid'] is False
    with pytest.raises(PermissionError):runtime.apply_cloud_lease(lease())
    with pytest.raises(RuntimeError):runtime.apply_cloud_decision(payload)
    assert runtime.list_approvals()[0]['status']=='INVALIDATED'
