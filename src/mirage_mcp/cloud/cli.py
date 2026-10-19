"""Interactive device enrollment; no privileged cloud credential reaches a model."""
from pathlib import Path
import hashlib
import json
import platform
import time
import webbrowser
from .client import CloudClient, CloudError, DEFAULT_CREDENTIAL_FILE, EnvelopeVerifier, load_credentials, save_credentials

def login(args):
    path=Path(args.credential_file)
    if path.exists():
        raise CloudError('Already enrolled. Revoke the existing device in your workspace and run elytra logout first.')
    client=CloudClient(args.cloud_url)
    config=client.request('/config')
    keys=config.get('signing_keys',[])
    # Check optional crypto dependency before issuing an enrollment.
    EnvelopeVerifier(keys,'enrolling','enrolling')
    enrollment=client.request('/enrollments/start',{'device_name':args.device_name or platform.node() or 'Elytra runtime'})
    url=enrollment['verification_url']
    if not url.startswith(client.origin+'/app/#/enroll/'):
        raise CloudError('Enrollment URL does not match the approved cloud origin')
    if args.code: print('One-time enrollment code:',enrollment['user_code'])
    else: webbrowser.open(url)
    print('Enrollment fingerprint:',hashlib.sha256(enrollment['user_code'].encode()).hexdigest()[:12])
    print('Confirm this fingerprint and workspace in the browser. Codes expire after use.')
    print('Waiting up to five minutes. The device credential will not be printed.')
    deadline=time.monotonic()+300
    while time.monotonic()<deadline:
        result=client.request('/enrollments/poll',{'device_secret':enrollment['device_secret']})
        if result.get('status')=='ACTIVE':
            value={'origin':client.origin,'device_id':result['device_id'],'workspace_id':result['workspace_id'],
                   'device_secret':enrollment['device_secret'],'signing_keys':keys,'enrolled_at':time.time()}
            save_credentials(value,path)
            print('Runtime enrolled. Restart elytra up to activate workspace-managed mode.')
            return 0
        time.sleep(3)
    raise CloudError('Enrollment expired; no local connection was saved')

def status(args):
    value=load_credentials(args.credential_file)
    if not value:
        print('Not connected to a hosted workspace. Standalone local mode is available.')
        return 0
    print(json.dumps({key:value[key] for key in ('origin','workspace_id','device_id')},indent=2))
    print('Enrollment is saved. Current management-lease status is available from the running local API.')
    return 0

def logout(args):
    path=Path(args.credential_file)
    value=load_credentials(path)
    if value:
        disconnected=False
        try:
            from mirage_mcp.sdk import RuntimeClient
            response=RuntimeClient(args.gateway,token_file=args.token_file)._request('POST','/api/v1/cloud/disconnect',{})
            disconnected=response.get('connected') is False
        except (ValueError,RuntimeError,OSError): pass
        path.unlink()
        if disconnected: print('Running runtime disconnected and its management lease invalidated.')
        else: print('Could not verify a running runtime; stop it to end any in-memory connection.')
        print('Local enrollment credential removed. Stop the running runtime and revoke the device in your hosted workspace.')
        print('Managed execution never automatically falls back to standalone permissions. Restart explicitly to use standalone mode.')
    else: print('No local cloud enrollment found.')
    return 0
