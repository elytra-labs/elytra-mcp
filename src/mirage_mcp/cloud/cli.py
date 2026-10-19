"""Interactive device enrollment; no privileged cloud credential reaches a model."""
from pathlib import Path
import hashlib
import json
import platform
import time
import webbrowser
from .client import CloudClient, CloudError, DEFAULT_CREDENTIAL_FILE, DEFAULT_LINK_FILE, EnvelopeVerifier, load_credentials, save_credentials

def _enroll(args, path, kind):
    client=CloudClient(args.cloud_url)
    config=client.request('/config')
    if config.get('enrollment_enabled') is False:
        raise CloudError('Accounts are not open yet on this deployment. Elytra keeps working locally.')
    keys=config.get('signing_keys',[])
    # Check optional crypto dependency before issuing an enrollment.
    EnvelopeVerifier(keys,'enrolling','enrolling')
    enrollment=client.request('/enrollments/start',{'device_name':args.device_name or platform.node() or 'Elytra runtime','kind':kind})
    url=enrollment['verification_url']
    if not url.startswith(client.origin+'/app/#/enroll/'):
        raise CloudError('Enrollment URL does not match the approved cloud origin')
    if args.code: print('One-time enrollment code:',enrollment['user_code'])
    else: webbrowser.open(url)
    print('Enrollment fingerprint:',hashlib.sha256(enrollment['user_code'].encode()).hexdigest()[:12])
    print('Confirm this fingerprint in the browser. Codes expire after use.')
    print('Waiting up to five minutes. The device credential will not be printed.')
    deadline=time.monotonic()+300
    while time.monotonic()<deadline:
        result=client.request('/enrollments/poll',{'device_secret':enrollment['device_secret']})
        if result.get('status')=='ACTIVE':
            value={'origin':client.origin,'device_id':result['device_id'],'workspace_id':result['workspace_id'],
                   'device_secret':enrollment['device_secret'],'signing_keys':keys,'enrolled_at':time.time()}
            save_credentials(value,path)
            return value
        time.sleep(3)
    raise CloudError('Enrollment expired; no local connection was saved')

def login(args):
    path=Path(args.credential_file)
    if path.exists():
        raise CloudError('Already enrolled. Revoke the existing device in your workspace and run elytra logout first.')
    _enroll(args,path,'managed')
    print('Runtime enrolled. Restart elytra up to activate workspace-managed mode.')
    return 0

def link(args):
    """Link this machine to your account so held actions can be approved from your phone."""
    path=Path(args.credential_file)
    if path.exists():
        raise CloudError('This machine is already linked. Run elytra unlink first to link another account.')
    if Path(args.managed_credential_file).exists():
        raise CloudError('This runtime is managed by a team workspace; personal links are not used in managed mode.')
    value=_enroll(args,path,'linked')
    print(f"Linked. Held actions now also appear at {value['origin']}/app/ for you to approve or deny.")
    print('Your guardrails, history and decisions stay on this machine. Only summaries of held actions are sent.')
    try:
        from mirage_mcp.sdk import RuntimeClient
        result=RuntimeClient(args.gateway,token_file=args.token_file)._request('POST','/api/v1/cloud/link/reload',{})
        print('The running runtime is now linked.' if result.get('linked') else 'Start the runtime to activate the link: elytra service start')
    except (ValueError,RuntimeError,OSError):
        print('Start the runtime to activate the link: elytra service start')
    return 0

def unlink(args):
    path=Path(args.credential_file)
    if not load_credentials(path):
        print('This machine is not linked to an account.')
        return 0
    try:
        from mirage_mcp.sdk import RuntimeClient
        RuntimeClient(args.gateway,token_file=args.token_file)._request('POST','/api/v1/cloud/link/disconnect',{})
        print('Stopped the link in the running runtime.')
    except (ValueError,RuntimeError,OSError):
        print('The runtime is not running; the link stops with it.')
    path.unlink()
    print('Unlinked. Remove this device from your account at the hosted dashboard to finish.')
    return 0

def status(args):
    value=load_credentials(args.credential_file)
    linked=load_credentials(getattr(args,'link_credential_file',DEFAULT_LINK_FILE))
    if not value and not linked:
        print('Not connected to an account or workspace. Local mode is active.')
        return 0
    if linked:
        print(json.dumps({'linked':True,**{key:linked[key] for key in ('origin','workspace_id','device_id')}},indent=2))
    if value:
        print(json.dumps({'managed':True,**{key:value[key] for key in ('origin','workspace_id','device_id')}},indent=2))
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
