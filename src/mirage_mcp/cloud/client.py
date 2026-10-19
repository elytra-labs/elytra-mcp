"""Bounded HTTPS transport and private device enrollment state."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

DEFAULT_CREDENTIAL_FILE = Path.home() / '.elytra' / 'cloud-device.json'

class CloudError(RuntimeError):
    pass

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class CloudClient:
    def __init__(self, origin, device_id=None, device_secret=None, *, allow_local=False):
        parsed = urlsplit(origin)
        local = allow_local and parsed.scheme == 'http' and parsed.hostname in {'localhost','127.0.0.1'}
        if (parsed.scheme != 'https' and not local) or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'','/'}:
            raise ValueError('Cloud origin must be an HTTPS origin without a path or credentials')
        self.origin = origin.rstrip('/')
        self.device_id, self.device_secret = device_id, device_secret
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, route, body=None):
        raw = json.dumps(body, allow_nan=False).encode() if body is not None else None
        if raw and len(raw) > 256 * 1024:
            raise CloudError('Cloud request exceeds 256 KiB')
        headers = {'Accept':'application/json','Content-Type':'application/json'}
        if self.device_id:
            headers.update(Authorization='Bearer '+self.device_secret, **{'X-Elytra-Device':self.device_id})
        req = Request(self.origin+'/api/cloud/v1'+route, data=raw, headers=headers, method='POST' if body is not None else 'GET')
        try:
            with self.opener.open(req, timeout=15) as response:
                payload = response.read(1024*1024+1)
                if len(payload) > 1024*1024: raise CloudError('Cloud response exceeds 1 MiB')
                value = json.loads(payload)
                if not isinstance(value, dict): raise CloudError('Invalid cloud response')
                return value
        except HTTPError as exc:
            # Do not reflect server bodies that may include credentials/payloads.
            raise CloudError(f'Cloud request rejected ({exc.code})') from None
        except (URLError, ValueError, TimeoutError) as exc:
            raise CloudError('Cloud is unavailable or returned an invalid response') from exc


def load_credentials(path=DEFAULT_CREDENTIAL_FILE):
    path = Path(path)
    if not os.path.lexists(path): return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise CloudError('Cloud credential file must be a private 0600 regular file owned by you')
        with os.fdopen(fd, 'r') as stream:
            fd = None
            value = json.load(stream)
        for key in ('origin','device_id','device_secret','workspace_id','signing_keys'):
            if key not in value: raise CloudError('Incomplete cloud enrollment; run elytra login again')
        for key in ('device_id','workspace_id'):
            if not isinstance(value[key],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',value[key]): raise CloudError('Invalid enrolled identity')
        if not isinstance(value['device_secret'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',value['device_secret']): raise CloudError('Invalid device credential')
        CloudClient(value['origin'])
        return value
    finally:
        if fd is not None: os.close(fd)


def save_credentials(value, path=DEFAULT_CREDENTIAL_FILE):
    import tempfile
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink(): raise CloudError('Refusing symlinked device credentials')
    if path.exists(): load_credentials(path)
    fd, temp = tempfile.mkstemp(prefix='.cloud-device-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp): os.unlink(temp)


class EnvelopeVerifier:
    def __init__(self, keys, workspace_id, device_id):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            raise CloudError('Cloud connection requires: pip install "elytra-mcp[cloud]"') from None
        self.keys = {}
        for entry in keys:
            jwk = entry.get('jwk', entry)
            if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519': raise CloudError('Unsupported cloud signing key')
            raw = self.decode(jwk['x'])
            self.keys[entry.get('kid',jwk.get('kid','alpha-1'))] = Ed25519PublicKey.from_public_bytes(raw)
        if not self.keys: raise CloudError('Cloud did not supply a signing key')
        self.workspace_id, self.device_id = workspace_id, device_id

    @staticmethod
    def decode(value):
        if not isinstance(value,str) or len(value)>2*1024*1024: raise CloudError('Invalid signed envelope')
        return base64.b64decode(value+'='*(-len(value)%4), altchars=b'-_', validate=True)

    def verify(self, envelope, kind):
        try:
            raw = self.decode(envelope['payload'])
            if len(raw)>512*1024: raise ValueError()
            self.keys[envelope['kid']].verify(self.decode(envelope['signature']),raw)
            payload = json.loads(raw)
            now = time.time()
            issued, expires = payload['issued_at'], payload['expires_at']
            if not all(isinstance(v,(int,float)) and not isinstance(v,bool) for v in (issued,expires)) or not issued <= now+30 or not now < expires or expires-issued > (300 if kind=='lease' else 120) or expires<=issued:
                raise ValueError()
            if payload['kind'] != kind or payload['workspace_id'] != self.workspace_id or payload['device_id'] != self.device_id:
                raise ValueError()
            if not isinstance(payload.get('epoch'),int) or payload['epoch']<0 or not isinstance(payload.get('policy_revision'),int): raise ValueError()
            return payload
        except Exception as exc:
            raise CloudError('Cloud signature, scope, or expiry could not be verified') from exc
