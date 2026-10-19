"""Outbound, replay-safe synchronization. Cloud loss never dispatches a call."""
from __future__ import annotations
import json
import threading
import time
from .client import CloudClient, CloudError, EnvelopeVerifier

class CloudConnector:
    def __init__(self,runtime,credentials):
        self.runtime=runtime
        self.client=CloudClient(credentials['origin'],credentials['device_id'],credentials['device_secret'])
        self.verifier=EnvelopeVerifier(credentials['signing_keys'],credentials['workspace_id'],credentials['device_id'])
        self._stop=threading.Event()
        self._wake=threading.Event()
        self._thread=None
        self.last_error=None
        self.last_sync=None
        self._acks={}
        self._synced=set()

    def notify(self,event=None): self._wake.set()

    def _request_body(self):
        snapshot=self.runtime.cloud_snapshot()
        events=sorted(snapshot.pop('events'),key=lambda e:(e['timestamp'],e['event_id']))
        # Only fresh metadata is uploaded; local retention remains independent.
        fresh=[e for e in events if e['event_id'] not in self._synced and e.get('timestamp_epoch',0)>time.time()-86400]
        snapshot['events']=[{'event_id':e['event_id'],'run_id':e['run_id'],'call_id':e['call_id'],'type':e.get('execution_status',e['decision']),'summary':e['reason'][:500],'decision':e['decision'],'occurred_at':e['timestamp']} for e in fresh[:20]]
        snapshot['approvals']=snapshot['approvals'][:30]
        required={a['binding']['run_id'] for a in snapshot['approvals']}
        runs=snapshot['runs']
        snapshot['runs']=([r for r in runs if r['run_id'] in required]+[r for r in runs if r['run_id'] not in required])[:30]
        uploaded_runs={r['run_id'] for r in snapshot['runs']}
        snapshot['approvals']=[a for a in snapshot['approvals'] if a['binding']['run_id'] in uploaded_runs]
        snapshot['acks']=(self.runtime.cloud_acknowledgements()+[{'command_id':key,'outcome':value} for key,value in list(self._acks.items())])[:50]
        # The protocol has a hard 256 KiB request bound; trim review batches,
        # never a tool definition's content or an exact argument binding.
        while len(json.dumps(snapshot).encode())>240*1024:
            choices=[name for name in ('events','runs','approvals','tools') if snapshot[name]]
            if not choices: raise CloudError('Cloud snapshot exceeds request bounds')
            name=max(choices,key=lambda key:len(json.dumps(snapshot[key])))
            removed=snapshot[name].pop()
            if name=='runs': snapshot['approvals']=[a for a in snapshot['approvals'] if a['binding']['run_id']!=removed['run_id']]
            if name=='tools': snapshot['tools_complete']=False
        return snapshot

    def sync_once(self):
        body=self._request_body()
        response=self.client.request('/devices/sync',body)
        # Never apply a permission from an unsigned result/command row.
        lease=self.verifier.verify(response['lease'],'lease')
        self.runtime.apply_cloud_lease(lease)
        self.runtime.mark_cloud_acknowledged(body['acks'])
        for ack in body['acks']:
            self._acks.pop(ack['command_id'],None)
        for envelope in response.get('decisions',[]):
            payload=self.verifier.verify(envelope,'approval')
            command_id=payload.get('command_id') or payload['approval_id']
            try:
                self.runtime.apply_cloud_decision(payload)
                # Successful decisions and subsequent outcomes are persisted
                # by the runtime and survive connector/process restart.
                pass
            except (PermissionError,ValueError,RuntimeError):
                self._acks[command_id]={'status':'INVALIDATED'}
        # Dropped quota-limited telemetry is not retried indefinitely. It stays
        # in the customer's local audit store with cloud capacity visible.
        self._synced.update(e['event_id'] for e in body['events'])
        if len(self._synced)>10000: self._synced=set(list(self._synced)[-10000:])
        self.last_sync=time.time(); self.last_error=None
        return response

    def _run(self):
        retry=3
        while not self._stop.is_set():
            began=time.monotonic()
            try:
                self.sync_once(); retry=3
                pending=any(a['status']=='PENDING' for a in self.runtime.list_approvals())
                delay=3 if pending or self._acks or self.runtime.cloud_acknowledgements() else 120
            except Exception:
                self.last_error='Cloud connection unavailable or authority rejected; no new permissions applied'
                delay=retry; retry=min(120,retry*2)
            self._wake.wait(delay); self._wake.clear()
            self._stop.wait(max(0,3-(time.monotonic()-began)))

    def start(self):
        if self._thread: return
        self._thread=threading.Thread(target=self._run,name='elytra-cloud',daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set(); self._wake.set()
        if self._thread: self._thread.join(timeout=20)
