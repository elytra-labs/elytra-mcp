"""Local execution remains authoritative; cloud commands supply bounded authority."""
from __future__ import annotations
import hashlib
import json
import time
from mirage_mcp.runtime.service import RuntimeService, RuntimeAuthorizationError, RuntimeValidationError, RuntimeConflictError, _atomic, _canonical, CATEGORIES, SINKS

class ManagedRuntimeService(RuntimeService):
    def __init__(self, db_path, credentials, event_callback=None):
        self._cloud_disabled = False
        self._lease_deadline = 0.0
        self.device_id = credentials['device_id']
        self.workspace_id = credentials['workspace_id']
        self.cloud_origin = credentials['origin']
        super().__init__(db_path, event_callback=event_callback)
        with self._lock:
            existing = self._get('meta','cloud_identity')
            identity = {'device_id':self.device_id,'workspace_id':self.workspace_id}
            if existing and existing != identity:
                self.close(); raise RuntimeConflictError('Managed database belongs to a different enrollment')
            self._put('meta','cloud_identity',identity)
            # A restart requires a fresh lease, never a persisted wall-clock assumption.
            self._put('meta','cloud_lease',{'expires_at':0,'epoch':(self._get('meta','cloud_authority') or {}).get('epoch',-1)})

    def _lease_valid(self):
        lease = self._get('meta','cloud_lease') or {}
        return not self._cloud_disabled and lease.get('expires_at',0)>time.time() and time.monotonic()<self._lease_deadline

    def _valid_binding(self, call):
        return super()._valid_binding(call) and (call['category'] not in SINKS or self._lease_valid())

    def create_run(self,intent,grants=None,ttl_seconds=3600):
        if grants:
            raise RuntimeAuthorizationError('Managed runs receive permissions through workspace policy or exact cloud approval')
        return super().create_run(intent, [], ttl_seconds)

    def register_tools(self,run_id,run_token,server_id,tools,classifications=None):
        if classifications:
            raise RuntimeAuthorizationError('Managed classifications require workspace review')
        result=super().register_tools(run_id,run_token,server_id,tools,classifications=None)
        notify=getattr(self,'cloud_notify',None)
        if notify: notify()
        return result

    def acknowledge_schema(self,*args,**kwargs):
        raise RuntimeAuthorizationError('Review managed tools in the hosted workspace')

    def save_policy(self,*args,**kwargs):
        raise RuntimeAuthorizationError('Manage policies in the hosted workspace')

    def resolve_approval(self,*args,**kwargs):
        raise RuntimeAuthorizationError('Resolve managed approvals in the hosted workspace')

    @_atomic
    def cloud_status(self):
        authority=self._get('meta','cloud_authority') or {}
        lease=self._get('meta','cloud_lease') or {}
        return {'managed':True,'cloud_origin':self.cloud_origin,'workspace_id':self.workspace_id,'device_id':self.device_id,
                'lease_valid':self._lease_valid(),'lease_expires_at':lease.get('expires_at',0),
                'policy_revision':authority.get('policy_revision'), 'epoch':authority.get('epoch'), 'management_revision':authority.get('management_revision')}

    @_atomic
    def apply_cloud_lease(self, payload):
        if self._cloud_disabled: raise RuntimeAuthorizationError('Cloud connection has been disconnected locally')
        if payload.get('kind')!='lease' or payload.get('workspace_id')!=self.workspace_id or payload.get('device_id')!=self.device_id or payload.get('expires_at',0)<=time.time():
            raise RuntimeAuthorizationError('Invalid managed lease scope or expiry')
        previous=self._get('meta','cloud_authority') or {'epoch':-1,'policy_revision':-1}
        epoch,revision=payload['epoch'],payload['policy_revision']
        management_revision=payload.get('management_revision',revision)
        if epoch<previous['epoch'] or revision<previous['policy_revision'] or management_revision<previous.get('management_revision',-1):
            raise RuntimeConflictError('Cloud authority rollback rejected')
        policies,classes=payload.get('policies',[]),payload.get('classifications',[])
        if not isinstance(policies,list) or not isinstance(classes,list) or len(policies)>100 or len(classes)>500:
            raise RuntimeValidationError('Managed policy manifest exceeds bounds')
        fingerprint=hashlib.sha256(_canonical({'policies':policies,'classifications':classes}).encode()).hexdigest()
        changed = revision!=previous['policy_revision'] or epoch!=previous['epoch'] or management_revision!=previous.get('management_revision')
        if not changed and previous.get('fingerprint')!=fingerprint:
            raise RuntimeConflictError('Cloud changed authority without a revision')
        if changed:
            self._bump_version('Workspace policy or membership revision changed')
            self._conn.execute('DELETE FROM rt_policies')
            for policy in policies:
                # Cloud policy rows may contain management columns; copy only runtime policy.
                rule = policy.get('definition',policy.get('rule',policy))
                RuntimeService.save_policy(self,rule)
        approved={}
        for entry in classes:
            category=entry.get('category')
            if category not in CATEGORIES: raise RuntimeValidationError('Unknown managed capability category')
            key=self._tool_key(entry['server_id'],entry['tool_name'])
            approved[key]=(entry.get('schema_hash',entry.get('sha256_hash')),category)
        for record in self._all('tools'):
            key=self._tool_key(record['server_id'],record['tool_name'])
            grant=approved.get(key)
            if grant and grant[0]==record['observed_sha256_hash'] and record.get('present',True):
                if record['category']!=grant[1] or record['status']!='VERIFIED' or record['sha256_hash']!=grant[0]:
                    RuntimeService.acknowledge_schema(self,record['server_id'],record['tool_name'],grant[0],grant[1])
            elif record['category']!='UNKNOWN':
                record.update(category='UNKNOWN',available=False,requires_review=True)
                self._put('tools',key,record)
                self._bump_version('Tool is not approved by current workspace authority')
        self._put('meta','cloud_authority',{'epoch':epoch,'policy_revision':revision,'management_revision':management_revision,'fingerprint':fingerprint})
        self._put('meta','cloud_lease',{'epoch':epoch,'expires_at':payload['expires_at']})
        self._lease_deadline=time.monotonic()+min(300,max(0,payload['expires_at']-time.time()))
        return self.cloud_status()

    @_atomic
    def apply_cloud_decision(self, payload):
        if payload.get('kind')!='approval' or payload.get('workspace_id')!=self.workspace_id or payload.get('device_id')!=self.device_id or payload.get('expires_at',0)<=time.time():
            raise RuntimeAuthorizationError('Invalid decision scope or expiry')
        authority=self._get('meta','cloud_authority') or {}
        if not self._lease_valid() or payload['epoch']!=authority.get('epoch') or payload['policy_revision']!=authority.get('policy_revision') or payload.get('management_revision',payload['policy_revision'])!=authority.get('management_revision'):
            raise RuntimeConflictError('Decision does not match current workspace authority')
        key=self._call_key(payload['run_id'],payload['call_id'])
        call=self._get('calls',key)
        if not call: raise RuntimeConflictError('Original pending call no longer exists')
        fields={'arguments_hash':'arguments_hash','schema_hash':'schema_hash','local_policy_version':'policy_version','server_id':'server_id','tool_name':'tool_name'}
        if any(payload.get(remote)!=call.get(local) for remote,local in fields.items()):
            raise RuntimeConflictError('Decision binding does not match original call')
        command_id=payload.get('command_id',payload['approval_id'])
        command_key='cloud-command:'+str(command_id)
        digest=hashlib.sha256(_canonical(payload).encode()).hexdigest()
        old=self._get('meta',command_key)
        if old:
            # Envelopes may be freshly signed on redelivery; the semantic binding must match.
            semantic={k:v for k,v in payload.items() if k not in {'issued_at','expires_at'}}
            if old['binding_hash']!=hashlib.sha256(_canonical(semantic).encode()).hexdigest():
                raise RuntimeConflictError('Command ID was reused with different authority')
            return {'command_id':command_id,'status':'APPLIED','execution_status':call['status']}
        decision=payload.get('decision')
        if decision not in {'APPROVED','DENIED'}: raise RuntimeValidationError('Invalid cloud decision')
        RuntimeService.resolve_approval(self,call['approval_id'],decision,actor='workspace-operator')
        semantic={k:v for k,v in payload.items() if k not in {'issued_at','expires_at'}}
        self._put('meta',command_key,{'binding_hash':hashlib.sha256(_canonical(semantic).encode()).hexdigest(),'created_at_epoch':time.time(),'payload_hash':digest,'run_id':payload['run_id'],'call_id':payload['call_id'],'command_id':command_id})
        for row in self._conn.execute("SELECT id,data FROM rt_meta WHERE id LIKE 'cloud-command:%'").fetchall():
            if json.loads(row[1]).get('created_at_epoch',0)<time.time()-7*86400:
                self._conn.execute('DELETE FROM rt_meta WHERE id=?',(row[0],))
        return {'command_id':command_id,'status':'APPLIED','execution_status':decision}

    @_atomic
    def disconnect_cloud(self):
        self._cloud_disabled=True
        self._lease_deadline=0
        self._put('meta','cloud_lease',{'expires_at':0,'epoch':(self._get('meta','cloud_authority') or {}).get('epoch',-1)})
        self._bump_version('Local operator disconnected cloud management')
        return {'managed':True,'connected':False,'lease_valid':False}

    @_atomic
    def cloud_snapshot(self):
        self._prune()
        tools=[]
        for record in self._all('tools'):
            if not record.get('present',True): continue
            definition=record['tool_definition']
            if len(_canonical(definition).encode())>8192:
                continue  # Ineligible for remote metadata review; never authorize a truncated schema.
            tools.append({'server_id':record['server_id'],'tool_name':record['tool_name'],'schema_hash':record['observed_sha256_hash'],
                'tool_definition':definition,'schema_status':record['status'],'poison_suspected':record['status']=='POISON_SUSPECTED'})
        tools=sorted(tools,key=lambda t:(t['server_id'],t['tool_name']))[:50]
        runs=[{'run_id':r['run_id'],'intent':r['intent'][:1000],'expires_at_epoch':r['expires_at_epoch'],'status':'UNCERTAIN' if r['status'] in {'FAILED','INTERRUPTED'} else r['status']} for r in sorted(self._all('runs'), key=lambda r:r['created_at_epoch'], reverse=True)]
        approvals=[{'local_approval_id':a['approval_id'],'status':a['status'],'arguments_preview':a['arguments_preview'],'binding':{key:a[key] for key in ('run_id','call_id','server_id','tool_name','arguments_hash','schema_hash','policy_version','expires_at_epoch')}} for a in self.list_approvals() if a['status'] in {'PENDING','INVALIDATED','EXPIRED','CANCELLED'} and not a.get('arguments_preview_truncated')]
        events=self.list_events(limit=10000)
        return {'tools':tools,'tools_complete':True,'runs':runs[:100],'approvals':approvals[:100],'events':events}

    @_atomic
    def cloud_acknowledgements(self):
        result=[]
        for row in self._conn.execute("SELECT id,data FROM rt_meta WHERE id LIKE 'cloud-command:%'").fetchall():
            record=json.loads(row[1])
            call=self._get('calls',self._call_key(record['run_id'],record['call_id']))
            if not call: continue
            state=call['status']
            state='APPLIED' if state=='APPROVED' else 'UNCERTAIN' if state=='FAILED' else 'INVALIDATED' if state=='CANCELLED' else state
            if state!=record.get('reported_status'):
                result.append({'command_id':record['command_id'],'outcome':{'status':state}})
        return result[:50]

    @_atomic
    def mark_cloud_acknowledged(self, acknowledgements):
        for ack in acknowledgements:
            key='cloud-command:'+ack['command_id']
            record=self._get('meta',key)
            if record:
                record['reported_status']=ack['outcome']['status']
                self._put('meta',key,record)
