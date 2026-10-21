import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { ArrowUpRight, Check, CheckCheck, Fingerprint, Plus, Search, ShieldCheck, SlidersHorizontal, X } from 'lucide-react';
import { Badge, Card, Chain, Code, Empty, PageHeader, Segmented, Select, Sheet, SkeletonRows, Switch } from '../components/ui';
import { ACTION_META, fullDate, humanize, PIN_META, prettyJson, shortHash, timeAgo, toolLabel } from '../lib/format';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import type { PolicyRule, SchemaPinRecord, StepUpApproval } from '../types/controlPlane';
import '../styles/governance.css';

const approvalTone = { PENDING: 'amber', APPROVED: 'green', DENIED: 'neutral', EXPIRED: 'neutral', INVALIDATED: 'amber', CONSUMED: 'green', CANCELLED: 'neutral', UNCERTAIN: 'red' } as const;
type ApprovalFilter = 'PENDING' | 'RESOLVED' | 'ALL';

/** Remaining time until an approval expires, or null when no expiry applies. */
function expiryState(expiresAt: string | null | undefined, now: number): { expired: boolean; urgent: boolean; label: string } | null {
  if (!expiresAt) return null;
  const end = Date.parse(expiresAt);
  if (!Number.isFinite(end)) return null;
  const left = Math.floor((end - now) / 1000);
  if (left <= 0) return { expired: true, urgent: false, label: 'Expired' };
  const h = Math.floor(left / 3600), m = Math.floor((left % 3600) / 60), s = left % 60;
  const label = h ? `${h}h ${String(m).padStart(2, '0')}m` : `${m}:${String(s).padStart(2, '0')}`;
  // Runtime approvals last at most 120s, so only the final stretch is flagged.
  return { expired: false, urgent: left <= 30, label: `Expires in ${label}` };
}

function ExpiryLabel({ expiresAt, now }: { expiresAt?: string | null; now: number }) {
  const state = expiryState(expiresAt, now);
  if (!state) return <span className="subtle">No expiry</span>;
  return <span className={`governance-expiry mono ${state.expired ? 'expired' : state.urgent ? 'urgent' : ''}`} title={fullDate(expiresAt)}>{state.label}</span>;
}

/** What the agent is trying to do, in the words a person would use: the command, the file, or the tool. */
const ACTION_KIND: Record<string, string> = {
  edit_files: 'Edits files', run_command: 'Runs a command Elytra does not recognize', send_data: 'Sends data out',
  delete_files: 'Deletes files', destroy_history: 'Rewrites version history', read_local: 'Reads local files', web_read: 'Reads the web',
};
function actionKind(approval: StepUpApproval) {
  return approval.server_id === 'agent' && ACTION_KIND[approval.tool_name] ? ACTION_KIND[approval.tool_name] : toolLabel(approval.tool_name, approval.server_id);
}

function actionText(approval: StepUpApproval) {
  const args = approval.arguments_preview || {};
  const command = args.command ?? args.cmd;
  if (typeof command === 'string' && command.trim()) return command.trim();
  if (Array.isArray(command)) return command.join(' ');
  const path = args.file_path ?? args.path;
  if (typeof path === 'string' && path) return `${humanize(approval.tool_name)}: ${path.split('/').pop()}`;
  return toolLabel(approval.tool_name, approval.server_id);
}

export function ApprovalsView() {
  const { approvals, loaded, offline, resolveApproval, config } = useStore();
  const [filter, setFilter] = useState<ApprovalFilter>('PENDING');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const clock = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(clock); }, []);
  const selected = approvals.find((item) => item.approval_id === selectedId);
  const expired = !!selected?.expires_at && Date.parse(selected.expires_at) <= now;
  const pending = approvals.filter((item) => item.status === 'PENDING').length;
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return approvals
      .filter((item) => filter === 'ALL' || (filter === 'PENDING' ? item.status === 'PENDING' : item.status !== 'PENDING'))
      .filter((item) => !q || `${item.agent ?? ''} ${actionText(item)} ${item.tool_name} ${toolLabel(item.tool_name, item.server_id)} ${item.server_id} ${item.rule_id} ${item.session_id} ${item.reason}`.toLowerCase().includes(q))
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
  }, [approvals, filter, query]);
  const blockedReason = !selected || selected.status !== 'PENDING' ? '' : config?.demo_mode ? 'Decisions are disabled in the demo workspace.' : offline ? 'Reconnect to the local runtime to record a decision.' : expired ? 'This request expired. The integration must issue a new call to request approval again.' : '';

  async function resolve(status: 'APPROVED' | 'DENIED') {
    if (!selected || busy) return;
    setBusy(true);
    try { await resolveApproval(selected.approval_id, status); }
    finally { setBusy(false); }
  }

  return (
    <div className="page governance-page">
      <PageHeader title="Approvals" description="Review tool calls that require a human decision." actions={<Badge tone={pending ? 'amber' : 'neutral'} dot>{pending} pending</Badge>} />
      <div className="governance-context"><ShieldCheck size={16} /><span>Each decision applies to one exact action. Check the command and why it was held before you approve.</span></div>
      <div className="toolbar governance-toolbar">
        <div className="input-wrap governance-search"><Search size={14} /><input className="input" aria-label="Search approval requests" placeholder="Search agents, commands, tools…" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
        <Segmented value={filter} onChange={setFilter} options={[{ value: 'PENDING', label: 'Pending', count: pending }, { value: 'RESOLVED', label: 'Resolved', count: approvals.length - pending }, { value: 'ALL', label: 'All requests' }]} />
        <span className="subtle governance-result-count">{filtered.length} {filtered.length === 1 ? 'request' : 'requests'}</span>
      </div>
      <Card bodyClass="governance-table-body">
        {!loaded ? <SkeletonRows /> : filtered.length === 0 ? <Empty icon={<CheckCheck size={18} />} title={offline ? 'Approvals unavailable' : query.trim() ? 'No matching requests' : filter === 'PENDING' ? 'No requests waiting' : 'No requests found'}>{offline ? 'Reconnect to the control plane to load approval requests.' : query.trim() ? <>Try a different search. <button className="btn ghost xs" onClick={() => setQuery('')}>Clear search</button></> : filter === 'PENDING' ? 'Calls that need your review will appear here.' : 'Recorded decisions will appear here as requests are reviewed.'}</Empty> : <div className="table-wrap"><table className="table">
          <thead><tr><th>Action</th><th>Status</th><th>Requested</th><th>Expiry</th><th><span className="governance-sr-only">Review</span></th></tr></thead>
          <tbody>{filtered.map((item) => <tr key={item.approval_id}>
            <td><button className="governance-text-button" onClick={() => setSelectedId(item.approval_id)}><span className="cell-main">{item.agent ?? 'Agent'} <span className="governance-inline-separator">·</span> <span className="mono">{actionText(item)}</span></span></button><div className="cell-sub">{item.reason}</div></td>
            <td><Badge tone={approvalTone[item.status]} dot>{humanize(item.status)}</Badge></td>
            <td><span className="muted" title={fullDate(item.created_at)}>{timeAgo(item.created_at)}</span></td>
            <td>{item.status === 'PENDING' ? <ExpiryLabel expiresAt={item.expires_at} now={now} /> : <span className="subtle">{item.resolved_at ? `Resolved ${timeAgo(item.resolved_at)}` : '—'}</span>}</td>
            <td className="right"><button className="btn ghost sm" onClick={() => setSelectedId(item.approval_id)}>Review<ArrowUpRight size={13} /></button></td>
          </tr>)}</tbody>
        </table></div>}
      </Card>
      <p className="governance-footnote">Approving lets that one action run once, exactly as shown. If anything about it changes, Elytra asks again.</p>
      <Sheet open={!!selected} onClose={() => setSelectedId(null)} title={selected ? `${selected.agent ?? 'An agent'} wants to run` : 'Review request'} subtitle={selected && actionKind(selected)} footer={selected?.status === 'PENDING' ? <>{blockedReason && <span className="governance-footer-note" role="note">{blockedReason}</span>}<button className="btn danger" disabled={busy || !!blockedReason} onClick={() => void resolve('DENIED')}><X size={14} />Deny</button><button className="btn primary" disabled={busy || !!blockedReason} onClick={() => void resolve('APPROVED')}><Check size={14} />{busy ? 'Saving…' : 'Approve this action'}</button></> : undefined}>
        {selected && <ApprovalDetails approval={selected} now={now} />}
      </Sheet>
    </div>
  );
}

const TAINT_LABEL: Record<string, string> = {
  CRITICAL: 'Looks like instructions aimed at AI agents', HIGH: 'Untrusted, and Elytra could not inspect it', MEDIUM: 'Untrusted, inspected and looked clean',
};

function sourceName(name: string) {
  const [kind, ...rest] = name.split(':');
  const detail = rest.join(':');
  if (!detail) return `${name} (MCP tool result)`;
  return kind === 'web' ? detail : kind === 'file' ? `${detail} (local file)` : detail;
}

function SessionSources({ approval }: { approval: StepUpApproval }) {
  const { toast } = useStore();
  const [busy, setBusy] = useState(false);
  const [trusted, setTrusted] = useState(false);
  const sources = approval.taint_lineage || [];
  if (!sources.length) return null;
  const evidence = approval.source_evidence || {};
  async function trust() {
    setBusy(true);
    try {
      const result = await api.trustSession(approval.session_id);
      setTrusted(true);
      toast(`Session trusted again (${result.cleared.length} source${result.cleared.length === 1 ? '' : 's'} cleared)`, 'green');
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Could not update the session', 'red');
    } finally {
      setBusy(false);
    }
  }
  return <section className="governance-sources">
    <h3 className="section-title">What this session read</h3>
    {approval.taint_level && TAINT_LABEL[approval.taint_level] && <Badge tone={approval.taint_level === 'CRITICAL' ? 'red' : 'amber'} dot>{TAINT_LABEL[approval.taint_level]}</Badge>}
    <ul>{sources.map((name) => <li key={name}><span className="mono">{sourceName(name)}</span>{(evidence[name] || []).map((snippet, index) => <blockquote key={index}>{snippet}</blockquote>)}</li>)}</ul>
    {approval.status === 'PENDING' && !trusted && <div className="governance-trust"><button className="btn ghost sm" disabled={busy} onClick={() => void trust()}>Trust this session again</button><span className="subtle">After you have checked what it read. This decision still needs your answer.</span></div>}
  </section>;
}

function ApprovalDetails({ approval, now }: { approval: StepUpApproval; now: number }) {
  return <div className="governance-detail-stack">
    <div className="governance-detail-status"><Badge tone={approvalTone[approval.status]} dot>{humanize(approval.status)}</Badge><span className="subtle">Requested {timeAgo(approval.created_at)}</span>{approval.status === 'PENDING' && <ExpiryLabel expiresAt={approval.expires_at} now={now} />}</div>
    <Code copy={false}>{actionText(approval)}</Code>
    <section><h3 className="section-title">Why Elytra held it</h3><p className="governance-reason">{approval.reason || 'This action matched a rule that asks you first.'}</p></section>
    <SessionSources approval={approval} />
    <section><h3 className="section-title">Arguments</h3><Code json>{prettyJson(approval.arguments_preview)}</Code><p className="field-hint">Secrets are redacted. If something looks unexpected, deny it.</p></section>
    <details className="governance-technical"><summary>Technical details</summary><dl className="meta"><dt>Server</dt><dd>{approval.server_id}</dd><dt>Policy</dt><dd className="mono">{approval.rule_id}</dd><dt>Rule score</dt><dd>{approval.risk_score} / 100</dd><dt>Requested</dt><dd>{fullDate(approval.created_at)}</dd><dt>Session</dt><dd className="mono governance-break">{approval.session_id}</dd>{approval.call_id && <><dt>Call ID</dt><dd className="mono governance-break">{approval.call_id}</dd></>}{approval.expires_at && <><dt>Expires</dt><dd>{fullDate(approval.expires_at)}</dd></>}{approval.execution_status && <><dt>Execution status</dt><dd>{humanize(approval.execution_status)}</dd></>}<dt>Request ID</dt><dd className="mono governance-break">{approval.approval_id}</dd>{approval.resolved_at && <><dt>Resolved</dt><dd>{fullDate(approval.resolved_at)}</dd></>}{approval.resolved_by && <><dt>Resolved by</dt><dd>{approval.resolved_by}</dd></>}</dl>
    <section><h3 className="section-title">Source lineage</h3>{approval.taint_lineage.length ? <Chain nodes={approval.taint_lineage[approval.taint_lineage.length - 1] === approval.tool_name ? approval.taint_lineage : [...approval.taint_lineage, toolLabel(approval.tool_name, approval.server_id)]} heldLast={approval.status === 'PENDING'} /> : <p className="subtle">No source lineage was recorded.</p>}</section>
    {approval.arguments_hash && <section><h3 className="section-title">Exact arguments digest</h3><Code>{approval.arguments_hash}</Code></section>}</details>
    <p className="governance-footnote">This decision is bound to the recorded run, tool, arguments, and policy version. Approval does not itself dispatch execution; the connected integration claims it once.</p>
  </div>;
}

const newPolicy = (): PolicyRule => ({ rule_id: '', name: '', description: '', source_pattern: '*', sink_pattern: '*', min_taint_level: 'HIGH', action: 'BLOCK_SECOND_HOP', enabled: true, hit_count: 0 });
type PolicyFilter = 'ALL' | 'ENABLED' | 'DISABLED';

export function PoliciesView() {
  const { policies, loaded, offline, togglePolicy, savePolicy } = useStore();
  const [filter, setFilter] = useState<PolicyFilter>('ALL');
  const [query, setQuery] = useState('');
  const [draft, setDraft] = useState<PolicyRule | null>(null);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [toggling, setToggling] = useState<string | null>(null);
  const filtered = policies.filter((policy) => (filter === 'ALL' || policy.enabled === (filter === 'ENABLED')) && `${policy.name} ${policy.rule_id} ${policy.source_pattern} ${policy.sink_pattern}`.toLowerCase().includes(query.toLowerCase()));

  function openEditor(policy?: PolicyRule) { setDraft(policy ? { ...policy } : newPolicy()); setEditing(!!policy); setError(''); }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || saving) return;
    const value = { ...draft, rule_id: draft.rule_id.trim(), name: draft.name.trim(), description: draft.description.trim(), source_pattern: draft.source_pattern.trim(), sink_pattern: draft.sink_pattern.trim() };
    if (!value.rule_id || !value.name || !value.description || !value.source_pattern || !value.sink_pattern) { setError('Complete all required fields.'); return; }
    if (!editing && policies.some((policy) => policy.rule_id === value.rule_id)) { setError('This rule ID already exists. Choose a unique ID or edit the existing rule.'); return; }
    setSaving(true); setError('');
    try { await savePolicy(value); setDraft(null); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'The policy could not be saved. Try again.'); }
    finally { setSaving(false); }
  }
  async function toggle(policy: PolicyRule, enabled: boolean) {
    if (toggling || offline) return;
    setToggling(policy.rule_id);
    try { await togglePolicy(policy.rule_id, enabled); }
    finally { setToggling(null); }
  }

  return <div className="page governance-page">
    <PageHeader title="Policies" description="Configure how tainted tool calls should be handled." actions={<button className="btn primary" disabled={offline} onClick={() => openEditor()}><Plus size={14} />New policy</button>} />
    <div className="toolbar governance-toolbar"><div className="input-wrap governance-search"><Search size={14} /><input className="input" aria-label="Search policies" placeholder="Search policies…" value={query} onChange={(event) => setQuery(event.target.value)} /></div><Segmented value={filter} onChange={setFilter} options={[{ value: 'ALL', label: 'All' }, { value: 'ENABLED', label: 'Enabled' }, { value: 'DISABLED', label: 'Disabled' }]} /><span className="subtle governance-result-count">{filtered.length} policies</span></div>
    <Card bodyClass="governance-table-body">
      {!loaded ? <SkeletonRows /> : filtered.length === 0 ? <Empty icon={<SlidersHorizontal size={18} />} title={offline ? 'Policies unavailable' : query || filter !== 'ALL' ? 'No matching policies' : 'No policies configured'}>{offline ? 'Reconnect to the control plane to load policies.' : query || filter !== 'ALL' ? 'Try a different search or filter.' : 'Create a policy to define a source, destination, and handling action.'}</Empty> : <div className="governance-policy-list">{filtered.map((policy) => <article className="governance-policy" key={policy.rule_id}>
        <div className="governance-policy-heading"><div className="governance-policy-title"><button className="governance-text-button" onClick={() => openEditor(policy)}>{policy.name}</button><Badge tone={ACTION_META[policy.action]?.tone}>{ACTION_META[policy.action]?.label ?? humanize(policy.action)}</Badge></div><div className="governance-policy-controls"><span className="subtle">{policy.enabled ? 'Enabled' : 'Disabled'}</span><span aria-busy={toggling === policy.rule_id}><Switch disabled={!!toggling || offline} checked={policy.enabled} onChange={(enabled) => void toggle(policy, enabled)} label={`Enable ${policy.name}`} /></span></div></div>
        <p className="governance-policy-description">{policy.description}</p>
        <div className="governance-policy-bottom"><div className="governance-patterns"><span className="mono" title="Source pattern">{policy.source_pattern}</span><span className="subtle">→</span><span className="mono" title="Sink pattern">{policy.sink_pattern}</span><span className="governance-policy-threshold">{humanize(policy.min_taint_level)} taint or above</span></div><button className="btn ghost xs" onClick={() => openEditor(policy)}>Edit rule<ArrowUpRight size={12} /></button></div>
        <div className="governance-policy-id"><span className="mono">{policy.rule_id}</span><span>{policy.hit_count.toLocaleString()} recorded matches</span></div>
      </article>)}</div>}
    </Card>
    <p className="governance-footnote">Saved policy versions apply to subsequent evaluations in the connected runtime. Calls outside the integration are outside coverage.</p>
    <Sheet open={!!draft} onClose={() => { if (!saving) setDraft(null); }} title={editing ? 'Edit policy' : 'New policy'} subtitle="Define the source, destination, and action for this rule." footer={<><button className="btn ghost" disabled={saving} onClick={() => setDraft(null)}>Cancel</button><button type="submit" form="governance-policy-form" className="btn primary" disabled={saving || offline}>{saving ? 'Saving…' : editing ? 'Save changes' : 'Create policy'}</button></>}>
      {draft && <form id="governance-policy-form" className="governance-form" onSubmit={(event) => void save(event)}>
        {error && <div className="governance-error" role="alert">{error}</div>}
        <label className="field"><span className="field-label">Policy name</span><input required className="input" autoFocus maxLength={160} value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="Require review for external writes" /></label>
        <label className="field"><span className="field-label">Rule ID</span><input required className="input mono" maxLength={100} readOnly={editing} value={draft.rule_id} onChange={(event) => setDraft({ ...draft, rule_id: event.target.value })} placeholder="REVIEW_EXTERNAL_WRITES" /><span className="field-hint">A unique identifier used in event records.{editing && ' The ID is fixed after creation.'}</span></label>
        <label className="field"><span className="field-label">Description</span><textarea required className="textarea" rows={3} value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="Describe when this policy applies." /></label>
        <div className="governance-form-pair"><label className="field"><span className="field-label">Source pattern</span><input required className="input mono" value={draft.source_pattern} onChange={(event) => setDraft({ ...draft, source_pattern: event.target.value })} placeholder="github.*" /></label><label className="field"><span className="field-label">Sink pattern</span><input required className="input mono" value={draft.sink_pattern} onChange={(event) => setDraft({ ...draft, sink_pattern: event.target.value })} placeholder="postgres.*" /></label></div>
        <label className="field"><span className="field-label">Minimum taint level</span><Select label="Minimum taint level" value={draft.min_taint_level} onChange={(level) => setDraft({ ...draft, min_taint_level: level })} options={(['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map((level) => ({ value: level, label: humanize(level) }))} /></label>
        <label className="field"><span className="field-label">Action</span><Select label="Action" value={draft.action} onChange={(action) => setDraft({ ...draft, action })} options={(Object.keys(ACTION_META) as PolicyRule['action'][]).map((action) => ({ value: action, label: ACTION_META[action].label }))} /></label>
        <div className="governance-form-switch"><div><div className="field-label">Enable policy</div><div className="field-hint">Save this rule as enabled in the registry.</div></div><Switch checked={draft.enabled} label="Enable this policy" onChange={(enabled) => setDraft({ ...draft, enabled })} /></div>
      </form>}
    </Sheet>
  </div>;
}

type IntegrityFilter = 'ALL' | 'ATTENTION' | 'VERIFIED';

export function IntegrityView() {
  const { pins, loaded, offline } = useStore();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<IntegrityFilter>('ALL');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const pinKey = (pin: SchemaPinRecord) => `${pin.server_id}\u0000${pin.tool_name}`;
  const attention = pins.filter((pin) => pin.status !== 'VERIFIED').length;
  const selected = pins.find((pin) => pinKey(pin) === selectedKey);
  const filtered = pins.filter((pin) => (filter === 'ALL' || (filter === 'ATTENTION' ? pin.status !== 'VERIFIED' : pin.status === 'VERIFIED')) && `${pin.server_id} ${pin.tool_name} ${pin.sha256_hash}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="page governance-page">
    <PageHeader title="Tool integrity" description="Inspect pinned tool schemas and changes detected during verification." actions={<Badge tone={attention ? 'amber' : 'neutral'} dot>{attention} need attention</Badge>} />
    <div className="governance-context"><Fingerprint size={16} /><span>Each tool schema has a SHA-256 fingerprint. Changes to a pinned schema are recorded for review.</span></div>
    <div className="toolbar governance-toolbar"><div className="input-wrap governance-search"><Search size={14} /><input className="input" aria-label="Search tool schemas" placeholder="Search tools, servers, or hashes…" value={query} onChange={(event) => setQuery(event.target.value)} /></div><Segmented value={filter} onChange={setFilter} options={[{ value: 'ALL', label: 'All tools', count: pins.length }, { value: 'ATTENTION', label: 'Needs attention', count: attention }, { value: 'VERIFIED', label: 'Verified' }]} /></div>
    <Card bodyClass="governance-table-body">
      {!loaded ? <SkeletonRows /> : filtered.length === 0 ? <Empty icon={<Fingerprint size={18} />} title={offline ? 'Registry unavailable' : pins.length === 0 ? 'No tool schemas pinned' : 'No matching tools'}>{offline ? 'Reconnect to the control plane to load the schema registry.' : pins.length === 0 ? 'Schemas appear here when tools are discovered and pinned.' : 'Try a different search or status filter.'}</Empty> : <div className="table-wrap"><table className="table"><thead><tr><th>Tool</th><th>Status</th><th>Fingerprint</th><th>Last verified</th><th><span className="governance-sr-only">Inspect</span></th></tr></thead><tbody>{filtered.map((pin) => <tr key={pinKey(pin)}><td><button className="governance-text-button mono" onClick={() => setSelectedKey(pinKey(pin))}>{toolLabel(pin.tool_name, pin.server_id)}</button><div className="cell-sub">{pin.server_id}</div></td><td><Badge tone={PIN_META[pin.status]?.tone} dot>{PIN_META[pin.status]?.label ?? humanize(pin.status)}</Badge></td><td className="mono subtle" title={pin.sha256_hash}>{shortHash(pin.sha256_hash)}</td><td className="muted" title={fullDate(pin.last_verified_at)}>{timeAgo(pin.last_verified_at)}</td><td className="right"><button className="btn ghost icon sm" aria-label={`Inspect ${pin.tool_name}`} onClick={() => setSelectedKey(pinKey(pin))}><ArrowUpRight size={14} /></button></td></tr>)}</tbody></table></div>}
    </Card>
    <p className="governance-footnote">{filtered.length} of {pins.length} pinned tools shown. Fingerprints identify schema versions, including tool descriptions.</p>
    <Sheet open={!!selected} onClose={() => setSelectedKey(null)} title={selected && toolLabel(selected.tool_name, selected.server_id)} subtitle={selected?.server_id}>
      {selected && <div className="governance-detail-stack"><div><Badge tone={PIN_META[selected.status]?.tone} dot>{PIN_META[selected.status]?.label ?? humanize(selected.status)}</Badge></div>{selected.drift_summary && <section className="governance-integrity-notice"><h3 className="section-title">Verification findings</h3><p>{selected.drift_summary}</p></section>}<dl className="meta"><dt>Server</dt><dd>{selected.server_id}</dd><dt>Tool</dt><dd className="mono governance-break">{selected.tool_name}</dd><dt>First pinned</dt><dd>{fullDate(selected.pinned_at)}</dd><dt>Last verified</dt><dd>{fullDate(selected.last_verified_at)}</dd></dl><section><h3 className="section-title">SHA-256 fingerprint</h3><Code>{selected.sha256_hash}</Code></section><section><h3 className="section-title">Tool description preview</h3><p className="governance-description-preview">{selected.description_preview || 'No description was recorded.'}</p></section><p className="governance-footnote">Review unexpected changes with the tool provider before updating a pin. Use Setup to review and acknowledge this metadata version.</p></div>}
    </Sheet>
  </div>;
}
