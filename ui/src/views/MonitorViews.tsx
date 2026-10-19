import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, CheckCheck, Filter, Fingerprint, Search, ShieldCheck, SlidersHorizontal, UserCheck, Waypoints, X } from 'lucide-react';
import { useStore } from '../lib/store';
import { Badge, Card, Chain, Code, CopyButton, DecisionBadge, Dot, Empty, PageHeader, Select, Sheet, Stat } from '../components/ui';
import { clockTime, fullDate, humanize, ms, prettyJson, timeAgo, toolLabel } from '../lib/format';
import type { InterceptionEvent } from '../types/controlPlane';

function downloadJson(value: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([prettyJson(value)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}

function EventDetail({ event, onClose, onFilterSession }: { event: InterceptionEvent | null; onClose: () => void; onFilterSession?: (sessionId: string) => void }) {
  return <Sheet open={!!event} onClose={onClose} title={event ? toolLabel(event.tool_name, event.server_id) : 'Event'} subtitle={event ? fullDate(event.timestamp) : ''} footer={event && onFilterSession ? <button className="btn ghost sm" onClick={() => { onFilterSession(event.session_id); onClose(); }}><Filter size={13} />Show this session’s activity</button> : undefined}>
    {event && <div className="stack gap-16">
      <div><DecisionBadge decision={event.decision} /></div>
      <p className="detail-reason">{event.reason}</p>
      <dl className="meta"><dt>Event</dt><dd className="mono break meta-copy">{event.event_id}<CopyButton text={event.event_id} /></dd><dt>Session</dt><dd className="mono break meta-copy">{event.session_id}<CopyButton text={event.session_id} /></dd><dt>Server</dt><dd>{event.server_id}</dd><dt>Direction</dt><dd className="mono">{event.direction}</dd><dt>Method</dt><dd className="mono">{event.jsonrpc_method}</dd><dt>Evaluation</dt><dd className="mono">{ms(event.eval_latency_ms)}</dd><dt>Policy</dt><dd className="mono">{event.rule_id ?? 'No matching rule'}</dd><dt>Taint level</dt><dd>{humanize(event.taint_level)}</dd><dt>Secrets redacted</dt><dd>{event.secrets_redacted}</dd></dl>
      <div><h3 className="section-title">Source lineage</h3>{event.source_lineage.length ? <Chain nodes={event.source_lineage} blockedLast={event.decision.includes('BLOCK')} /> : <span className="subtle">No source lineage recorded.</span>}</div>
      <div><h3 className="section-title">Arguments preview</h3><Code json>{prettyJson(event.arguments_preview)}</Code></div>
    </div>}
  </Sheet>;
}

function EventTable({ events, onSelect }: { events: InterceptionEvent[]; onSelect: (e: InterceptionEvent) => void }) {
  return <div className="table-wrap"><table className="table event-table"><thead><tr><th>Decision</th><th>Tool call</th><th>Server</th><th>Time</th><th className="right">Evaluation</th><th><span className="sr-only">Details</span></th></tr></thead><tbody>
    {events.map((e) => <tr key={e.event_id} className="clickable" onClick={() => onSelect(e)}><td><DecisionBadge decision={e.decision} /></td><td><button className="table-link mono" onClick={(ev) => { ev.stopPropagation(); onSelect(e); }}>{toolLabel(e.tool_name, e.server_id)}</button><div className="cell-sub">{e.rule_id ?? humanize(e.tool_role)}</div></td><td className="muted">{e.server_id}</td><td className="mono subtle" title={fullDate(e.timestamp)}>{clockTime(e.timestamp)}</td><td className="right mono muted">{ms(e.eval_latency_ms)}</td><td><ArrowUpRight size={13} className="subtle" /></td></tr>)}
  </tbody></table></div>;
}

function ActivityChart({ events }: { events: InterceptionEvent[] }) {
  const buckets = useMemo(() => {
    const valid = events.filter((e) => Number.isFinite(Date.parse(e.timestamp)));
    if (!valid.length) return null;
    const end = Math.max(...valid.map((e) => Date.parse(e.timestamp)));
    const start = end - 60 * 60 * 1000;
    const bins = Array.from({ length: 30 }, () => ({ allowed: 0, held: 0, blocked: 0, tainted: 0 }));
    valid.forEach((e) => {
      const t = Date.parse(e.timestamp); if (t < start || t > end) return;
      const bin = bins[Math.min(29, Math.floor((t - start) / 120000))];
      if (e.decision.includes('BLOCK')) bin.blocked++;
      else if (e.decision === 'STEP_UP_REQUIRED') bin.held++;
      else if (e.decision === 'TAINT_PROPAGATE') bin.tainted++;
      else bin.allowed++;
    });
    return { bins, start, end, max: Math.max(1, ...bins.map((b) => b.allowed + b.held + b.blocked + b.tainted)) };
  }, [events]);
  if (!buckets) return <Empty title="No activity yet">Events will appear here when recorded.</Empty>;
  const { bins, start, end, max } = buckets;
  return <div className="activity-chart"><div className="chart-y"><span>{max}</span><span>{Math.round(max / 2)}</span><span>0</span></div><div className="chart-bars" role="img" aria-label="Recorded events in two minute buckets over the hour ending at the latest event">
    {bins.map((b, i) => <div className="chart-bar" key={i} title={`${clockTime(new Date(start + i * 120000).toISOString())}: ${b.allowed} allowed, ${b.tainted} tainted, ${b.held} held, ${b.blocked} blocked`}>
      {(['allowed', 'tainted', 'held', 'blocked'] as const).map((k) => <span key={k} className={k} style={{ height: `${b[k] / max * 100}%` }} />)}
    </div>)}
  </div><div className="chart-axis"><span>{clockTime(new Date(start).toISOString()).slice(0, 5)}</span><span>{clockTime(new Date((start + end) / 2).toISOString()).slice(0, 5)}</span><span>{clockTime(new Date(end).toISOString()).slice(0, 5)}</span></div></div>;
}

export function OverviewView() {
  const { overview: m, events, approvals, policies, pins, navigate, topology } = useStore();
  const [selected, setSelected] = useState<InterceptionEvent | null>(null);
  const pending = approvals.filter((a) => a.status === 'PENDING').length;
  const issues = pins.filter((p) => p.status !== 'VERIFIED').length;
  const latest = Math.max(0, ...events.map((e) => Date.parse(e.timestamp)).filter(Number.isFinite));
  const hourEvents = events.filter((e) => Date.parse(e.timestamp) >= latest - 3600000);
  const decisionCounts = { allowed: hourEvents.filter((e) => e.decision === 'ALLOW').length, tainted: hourEvents.filter((e) => e.decision === 'TAINT_PROPAGATE').length, held: hourEvents.filter((e) => e.decision === 'STEP_UP_REQUIRED').length, blocked: hourEvents.filter((e) => e.decision.includes('BLOCK')).length };
  return <div className="page overview-page">
    <PageHeader title="Overview" description="Understand what your agents can reach, and what needs your attention." actions={<button className="btn" onClick={() => navigate('graph')}><Waypoints size={14} />Explore blast radius<ArrowUpRight size={13} /></button>} />
    <div className="overview-context"><span className="row gap-8"><ShieldCheck size={15} />Gateway activity</span><span className="subtle">Persisted local records · all time</span></div>
    <div className="grid grid-4 metric-grid">
      <Stat label="Tool calls evaluated" value={m?.total_events.toLocaleString() ?? '—'} hint={`${m?.active_sessions ?? 0} recorded sessions`} icon={<Activity size={13} />} />
      <Stat label="Second hops blocked" value={m?.blocked_second_hops ?? '—'} hint="Calls blocked by recorded runtime decisions" icon={<ShieldCheck size={13} />} />
      <Stat label="Awaiting approval" value={pending} hint="Requests that need a human decision" tone={pending ? 'amber' : undefined} icon={<UserCheck size={13} />} />
      <Stat label="Evaluation latency · p99" value={ms(m?.p99_eval_ms)} hint="Recorded local evaluations" icon={<CheckCheck size={13} />} />
    </div>
    <div className="grid grid-main overview-middle">
      <Card title="Decision activity" description="One hour ending at the latest recorded event" action={<Badge>{events.length} loaded events</Badge>} footer={<div className="legend">{(['allowed', 'tainted', 'held', 'blocked'] as const).map((k) => <span className="legend-item" key={k}><Dot tone={k === 'allowed' ? 'green' : k === 'tainted' ? 'blue' : k === 'held' ? 'amber' : 'red'} />{humanize(k)} <span className="num">{decisionCounts[k]}</span></span>)}</div>}>
        <ActivityChart events={events} />
      </Card>
      <Card title="Needs attention" description="Review requests and changes to your tool surface" bodyClass="attention-list">
        <button className="attention-item" onClick={() => navigate('approvals')}><span className="attention-icon amber"><UserCheck size={17} /></span><span className="stack"><span>{pending ? `${pending} requests awaiting review` : 'No pending requests'}</span><span className="subtle">Inspect arguments and source lineage</span></span><ArrowRight size={15} /></button>
        <button className="attention-item" onClick={() => navigate('integrity')}><span className={`attention-icon ${issues ? 'red' : ''}`}><Fingerprint size={17} /></span><span className="stack"><span>{issues ? `${issues} tool integrity findings` : pins.length ? 'Tool schemas verified' : 'No tool schemas reviewed'}</span><span className="subtle">Review schema and description changes</span></span><ArrowRight size={15} /></button>
        <button className="attention-item" onClick={() => navigate('policies')}><span className="attention-icon"><SlidersHorizontal size={17} /></span><span className="stack"><span>{policies.filter((p) => p.enabled).length} policies enabled</span><span className="subtle">Manage source and sink rules</span></span><ArrowRight size={15} /></button>
      </Card>
    </div>
    <Card title="Recent activity" description="The latest tool decisions recorded by the gateway" action={<button className="btn ghost xs" onClick={() => navigate('activity')}>View all activity<ArrowRight size={12} /></button>} bodyClass="" footer={<><span>{topology?.nodes.length ?? 0} tools and gates in the current topology</span><button className="btn ghost xs" onClick={() => navigate('graph')}>Inspect topology<ArrowUpRight size={12} /></button></>}>
      {events.length ? <EventTable events={events.slice(0, 6)} onSelect={setSelected} /> : <Empty title="No recorded events">Connect an explicit run in Setup to inspect your own tool calls.</Empty>}
    </Card>
    <p className="page-footnote">Metrics describe records from this local runtime. Fixture evaluations run separately from live activity.</p>
    <EventDetail event={selected} onClose={() => setSelected(null)} />
  </div>;
}

export function ActivityView() {
  const { events, live } = useStore();
  const [q, setQ] = useState(''); const [decision, setDecision] = useState('all');
  const [server, setServer] = useState('all'); const [session, setSession] = useState<string | null>(null);
  const [selected, setSelected] = useState<InterceptionEvent | null>(null);
  const search = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing = !!target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
      if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey && !document.querySelector('[role="dialog"]')) { e.preventDefault(); search.current?.focus(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  const servers = [...new Set(events.map((e) => e.server_id))].sort();
  const needle = q.trim().toLowerCase();
  const filtered = events.filter((e) => (decision === 'all' || e.decision === decision) && (server === 'all' || e.server_id === server) && (!session || e.session_id === session) && (!needle || `${e.tool_name} ${toolLabel(e.tool_name, e.server_id)} ${e.server_id} ${e.session_id} ${e.rule_id} ${e.reason}`.toLowerCase().includes(needle)));
  const filtering = !!needle || decision !== 'all' || server !== 'all' || !!session;
  const clear = () => { setQ(''); setDecision('all'); setServer('all'); setSession(null); };
  return <div className="page">
    <PageHeader title="Activity" description="Inspect tool calls, policy decisions, and the data behind them." actions={<button className="btn" disabled={!filtered.length} onClick={() => downloadJson(filtered, 'elytra-activity.json')}><ArrowDownToLine size={14} />Export {filtering ? 'filtered ' : ''}JSON</button>} />
    <div className="toolbar activity-toolbar">
      <div className="input-wrap activity-search"><Search size={14} /><input ref={search} className="input" aria-label="Search activity" aria-keyshortcuts="/" placeholder="Search tools, sessions, or rules…" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === 'Escape' && q) { e.stopPropagation(); setQ(''); } }} /><span className="kbd activity-kbd" aria-hidden="true">/</span></div>
      <Select label="Filter by decision" value={decision} onChange={setDecision} options={[{ value: 'all', label: 'All decisions' }, ...['ALLOW', 'TAINT_PROPAGATE', 'BLOCK_SECOND_HOP', 'STEP_UP_REQUIRED', 'SCHEMA_DRIFT_BLOCK'].map((v) => ({ value: v, label: humanize(v) }))]} />
      <Select label="Filter by server" value={server} onChange={setServer} options={[{ value: 'all', label: 'All servers' }, ...servers.map((s) => ({ value: s, label: s }))]} />
      {filtering && <button className="btn ghost sm" onClick={clear}><X size={13} />Clear filters</button>}
    </div>
    {session && <div className="activity-chip-row"><span className="activity-chip"><span className="subtle">Session</span><span className="mono">{session}</span><button className="btn ghost icon xs" aria-label="Remove session filter" onClick={() => setSession(null)}><X size={12} /></button></span></div>}
    <Card title={`${filtered.length} ${filtered.length === 1 ? 'event' : 'events'}${filtering ? ` of ${events.length}` : ''}`} action={<span className="row gap-6 subtle"><Dot tone={live ? 'green' : 'neutral'} />{live ? 'Updating live' : 'Stream disconnected'}</span>} bodyClass="" footer={<><span>Showing the latest {events.length} loaded events</span><span>Latest {timeAgo(events[0]?.timestamp)}</span></>}>
      {filtered.length ? <EventTable events={filtered} onSelect={setSelected} /> : <Empty icon={<Activity size={18} />} title={events.length ? 'No matching events' : 'No recorded events'}>{events.length ? <>Try a different search or <button className="btn ghost xs" onClick={clear}>clear your filters</button></> : 'Connect an explicit run in Setup to inspect your own tool calls.'}</Empty>}
    </Card>
    <EventDetail event={selected} onClose={() => setSelected(null)} onFilterSession={(id) => { setSession(id); setQ(''); }} />
  </div>;
}
