import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Check, Fingerprint, Link2, RefreshCw, ShieldCheck } from 'lucide-react';
import { Badge, Card, Code, Empty, PageHeader, Sheet, Stat } from '../components/ui';
import { useStore } from '../lib/store';
import { humanize, prettyJson } from '../lib/format';
import '../styles/onboarding.css';

interface Tool { server_id: string; tool_name: string; category: string; status: string; sha256_hash: string; observed_sha256_hash?: string; available?: boolean; description_preview?: string; schema?: unknown; }
interface Run { run_id: string; intent: string; created_at?: string; status?: string; expires_at_epoch?: number; run_token?: string; }
interface Coverage { managed?: boolean; cloud_origin?: string; active_runs?: number; registered_tools?: number; unknown_tools?: number; coverage?: string; generic_host_coverage?: string; dispatch_guarantee?: string; }
const CATEGORIES = ['SOURCE_UNTRUSTED', 'SOURCE_TRUSTED', 'SINK_PRIVILEGED_WRITE', 'SINK_EXFILTRATION'];
async function runtime<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/api/v1${path}`, { credentials: 'same-origin', signal: AbortSignal.timeout(15000), ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }), headers: { 'Content-Type': 'application/json', 'X-Elytra-Request': '1' } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
const SDK_EXAMPLE = `import asyncio
from mirage_mcp.sdk import RuntimeClient

async def main():
    client = RuntimeClient()
    run = client.create_run(intent="Inspect a GitHub issue", grants=[])
    scoped = client.for_run(run["run_id"], run["run_token"])
    async with scoped.proxy("github", ["python", "your_mcp_server.py"]) as tools:
        metadata = await tools.list_tools()
        print(metadata)  # Review and classify these tools in Setup.
        input("Press Enter after reviewing tools in the local console: ")
        result = await tools.call_tool("get_issue", {"number": 218})
        print(result)

asyncio.run(main())`;

export function OnboardingView() {
  const { offline, toast, navigate, config } = useStore();
  const [coverage, setCoverage] = useState<Coverage>({});
  const [tools, setTools] = useState<Tool[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Tool | null>(null);
  const [category, setCategory] = useState('SOURCE_UNTRUSTED');
  const [reviewed, setReviewed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [intent, setIntent] = useState('');
  const [grants, setGrants] = useState('[]');
  const [newRun, setNewRun] = useState<Run | null>(null);
  const [creating, setCreating] = useState(false);
  const [runError, setRunError] = useState('');
  const locked = offline || !!config?.demo_mode;
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const [c, t, r] = await Promise.all([runtime<Coverage>('/runtime/coverage'), runtime<{ tools: Tool[] }>('/tools'), runtime<{ runs: Run[] }>('/runs')]);
      setCoverage(c); setTools(t.tools); setRuns(r.runs);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  async function acknowledge() {
    if (!selected || !reviewed || locked || coverage.managed) return;
    setSaving(true); setError('');
    try {
      await runtime('/schema-pins/acknowledge', { server_id: selected.server_id, tool_name: selected.tool_name, sha256_hash: selected.observed_sha256_hash || selected.sha256_hash, category });
      setSelected(null); toast('Tool version and capability reviewed', 'green'); await load();
    } catch (e) { setError((e as Error).message); }
    finally { setSaving(false); }
  }
  async function create(event: FormEvent) {
    event.preventDefault(); if (locked || creating) return;
    setRunError('');
    let parsed: unknown;
    try { parsed = JSON.parse(grants); if (!Array.isArray(parsed)) throw new Error('Grants must be a JSON array.'); }
    catch (e) { setRunError(`Invalid grants: ${(e as Error).message}`); return; }
    setCreating(true);
    try { setNewRun(await runtime<Run>('/runs', { intent: intent.trim(), grants: parsed })); await load(); toast('Explicit run created', 'green'); }
    catch (e) { setRunError((e as Error).message); }
    finally { setCreating(false); }
  }
  return <div className="page onboarding-page"><PageHeader title="Setup" description="Connect one workflow and verify which actions are covered." actions={<button className="btn" disabled={loading} onClick={() => void load()}><RefreshCw size={14} />{loading ? 'Checking…' : 'Refresh coverage'}</button>} />
    {error && <div className="setup-error" role="alert">{error}</div>}
    <div className="onboarding-intro"><span className="onboarding-intro-icon"><ShieldCheck size={22} /></span><div><h2>Start with an explicit run</h2><p>Use the Python integration to keep one task’s identity across its MCP servers. Generic host configurations provide inventory; they do not establish conversation identity.</p></div><a className="btn sm" href="/docs">Read the guide<ArrowRight size={13} /></a></div>
    {coverage.managed && <div className="onboarding-note"><ShieldCheck size={16} /><span>This runtime is managed by your hosted workspace. Review tools, policies, and approvals there. Local grants and administration cannot override workspace authority. <a href={coverage.cloud_origin ? `${coverage.cloud_origin}/app/` : '/docs'} target="_blank" rel="noreferrer">Open hosted workspace</a></span></div>}
    <div className="grid grid-4 onboarding-stats"><Stat label="Browser session" value={config?.authenticated ? 'Paired' : 'Unpaired'} hint="Local control plane authentication" /><Stat label="Active runs" value={loading ? '—' : coverage.active_runs ?? runs.filter((run) => run.status === 'ACTIVE' && (run.expires_at_epoch === undefined || run.expires_at_epoch > Date.now() / 1000)).length} hint="Explicit run identities" /><Stat label="Registered tools" value={loading ? '—' : coverage.registered_tools ?? tools.length} hint="Reported by connected integrations" /><Stat label="Tools awaiting review" value={loading ? '—' : coverage.unknown_tools ?? tools.filter((tool) => !tool.available || tool.category === 'UNKNOWN').length} hint="Unclassified or changed metadata" /></div>
    <Card title="1. Review your tool surface" description="Read the tool metadata before acknowledging its version and assigning a capability." bodyClass="" footer={<span>A fingerprint identifies metadata. It does not verify that a tool’s implementation is safe.</span>}>
      {tools.length ? <div className="table-wrap"><table className="table"><thead><tr><th>Tool</th><th>Category</th><th>Status</th><th className="right">Review</th></tr></thead><tbody>{tools.map((tool) => <tr key={`${tool.server_id}:${tool.tool_name}`}><td><span className="mono">{tool.tool_name}</span><div className="cell-sub">{tool.server_id}</div></td><td>{humanize(tool.category || 'UNKNOWN')}</td><td><Badge tone={tool.available && tool.category !== 'UNKNOWN' ? 'green' : 'amber'}>{humanize(tool.available && tool.category !== 'UNKNOWN' ? tool.status : 'REVIEW_REQUIRED')}</Badge></td><td className="right"><button className="btn sm" disabled={locked || coverage.managed} onClick={() => { setSelected(tool); setCategory(CATEGORIES.includes(tool.category) ? tool.category : 'SOURCE_UNTRUSTED'); setReviewed(false); }}><Fingerprint size={13} />Inspect metadata</button></td></tr>)}</tbody></table></div> : <Empty icon={<Link2 size={18} />} title={loading ? 'Checking connected tools' : 'No tools registered yet'}>Use the Python integration below to list tools. Listing registers their metadata; it does not authorize their execution.</Empty>}
    </Card>
    <Card title="2. Declare a task and exact permissions" description="Intent describes the task. Only explicit grants and runtime policy authorize calls." style={{ marginTop: 24 }}>
      <form className="onboarding-run-form" onSubmit={(event) => void create(event)}><label className="field"><span className="field-label">Task intent</span><input className="input" required maxLength={1000} placeholder="Investigate issue #218 and propose a fix" value={intent} onChange={(event) => setIntent(event.target.value)} /></label><label className="field"><span className="field-label">Exact grants · JSON array</span><textarea className="textarea mono" rows={5} value={grants} spellCheck={false} onChange={(event) => setGrants(event.target.value)} /><span className="field-hint">Start with [] for no preapproved calls. A grant has server_id, tool_name, and an exact arguments object. It does not authorize other argument values.</span></label>{runError && <div className="setup-error" role="alert">{runError}</div>}<button className="btn primary" type="submit" disabled={locked || creating || !intent.trim()}>{creating ? 'Creating…' : 'Create explicit run'}<ArrowRight size={13} /></button></form>
      {newRun && <div className="onboarding-created"><h3><Check size={15} />Run created</h3><p>Keep this run token private. It is shown from the creation response; the run list does not reveal it.</p><Code json>{prettyJson(newRun)}</Code><button className="btn sm" onClick={() => setNewRun(null)}>Hide credentials</button></div>}
      {runs.length > 0 && <div className="onboarding-runs"><h3 className="section-title">Recent runs</h3>{runs.slice(0, 8).map((run) => <div className="onboarding-run" key={run.run_id}><span>{run.intent}</span><code>{run.run_id}</code><Badge>{humanize(run.status || 'ACTIVE')}</Badge></div>)}</div>}
    </Card>
    <Card title="3. Route execution through the Python integration" description="Create a run in code, or use the credentials from the run above. Never route unrelated tasks through one run." style={{ marginTop: 24 }}><Code>{SDK_EXAMPLE}</Code><p className="field-hint">Replace the server process and example tool with your actual MCP server. RuntimeClient reads the local control token; run tokens scope subsequent calls. Keep a waiting integration alive while reviewing approvals.</p><div className="onboarding-note"><ShieldCheck size={16} /><span>Calls that bypass this integration are outside coverage. A registered tool or discovered host entry does not prove that future calls are intercepted.</span></div></Card>
    <Card title="4. Verify the boundary" description="Check an allowed read and a safely held fixture before connecting consequential tools." style={{ marginTop: 24 }}><ol className="onboarding-checks"><li>Observe a harmless read in Activity under the correct run identity.</li><li>Propose a fixture write without a matching grant. Confirm it is held and the destination is not called.</li><li>Deny the call, then verify that the client does not dispatch it.</li><li>Test a separate exact call approval. Check the destination receives it once.</li></ol><div className="row gap-8"><button className="btn" onClick={() => navigate('activity')}>Inspect activity<ArrowRight size={13} /></button><button className="btn" onClick={() => navigate('approvals')}>Review approvals<ArrowRight size={13} /></button></div></Card>
    <Sheet open={!!selected} onClose={() => { if (!saving) setSelected(null); }} title="Review tool metadata" subtitle={selected ? `${selected.server_id} · ${selected.tool_name}` : ''} footer={<><button className="btn" disabled={saving} onClick={() => setSelected(null)}>Cancel</button><button className="btn primary" disabled={saving || !reviewed || locked} onClick={() => void acknowledge()}>{saving ? 'Saving…' : 'Acknowledge this version'}</button></>}>
      {selected && <div className="stack gap-16"><div className="onboarding-note"><Fingerprint size={17} /><span>Review the complete tool description and schema using trusted provider documentation. Metadata may itself contain malicious instructions. Assign the category according to the tool’s actual capabilities.</span></div><div><h3 className="section-title">Description preview</h3><p className="onboarding-description">{selected.description_preview || 'No description supplied. Inspect the server before classification.'}</p></div>{selected.schema !== undefined && <div><h3 className="section-title">Reported schema</h3><Code json>{prettyJson(selected.schema)}</Code></div>}<div><h3 className="section-title">Metadata fingerprint</h3><Code>{selected.observed_sha256_hash || selected.sha256_hash}</Code></div><label className="field"><span className="field-label">Capability category</span><select className="select" value={category} onChange={(event) => setCategory(event.target.value)}>{CATEGORIES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select><span className="field-hint">Trusted sources still need explicit operator trust. Writes, execution, and external data transfer require the appropriate sink category.</span></label><label className="onboarding-confirm"><input type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} /><span>I reviewed this metadata version and its actual capabilities before assigning this category.</span></label>{error && <div className="setup-error" role="alert">{error}</div>}</div>}
    </Sheet>
  </div>;
}
