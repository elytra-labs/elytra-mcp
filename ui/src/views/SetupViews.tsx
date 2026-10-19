import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowRight, FileJson2, FlaskConical, Info, Play, RefreshCw, Search, Server, Terminal } from 'lucide-react';
import { Badge, Card, Chain, Code, Empty, PageHeader, Sheet, SkeletonRows, Stat } from '../components/ui';
import { api, type WrapResult } from '../lib/api';
import { fullDate, humanize, ms, pct, prettyJson, scenarioNumber, scenarioTitle } from '../lib/format';
import { useStore } from '../lib/store';
import type { DiscoveredServer, RedTeamBenchmarkReport, RedTeamScenarioSummary } from '../types/controlPlane';
import '../styles/setup.css';

type InventoryServer = DiscoveredServer & { origin?: 'discovered' | 'example' };

function inventoryLabel(server: InventoryServer): string {
  return server.origin === 'discovered' ? 'Local configuration' : server.origin === 'example' ? 'Example' : 'Unverified entry';
}

function ErrorNotice({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="setup-error" role="alert">
      <span>{message}</span>
      {retry && <button className="btn sm" type="button" onClick={retry}>Try again</button>}
    </div>
  );
}

export function ServersView() {
  const store = useStore();
  const [servers, setServers] = useState<InventoryServer[]>(store.servers);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [host, setHost] = useState('all');
  const [selected, setSelected] = useState<InventoryServer | null>(null);
  const [result, setResult] = useState<WrapResult | null>(null);
  const [generating, setGenerating] = useState(false);
  const [wrapError, setWrapError] = useState('');
  const [runId, setRunId] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setServers(await api.discovery());
    } catch (e) {
      setError(`Unable to read the server inventory. ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const hosts = useMemo(() => [...new Set(servers.map((s) => s.host_app))].sort(), [servers]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return servers.filter((s) => (host === 'all' || s.host_app === host) &&
      (!q || [s.server_name, s.host_app, s.command, s.config_path, ...s.args].join(' ').toLowerCase().includes(q)));
  }, [servers, query, host]);
  const discovered = servers.filter((s) => s.origin === 'discovered').length;
  const examples = servers.filter((s) => s.origin === 'example').length;

  function select(server: InventoryServer) {
    setSelected(server);
    setResult(null);
    setWrapError('');
  }

  async function generate() {
    if (!selected || !runId.trim()) return;
    setGenerating(true);
    setWrapError('');
    try {
      setResult(await api.wrapServer({ server_name: selected.server_name, command: selected.command, args: selected.args, run_id: runId.trim() }));
    } catch (e) {
      setWrapError(`Unable to generate configuration. ${(e as Error).message}`);
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="page setup-page">
      <PageHeader
        title="MCP servers"
        description="Review host configurations and prepare a proxy wrapper for each server."
        actions={<button className="btn" type="button" disabled={loading} onClick={() => void load()}><RefreshCw size={14} />{loading ? 'Scanning…' : 'Rescan hosts'}</button>}
      />

      <div className="setup-intro">
        <div className="setup-intro-icon"><Server size={20} strokeWidth={1.5} /></div>
        <div>
          <h2>Bring your tools into view</h2>
          <p>Use the Python integration for task identity. Advanced host wrappers require one explicit run and stop when it expires.</p>
        </div>
      </div>

      <div className="setup-toolbar toolbar">
        <div className="input-wrap setup-search"><Search size={14} /><input className="input" aria-label="Search servers" placeholder="Search servers or commands…" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
        <select className="select setup-filter" aria-label="Filter by host" value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="all">All hosts</option>
          {hosts.map((name) => <option key={name} value={name}>{name}</option>)}
        </select>
      </div>

      {error && <ErrorNotice message={error} retry={() => void load()} />}
      <Card
        title="Server inventory"
        description={loading ? 'Reading host configuration files…' : `${discovered} local configuration${discovered === 1 ? '' : 's'}${examples ? ` · ${examples} examples` : ''} · ${filtered.length} shown`}
        bodyClass=""
        footer={<span>Configuration entries describe setup. They do not confirm an active proxy connection.</span>}
      >
        {loading && !servers.length ? <SkeletonRows rows={5} /> : filtered.length ? (
          <div className="table-wrap">
            <table className="table setup-server-table">
              <thead><tr><th>Server</th><th>Host</th><th>Wrapper</th><th className="right">Configuration</th></tr></thead>
              <tbody>{filtered.map((server, index) => (
                <tr key={`${server.config_path}:${server.server_name}:${index}`}>
                  <td><div className="cell-main">{server.server_name}</div><div className="cell-sub setup-command" title={[server.command, ...server.args].join(' ')}>{[server.command, ...server.args].join(' ')}</div></td>
                  <td><div>{server.host_app}</div><div className="cell-sub">{inventoryLabel(server)}</div></td>
                  <td><Badge tone={server.wrapped ? 'blue' : 'neutral'}>{server.wrapped ? 'Present in config' : 'Not configured'}</Badge></td>
                  <td className="right"><button type="button" className="btn sm" onClick={() => select(server)}>Review setup<ArrowRight size={13} /></button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <Empty icon={<Server size={18} />} title={query || host !== 'all' ? 'No matching servers' : 'No servers found'}>{query || host !== 'all' ? 'Try another search or host.' : 'Add a stdio MCP server to your host configuration, then rescan.'}</Empty>}
      </Card>

      <div className="setup-footnote"><Info size={14} /><span>Discovery checks Claude Desktop, Cursor, Windsurf, and VS Code configuration files on the backend machine. Example entries, when shown, are sample configurations.</span></div>

      <Card title="Connect a server" description="A small change to your existing host configuration." style={{ marginTop: 28 }}>
        <div className="setup-steps">
          <div><span className="setup-step-number">1</span><h3>Review the entry</h3><p>Confirm the server command and arguments match the tool you want to use.</p></div>
          <div><span className="setup-step-number">2</span><h3>Generate a wrapper</h3><p>Copy the generated command and arguments into that server’s existing entry.</p></div>
          <div><span className="setup-step-number">3</span><h3>Restart your host</h3><p>Run a tool call and verify proxy behavior in the host. Generic hosts cannot establish conversation-level identity across MCP servers. Use the explicit Python integration for run coverage.</p></div>
        </div>
      </Card>

      <Sheet open={!!selected} onClose={() => { if (!generating) setSelected(null); }} title={selected?.server_name ?? 'Server setup'} subtitle={selected ? `${selected.host_app} · ${inventoryLabel(selected)}` : undefined} footer={
        <><button className="btn" type="button" disabled={generating} onClick={() => setSelected(null)}>Close</button><button className="btn primary" type="button" disabled={generating || !runId.trim()} onClick={() => void generate()}><FileJson2 size={14} />{generating ? 'Generating…' : result ? 'Regenerate config' : 'Generate wrapper'}</button></>
      }>
        {selected && <div className="stack gap-16">
          {selected.origin !== 'discovered' && <div className="setup-note"><Info size={14} /><span>{selected.origin === 'example' ? 'This is an example entry. Confirm the command and path before using it.' : 'The API has not identified this entry as a discovered configuration. Confirm it in your host first.'}</span></div>}
          <div><h3 className="section-title">Host configuration path</h3><div className="setup-path mono">{selected.config_path}</div></div>
          <div><h3 className="section-title">Current launch configuration</h3><Code json>{prettyJson({ command: selected.command, args: selected.args, run_id: runId.trim() })}</Code></div>
          <label className="field"><span className="field-label">Active run ID</span><input className="input mono" aria-label="Active run ID" value={runId} onChange={(event) => { setRunId(event.target.value); setResult(null); }} placeholder="Create a run in Setup first" /><span className="field-hint">Use a separate run for each task. Set its private run token in the generated environment placeholder. Never share it across unrelated conversations.</span></label>
          <div className="setup-note"><Info size={14} /><span>Apply the generated configuration manually. Generating a wrapper does not edit your host files or start a connection.</span></div>
          {wrapError && <ErrorNotice message={wrapError} />}
          {result && <>
            <div><h3 className="section-title">Generated host entry</h3><Code json>{prettyJson(result.wrapped_config)}</Code></div>
            <div className="setup-next"><h3>Apply and restart</h3><ol><li>Back up your host configuration.</li><li>Merge the generated server command and arguments into its existing entry. Keep existing environment variables and other server entries.</li><li>Ensure the <span className="mono">elytra</span> command is available to the host, then restart the host.</li><li>Verify the proxy in your host. Use the explicit Python integration to verify run coverage.</li></ol></div>
            <button type="button" className="btn" onClick={() => { setSelected(null); store.navigate('activity'); }}>Open activity<ArrowRight size={13} /></button>
          </>}
        </div>}
      </Sheet>
    </div>
  );
}

export function EvaluationsView() {
  const store = useStore();
  const [report, setReport] = useState<RedTeamBenchmarkReport | null>(store.evaluations);
  const [loading, setLoading] = useState(!store.evaluations);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try { setReport(await api.evaluations()); }
    catch (e) { setError(`Unable to load evaluations. ${(e as Error).message}`); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (store.evaluations) setReport(store.evaluations); }, [store.evaluations]);

  const categories = useMemo(() => [...new Set(report?.scenarios.map((s) => s.category) ?? [])].sort(), [report]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (report?.scenarios ?? []).filter((s) => (category === 'all' || s.category === category) &&
      (!q || [s.setup_id, s.name, s.category, s.source_server, s.source_tool, s.sink_server, s.sink_tool, s.expected_rule].join(' ').toLowerCase().includes(q)));
  }, [report, query, category]);
  const selected = report?.scenarios.find((s) => s.setup_id === selectedId);

  return (
    <div className="page setup-page">
      <PageHeader title="Evaluations" description="Inspect isolated deterministic regression fixtures; these do not exercise your live MCP services." actions={
        <button type="button" className="btn primary" disabled={!!store.replaying || loading || store.offline || !!store.config?.demo_mode} onClick={() => void store.replay()}><Play size={13} />{store.replaying ? 'Running…' : 'Run fixture checks'}</button>
      } />

      <div className="setup-evaluation-heading"><div className="row gap-8"><FlaskConical size={15} className="subtle" /><span>Synthetic benchmark</span><Badge>Local</Badge></div><span className="subtle">{report ? `Last run ${fullDate(report.run_at)}` : 'No report loaded'}</span></div>
      {error && <ErrorNotice message={error} retry={() => void load()} />}

      {report ? <>
        <div className="grid grid-4 setup-stats">
          <Stat label="Attack scenarios blocked" value={pct(report.block_rate_pct)} hint={`${report.blocked_attacks} of ${report.total_attack_setups} synthetic attacks`} />
          <Stat label="Clean workflows flagged" value={report.false_positives} hint={`${report.total_clean_workflows} clean workflows evaluated`} />
          <Stat label="Mean evaluation" value={ms(report.mean_latency_ms)} hint="Legacy graph fixtures only" />
          <Stat label="P99 evaluation" value={ms(report.p99_latency_ms)} hint={`P95 ${ms(report.p95_latency_ms)}`} />
        </div>
        <div className="setup-note setup-benchmark-note"><Info size={14} /><span>These results describe this synthetic suite. They do not measure protection across all real workflows. Checks execute in an isolated fixture environment. They do not add events to live activity or measure general real-world protection.</span></div>

        <div className="toolbar setup-toolbar">
          <div className="input-wrap setup-search"><Search size={14} /><input className="input" aria-label="Search evaluation scenarios" placeholder="Search scenarios, tools, or rules…" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
          <select className="select setup-filter" aria-label="Filter by injection technique" value={category} onChange={(e) => setCategory(e.target.value)}><option value="all">All techniques</option>{categories.map((item) => <option value={item} key={item}>{humanize(item)}</option>)}</select>
        </div>

        <Card title="Scenario results" description={`${filtered.length} of ${report.scenarios.length} scenarios`} bodyClass="" footer={<span>Inspect a fixture or rerun its deterministic checks. Live activity is separate.</span>}>
          {filtered.length ? <div className="table-wrap"><table className="table setup-scenario-table">
            <thead><tr><th>Scenario</th><th>Tool chain</th><th>Result</th><th className="right">Evaluation</th></tr></thead>
            <tbody>{filtered.map((scenario) => <tr key={scenario.setup_id}>
              <td><button type="button" className="setup-scenario-link" onClick={() => setSelectedId(scenario.setup_id)}><span className="setup-scenario-title">{scenarioTitle(scenario.name)}</span><span className="cell-sub">{scenarioNumber(scenario.setup_id)} · {humanize(scenario.category)}</span></button></td>
              <td><div className="setup-tool-pair mono"><span>{scenario.source_server}.{scenario.source_tool}</span><ArrowRight size={11} /><span>{scenario.sink_server}.{scenario.sink_tool}</span></div></td>
              <td><Badge tone={scenario.blocked ? 'green' : 'red'} dot>{scenario.blocked ? 'Blocked' : 'Not blocked'}</Badge></td>
              <td className="right mono">{ms(scenario.eval_latency_ms)}</td>
            </tr>)}</tbody>
          </table></div> : <Empty icon={<Search size={18} />} title="No matching scenarios">Try another term or injection technique.</Empty>}
        </Card>
      </> : loading ? <Card title="Loading local benchmark" bodyClass=""><SkeletonRows rows={7} /></Card> : <Card bodyClass=""><Empty icon={<FlaskConical size={18} />} title="No evaluation report available">Load a report to inspect the synthetic suite.</Empty></Card>}

      <Sheet open={!!selected} onClose={() => setSelectedId(null)} title={selected ? scenarioTitle(selected.name) : 'Scenario'} subtitle={selected ? `${scenarioNumber(selected.setup_id)} · ${humanize(selected.category)} · Synthetic scenario` : undefined} footer={selected && <><button type="button" className="btn" onClick={() => { setSelectedId(null); store.navigate('graph'); }}>Open graph<ArrowRight size={13} /></button><button type="button" className="btn primary" disabled={!!store.replaying || store.offline || !!store.config?.demo_mode} onClick={() => void store.replay(selected.setup_id)}><Play size={13} />{store.replaying === selected.setup_id ? 'Checking…' : 'Run fixture checks'}</button></>}>
        {selected && <ScenarioDetail scenario={selected} />}
      </Sheet>
    </div>
  );
}

function ScenarioDetail({ scenario }: { scenario: RedTeamScenarioSummary }) {
  return <div className="stack gap-16">
    <div className="row gap-8"><Badge tone={scenario.blocked ? 'green' : 'red'} dot>{scenario.blocked ? 'Blocked in benchmark' : 'Not blocked in benchmark'}</Badge><span className="subtle">{ms(scenario.eval_latency_ms)}</span></div>
    <div><h3 className="section-title">Tool chain</h3><Chain nodes={[`${scenario.source_server}.${scenario.source_tool}`, 'context_core', `${scenario.sink_server}.${scenario.sink_tool}`]} blockedLast={scenario.blocked} /></div>
    <div><h3 className="section-title">Scenario narrative</h3><p className="setup-narrative">{scenario.attack_narrative}</p></div>
    <dl className="meta"><dt>Expected rule</dt><dd className="mono">{scenario.expected_rule}</dd><dt>Observed rule</dt><dd className="mono">{scenario.actual_rule ?? 'No rule triggered'}</dd></dl>
    <div><h3 className="section-title">Injection payload preview</h3><Code>{scenario.poison_snippet || 'No payload preview available.'}</Code><p className="field-hint">The API returns a truncated preview of the synthetic payload.</p></div>
    <div className="setup-note"><Terminal size={14} /><span>Fixture checks use an isolated environment. They do not invoke the named external services or add records to live activity.</span></div>
  </div>;
}
