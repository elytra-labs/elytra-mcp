import { useCallback, useEffect, useState } from 'react';
import { Check, MonitorSmartphone, ShieldCheck } from 'lucide-react';
import { api, type CatalogState, type LinkStatus, type GuardrailDecision, type GuardrailPreset, type GuardrailsState, type HostRecord } from '../lib/api';
import type { SchemaPinRecord } from '../types/controlPlane';
import { useStore } from '../lib/store';
import { Badge, Card, Code, Empty, PageHeader, SkeletonRows } from '../components/ui';
import { timeAgo } from '../lib/format';
import '../styles/guardrails.css';

const ROWS: { key: keyof GuardrailPreset['matrix']; label: string; hint: string }[] = [
  { key: 'reads', label: 'Reads', hint: 'Issues, files, queries, pages' },
  { key: 'writes', label: 'Writes', hint: 'Commits, records, edits' },
  { key: 'sends', label: 'Sending data out', hint: 'Messages, comments, form submissions' },
  { key: 'destructive', label: 'Deletes and payments', hint: 'Delete, drop, remove, charge, transfer' },
];
const TONE: Record<GuardrailDecision, 'green' | 'amber' | 'red'> = { allow: 'green', ask: 'amber', block: 'red' };
const WORD: Record<GuardrailDecision, string> = { allow: 'Runs', ask: 'Asks you', block: 'Blocked' };

export function GuardrailsView() {
  const { toast, navigate, config } = useStore();
  const [state, setState] = useState<GuardrailsState | null>(null);
  const [hosts, setHosts] = useState<HostRecord[]>([]);
  const [catalog, setCatalog] = useState<CatalogState | null>(null);
  const [pins, setPins] = useState<SchemaPinRecord[]>([]);
  const [link, setLink] = useState<LinkStatus | null>(null);
  const [selected, setSelected] = useState<GuardrailPreset['id'] | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const [g, h, c, p] = await Promise.all([api.guardrails(), api.hosts(), api.catalog(), api.schemaPins()]);
      setState(g); setHosts(h); setCatalog(c); setPins(p);
      api.linkStatus().then(setLink).catch(() => setLink(null));
      setSelected((current) => current ?? g.preset ?? g.default);
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load guardrails');
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const preset = state?.presets.find((p) => p.id === selected) ?? null;
  const dirty = !!state && selected !== state.preset;

  async function apply() {
    if (!selected || busy) return;
    setBusy(true);
    try {
      setState(await api.applyGuardrails(selected));
      toast(`Guardrails set to ${state?.presets.find((p) => p.id === selected)?.label}`, 'green');
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not apply guardrails', 'red');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(host: HostRecord) {
    if (confirming !== host.host_id) { setConfirming(host.host_id); return; }
    setConfirming(null);
    try {
      await api.revokeHost(host.host_id);
      toast(`${host.label} disconnected. Its sessions were cancelled.`, 'neutral');
      await load();
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not revoke host', 'red');
    }
  }

  const activeHosts = hosts.filter((h) => !h.revoked_at);
  const recognized = Object.entries(catalog?.servers ?? {});
  const unclassified = pins.filter((p) => p.observed_via === 'hook' && p.category === 'UNKNOWN' && p.status === 'VERIFIED');

  return (
    <div className="page">
      <PageHeader title="Guardrails" description="What agents can do without asking you. Applies to every connected agent session." />
      {error && <div className="governance-integrity-notice"><p>{error}</p></div>}
      {!state ? <SkeletonRows /> : (
        <>
          <div className="guard-presets" role="radiogroup" aria-label="Guardrail preset">
            {state.presets.map((p) => (
              <button key={p.id} role="radio" aria-checked={selected === p.id} className={`guard-preset ${selected === p.id ? 'selected' : ''}`} onClick={() => setSelected(p.id)}>
                <span className="guard-preset-head">
                  <strong>{p.label}</strong>
                  {state.preset === p.id ? <Badge tone="green" dot>Active</Badge> : p.id === state.default ? <span className="subtle">Recommended</span> : null}
                </span>
                <span className="guard-preset-summary">{p.summary}</span>
              </button>
            ))}
          </div>

          {preset && (
            <Card title={`${preset.label}: what happens`} description="A session becomes untrusted once the agent reads content it did not write, such as an issue, an email, or a web page." bodyClass="">
              <div className="table-wrap">
                <table className="table guard-matrix">
                  <thead><tr><th>Action</th><th>Clean session</th><th>After untrusted content</th></tr></thead>
                  <tbody>
                    {ROWS.map((row) => (
                      <tr key={row.key}>
                        <td><span className="cell-main">{row.label}</span><div className="cell-sub">{row.hint}</div></td>
                        {preset.matrix[row.key].map((decision, i) => <td key={i}><Badge tone={TONE[decision]} dot>{WORD[decision]}</Badge></td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          <div className="guard-apply">
            <p className="subtle">
              {state.custom_rules > 0
                ? <>Your {state.custom_rules} custom rule{state.custom_rules === 1 ? '' : 's'} on <button className="governance-text-button" onClick={() => navigate('policies')}>Policies</button> take precedence over the preset.</>
                : <>Need something specific? Rules you add on <button className="governance-text-button" onClick={() => navigate('policies')}>Policies</button> take precedence over the preset.</>}
            </p>
            <button className="btn primary" disabled={!dirty || busy || !!config?.demo_mode} onClick={() => void apply()}>
              <Check size={14} />{busy ? 'Applying…' : state.preset ? 'Apply preset' : 'Turn on guardrails'}
            </button>
          </div>
        </>
      )}

      {unclassified.length > 0 && (
        <div className="guard-unclassified">
          <span><strong>{unclassified.length} tool{unclassified.length === 1 ? '' : 's'} seen through your agents need a classification.</strong> Until you classify them, agents are asked or blocked each time they use them: {unclassified.slice(0, 3).map((p) => `${p.server_id}.${p.tool_name}`).join(', ')}{unclassified.length > 3 ? '…' : ''}</span>
          <button className="btn sm" onClick={() => navigate('integrity')}>Classify tools</button>
        </div>
      )}

      <Card title="Connected agents" description="Shell commands, file edits and web access are checked through each agent's hooks; MCP servers through Elytra's proxy. Each agent session is reviewed as one run." bodyClass="">
        {activeHosts.length === 0 ? (
          <Empty icon={<MonitorSmartphone size={18} />} title="No agents connected">Run <code className="mono">elytra setup</code> in a terminal to protect Claude Code, Codex, Grok, Antigravity, Cursor, or Claude Desktop.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Agent</th><th>Sessions</th><th>Approval window</th><th>Connected</th><th><span className="governance-sr-only">Actions</span></th></tr></thead>
              <tbody>
                {activeHosts.map((host) => (
                  <tr key={host.host_id}>
                    <td><span className="cell-main">{host.label}</span><div className="cell-sub mono">{host.host_id}</div></td>
                    <td>{host.active_sessions ? <Badge tone="green" dot>{host.active_sessions} active</Badge> : <span className="subtle">None active</span>}</td>
                    <td className="mono">{Math.round(host.approval_window / 60)} min</td>
                    <td><span className="muted">{timeAgo(host.created_at)}</span></td>
                    <td className="right"><button className={`btn sm ${confirming === host.host_id ? 'danger' : 'ghost'}`} onClick={() => void revoke(host)}>{confirming === host.host_id ? 'Confirm disconnect' : 'Disconnect'}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {link && (
        <Card title="Approve from your phone" description={link.linked ? `Held actions also appear at ${link.origin}/app/. A decision there applies only to the exact action, and this machine checks it before anything runs.` : 'Codex, Antigravity and agents running with permissions bypassed wait up to ten minutes for you. Link a free account to approve or deny them from any device.'}>
          {link.linked ? (
            <div className="guard-link">
              {link.last_error ? <Badge tone="amber" dot>{link.last_error}</Badge> : link.connected ? <Badge tone="green" dot>Linked</Badge> : <Badge dot>Connecting</Badge>}
              {link.last_sync ? <span className="subtle">Last checked {timeAgo(new Date(link.last_sync * 1000).toISOString())}</span> : null}
              <span className="subtle">To stop, run <code className="mono">elytra unlink</code>.</span>
            </div>
          ) : (
            <div className="guard-link">
              <Code>{'elytra link'}</Code>
              <p className="subtle">Run it in a terminal and sign in with GitHub or Google. Your guardrails, history and decisions stay on this machine; only summaries of held actions are sent.</p>
            </div>
          )}
        </Card>
      )}

      {recognized.length > 0 && catalog && (
        <Card title="Recognized servers" description="Listed tools from these servers were classified from Elytra's catalog when you accepted it. Unlisted or changed tools still wait for review." bodyClass="">
          <div className="guard-servers">
            {recognized.map(([server, id]) => (
              <div key={server} className="guard-server">
                <ShieldCheck size={15} />
                <div><strong className="mono">{server}</strong><span className="subtle"> · {catalog.catalog[id]?.label ?? id}</span>{catalog.catalog[id]?.note && <p className="subtle">{catalog.catalog[id]?.note}</p>}</div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
