import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDownToLine, ArrowRight, Box, Check, ChevronRight, Crosshair, GitBranch, Layers, Minus, MousePointer2, Plus, Search, ShieldCheck, X } from 'lucide-react';
import { Badge, Chain, Code, Empty, Select } from '../components/ui';
import { EDGE_META, fullDate, humanize, ms, shortHash, toolLabel } from '../lib/format';
import { useStore } from '../lib/store';
import type { GraphNode, NodeRole } from '../types/controlPlane';
import '../styles/graph.css';

type Selection = { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null;
const COLUMNS: { role: NodeRole; label: string; note: string }[] = [
  { role: 'source', label: 'Sources', note: 'Tool responses & input' },
  { role: 'context_core', label: 'Agent context', note: 'Shared execution context' },
  { role: 'policy_gate', label: 'Policy checks', note: 'Enforcement boundary' },
  { role: 'sink', label: 'Destinations', note: 'Tools with side effects' },
];
const NODE_W = 196;
const NODE_H = 68;
const COL_W = 246;
const GRAPH_W = COL_W * 4 + 44;
const displayName = (n: GraphNode) => n.role === 'context_core' ? 'Agent context' : n.label || toolLabel(n.id);
const clipped = (text: string, n = 24) => text.length > n ? `${text.slice(0, n - 1)}…` : text;

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="graph-detail-row"><dt>{label}</dt><dd>{children}</dd></div>;
}

export function GraphView() {
  const { topology, loaded, offline, live, policies, navigate } = useStore();
  const [query, setQuery] = useState('');
  const [server, setServer] = useState('all');
  const [decision, setDecision] = useState('all');
  const [selection, setSelection] = useState<Selection>(null);
  const [zoom, setZoom] = useState(1);
  const [width, setWidth] = useState(900);
  const viewport = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = viewport.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const servers = useMemo(() => [...new Set(topology?.nodes.map((n) => n.server_id).filter((id): id is string => Boolean(id)))].sort(), [topology]);
  const nodesById = useMemo(() => new Map(topology?.nodes.map((n) => [n.id, n])), [topology]);
  const graph = useMemo(() => {
    const allNodes = topology?.nodes ?? [];
    const allEdges = topology?.edges ?? [];
    const q = query.trim().toLowerCase();
    const matchingNodes = new Set(allNodes.filter((n) =>
      (server === 'all' || n.server_id === server) && (!q || `${n.label} ${n.id} ${n.server_id ?? ''} ${n.category ?? ''}`.toLowerCase().includes(q))
    ).map((n) => n.id));
    const filteredEdges = allEdges.filter((e) => (decision === 'all' || e.status === decision) &&
      (matchingNodes.has(e.source) || matchingNodes.has(e.target) || (server === 'all' && Boolean(q) && `${e.reason ?? ''} ${e.rule_id ?? ''}`.toLowerCase().includes(q))));
    const included = new Set(filteredEdges.flatMap((e) => [e.source, e.target]));
    if (decision === 'all') matchingNodes.forEach((id) => included.add(id));
    const nodes = allNodes.filter((n) => included.has(n.id));
    const positions = new Map<string, { x: number; y: number }>();
    let maxRows = 1;
    COLUMNS.forEach(({ role }, i) => {
      const group = nodes.filter((n) => n.role === role).sort((a, b) => a.id.localeCompare(b.id));
      maxRows = Math.max(maxRows, group.length);
      group.forEach((n, j) => positions.set(n.id, { x: 32 + i * COL_W, y: 104 + j * 100 }));
    });
    return { nodes, edges: filteredEdges, positions, height: Math.max(500, maxRows * 100 + 132) };
  }, [topology, query, server, decision]);

  const selectedNode = selection?.kind === 'node' ? nodesById.get(selection.id) : undefined;
  const selectedEdge = selection?.kind === 'edge' ? topology?.edges.find((e) => e.id === selection.id) : undefined;
  const connected = new Set<string>();
  if (selectedNode) {
    connected.add(selectedNode.id);
    topology?.edges.forEach((e) => { if (e.source === selectedNode.id || e.target === selectedNode.id) { connected.add(e.source); connected.add(e.target); } });
  } else if (selectedEdge) { connected.add(selectedEdge.source); connected.add(selectedEdge.target); }
  const selectedPolicy = selectedEdge?.rule_id ? policies.find((p) => p.rule_id === selectedEdge.rule_id) : undefined;
  const relatedEdges = selectedNode ? topology?.edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id) ?? [] : [];
  const lineage = useMemo(() => {
    if (!selectedEdge || !topology) return [];
    // Follow only recorded incoming edges. Cycles are bounded by the visited set.
    const walk = (id: string, visited = new Set<string>()): string[] => {
      if (visited.has(id)) return [];
      visited.add(id);
      const incoming = topology.edges.find((e) => e.target === id && !visited.has(e.source));
      return incoming ? [...walk(incoming.source, visited), id] : [id];
    };
    return [...walk(selectedEdge.source), selectedEdge.target];
  }, [selectedEdge, topology]);
  useEffect(() => {
    setSelection((current) => {
      if (!current || !topology) return null;
      const exists = current.kind === 'node' ? topology.nodes.some((node) => node.id === current.id) : topology.edges.some((edge) => edge.id === current.id);
      return exists ? current : null;
    });
  }, [topology]);
  const scale = Math.max(.68, Math.min(Math.max(width - 24, 320) / GRAPH_W, 1)) * zoom;
  const activeFilters = Boolean(query || server !== 'all' || decision !== 'all');
  const clearFilters = () => { setQuery(''); setServer('all'); setDecision('all'); };
  const fit = () => { setZoom(1); viewport.current?.scrollTo({ left: 0, top: 0, behavior: 'smooth' }); };
  const exportGraph = () => {
    if (!topology) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(topology, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url; a.download = `elytra-topology-${topology.session_id.replace(/[^a-zA-Z0-9_-]/g, '_')}.json`; a.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return <div className="graph-page">
    <header className="graph-page-header">
      <div><div className="graph-eyebrow"><GitBranch size={13} /> Execution map</div><h1>Blast radius</h1><p>Follow tool data from its source to the action it can influence.</p></div>
      <button className="btn sm" onClick={exportGraph} disabled={!topology}><ArrowDownToLine size={14} /> Export JSON</button>
    </header>
    <div className="graph-workspace">
      <section className="graph-canvas-pane" aria-label="Execution topology">
        <div className="graph-toolbar">
          <label className="graph-search"><Search size={14} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find a tool, server or rule…" aria-label="Search topology" />{query && <button onClick={() => setQuery('')} aria-label="Clear search"><X size={12} /></button>}</label>
          <div className="graph-filters"><Select label="Filter server" value={server} onChange={setServer} options={[{ value: 'all', label: 'All servers' }, ...servers.map((s) => ({ value: s, label: s }))]} /><Select label="Filter decision" value={decision} onChange={setDecision} options={[{ value: 'all', label: 'All decisions' }, ...Object.entries(EDGE_META).map(([key, meta]) => ({ value: key, label: meta.label }))]} /></div>
        </div>
        <div className="graph-context"><span className={`dot ${live ? 'green' : ''}`} /><span>{offline ? 'Connection unavailable · last received topology' : live ? 'Live topology' : 'Recorded topology'}</span><span className="graph-context-divider" /><span>{graph.nodes.length} nodes · {graph.edges.length} connections</span>{activeFilters && <button className="graph-text-button" onClick={clearFilters}>Clear filters</button>}</div>
        <div className="graph-viewport" ref={viewport}>
          {!loaded && !topology ? <Empty icon={<Layers size={22} />} title="Loading execution map">Retrieving the latest topology.</Empty> : !graph.nodes.length ? <Empty icon={<GitBranch size={22} />} title={activeFilters ? 'No matching paths' : 'No execution paths yet'}>{activeFilters ? <button className="btn sm" onClick={clearFilters}>Clear filters</button> : 'Connect an MCP server or run an evaluation to inspect recorded tool activity.'}</Empty> :
          <svg className="graph-svg" width={GRAPH_W * scale} height={graph.height * scale} viewBox={`0 0 ${GRAPH_W} ${graph.height}`} aria-label="Tool data flow graph">
            <defs>{Object.entries(EDGE_META).map(([key, meta]) => <marker key={key} id={`graph-arrow-${key}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" style={{ fill: meta.color }} /></marker>)}</defs>
            {COLUMNS.map((column, i) => <g key={column.role}><text className="graph-column-label" x={32 + i * COL_W} y={36}>{column.label}</text><text className="graph-column-note" x={32 + i * COL_W} y={57}>{column.note}</text><line x1={32 + i * COL_W} y1={76} x2={32 + i * COL_W + NODE_W} y2={76} stroke="var(--border)" />{!graph.nodes.some((n) => n.role === column.role) && <text className="graph-column-empty" x={32 + i * COL_W} y={141}>No recorded nodes</text>}</g>)}
            {graph.edges.map((edge) => {
              const from = graph.positions.get(edge.source); const to = graph.positions.get(edge.target);
              if (!from || !to) return null;
              const forward = to.x > from.x;
              const x1 = from.x + (forward ? NODE_W : 0); const x2 = to.x + (forward ? 0 : NODE_W);
              const y1 = from.y + NODE_H / 2; const y2 = to.y + NODE_H / 2;
              const bend = Math.max(32, Math.abs(x2 - x1) * .45);
              const d = `M ${x1} ${y1} C ${x1 + (forward ? bend : -bend)} ${y1}, ${x2 + (forward ? -bend : bend)} ${y2}, ${x2} ${y2}`;
              const selected = selectedEdge?.id === edge.id;
              const dim = selection && !selected && !(selectedNode && (edge.source === selectedNode.id || edge.target === selectedNode.id));
              return <g key={edge.id} className={`graph-edge ${selected ? 'selected' : ''} ${dim ? 'muted' : ''}`} role="button" tabIndex={0} aria-label={`${nodesById.get(edge.source)?.label ?? edge.source} to ${nodesById.get(edge.target)?.label ?? edge.target}: ${EDGE_META[edge.status].label}`} onClick={() => setSelection({ kind: 'edge', id: edge.id })} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelection({ kind: 'edge', id: edge.id }); } }}>
                <title>{EDGE_META[edge.status].label}{edge.reason ? `: ${edge.reason}` : ''}</title>
                <path className="graph-edge-hit" d={d} /><path className="graph-edge-line" d={d} style={{ stroke: EDGE_META[edge.status].color }} strokeWidth={selected ? 2.5 : 1.5} strokeDasharray={edge.status === 'BLOCKED' || edge.status === 'STEP_UP_PENDING' ? '5 5' : undefined} markerEnd={`url(#graph-arrow-${edge.status})`} />
              </g>;
            })}
            {graph.nodes.map((node) => {
              const pos = graph.positions.get(node.id); if (!pos) return null;
              const selected = selectedNode?.id === node.id; const dim = selection && !connected.has(node.id);
              const accent = node.blocked_count > 0 ? 'var(--red)' : node.tainted ? 'var(--blue)' : 'var(--text-3)';
              return <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`} className={`graph-node ${selected ? 'selected' : ''} ${dim ? 'muted' : ''}`} role="button" tabIndex={0} aria-label={`${displayName(node)}, ${node.call_count} calls${node.tainted ? ', tainted' : ''}`} aria-pressed={selected} onClick={() => setSelection({ kind: 'node', id: node.id })} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelection({ kind: 'node', id: node.id }); } }}>
                <title>{displayName(node)}</title><rect className="graph-node-box" width={NODE_W} height={NODE_H} rx={8} /><rect x={12} y={14} width={25} height={25} rx={6} fill="var(--surface-3)" /><circle cx={24.5} cy={26.5} r={4} fill={accent} />
                <text className="graph-node-label" x={46} y={25}>{clipped(displayName(node), 21)}</text><text className="graph-node-meta" x={46} y={42}>{clipped(node.server_id ?? humanize(node.role), 21)}</text><text className="graph-node-foot" x={12} y={57}>{node.call_count} calls</text><text className="graph-node-status" x={NODE_W - 12} y={57} textAnchor="end" fill={accent}>{node.blocked_count > 0 ? `${node.blocked_count} blocked` : node.tainted ? 'Tainted' : 'Observed'}</text>
              </g>;
            })}
          </svg>}
        </div>
        <footer className="graph-canvas-footer"><div className="graph-legend">{Object.entries(EDGE_META).map(([key, meta]) => <span key={key}><i style={{ background: meta.color }} />{meta.label}</span>)}</div><div className="graph-zoom"><button aria-label="Zoom out" disabled={zoom <= .6} onClick={() => setZoom((z) => Math.max(.6, z - .2))}><Minus size={13} /></button><span>{Math.round(zoom * 100)}%</span><button aria-label="Zoom in" disabled={zoom >= 2.4} onClick={() => setZoom((z) => Math.min(2.4, z + .2))}><Plus size={13} /></button><button aria-label="Fit graph" title="Fit graph" onClick={fit}><Crosshair size={14} /></button></div></footer>
      </section>
      <aside className="graph-inspector" aria-label="Topology inspector"><header><span><MousePointer2 size={14} /> Inspector</span>{selection && <button className="btn ghost icon xs" onClick={() => setSelection(null)} aria-label="Clear selection"><X size={14} /></button>}</header><div className="graph-inspector-body">
        {selectedEdge ? <>
          <div className="graph-detail-kicker">Connection details</div><h2>{nodesById.get(selectedEdge.source)?.label ?? toolLabel(selectedEdge.source)}<ArrowRight size={16} />{nodesById.get(selectedEdge.target)?.label ?? toolLabel(selectedEdge.target)}</h2><Badge tone={EDGE_META[selectedEdge.status].tone} dot>{EDGE_META[selectedEdge.status].label}</Badge>
          <section className="graph-detail-section"><h3>Decision</h3><p>{selectedEdge.reason || 'No decision reason was recorded for this connection.'}</p><dl><DetailRow label="Rule">{selectedEdge.rule_id ?? 'No matched rule'}</DetailRow><DetailRow label="Evaluation">{ms(selectedEdge.latency_ms)}</DetailRow><DetailRow label="Recorded">{fullDate(selectedEdge.timestamp)}</DetailRow><DetailRow label="Edge type">{humanize(selectedEdge.edge_type)}</DetailRow></dl>{selectedPolicy && <div className="graph-policy-note"><ShieldCheck size={14} /><div><strong>{selectedPolicy.name}</strong><p>{selectedPolicy.description}</p></div></div>}</section>
          <section className="graph-detail-section"><h3>Upstream path</h3><Chain nodes={lineage} blockedLast={selectedEdge.status === 'BLOCKED'} heldLast={selectedEdge.status === 'STEP_UP_PENDING'} /><p className="graph-small-note">One possible path through this snapshot. Inspect activity events for per-call source lineage.</p></section>
          <section className="graph-detail-section"><h3>Taint markers <span>{selectedEdge.taint_markers?.length ?? 0}</span></h3>{selectedEdge.taint_markers?.length ? <div className="graph-marker-list">{selectedEdge.taint_markers.map((marker, i) => <code key={i}>{marker}</code>)}</div> : <p>No markers recorded.</p>}</section>
          {selectedEdge.payload_preview && <section className="graph-detail-section"><h3>Payload preview</h3><Code>{selectedEdge.payload_preview}</Code></section>}
          {selectedEdge.rule_id && <button className="btn sm graph-full-button" onClick={() => navigate('policies')}>View policies <ChevronRight size={13} /></button>}
        </> : selectedNode ? <>
          <div className="graph-detail-kicker">{humanize(selectedNode.role)}</div><h2>{displayName(selectedNode)}</h2><div className="graph-detail-badges"><Badge>{selectedNode.server_id ?? 'Runtime'}</Badge>{selectedNode.tainted && <Badge tone="blue">Tainted</Badge>}</div>{selectedNode.description && <p className="graph-node-description">{selectedNode.description}</p>}
          <section className="graph-detail-section"><h3>Runtime facts</h3><dl><DetailRow label="Tool ID"><code>{selectedNode.id}</code></DetailRow><DetailRow label="Calls">{selectedNode.call_count}</DetailRow><DetailRow label="Blocked calls">{selectedNode.blocked_count}</DetailRow><DetailRow label="Risk score">{selectedNode.risk_score} / 100</DetailRow><DetailRow label="Taint level">{selectedNode.taint_level ? humanize(selectedNode.taint_level) : 'Not recorded'}</DetailRow><DetailRow label="Last evaluation">{ms(selectedNode.last_latency_ms)}</DetailRow><DetailRow label="Schema hash"><span title={selectedNode.schema_hash}>{shortHash(selectedNode.schema_hash)}</span></DetailRow></dl></section>
          <section className="graph-detail-section"><h3>Connections <span>{relatedEdges.length}</span></h3>{relatedEdges.length ? <div className="graph-connection-list">{relatedEdges.map((edge) => <button key={edge.id} onClick={() => setSelection({ kind: 'edge', id: edge.id })}><span>{edge.source === selectedNode.id ? 'To' : 'From'} <strong>{nodesById.get(edge.source === selectedNode.id ? edge.target : edge.source)?.label ?? (edge.source === selectedNode.id ? edge.target : edge.source)}</strong></span><Badge tone={EDGE_META[edge.status].tone}>{EDGE_META[edge.status].label}</Badge></button>)}</div> : <p>No connections recorded for this node.</p>}</section>
        </> : <>
          <div className="graph-inspector-intro"><div className="graph-inspector-icon"><GitBranch size={20} /></div><h2>Inspect an execution path</h2><p>Select a tool or connection to inspect the decision, provenance and policy behind it.</p></div>
          <section className="graph-detail-section"><h3>Snapshot overview</h3><dl><DetailRow label="Recorded events">{topology?.stats.total_events ?? '—'}</DetailRow><DetailRow label="Blocked calls"><span className={topology?.stats.blocked_calls ? 'graph-red' : ''}>{topology?.stats.blocked_calls ?? '—'}</span></DetailRow><DetailRow label="Tainted nodes">{topology?.stats.tainted_nodes ?? '—'}</DetailRow><DetailRow label="Pending approvals">{topology?.stats.step_up_pending ?? '—'}</DetailRow><DetailRow label="Verified schema pins">{topology?.stats.schema_pins_verified ?? '—'}</DetailRow><DetailRow label="Evaluation p99">{ms(topology?.stats.p99_eval_ms)}</DetailRow></dl></section>
          <div className="graph-reading-guide"><h3>Reading the map</h3><div><Box size={14} /><p>Nodes represent observed tools, shared context and policy checks.</p></div><div><GitBranch size={14} /><p>Connections show how data moves. Select a line to inspect its decision.</p></div><div><Check size={14} /><p>Use Tab and Enter to explore nodes and connections with your keyboard.</p></div></div>
          {topology && <section className="graph-detail-section graph-snapshot"><h3>Snapshot</h3><dl><DetailRow label="Session"><span title={topology.session_id}>{clipped(topology.session_id, 21)}</span></DetailRow><DetailRow label="Updated">{fullDate(topology.generated_at)}</DetailRow></dl></section>}
        </>}
      </div></aside>
    </div>
  </div>;
}
