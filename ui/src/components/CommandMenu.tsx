import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ShieldCheck,
  Activity,
  ArrowRight,
  CornerDownLeft,
  FileLock2,
  Fingerprint,
  FlaskConical,
  LayoutGrid,
  Settings2,
  Play,
  RefreshCw,
  Server,
  UserCheck,
  Waypoints,
} from 'lucide-react';
import { useStore, type Route } from '../lib/store';
import { scenarioNumber, scenarioTitle } from '../lib/format';
import { useDialogFocus } from '../lib/useDialogFocus';

interface Item {
  id: string;
  group: string;
  label: string;
  hint?: string;
  icon: React.ReactNode;
  run: () => void;
  keywords?: string;
}

export function CommandMenu() {
  const { openCommand, setOpenCommand, navigate, replay, evaluations, refresh } = useStore();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  const close = () => setOpenCommand(false);
  useDialogFocus(openCommand, dialogRef, close);

  const items = useMemo<Item[]>(() => {
    const go = (r: Route) => () => {
      navigate(r);
      close();
    };
    const pages: Item[] = [
      { id: 'p-setup', group: 'Go to', label: 'Setup & coverage', icon: <Settings2 size={15} />, run: go('setup'), keywords: 'onboarding run tools classify connect' },
      { id: 'p-overview', group: 'Go to', label: 'Overview', icon: <LayoutGrid size={15} />, run: go('overview') },
      { id: 'p-graph', group: 'Go to', label: 'Blast radius', icon: <Waypoints size={15} />, run: go('graph'), keywords: 'graph topology flow' },
      { id: 'p-activity', group: 'Go to', label: 'Activity', icon: <Activity size={15} />, run: go('activity'), keywords: 'events wiretap log json-rpc' },
      { id: 'p-approvals', group: 'Go to', label: 'Approvals', icon: <UserCheck size={15} />, run: go('approvals'), keywords: 'step-up human review' },
      { id: 'p-guardrails', group: 'Go to', label: 'Guardrails', icon: <ShieldCheck size={15} />, run: go('guardrails'), keywords: 'preset balanced cautious autonomous hosts claude cursor' },
      { id: 'p-policies', group: 'Go to', label: 'Policies', icon: <FileLock2 size={15} />, run: go('policies'), keywords: 'rules taint' },
      { id: 'p-integrity', group: 'Go to', label: 'Tool integrity', icon: <Fingerprint size={15} />, run: go('integrity'), keywords: 'schema pins hash rug pull' },
      { id: 'p-servers', group: 'Go to', label: 'Servers', icon: <Server size={15} />, run: go('servers'), keywords: 'discovery wrap claude cursor' },
      { id: 'p-evals', group: 'Go to', label: 'Evaluations', icon: <FlaskConical size={15} />, run: go('evaluations'), keywords: 'red team benchmark attacks' },
    ];
    const actions: Item[] = [
      {
        id: 'a-suite',
        group: 'Actions',
        label: 'Run fixture checks',
        hint: 'Synthetic checks',
        icon: <Play size={15} />,
        run: () => {
          close();
          navigate('evaluations');
          replay();
        },
      },
      {
        id: 'a-refresh',
        group: 'Actions',
        label: 'Refresh data',
        icon: <RefreshCw size={15} />,
        run: () => {
          close();
          refresh();
        },
      },
    ];
    const scenarios: Item[] = (evaluations?.scenarios ?? []).map((s) => ({
      id: `s-${s.setup_id}`,
      group: 'Evaluate fixture',
      label: scenarioTitle(s.name),
      hint: scenarioNumber(s.setup_id),
      icon: <ArrowRight size={15} />,
      keywords: `${s.category} ${s.source_server} ${s.sink_server} ${s.setup_id}`,
      run: () => {
        close();
        navigate('evaluations');
        replay(s.setup_id);
      },
    }));
    return [...pages, ...actions, ...scenarios];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evaluations, navigate, replay, refresh]);

  const filtered = useMemo(() => {
    const term = q.trim().toLowerCase();
    if (!term) return items.filter((i) => i.group !== 'Evaluate fixture').concat(items.filter((i) => i.group === 'Evaluate fixture').slice(0, 6));
    return items.filter((i) => `${i.label} ${i.group} ${i.keywords ?? ''} ${i.hint ?? ''}`.toLowerCase().includes(term)).slice(0, 40);
  }, [items, q]);

  useEffect(() => {
    if (openCommand) {
      setQ('');
      setIdx(0);
      window.setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [openCommand]);

  useEffect(() => setIdx(0), [q]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${idx}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [idx]);

  if (!openCommand) return null;

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setIdx((i) => Math.max(0, Math.min(filtered.length - 1, i + 1)));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setIdx((i) => Math.max(0, i - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      filtered[idx]?.run();
    } else if (e.key === 'Escape') {
      close();
    }
  };

  let lastGroup = '';
  return (
    <div className="cmd-overlay" onMouseDown={close}>
      <div ref={dialogRef} className="cmd" role="dialog" aria-modal="true" aria-label="Search pages and commands" tabIndex={-1} onMouseDown={(e) => e.stopPropagation()} onKeyDown={onKey}>
        <input
          ref={inputRef}
          className="cmd-input"
          placeholder="Type a command or search…"
          aria-label="Search pages and commands"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <div className="cmd-list" ref={listRef}>
          {filtered.length === 0 && <div className="empty">No results for “{q}”</div>}
          {filtered.map((it, i) => {
            const header = it.group !== lastGroup ? it.group : null;
            lastGroup = it.group;
            return (
              <React.Fragment key={it.id}>
                {header && <div className="cmd-group">{header}</div>}
                <button
                  type="button"
                  data-idx={i}
                  className={`cmd-item ${i === idx ? 'on' : ''}`}
                  onMouseMove={() => setIdx(i)}
                  onClick={it.run}
                >
                  {it.icon}
                  <span className="truncate">{it.label}</span>
                  {it.hint && <span className="cmd-hint">{it.hint}</span>}
                </button>
              </React.Fragment>
            );
          })}
        </div>
        <div className="cmd-footer">
          <span>
            <span className="kbd">↑</span>
            <span className="kbd">↓</span> navigate
          </span>
          <span>
            <span className="kbd">
              <CornerDownLeft size={10} />
            </span>{' '}
            select
          </span>
          <span>
            <span className="kbd">esc</span> close
          </span>
        </div>
      </div>
    </div>
  );
}
