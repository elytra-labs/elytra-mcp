import React from 'react';
import { ShieldCheck,
  Activity,
  FileLock2,
  Fingerprint,
  FlaskConical,
  LayoutGrid,
  Settings2,
  Search,
  Server,
  UserCheck,
  Waypoints,
} from 'lucide-react';
import { useStore, type Route } from '../lib/store';
import { ms } from '../lib/format';

export function Logo({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 2.5 2 13.5h3.2L8 8.4l2.8 5.1H14L8 2.5Z" fill="currentColor" />
    </svg>
  );
}

interface NavDef {
  route: Route;
  label: string;
  icon: React.ReactNode;
}

const SETUP: NavDef[] = [{ route: 'setup', label: 'Setup & coverage', icon: <Settings2 size={15} /> }];

const MONITOR: NavDef[] = [
  { route: 'overview', label: 'Overview', icon: <LayoutGrid size={15} /> },
  { route: 'graph', label: 'Blast radius', icon: <Waypoints size={15} /> },
  { route: 'activity', label: 'Activity', icon: <Activity size={15} /> },
  { route: 'approvals', label: 'Approvals', icon: <UserCheck size={15} /> },
];

const PROTECT: NavDef[] = [
  { route: 'guardrails', label: 'Guardrails', icon: <ShieldCheck size={15} /> },
  { route: 'policies', label: 'Policies', icon: <FileLock2 size={15} /> },
  { route: 'integrity', label: 'Tool integrity', icon: <Fingerprint size={15} /> },
  { route: 'servers', label: 'Servers', icon: <Server size={15} /> },
];

const TEST: NavDef[] = [{ route: 'evaluations', label: 'Evaluations', icon: <FlaskConical size={15} /> }];

export function Sidebar() {
  const { route, navigate, approvals, pins, overview, live, offline, setOpenCommand } = useStore();

  const pending = approvals.filter((a) => a.status === 'PENDING').length;
  const integrityIssues = pins.filter((p) => p.status !== 'VERIFIED').length;

  const counts: Partial<Record<Route, { n: number; cls: string }>> = {
    approvals: pending ? { n: pending, cls: 'attention' } : undefined,
    integrity: integrityIssues ? { n: integrityIssues, cls: 'danger' } : undefined,
  };

  const renderSection = (label: string, items: NavDef[]) => (
    <nav className="nav-section" aria-label={label}>
      <div className="nav-label">{label}</div>
      {items.map((it) => {
        const c = counts[it.route];
        return (
          <button
            key={it.route}
            type="button"
            className={`nav-item ${route === it.route ? 'active' : ''}`}
            aria-current={route === it.route ? 'page' : undefined}
            onClick={() => navigate(it.route)}
          >
            {it.icon}
            <span>{it.label}</span>
            {c && <span className={`nav-count ${c.cls}`}>{c.n}</span>}
          </button>
        );
      })}
    </nav>
  );

  return (
    <aside className="sidebar">
      <div className="workspace">
        <div className="workspace-mark">
          <Logo />
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="workspace-name">Elytra</div>
          <div className="workspace-env">Local gateway</div>
        </div>
      </div>

      <button type="button" className="search-trigger" onClick={() => setOpenCommand(true)}>
        <Search size={14} />
        <span>Search or jump to…</span>
        <span className="kbd">⌘K</span>
      </button>

      {renderSection('Workspace', SETUP)}
      {renderSection('Monitor', MONITOR)}
      {renderSection('Protect', PROTECT)}
      {renderSection('Test', TEST)}

      <div className="sidebar-footer">
        <div className="health">
          <div className="health-row">
            <span className={`live-dot ${live && !offline ? '' : 'off'}`} />
            <span>{offline ? 'Gateway unreachable' : live ? 'API connected' : 'Connecting…'}</span>
          </div>
          <div className="health-meta">
            <span>Local control plane</span>
            <span className="num">{overview?.total_events ? `p99 ${ms(overview?.p99_eval_ms)}` : 'No recorded calls'}</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
