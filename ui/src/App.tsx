import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ArrowUpRight, Check, ChevronRight, Menu, RefreshCw, X } from 'lucide-react';
import { StoreProvider, useStore, type Route } from './lib/store';
import { Sidebar, Logo } from './components/Sidebar';
import { CommandMenu } from './components/CommandMenu';
import { Dot, SkeletonRows } from './components/ui';
import { OverviewView, ActivityView } from './views/MonitorViews';
import { GraphView } from './views/GraphView';
import { ApprovalsView, PoliciesView, IntegrityView } from './views/GovernanceViews';
import { ServersView, EvaluationsView } from './views/SetupViews';
import { OnboardingView } from './views/OnboardingView';
import { GuardrailsView } from './views/GuardrailsView';
import './styles/onboarding.css';

const TITLES: Record<Route, string> = {
  setup: 'Setup', overview: 'Overview', graph: 'Blast radius', activity: 'Activity', approvals: 'Approvals',
  guardrails: 'Guardrails', policies: 'Policies', integrity: 'Tool integrity', servers: 'Servers', evaluations: 'Evaluations',
};

function Console() {
  const { route, loaded, offline, live, refresh, toasts, setOpenCommand, config } = useStore();
  const [mobileNav, setMobileNav] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const main = useRef<HTMLElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault(); setOpenCommand((v) => !v);
      }
      if (e.key === 'Escape') setMobileNav(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [setOpenCommand]);
  useEffect(() => {
    document.title = `${TITLES[route]} · Elytra`;
    setMobileNav(false); main.current?.scrollTo(0, 0);
  }, [route]);
  const screens = {
    setup: <OnboardingView />, overview: <OverviewView />, graph: <GraphView />, activity: <ActivityView />,
    approvals: <ApprovalsView />, guardrails: <GuardrailsView />, policies: <PoliciesView />, integrity: <IntegrityView />,
    servers: <ServersView />, evaluations: <EvaluationsView />,
  };
  return (
    <div className={`app ${mobileNav ? 'nav-open' : ''}`}>
      <a className="skip-link" href="#main" onClick={(e) => { e.preventDefault(); main.current?.focus(); }}>Skip to content</a>
      {mobileNav && <button className="nav-backdrop" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
      <Sidebar />
      <div className="content-shell">
        <header className="topbar">
          <button className="btn ghost icon mobile-toggle" aria-label={mobileNav ? 'Close navigation' : 'Open navigation'} onClick={() => setMobileNav((v) => !v)}>{mobileNav ? <X size={17} /> : <Menu size={17} />}</button>
          <span className="subtle">Local workspace</span><ChevronRight size={12} className="subtle" /><span>{TITLES[route]}</span>
          <span className="spacer" />
          <span className="connection-label"><Dot tone={live && !offline ? 'green' : 'neutral'} />{offline ? 'Offline' : live ? 'Live updates' : 'Reconnecting'}</span>
          <button className="btn ghost icon sm" aria-label="Refresh data" disabled={refreshing} onClick={async () => { setRefreshing(true); try { await refresh(); } finally { setRefreshing(false); } }}><RefreshCw size={14} className={refreshing ? 'spinning' : ''} /></button>
          <a className="btn ghost sm repo-link" href="https://github.com/elytra-labs/elytra-mcp" target="_blank" rel="noreferrer">Repository <ArrowUpRight size={13} /></a>
        </header>
        {config?.demo_mode && <div className="demo-strip"><span className="preview-label">DEMO WORKSPACE</span><span>Illustrative data. No customer tool execution.</span></div>}
        <main id="main" ref={main} tabIndex={-1} className={`main ${route === 'graph' ? 'flush' : ''}`}>
          {offline && <div className="offline-banner" role="alert">Gateway unreachable. Displaying the last loaded data. <button className="btn xs" onClick={() => void refresh()}>Retry connection</button></div>}
          {!loaded ? <div className="page"><SkeletonRows rows={10} /></div> : screens[route]}
        </main>
      </div>
      <CommandMenu />
      <div className="toasts" role="status" aria-live="polite">{toasts.map((t) => <div className="toast" key={t.id}>{t.tone === 'green' ? <Check size={15} color="var(--green)" /> : <Dot tone={t.tone} />}{t.title}</div>)}</div>
    </div>
  );
}
function PairingScreen() {
  const { config, authenticate, refresh } = useStore();
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function pair(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try { await authenticate(code.trim()); setCode(''); }
    catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }
  return <main className="pairing-page"><div className="pairing-panel"><a className="pairing-brand" href="/"><Logo size={22} />elytra</a><h1>{config ? 'Connect to your local runtime' : 'Looking for your runtime'}</h1><p>{config ? 'Run elytra connect --open to connect this browser automatically, or elytra connect --code to print a code and enter it below. Codes expire after use.' : 'The console needs a running Elytra service at this address. Start it locally and open the address printed by the CLI.'}</p>{config ? <form onSubmit={(event) => void pair(event)}><label className="field"><span className="field-label">Pairing code</span><input className="input mono" autoComplete="off" required autoFocus value={code} onChange={(event) => setCode(event.target.value)} placeholder="Code from elytra connect --code" /></label>{error && <div role="alert" className="setup-error">{error}</div>}<button type="submit" className="btn primary" disabled={busy || !code.trim()}>{busy ? 'Connecting…' : 'Connect runtime'}<ChevronRight size={14} /></button></form> : <div className="pairing-retry"><p>Run <code>elytra up</code> in your terminal.</p><button className="btn" onClick={() => void refresh()}><RefreshCw size={14} />Retry connection</button></div>}<div className="pairing-links"><a href="/docs">Installation guide</a><a href="/security">Security & data</a><a href="/">Back to home</a></div></div></main>;
}
function ConsoleBoundary() {
  const { config } = useStore();
  return config?.authenticated ? <Console /> : <PairingScreen />;
}
export function App() { return <StoreProvider><ConsoleBoundary /></StoreProvider>; }
