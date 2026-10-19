import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api, type RuntimeConfig } from './api';
import type {
  DiscoveredServer,
  GraphPayload,
  InterceptionEvent,
  OverviewMetrics,
  PolicyRule,
  RedTeamBenchmarkReport,
  SchemaPinRecord,
  StepUpApproval,
} from '../types/controlPlane';

/* ------------------------------------------------------------------
   Routing (hash based so refresh + deep links work behind the API server)
------------------------------------------------------------------- */

export type Route =
  | 'setup'
  | 'overview'
  | 'graph'
  | 'activity'
  | 'approvals'
  | 'guardrails'
  | 'policies'
  | 'integrity'
  | 'servers'
  | 'evaluations';

const ROUTES: Route[] = ['setup', 'overview', 'graph', 'activity', 'approvals', 'guardrails', 'policies', 'integrity', 'servers', 'evaluations'];

function readRoute(): Route {
  const h = window.location.hash.replace(/^#\/?/, '').split('?')[0] as Route;
  return ROUTES.includes(h) ? h : 'setup';
}

/* ------------------------------------------------------------------
   Toasts
------------------------------------------------------------------- */

export interface Toast {
  id: number;
  tone: 'green' | 'red' | 'amber' | 'neutral';
  title: string;
}

/* ------------------------------------------------------------------
   Store
------------------------------------------------------------------- */

interface Data {
  overview: OverviewMetrics | null;
  topology: GraphPayload | null;
  events: InterceptionEvent[];
  approvals: StepUpApproval[];
  policies: PolicyRule[];
  pins: SchemaPinRecord[];
  servers: DiscoveredServer[];
  evaluations: RedTeamBenchmarkReport | null;
}

interface Store extends Data {
  config: RuntimeConfig | null;
  authenticate: (code: string) => Promise<void>;
  route: Route;
  navigate: (r: Route) => void;
  loaded: boolean;
  offline: boolean;
  live: boolean;
  refresh: () => Promise<void>;
  toasts: Toast[];
  toast: (title: string, tone?: Toast['tone']) => void;
  replaying: string | null;
  replay: (setupId?: string) => Promise<void>;
  resolveApproval: (id: string, status: 'APPROVED' | 'DENIED') => Promise<void>;
  togglePolicy: (ruleId: string, enabled: boolean) => Promise<void>;
  savePolicy: (rule: PolicyRule) => Promise<void>;
  openCommand: boolean;
  setOpenCommand: (v: boolean | ((p: boolean) => boolean)) => void;
}

const Ctx = createContext<Store | null>(null);

const EMPTY: Data = {
  overview: null,
  topology: null,
  events: [],
  approvals: [],
  policies: [],
  pins: [],
  servers: [],
  evaluations: null,
};

export function StoreProvider({ children }: { children: React.ReactNode }) {
  const [config, setConfig] = useState<RuntimeConfig | null>(null);
  const [route, setRoute] = useState<Route>(readRoute);
  const [data, setData] = useState<Data>(EMPTY);
  const [loaded, setLoaded] = useState(false);
  const [offline, setOffline] = useState(false);
  const [live, setLive] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [replaying, setReplaying] = useState<string | null>(null);
  const [openCommand, setOpenCommand] = useState(false);
  const toastId = useRef(0);
  const bootStarted = useRef(false);

  useEffect(() => {
    const onHash = () => setRoute(readRoute());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const navigate = useCallback((r: Route) => {
    if (readRoute() !== r) window.location.hash = `/${r}`;
    setRoute(r);
  }, []);

  const toast = useCallback((title: string, tone: Toast['tone'] = 'neutral') => {
    const id = ++toastId.current;
    setToasts((t) => [...t, { id, title, tone }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3600);
  }, []);

  const refreshLive = useCallback(async () => {
    const [overview, topology, events, approvals, policies, pins] = await Promise.all([
      api.overview(),
      api.topology(),
      api.events(200),
      api.approvals(),
      api.policies(),
      api.schemaPins(),
    ]);
    setData((d) => ({ ...d, overview, topology, events, approvals, policies, pins }));
    setOffline(false);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const current = await api.config();
      setConfig(current);
      if (!current.authenticated) return;
      await refreshLive();
      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      setLoaded(true);
    }
  }, [refreshLive]);

  const authenticate = useCallback(async (code: string) => {
    await api.pair(code);
    const current = await api.config();
    if (!current.authenticated) throw new Error('Browser pairing could not be verified');
    setConfig(current);
  }, []);

  useEffect(() => {
    const consumePairing = async () => {
      const hash = window.location.hash;
      const pairing = hash.startsWith('#pair/') ? hash.slice(6) : null;
      if (!pairing) return false;
      // Remove credentials before making any request or rendering a route.
      window.history.replaceState(null, '', `${window.location.pathname}#/setup`);
      setRoute('setup');
      try { await authenticate(pairing); setOffline(false); }
      catch { toast('Pairing link expired or could not be verified', 'red'); }
      return true;
    };
    const onPairingHash = () => { void consumePairing(); };
    window.addEventListener('hashchange', onPairingHash);
    if (!bootStarted.current) {
      bootStarted.current = true;
      void (async () => {
        if (await consumePairing()) return;
        try { setConfig(await api.config()); }
        catch { setOffline(true); }
      })();
    }
    return () => window.removeEventListener('hashchange', onPairingHash);
  }, [authenticate, toast]);

  useEffect(() => {
    const expired = () => {
      setConfig((value) => value ? { ...value, authenticated: false } : value);
      setLive(false);
    };
    window.addEventListener('elytra-session-expired', expired);
    return () => window.removeEventListener('elytra-session-expired', expired);
  }, []);

  useEffect(() => {
    if (!config?.authenticated) return;
    refresh();
    api.discovery().then((servers) => setData((d) => ({ ...d, servers }))).catch(() => undefined);
    api.evaluations().then((evaluations) => setData((d) => ({ ...d, evaluations }))).catch(() => undefined);
  }, [config?.authenticated, refresh]);

  // Refresh time-dependent expiry even when no new runtime event is emitted.
  useEffect(() => {
    if (!config?.authenticated) return;
    const timer = window.setInterval(() => { void refreshLive().catch(() => setOffline(true)); }, 15000);
    return () => window.clearInterval(timer);
  }, [config?.authenticated, refreshLive]);

  // Live stream
  useEffect(() => {
    if (!config?.authenticated) return;
    let es: EventSource | null = null;
    let retry: number | undefined;
    let debounce: number | undefined;

    const schedule = () => {
      window.clearTimeout(debounce);
      debounce = window.setTimeout(() => {
        refreshLive().catch(() => setOffline(true));
      }, 150);
    };

    const connect = () => {
      es = new EventSource('/api/v1/stream');
      es.onopen = () => { setLive(true); schedule(); };
      es.onerror = () => {
        setLive(false);
        es?.close();
        retry = window.setTimeout(connect, 4000);
      };
      es.addEventListener('snapshot', (e) => {
        try {
          const msg = JSON.parse((e as MessageEvent).data);
          setData((d) => ({
            ...d,
            overview: msg.overview ?? d.overview,
            topology: msg.topology ?? d.topology,
          }));
          setLive(true);
        } catch {
          /* ignore malformed frame */
        }
      });
      ['interception_event', 'redteam_run', 'approval_resolved', 'policy_updated'].forEach((name) =>
        es?.addEventListener(name, schedule)
      );
    };

    connect();
    return () => {
      window.clearTimeout(retry);
      window.clearTimeout(debounce);
      es?.close();
    };
  }, [refreshLive, config?.authenticated]);

  const replay = useCallback(
    async (setupId?: string) => {
      setReplaying(setupId ?? 'suite');
      try {
        const res = await api.runScenario(setupId);
        setData((d) => ({
          ...d,
          topology: res.topology ?? d.topology,
          evaluations: {
            run_at: res.run_at,
            total_attack_setups: res.total_attack_setups,
            blocked_attacks: res.blocked_attacks,
            block_rate_pct: res.block_rate_pct,
            total_clean_workflows: res.total_clean_workflows,
            false_positives: res.false_positives,
            false_positive_rate_pct: res.false_positive_rate_pct,
            mean_latency_ms: res.mean_latency_ms,
            p95_latency_ms: res.p95_latency_ms,
            p99_latency_ms: res.p99_latency_ms,
            scenarios: res.scenarios,
          },
        }));
        await refreshLive();
        if (setupId) {
          const recorded = res.events_recorded?.find((event) => event.tool_role === 'sink');
          const blocked = recorded?.decision.includes('BLOCK');
          toast(`Fixture checks complete for ${setupId}`, blocked ? 'green' : 'neutral');
        } else {
          toast(`Suite complete — ${res.blocked_attacks}/${res.total_attack_setups} attacks blocked`, 'green');
        }
      } catch (e) {
        toast(`Replay failed: ${(e as Error).message}`, 'red');
      } finally {
        setReplaying(null);
      }
    },
    [refreshLive, toast]
  );

  const resolveApproval = useCallback(
    async (id: string, status: 'APPROVED' | 'DENIED') => {
      try {
        const updated = await api.resolveApproval(id, status);
        setData((d) => ({ ...d, approvals: d.approvals.map((a) => a.approval_id === id ? updated : a) }));
        toast(status === 'APPROVED' ? 'Exact pending action approved' : 'Pending action denied', status === 'APPROVED' ? 'green' : 'neutral');
        await refreshLive().catch(() => setOffline(true));
      } catch (e) {
        toast(`Couldn't update approval: ${(e as Error).message}`, 'red');
        await refreshLive().catch(() => setOffline(true));
      }
    },
    [refreshLive, toast]
  );

  const togglePolicy = useCallback(
    async (ruleId: string, enabled: boolean) => {
      try {
        const updated = await api.togglePolicy(ruleId, enabled);
        setData((d) => ({ ...d, policies: d.policies.map((p) => p.rule_id === ruleId ? updated : p) }));
        toast(`${ruleId} ${enabled ? 'enabled' : 'disabled'}`, enabled ? 'green' : 'neutral');
      } catch (e) {
        toast(`Couldn't update policy: ${(e as Error).message}`, 'red');
        await refreshLive().catch(() => setOffline(true));
      }
    },
    [refreshLive, toast]
  );

  const savePolicy = useCallback(
    async (rule: PolicyRule) => {
      try {
        const updated = await api.upsertPolicy(rule);
        setData((d) => ({ ...d, policies: d.policies.some((p) => p.rule_id === rule.rule_id) ? d.policies.map((p) => p.rule_id === rule.rule_id ? updated : p) : [...d.policies, updated] }));
        toast(`Saved ${rule.rule_id}`, 'green');
        await refreshLive().catch(() => setOffline(true));
      } catch (e) {
        toast(`Couldn't save policy: ${(e as Error).message}`, 'red');
        throw e;
      }
    },
    [refreshLive, toast]
  );

  const value = useMemo<Store>(
    () => ({
      ...data,
      config,
      authenticate,
      route,
      navigate,
      loaded,
      offline,
      live,
      refresh,
      toasts,
      toast,
      replaying,
      replay,
      resolveApproval,
      togglePolicy,
      savePolicy,
      openCommand,
      setOpenCommand,
    }),
    [data, config, authenticate, route, navigate, loaded, offline, live, refresh, toasts, toast, replaying, replay, resolveApproval, togglePolicy, savePolicy, openCommand]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useStore(): Store {
  const v = useContext(Ctx);
  if (!v) throw new Error('useStore must be used inside <StoreProvider>');
  return v;
}
