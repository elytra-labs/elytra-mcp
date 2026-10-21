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

export interface RuntimeConfig { demo_mode: boolean; authenticated: boolean; version: string; local: boolean; }
const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: 'same-origin',
    signal: init?.signal ?? AbortSignal.timeout(15000),
    headers: { 'Content-Type': 'application/json', 'X-Elytra-Request': '1', ...(init?.headers || {}) },
  });
  if (!res.ok) {
    if (res.status === 401 && path !== '/session') window.dispatchEvent(new Event('elytra-session-expired'));
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(message, res.status);
  }
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}) });

export interface WrapResult {
  server_name?: string;
  wrapped_config: { mcpServers: Record<string, { command: string; args: string[] }> };
  cli_snippet?: string;
}

export interface RedTeamRunResult extends RedTeamBenchmarkReport {
  active_setup_id: string;
  topology: GraphPayload;
  events_recorded: InterceptionEvent[];
}

export type GuardrailDecision = 'allow' | 'ask' | 'block';
export interface GuardrailPreset {
  id: 'balanced' | 'cautious' | 'autonomous';
  label: string;
  summary: string;
  matrix: Record<'reads' | 'writes' | 'sends' | 'destructive', [GuardrailDecision, GuardrailDecision]>;
}
export type LinkStatus = { linked: boolean; origin?: string; connected?: boolean; last_sync?: number | null; last_error?: string | null; decisions_applied?: number };

export interface GuardrailsState {
  preset: GuardrailPreset['id'] | null;
  applied_at: string | null;
  default: GuardrailPreset['id'];
  presets: GuardrailPreset[];
  custom_rules: number;
}
export interface HostRecord {
  host_id: string;
  label: string;
  kind: string;
  approval_window: number;
  created_at: string;
  revoked_at: string | null;
  active_sessions: number;
}
export interface CatalogState {
  servers: Record<string, string>;
  catalog: Record<string, { label: string; note?: string | null; tools: number }>;
}

export const api = {
  config: () => request<RuntimeConfig>('/config'),
  pair: (pairing_code: string) => post<{authenticated: boolean}>('/session', {pairing_code}),
  logout: () => post('/session/logout', {}),
  overview: () => request<OverviewMetrics>('/overview'),
  topology: () => request<GraphPayload>('/topology'),
  events: (limit = 200) =>
    request<{ events: InterceptionEvent[] }>(`/events?limit=${limit}`).then((r) => r.events),
  approvals: () =>
    request<{ approvals: StepUpApproval[] }>('/approvals').then((r) => r.approvals),
  policies: () => request<{ policies: PolicyRule[] }>('/policies').then((r) => r.policies),
  schemaPins: () => request<{ pins: SchemaPinRecord[] }>('/schema-pins').then((r) => r.pins),
  discovery: () =>
    request<{ servers: DiscoveredServer[] }>('/discovery').then((r) => r.servers),
  evaluations: () => request<RedTeamBenchmarkReport>('/redteam/scenarios'),
  guardrails: () => request<GuardrailsState>('/guardrails'),
  linkStatus: () => request<LinkStatus>('/cloud/link'),
  applyGuardrails: (preset: GuardrailPreset['id']) => post<GuardrailsState>('/guardrails', { preset }),
  hosts: () => request<{ hosts: HostRecord[] }>('/hosts').then((r) => r.hosts),
  revokeHost: (host_id: string) => post<HostRecord>(`/hosts/${encodeURIComponent(host_id)}/revoke`, {}),
  catalog: () => request<CatalogState>('/catalog'),

  trustSession: (runId: string) => post<{ run_id: string; cleared: string[] }>(`/sessions/${encodeURIComponent(runId)}/trust`, {}),
  resolveApproval: (id: string, status: 'APPROVED' | 'DENIED') =>
    post<StepUpApproval>(`/approvals/${encodeURIComponent(id)}/resolve`, { status }),
  togglePolicy: (rule_id: string, enabled: boolean) =>
    post<PolicyRule>('/policies', { rule_id, enabled }),
  upsertPolicy: (rule: PolicyRule) => {
    // Hit counts belong to the runtime; editing a rule must not reset them.
    const { hit_count: _hits, ...editable } = rule;
    return post<PolicyRule>('/policies', editable);
  },
  wrapServer: (payload: { server_name: string; command: string; args: string[]; run_id: string }) =>
    post<WrapResult>('/discovery/wrap', payload),
  wrapConfig: (config: unknown) => post<WrapResult>('/discovery/wrap', config),
  runScenario: (setup_id?: string) =>
    post<RedTeamRunResult>('/redteam/run', setup_id ? { setup_id } : {}),
};
