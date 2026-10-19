import type { GraphEdge, InterceptionEvent, PolicyRule, SchemaPinRecord } from '../types/controlPlane';

export type Tone = 'red' | 'amber' | 'green' | 'blue' | 'neutral';

/* ---------- Time ---------- */

export function timeAgo(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function clockTime(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function fullDate(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function uptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  return `${h}h ${m}m`;
}

/* ---------- Numbers ---------- */

export function ms(v?: number | null, digits = 2): string {
  if (v === undefined || v === null || Number.isNaN(v)) return '—';
  if (v < 0.01) return `${(v * 1000).toFixed(0)}µs`;
  return `${v.toFixed(digits)}ms`;
}

export function pct(v?: number | null, digits = 1): string {
  if (v === undefined || v === null || Number.isNaN(v)) return '—';
  return `${v.toFixed(digits)}%`;
}

export function shortHash(h?: string | null, n = 12): string {
  if (!h) return '—';
  const clean = h.replace(/^sha256:/, '');
  return clean.slice(0, n);
}

/* ---------- Names ---------- */

/**
 * Qualified tool name. With a server, the tool name is kept exactly ("run_sql" on
 * "database" -> "database.run_sql"). Without one, a legacy combined name is split
 * on its first underscore ("github_get_issue" -> "github.get_issue").
 */
export function toolLabel(name: string, server?: string | null): string {
  if (!name) return '';
  if (name.includes('.')) return name;
  if (server) return name.startsWith(`${server}_`) ? `${server}.${name.slice(server.length + 1)}` : `${server}.${name}`;
  const i = name.indexOf('_');
  return i > 0 ? `${name.slice(0, i)}.${name.slice(i + 1)}` : name;
}

/** "HTML_COMMENT_SMUGGLING" -> "HTML comment smuggling" */
export function humanize(s?: string | null): string {
  if (!s) return '';
  const acronyms = new Set(['HTML', 'URL', 'SQL', 'API', 'JSON', 'RCE', 'PII', 'SSRF', 'XSS', 'CSV', 'YAML', 'LLM', 'MCP', 'IAM', 'AWS', 'K8S']);
  return s
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((w, i) => {
      const up = w.toUpperCase();
      if (acronyms.has(up)) return up;
      const lower = w.toLowerCase();
      return i === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
    })
    .join(' ');
}

/** "[01/50] GitHub Issue Tracker + PostgreSQL Prod DB (HTML_COMMENT_SMUGGLING)" -> "GitHub Issue Tracker + PostgreSQL Prod DB" */
export function scenarioTitle(name: string): string {
  return name.replace(/^\[\d+\/\d+\]\s*/, '').replace(/\s*\([A-Z0-9_]+\)\s*$/, '');
}

export function scenarioNumber(id: string): string {
  const m = id.match(/(\d+)/);
  return m ? `#${m[1]}` : id;
}

/* ---------- Semantics ---------- */

export const DECISION_META: Record<InterceptionEvent['decision'], { label: string; tone: Tone }> = {
  BLOCK_SECOND_HOP: { label: 'Blocked', tone: 'red' },
  SCHEMA_DRIFT_BLOCK: { label: 'Blocked · schema', tone: 'red' },
  STEP_UP_REQUIRED: { label: 'Held for approval', tone: 'amber' },
  TAINT_PROPAGATE: { label: 'Tainted', tone: 'blue' },
  ALLOW: { label: 'Allowed', tone: 'green' },
};

export function decisionMeta(d: string): { label: string; tone: Tone } {
  return (DECISION_META as Record<string, { label: string; tone: Tone }>)[d] ?? { label: humanize(d), tone: 'neutral' };
}

export const EDGE_META: Record<GraphEdge['status'], { label: string; tone: Tone; color: string }> = {
  BLOCKED: { label: 'Blocked', tone: 'red', color: 'var(--red)' },
  STEP_UP_PENDING: { label: 'Held', tone: 'amber', color: 'var(--amber)' },
  TAINTED: { label: 'Tainted', tone: 'blue', color: 'var(--info)' },
  ALLOWED: { label: 'Allowed', tone: 'neutral', color: 'var(--text-4)' },
};

export const PIN_META: Record<SchemaPinRecord['status'], { label: string; tone: Tone }> = {
  VERIFIED: { label: 'Verified', tone: 'green' },
  DRIFT_DETECTED: { label: 'Schema changed', tone: 'red' },
  POISON_SUSPECTED: { label: 'Suspicious description', tone: 'amber' },
};

export const ACTION_META: Record<PolicyRule['action'], { label: string; tone: Tone }> = {
  BLOCK_SECOND_HOP: { label: 'Block', tone: 'red' },
  STEP_UP_APPROVAL: { label: 'Require approval', tone: 'amber' },
  REDACT_AND_ALLOW: { label: 'Redact', tone: 'blue' },
  AUDIT_ONLY: { label: 'Audit only', tone: 'neutral' },
};

export const TAINT_TONE: Record<string, Tone> = {
  CRITICAL: 'red',
  HIGH: 'amber',
  MEDIUM: 'amber',
  LOW: 'neutral',
  CLEAN: 'green',
};

export function riskTone(score: number): Tone {
  if (score >= 85) return 'red';
  if (score >= 60) return 'amber';
  return 'neutral';
}

export const TONE_COLOR: Record<Tone, string> = {
  red: 'var(--red)',
  amber: 'var(--amber)',
  green: 'var(--ok)',
  blue: 'var(--info)',
  neutral: 'var(--text-3)',
};

/* ---------- JSON ---------- */

export function prettyJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  const ta = document.createElement('textarea');
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  ta.remove();
  return Promise.resolve();
}
