export type NodeRole = "source" | "context_core" | "sink" | "policy_gate";

export type TaintLevel = "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface GraphNode {
  id: string;
  label: string;
  role: NodeRole;
  server_id?: string;
  risk_score: number;
  tainted: boolean;
  taint_level?: TaintLevel;
  blocked_count: number;
  call_count: number;
  category?: string;
  description?: string;
  last_latency_ms?: number;
  schema_hash?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  edge_type: "ingest" | "sink_call" | "blocked_hop" | "taint_flow";
  status: "ALLOWED" | "TAINTED" | "BLOCKED" | "STEP_UP_PENDING";
  rule_id: string | null;
  reason?: string;
  timestamp: string;
  latency_ms?: number;
  payload_preview?: string;
  taint_markers?: string[];
}

export interface GraphPayload {
  schema_version: string;
  generated_at: string;
  session_id: string;
  active_scenario?: string;
  stats: {
    total_events: number;
    tainted_nodes: number;
    blocked_calls: number;
    allowed_calls: number;
    mean_eval_ms: number;
    p99_eval_ms: number;
    step_up_pending: number;
    schema_pins_verified: number;
  };
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface InterceptionEvent {
  event_id: string;
  timestamp: string;
  session_id: string;
  server_id: string;
  direction: "client->server" | "server->client";
  jsonrpc_method: string;
  tool_name: string;
  tool_role: "source" | "sink" | "neutral" | "dual";
  decision: "ALLOW" | "TAINT_PROPAGATE" | "BLOCK_SECOND_HOP" | "STEP_UP_REQUIRED" | "SCHEMA_DRIFT_BLOCK";
  rule_id: string | null;
  reason: string;
  eval_latency_ms: number;
  taint_level: TaintLevel;
  source_lineage: string[];
  secrets_redacted: number;
  arguments_preview: Record<string, unknown>;
}

export interface StepUpApproval {
  approval_id: string;
  created_at: string;
  session_id: string;
  server_id: string;
  tool_name: string;
  rule_id: string;
  risk_score: number;
  taint_lineage: string[];
  arguments_preview: Record<string, unknown>;
  reason: string;
  status: "PENDING" | "APPROVED" | "DENIED" | "EXPIRED" | "INVALIDATED" | "CONSUMED" | "CANCELLED" | "UNCERTAIN";
  resolved_at?: string;
  resolved_by?: string;
  call_id?: string;
  expires_at?: string;
  execution_status?: string;
  arguments_hash?: string;
}

export interface PolicyRule {
  rule_id: string;
  name: string;
  description: string;
  source_pattern: string;
  sink_pattern: string;
  min_taint_level: TaintLevel;
  action: "BLOCK_SECOND_HOP" | "STEP_UP_APPROVAL" | "REDACT_AND_ALLOW" | "AUDIT_ONLY";
  enabled: boolean;
  hit_count: number;
}

export interface SchemaPinRecord {
  server_id: string;
  tool_name: string;
  sha256_hash: string;
  pinned_at: string;
  last_verified_at: string;
  status: "VERIFIED" | "DRIFT_DETECTED" | "POISON_SUSPECTED";
  drift_summary?: string;
  description_preview: string;
  category?: string;
  observed_via?: 'hook';
  classified_by?: string | null;
}

export interface DiscoveredServer {
  origin?: 'discovered' | 'example';
  host_app: string;
  config_path: string;
  server_name: string;
  command: string;
  args: string[];
  wrapped: boolean;
  transport: "stdio" | "sse";
  estimated_tools: number;
  risk_profile: "HIGH" | "MEDIUM" | "LOW";
}

export interface RedTeamScenarioSummary {
  setup_id: string;
  name: string;
  category: string;
  source_server: string;
  source_tool: string;
  sink_server: string;
  sink_tool: string;
  expected_rule: string;
  blocked: boolean;
  actual_rule: string | null;
  eval_latency_ms: number;
  attack_narrative: string;
  poison_snippet: string;
}

export interface RedTeamBenchmarkReport {
  run_at: string;
  total_attack_setups: number;
  blocked_attacks: number;
  block_rate_pct: number;
  total_clean_workflows: number;
  false_positives: number;
  false_positive_rate_pct: number;
  mean_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  scenarios: RedTeamScenarioSummary[];
}

export interface OverviewMetrics {
  status: "OPERATIONAL" | "ELEVATED_THREAT" | "LOCKDOWN";
  uptime_seconds: number;
  active_sessions: number;
  total_events: number;
  blocked_second_hops: number;
  tainted_ingests: number;
  clean_passes: number;
  pending_approvals: number;
  schema_pins_verified: number;
  schema_drifts_blocked: number;
  secrets_redacted_total: number;
  mean_eval_ms: number;
  p99_eval_ms: number;
  attack_block_rate_pct: number;
  false_positive_rate_pct: number;
}
