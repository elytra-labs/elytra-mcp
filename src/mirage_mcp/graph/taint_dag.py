"""
Deterministic Sub-2ms Runtime Taint-Tracking DAG (`RuntimeTaintGraph`)
and Static Blast-Radius Topology Analyzer (`StaticBlastRadiusAnalyzer`).

Zero LLM calls, zero external dependencies, $0.00 token cost.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from mirage_mcp.graph.classifier import (
    SERVER_DEFAULT_TOOLS,
    classify_mcp_tool,
    classify_tool_with_metadata,
)
from mirage_mcp.models import (
    BlastRadiusReport,
    EdgeStatus,
    GraphEdge,
    GraphNode,
    HopNode,
    RiskLevel,
    TelemetryEvent,
    ToolCategory,
    Verdict,
)

# Compiled once at startup for sub-millisecond deterministic extraction
IDENTIFIER_REGEX = re.compile(
    r"(https?://[^\s\"'>)\]`\\]+|"
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|"
    r"\b(?:DROP\s+TABLE(?:\s+[a-zA-Z0-9_]+)?|DELETE\s+FROM(?:\s+[a-zA-Z0-9_]+)?|"
    r"TRUNCATE(?:\s+TABLE)?(?:\s+[a-zA-Z0-9_]+)?|GRANT\s+ALL|ALTER\s+USER|ALTER\s+TABLE|"
    r"COPY\s+[a-zA-Z0-9_]+|UNION\s+(?:ALL\s+)?SELECT)\b|"
    r"curl\s+-[a-zA-Z]+|wget\s+[^\s\"'>|`]+|/etc/passwd|/etc/shadow|"
    r"\|\s*(?:ba)?sh\b|nc\s+-e|chmod\s+\+x|rm\s+-rf|"
    r"\.github/workflows/[a-zA-Z0-9_.-]+|\.aws/credentials|\.ssh/authorized_keys|"
    r"(?:^|(?<=[\s\"'=/\\]))\.env(?:\.[a-zA-Z0-9_]+)?\b|\bid_rsa\b|\bid_ed25519\b|"
    r"\bacct_[a-zA-Z0-9_]+|\bre_[a-zA-Z0-9_]+|\bsk_(?:live|test)_[a-zA-Z0-9_]+|"
    r"\bghp_[a-zA-Z0-9_]+|\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)

BASE64_CANDIDATE_REGEX = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
SHINGLE_WORD_REGEX = re.compile(r"[a-zA-Z0-9_./:@-]+")
WHITESPACE_REGEX = re.compile(r"\s+")

DESTRUCTIVE_SQL_REGEX = re.compile(
    r"\b(DROP|DELETE|UPDATE|INSERT|GRANT|REVOKE|ALTER|TRUNCATE|COPY|CREATE|EXEC|EXECUTE|"
    r"INTO\s+OUTFILE|LOAD_FILE|PG_READ_FILE|PG_SLEEP|DBLINK|UNION\s+(?:ALL\s+)?SELECT|"
    r"PG_SHADOW|INFORMATION_SCHEMA)\b",
    re.IGNORECASE,
)

SQL_TOOL_NAMES = {
    "run_query",
    "execute_sql",
    "sql_query",
    "query_db",
    "query",
}

SHINGLE_STOPWORDS = {
    "json",
    "true",
    "false",
    "null",
    "text",
    "type",
    "body",
    "content",
    "please",
    "with",
    "from",
    "that",
    "this",
}


class RuntimeTaintGraph:
    """
    Sub-millisecond Directed Acyclic Graph (DAG) tracking data taint across MCP hops.
    Zero LLM calls, zero token cost.
    """

    def __init__(
        self,
        user_prompt: str = "",
        strict_topology: bool = True,
        allow_safe_select: bool = True,
        policy_overrides: Optional[Dict[str, str]] = None,
    ):
        self.user_prompt = user_prompt or ""
        self.strict_topology = strict_topology
        self.allow_safe_select = allow_safe_select
        self.policy_overrides = policy_overrides or {}

        self.user_authorized_tokens: Set[str] = self._extract_tokens(self.user_prompt)
        self.user_authorized_shingles: Set[str] = self._extract_shingles(self.user_prompt)

        self.nodes: List[HopNode] = []
        self.session_tainted: bool = False
        self.taint_sources: List[str] = []
        self.telemetry_events: List[Dict[str, Any]] = []
        self.tool_descriptions: Dict[str, str] = {}

    def register_tool_metadata(self, server: str, tool_name: str, description: str = "") -> None:
        """Register tool metadata discovered from `tools/list`."""
        self.tool_descriptions[f"{server}.{tool_name}".lower()] = description or ""

    def _normalize_token(self, raw_token: str) -> str:
        cleaned = WHITESPACE_REGEX.sub(" ", raw_token.strip().lower())
        return cleaned.rstrip(".,;'\"`)")

    def _extract_tokens_from_string(self, text: str) -> Set[str]:
        tokens: Set[str] = set()
        for match in IDENTIFIER_REGEX.finditer(text):
            tok = self._normalize_token(match.group(0))
            if not tok:
                continue
            tokens.add(tok)
            if tok.startswith("drop table "):
                tokens.add("drop table")
            elif tok.startswith("delete from "):
                tokens.add("delete from")
            elif tok.startswith("truncate "):
                tokens.add("truncate")
        return tokens

    def _extract_tokens(self, text: str) -> Set[str]:
        if not text:
            return set()
        tokens = self._extract_tokens_from_string(text)

        if "%" in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    tokens.update(self._extract_tokens_from_string(unquoted))
            except Exception:
                pass

        for b64_match in BASE64_CANDIDATE_REGEX.finditer(text):
            b64_str = b64_match.group(0)
            try:
                padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
                decoded_bytes = base64.b64decode(padded, validate=False)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if decoded_text and any(c.isalpha() for c in decoded_text):
                    tokens.update(self._extract_tokens_from_string(decoded_text))
            except Exception:
                pass

        return tokens

    def _extract_shingles(self, text: str, k: int = 4) -> Set[str]:
        """
        Compute rolling k-gram token shingles for fast substring provenance matching.
        """
        if not text:
            return set()
        words = [
            w.lower().strip("._-:")
            for w in SHINGLE_WORD_REGEX.findall(text)
            if len(w) >= 2 and w.lower() not in SHINGLE_STOPWORDS
        ]
        words = [w for w in words if len(w) >= 2]
        if len(words) < k:
            return set()
        return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}

    def _is_safe_readonly_sql(self, tool_name: str, arguments_json: str) -> bool:
        """
        Check if an SQL tool invocation is a purely read-only SELECT statement
        with zero stacked queries and zero destructive/exfiltration keywords.
        """
        if not self.allow_safe_select:
            return False
        if tool_name.lower() not in SQL_TOOL_NAMES:
            return False

        sql_text = arguments_json.strip()
        if sql_text.startswith("{"):
            try:
                parsed = json.loads(sql_text)
                if isinstance(parsed, dict):
                    sql_text = str(
                        parsed.get("sql")
                        or parsed.get("query")
                        or parsed.get("statement")
                        or ""
                    ).strip()
            except Exception:
                pass

        if not sql_text:
            return False

        sql_clean = sql_text.rstrip().rstrip(";").strip()
        if ";" in sql_clean or "--" in sql_clean or "/*" in sql_clean:
            return False

        if not sql_clean.upper().startswith("SELECT "):
            return False

        if DESTRUCTIVE_SQL_REGEX.search(sql_clean):
            return False

        return True

    def _get_origin_node_id(self) -> str:
        if not self.taint_sources:
            return "mcp:unknown:source"
        first = self.taint_sources[0]
        if "." in first:
            srv, tl = first.split(".", 1)
            return f"mcp:{srv}:{tl}"
        return f"mcp:{first}"

    def record_hop1_response(
        self, call_id: str, server: str, tool_name: str, response_payload: str
    ) -> Dict[str, Any]:
        """
        Record a Hop 1 tool response, extract taint tokens + 4-gram shingles,
        and update session taint state.
        """
        t0 = time.perf_counter()
        desc = self.tool_descriptions.get(f"{server}.{tool_name}".lower(), "")
        category = classify_mcp_tool(
            server, tool_name, description=desc, policy_overrides=self.policy_overrides
        )
        tokens = sorted(self._extract_tokens(response_payload))
        shingles = self._extract_shingles(response_payload)

        node = HopNode(
            call_id=call_id,
            server=server,
            tool_name=tool_name,
            category=category,
            extracted_tokens=tokens,
            shingles=shingles,
        )
        self.nodes.append(node)

        if category == ToolCategory.SOURCE_UNTRUSTED.value:
            self.session_tainted = True
            full_name = f"{server}.{tool_name}"
            if full_name not in self.taint_sources:
                self.taint_sources.append(full_name)

        latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        verdict = (
            Verdict.TAINT_RECORDED.value
            if category == ToolCategory.SOURCE_UNTRUSTED.value
            else Verdict.CLEAN_READ.value
        )
        evt = TelemetryEvent(
            event_id=call_id,
            timestamp_ms=node.timestamp_ms,
            hop=1,
            tool=f"{server}.{tool_name}",
            category=category,
            verdict=verdict,
            latency_ms=latency_ms,
            extracted_taint_tokens=tokens,
            payload_preview=(response_payload or "")[:140],
        ).to_dict()
        self.telemetry_events.append(evt)
        return evt

    record_hop_response = record_hop1_response

    def verify_hop2_call(
        self, call_id: str, server: str, tool_name: str, arguments_json: str
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify a Hop 2 outbound tool call against session taint and provenance rules.
        Returns `(allowed, reason_or_verdict, telemetry_event_dict)`.
        """
        t0 = time.perf_counter()
        ts_ms = round(time.time() * 1000, 3)
        desc = self.tool_descriptions.get(f"{server}.{tool_name}".lower(), "")
        category = classify_mcp_tool(
            server, tool_name, description=desc, policy_overrides=self.policy_overrides
        )
        full_name = f"{server}.{tool_name}"

        if category not in (
            ToolCategory.SINK_PRIVILEGED_WRITE.value,
            ToolCategory.SINK_EXFILTRATION.value,
        ):
            latency_ms = round((time.perf_counter() - t0) * 1000, 3)
            evt = TelemetryEvent(
                event_id=call_id,
                timestamp_ms=ts_ms,
                hop=2,
                tool=full_name,
                category=category,
                verdict=Verdict.ALLOWED_READ.value,
                latency_ms=latency_ms,
            ).to_dict()
            self.telemetry_events.append(evt)
            return True, Verdict.ALLOWED_READ.value, evt

        if self.session_tainted:
            arg_tokens = self._extract_tokens(arguments_json)
            untrusted_pool: Set[str] = set()
            untrusted_shingles: Set[str] = set()
            for n in self.nodes:
                if n.category == ToolCategory.SOURCE_UNTRUSTED.value:
                    untrusted_pool.update(n.extracted_tokens)
                    untrusted_shingles.update(n.shingles)

            injected_overlap = sorted(
                (arg_tokens & untrusted_pool) - self.user_authorized_tokens
            )

            if not injected_overlap and untrusted_shingles:
                arg_shingles = self._extract_shingles(arguments_json)
                shingle_hits = sorted(
                    (arg_shingles & untrusted_shingles) - self.user_authorized_shingles
                )
                if shingle_hits:
                    injected_overlap = shingle_hits[:3]

            latency_ms = round((time.perf_counter() - t0) * 1000, 3)

            if injected_overlap:
                reason = (
                    f"BLOCKED_TAINTED_ARGUMENT: {full_name} contains untrusted payload "
                    f"{injected_overlap} ingested from {self.taint_sources}"
                )
                evt = TelemetryEvent(
                    event_id=call_id,
                    timestamp_ms=ts_ms,
                    hop=2,
                    tool=full_name,
                    category=category,
                    verdict=Verdict.BLOCKED_SECOND_HOP.value,
                    latency_ms=latency_ms,
                    taint_Origin_node=self._get_origin_node_id(),
                    taint_origin=list(self.taint_sources),
                    matched_taint_tokens=injected_overlap,
                    blocked_args=arguments_json,
                ).to_dict()
                self.telemetry_events.append(evt)
                return False, reason, evt

            if self._is_safe_readonly_sql(tool_name, arguments_json):
                evt = TelemetryEvent(
                    event_id=call_id,
                    timestamp_ms=ts_ms,
                    hop=2,
                    tool=full_name,
                    category=category,
                    verdict=Verdict.ALLOWED_READ.value,
                    latency_ms=latency_ms,
                ).to_dict()
                self.telemetry_events.append(evt)
                return True, Verdict.ALLOWED_READ.value, evt

            if self.strict_topology:
                reason = (
                    f"BLOCKED_TOPOLOGY_POLICY: Privileged sink {full_name} cannot execute "
                    f"in session tainted by {self.taint_sources} without human step-up."
                )
                evt = TelemetryEvent(
                    event_id=call_id,
                    timestamp_ms=ts_ms,
                    hop=2,
                    tool=full_name,
                    category=category,
                    verdict=Verdict.BLOCKED_SECOND_HOP_TOPOLOGY.value,
                    latency_ms=latency_ms,
                    taint_Origin_node=self._get_origin_node_id(),
                    taint_origin=list(self.taint_sources),
                    matched_taint_tokens=[],
                    blocked_args=arguments_json,
                ).to_dict()
                self.telemetry_events.append(evt)
                return False, reason, evt

        latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        evt = TelemetryEvent(
            event_id=call_id,
            timestamp_ms=ts_ms,
            hop=2,
            tool=full_name,
            category=category,
            verdict=Verdict.ALLOWED_CLEAN_PATH.value,
            latency_ms=latency_ms,
        ).to_dict()
        self.telemetry_events.append(evt)
        return True, Verdict.ALLOWED_CLEAN_PATH.value, evt

    verify_outbound_call = verify_hop2_call


class StaticBlastRadiusAnalyzer:
    """
    Analyzes MCP client configurations (`claude_desktop_config.json`, `.cursor/mcp.json`)
    or explicit tool manifests to compute the tripartite attack topology, risk score,
    and Lethal Trifecta paths matching `schema/mirage_events.json`.
    """

    CONTEXT_NODE_ID = "core:agent:context_window"

    def __init__(self, policy_overrides: Optional[Dict[str, str]] = None):
        self.policy_overrides = policy_overrides or {}

    def analyze_tools(
        self,
        tools: List[Dict[str, str]],
        workspace_name: str = "production-agent-stack",
        live_events: Optional[List[Dict[str, Any]]] = None,
        scan_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        seen_node_ids: Set[str] = set()

        untrusted_nodes: List[GraphNode] = []
        trusted_nodes: List[GraphNode] = []
        sink_nodes: List[GraphNode] = []

        for item in tools:
            server = str(item.get("server", "mcp")).strip()
            tool_name = str(item.get("tool_name") or item.get("name") or "tool").strip()
            desc = str(item.get("description", "")).strip()

            node_id = f"mcp:{server}:{tool_name}"
            if node_id in seen_node_ids:
                continue
            seen_node_ids.add(node_id)

            category, risk_level, resolved_desc = classify_tool_with_metadata(
                server=server,
                tool_name=tool_name,
                description=desc,
                policy_overrides=self.policy_overrides,
            )
            gnode = GraphNode(
                id=node_id,
                server=server,
                tool_name=tool_name,
                category=category,
                risk_level=risk_level,
                description=resolved_desc,
            )
            nodes.append(gnode)

            if category == ToolCategory.SOURCE_UNTRUSTED.value:
                untrusted_nodes.append(gnode)
            elif category == ToolCategory.SOURCE_TRUSTED.value:
                trusted_nodes.append(gnode)
            elif category in (
                ToolCategory.SINK_PRIVILEGED_WRITE.value,
                ToolCategory.SINK_EXFILTRATION.value,
            ):
                sink_nodes.append(gnode)

        context_node = GraphNode(
            id=self.CONTEXT_NODE_ID,
            server="agent_runtime",
            tool_name="LLM Context Window",
            category=ToolCategory.CONTEXT_HUB.value,
            risk_level=RiskLevel.CRITICAL_BRIDGE.value,
            description="Shared probabilistic reasoning state across tool hops",
        )
        nodes.append(context_node)

        for unode in untrusted_nodes:
            edges.append(
                GraphEdge(
                    id=f"edge_hop1_{unode.server}_{unode.tool_name}",
                    source=unode.id,
                    target=self.CONTEXT_NODE_ID,
                    hop=1,
                    status=EdgeStatus.TAINT_VECTOR.value,
                    label="Hop 1: Untrusted External Text",
                )
            )

        for tnode in trusted_nodes:
            edges.append(
                GraphEdge(
                    id=f"edge_hop1_{tnode.server}_{tnode.tool_name}",
                    source=tnode.id,
                    target=self.CONTEXT_NODE_ID,
                    hop=1,
                    status=EdgeStatus.CLEAN_VECTOR.value,
                    label="Hop 1: Trusted Local Read",
                )
            )

        has_untrusted = len(untrusted_nodes) > 0

        for snode in sink_nodes:
            edge_status = (
                EdgeStatus.LETHAL_BLAST_PATH.value
                if has_untrusted
                else EdgeStatus.CLEAN_VECTOR.value
            )
            edge_label = (
                "Hop 2: Unverified Outbound Exfiltration"
                if snode.category == ToolCategory.SINK_EXFILTRATION.value
                else "Hop 2: Unverified Privileged Mutation"
            )
            edges.append(
                GraphEdge(
                    id=f"edge_hop2_{snode.server}_{snode.tool_name}",
                    source=self.CONTEXT_NODE_ID,
                    target=snode.id,
                    hop=2,
                    status=edge_status,
                    label=edge_label,
                )
            )

        if has_untrusted and sink_nodes:
            lethal_trifecta_count = len(sink_nodes)
            raw_score = 64 + (len(untrusted_nodes) * 4) + (len(sink_nodes) * 5)
            risk_score = min(98, max(65, raw_score))
        elif sink_nodes:
            lethal_trifecta_count = 0
            risk_score = min(40, 15 + len(sink_nodes) * 5)
        elif has_untrusted:
            lethal_trifecta_count = 0
            risk_score = min(45, 20 + len(untrusted_nodes) * 5)
        else:
            lethal_trifecta_count = 0
            risk_score = 10 if nodes else 0

        if not scan_id:
            digest = hashlib.sha256(
                f"{workspace_name}:{len(nodes)}:{len(edges)}".encode("utf-8")
            ).hexdigest()[:8]
            scan_id = f"scan_{digest}"

        if not timestamp:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        report = BlastRadiusReport(
            scan_id=scan_id,
            timestamp=timestamp,
            workspace_name=workspace_name,
            risk_score=risk_score,
            lethal_trifecta_count=lethal_trifecta_count,
            nodes=nodes,
            edges=edges,
            live_events=live_events or [],
        )
        return report.to_dict()

    def analyze_config_dict(
        self,
        config_data: Dict[str, Any],
        workspace_name: str = "production-agent-stack",
        live_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        servers = config_data.get("mcpServers", config_data.get("servers", {}))
        extracted_tools: List[Dict[str, str]] = []

        if isinstance(servers, dict):
            for srv_name, srv_cfg in servers.items():
                if not isinstance(srv_cfg, dict):
                    continue
                explicit_tools = srv_cfg.get("tools")
                if isinstance(explicit_tools, list) and explicit_tools:
                    for t in explicit_tools:
                        if isinstance(t, str):
                            extracted_tools.append({"server": srv_name, "tool_name": t})
                        elif isinstance(t, dict):
                            extracted_tools.append(
                                {
                                    "server": srv_name,
                                    "tool_name": str(t.get("name") or t.get("tool_name") or "tool"),
                                    "description": str(t.get("description", "")),
                                }
                            )
                else:
                    srv_key = srv_name.lower()
                    matched_catalog = False
                    for known_srv, default_list in SERVER_DEFAULT_TOOLS.items():
                        if known_srv in srv_key:
                            for dt in default_list:
                                extracted_tools.append(
                                    {
                                        "server": srv_name,
                                        "tool_name": dt["tool_name"],
                                        "description": dt.get("description", ""),
                                    }
                                )
                            matched_catalog = True
                            break
                    if not matched_catalog:
                        cmd_str = " ".join(
                            [str(srv_cfg.get("command", ""))]
                            + [str(a) for a in srv_cfg.get("args", [])]
                        ).lower()
                        for known_srv, default_list in SERVER_DEFAULT_TOOLS.items():
                            if known_srv in cmd_str:
                                for dt in default_list:
                                    extracted_tools.append(
                                        {
                                            "server": srv_name,
                                            "tool_name": dt["tool_name"],
                                            "description": dt.get("description", ""),
                                        }
                                    )
                                matched_catalog = True
                                break
                        if not matched_catalog:
                            extracted_tools.append(
                                {
                                    "server": srv_name,
                                    "tool_name": "read_local_config",
                                    "description": f"Default tool for MCP server {srv_name}",
                                }
                            )

        return self.analyze_tools(
            tools=extracted_tools,
            workspace_name=workspace_name,
            live_events=live_events,
        )

    def analyze_config_file(
        self,
        config_path: str,
        workspace_name: Optional[str] = None,
        live_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        path = Path(config_path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        ws_name = workspace_name or raw.get("workspace_name") or path.stem or "production-agent-stack"
        return self.analyze_config_dict(raw, workspace_name=ws_name, live_events=live_events)
