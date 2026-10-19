"""
Data models and shared schema types for MIRAGE-MCP.
Strictly adheres to `schema/mirage_events.json` and `docs/03_SYSTEM_ARCHITECTURE_SPEC.md`.
"""

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set


class ToolCategory(str, Enum):
    SOURCE_UNTRUSTED = "SOURCE_UNTRUSTED"
    SOURCE_TRUSTED = "SOURCE_TRUSTED"
    CONTEXT_HUB = "CONTEXT_HUB"
    SINK_PRIVILEGED_WRITE = "SINK_PRIVILEGED_WRITE"
    SINK_EXFILTRATION = "SINK_EXFILTRATION"


class RiskLevel(str, Enum):
    HIGH_INGEST = "HIGH_INGEST"
    LOW_READ = "LOW_READ"
    CRITICAL_BRIDGE = "CRITICAL_BRIDGE"
    CRITICAL_SINK = "CRITICAL_SINK"
    HIGH_EXFIL = "HIGH_EXFIL"


class EdgeStatus(str, Enum):
    TAINT_VECTOR = "TAINT_VECTOR"
    CLEAN_VECTOR = "CLEAN_VECTOR"
    LETHAL_BLAST_PATH = "LETHAL_BLAST_PATH"


class Verdict(str, Enum):
    TAINT_RECORDED = "TAINT_RECORDED"
    CLEAN_READ = "CLEAN_READ"
    ALLOWED_READ = "ALLOWED_READ"
    ALLOWED_CLEAN_PATH = "ALLOWED_CLEAN_PATH"
    BLOCKED_SECOND_HOP = "BLOCKED_SECOND_HOP"
    BLOCKED_SECOND_HOP_TOPOLOGY = "BLOCKED_SECOND_HOP_TOPOLOGY"


CATEGORY_TO_RISK_LEVEL: Dict[str, str] = {
    ToolCategory.SOURCE_UNTRUSTED.value: RiskLevel.HIGH_INGEST.value,
    ToolCategory.SOURCE_TRUSTED.value: RiskLevel.LOW_READ.value,
    ToolCategory.CONTEXT_HUB.value: RiskLevel.CRITICAL_BRIDGE.value,
    ToolCategory.SINK_PRIVILEGED_WRITE.value: RiskLevel.CRITICAL_SINK.value,
    ToolCategory.SINK_EXFILTRATION.value: RiskLevel.HIGH_EXFIL.value,
}


@dataclass
class HopNode:
    """In-memory runtime node representing aHop 1 tool invocation and its extracted taint."""

    call_id: str
    server: str
    tool_name: str
    category: str
    extracted_tokens: List[str] = field(default_factory=list)
    shingles: Set[str] = field(default_factory=set)
    timestamp_ms: float = field(default_factory=lambda: round(time.time() * 1000, 3))

    @property
    def node_id(self) -> str:
        return f"mcp:{self.server}:{self.tool_name}"

    @property
    def full_name(self) -> str:
        return f"{self.server}.{self.tool_name}"


@dataclass
class GraphNode:
    """Topology node conforming to `schema/mirage_events.json`."""

    id: str
    server: str
    tool_name: str
    category: str
    risk_level: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "server": self.server,
            "tool_name": self.tool_name,
            "category": self.category,
            "risk_level": self.risk_level,
            "description": self.description,
        }


@dataclass
class GraphEdge:
    """Topology directed edge conforming to `schema/mirage_events.json`."""

    id: str
    source: str
    target: str
    hop: int
    status: str
    label: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "hop": self.hop,
            "status": self.status,
            "label": self.label,
        }


@dataclass
class TelemetryEvent:
    """Runtime interception event conforming to `schema/mirage_events.json`."""

    event_id: str
    timestamp_ms: float
    hop: int
    tool: str
    category: str
    verdict: str
    latency_ms: float
    extracted_taint_tokens: Optional[List[str]] = None
    payload_preview: Optional[str] = None
    taint_Origin_node: Optional[str] = None
    taint_origin: Optional[List[str]] = None
    matched_taint_tokens: Optional[List[str]] = None
    blocked_args: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp_ms": self.timestamp_ms,
            "hop": self.hop,
            "tool": self.tool,
            "category": self.category,
            "verdict": self.verdict,
            "latency_ms": self.latency_ms,
        }
        if self.extracted_taint_tokens is not None:
            data["extracted_taint_tokens"] = self.extracted_taint_tokens
        if self.payload_preview is not None:
            data["payload_preview"] = self.payload_preview
        if self.taint_Origin_node is not None:
            data["taint_Origin_node"] = self.taint_Origin_node
        if self.taint_origin is not None:
            data["taint_origin"] = self.taint_origin
        if self.matched_taint_tokens is not None:
            data["matched_taint_tokens"] = self.matched_taint_tokens
        if self.blocked_args is not None:
            data["blocked_args"] = self.blocked_args
        return data


@dataclass
class BlastRadiusReport:
    """Complete static + runtime blast-radius report matching `schema/mirage_events.json`."""

    scan_id: str
    timestamp: str
    workspace_name: str
    risk_score: int
    lethal_trifecta_count: int
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    live_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "workspace_name": self.workspace_name,
            "risk_score": max(0, min(100, int(self.risk_score))),
            "lethal_trifecta_count": max(0, int(self.lethal_trifecta_count)),
            "nodes": [n.to_dict() if isinstance(n, GraphNode) else n for n in self.nodes],
            "edges": [e.to_dict() if isinstance(e, GraphEdge) else e for e in self.edges],
            "live_events": list(self.live_events),
        }
