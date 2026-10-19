"""Mirage-MCP Blast-Radius Topology Artifact & Production UI Locator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

REPO_ROOT = Path(__file__).resolve().parents[3]
UI_ROOT = REPO_ROOT / "ui"
UI_DIST_PATH = UI_ROOT / "dist"
BUNDLED_UI_PATH = Path(__file__).resolve().parents[1] / "web"


def get_ui_dist_path() -> Path:
    """Prefer bundled release assets; source development uses ui/dist."""
    return BUNDLED_UI_PATH if (BUNDLED_UI_PATH / "index.html").is_file() else UI_DIST_PATH


def serialize_blast_radius_payload(graph_data: Optional[Dict[str, Any]] = None) -> str:
    """Serialize `blast_radius_graph.json` payload for the Control Plane and 3D WebGL UI."""
    payload = graph_data or {"schema_version": "1.0.0", "nodes": [], "edges": []}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def write_blast_radius_snapshot(
    graph_data: Optional[Dict[str, Any]],
    output_path: Union[str, Path],
) -> Path:
    """Write a canonical blast-radius JSON snapshot consumed by the Control Plane API."""
    target = Path(output_path)
    target.write_text(serialize_blast_radius_payload(graph_data), encoding="utf-8")
    return target


__all__ = [
    "UI_ROOT",
    "UI_DIST_PATH",
    "get_ui_dist_path",
    "serialize_blast_radius_payload",
    "write_blast_radius_snapshot",
]
