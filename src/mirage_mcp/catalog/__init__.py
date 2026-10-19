"""Suggested classifications for common MCP servers.

The catalog only proposes categories. An operator accepts a server's catalog
entry once (``elytra setup`` or the console); unlisted tools and changed
schemas still return to review. Matching uses the server's launch package,
not its display name, so a renamed or unrelated server is not matched.
"""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

CATEGORIES = {"SOURCE_TRUSTED", "SOURCE_UNTRUSTED", "SINK_PRIVILEGED_WRITE", "SINK_EXFILTRATION"}


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, dict]:
    raw = json.loads(resources.files(__package__).joinpath("known_servers.json").read_text())
    for entry in raw.values():
        if any(category not in CATEGORIES for category in entry["tools"].values()):
            raise ValueError("Catalog contains an unknown category")
    return raw


def _package(token: str) -> str:
    """Strip a version suffix: '@scope/pkg@1.2' -> '@scope/pkg', 'pkg==1.0' -> 'pkg', 'image:tag' -> 'image'."""
    token = token.strip()
    if token.startswith("@"):
        scope, _, rest = token[1:].partition("/")
        return "@" + scope + "/" + rest.split("@", 1)[0] if rest else token
    for separator in ("==", "@"):
        token = token.split(separator, 1)[0]
    if "/" in token and ":" in token.rsplit("/", 1)[-1]:
        token = token.rsplit(":", 1)[0]
    return token


def match_server(command: str, args: list[str] | None = None) -> str | None:
    """Return the catalog id whose package appears in the launch command, if any."""
    tokens = {_package(token) for token in [command, *(args or [])] if isinstance(token, str)}
    tokens |= {token.rsplit("/", 1)[-1] for token in tokens if not token.startswith("@")}
    for catalog_id, entry in load_catalog().items():
        if any(pattern in tokens for pattern in entry["match"]):
            return catalog_id
    return None


def suggested_category(catalog_id: str, tool_name: str) -> str | None:
    entry = load_catalog().get(catalog_id)
    return entry["tools"].get(tool_name) if entry else None
