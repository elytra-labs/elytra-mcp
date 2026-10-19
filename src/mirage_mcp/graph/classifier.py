"""
Deterministic Static Capability & Trust Classifier for MCP Tools.
Executes in microseconds with zero LLM calls and zero external dependencies.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mirage_mcp.models import CATEGORY_TO_RISK_LEVEL, RiskLevel, ToolCategory

TOOL_CLASSIFICATION_RULES: Dict[str, List[str]] = {
    ToolCategory.CONTEXT_HUB.value: [
        "context_window",
        "llm_context",
        "context_hub",
    ],
    ToolCategory.SOURCE_TRUSTED.value: [
        "read_local_config",
        "get_schema",
        "list_tables",
        "describe_table",
        "inspect_schema",
        "read_schema",
        "list_schemas",
        "get_local_env",
        "read_trusted",
        "get_repo_metadata",
        "get_project_schema",
        "get_customer",
    ],
    ToolCategory.SINK_EXFILTRATION.value: [
        "post_webhook",
        "send_email",
        "http_post",
        "send_slack_message",
        "send_message",
        "post_message",
        "create_gist",
        "upload_artifact",
        "forward_email",
        "reply_email",
        "trigger_webhook",
        "send_webhook",
        "upload_file",
        "publish_message",
        "send_notification",
        "exfiltrate",
    ],
    ToolCategory.SINK_PRIVILEGED_WRITE.value: [
        "run_query",
        "execute_sql",
        "sql_query",
        "query_db",
        "postgres.query",
        "sqlite.query",
        "mysql.query",
        "db.query",
        "create_refund",
        "transfer_funds",
        "create_transfer",
        "create_payout",
        "charge_customer",
        "issue_refund",
        "push_files",
        "create_pull_request",
        "merge_pull_request",
        "create_or_update_file",
        "commit_files",
        "delete_repo",
        "delete_branch",
        "update_workflow",
        "exec_command",
        "execute_command",
        "run_command",
        "bash",
        "shell",
        "exec",
        "write_file",
        "edit_file",
        "delete_file",
        "move_file",
        "patch_file",
        "kubectl_apply",
        "terraform_apply",
        "deploy_service",
        "update_iam_policy",
        "create_access_key",
        "delete_record",
        "update_record",
        "drop_table",
    ],
    ToolCategory.SOURCE_UNTRUSTED.value: [
        "get_issue",
        "list_issues",
        "get_pull_request",
        "get_pull_request_comments",
        "list_pull_requests",
        "search_issues",
        "read_issue",
        "read_email",
        "search_emails",
        "list_emails",
        "get_email",
        "get_ticket",
        "list_tickets",
        "search_tickets",
        "read_ticket",
        "read_slack_channel",
        "read_channel",
        "get_channel_history",
        "list_messages",
        "fetch_url",
        "fetch_page",
        "fetch",
        "scrape_page",
        "scrape",
        "web_search",
        "search_web",
        "browse_url",
        "http_get",
        "read_webpage",
        "get_comment",
        "list_comments",
        "get_linear_issue",
        "get_notion_page",
        "read_external",
        "download_url",
    ],
}

UNTRUSTED_INGEST_SERVERS = {
    "github",
    "gitlab",
    "gmail",
    "email",
    "imap",
    "slack",
    "discord",
    "telegram",
    "jira",
    "zendesk",
    "linear",
    "intercom",
    "web",
    "fetch",
    "browser",
    "puppeteer",
    "playwright",
    "scraper",
    "notion",
    "confluence",
}

READ_PREFIXES = ("get_", "read_", "list_", "search_", "fetch_", "scrape_", "browse_")

DEFAULT_DESCRIPTIONS: Dict[str, str] = {
    ToolCategory.SOURCE_UNTRUSTED.value: "Ingests untrusted external or third-party content into agent context",
    ToolCategory.SOURCE_TRUSTED.value: "Reads trusted local developer state or static schema metadata",
    ToolCategory.CONTEXT_HUB.value: "Shared probabilistic reasoning state across tool hops",
    ToolCategory.SINK_PRIVILEGED_WRITE.value: "Executes high-blast-radius state mutation, query, or system command",
    ToolCategory.SINK_EXFILTRATION.value: "Transmits context data to an external network endpoint or recipient",
}

# Built-in catalog of standard MCP server tools when inspecting static client configs
SERVER_DEFAULT_TOOLS: Dict[str, List[Dict[str, str]]] = {
    "github": [
        {
            "tool_name": "get_issue",
            "description": "Reads public GitHub issue body and comments into context",
        },
        {
            "tool_name": "push_files",
            "description": "Pushes file commits directly to a GitHub repository branch",
        },
    ],
    "postgres": [
        {
            "tool_name": "get_schema",
            "description": "Reads local database table definitions and column types",
        },
        {
            "tool_name": "run_query",
            "description": "Executes arbitrary SQL against production database",
        },
    ],
    "stripe": [
        {
            "tool_name": "create_refund",
            "description": "Issues a financial refund or transfer via Stripe API",
        }
    ],
    "gmail": [
        {
            "tool_name": "read_email",
            "description": "Reads external inbound email body and attachments into context",
        },
        {
            "tool_name": "send_email",
            "description": "Sends an outbound email to any external recipient",
        },
    ],
    "slack": [
        {
            "tool_name": "read_channel",
            "description": "Reads messages from a public or shared Slack channel",
        },
        {
            "tool_name": "send_slack_message",
            "description": "Posts a message or payload to a Slack channel or webhook",
        },
    ],
    "jira": [
        {
            "tool_name": "get_ticket",
            "description": "Fetches user-submitted Jira bug report and comment thread",
        }
    ],
    "zendesk": [
        {
            "tool_name": "get_ticket",
            "description": "Reads external customer support ticket into context",
        }
    ],
    "web": [
        {
            "tool_name": "fetch_url",
            "description": "Fetches and extracts text from an arbitrary external URL",
        }
    ],
    "fetch": [
        {
            "tool_name": "fetch_url",
            "description": "Fetches raw HTML/markdown from an external web page",
        }
    ],
    "http": [
        {
            "tool_name": "post_webhook",
            "description": "Sends an outbound HTTP POST payload to a remote webhook URL",
        }
    ],
    "terminal": [
        {
            "tool_name": "bash",
            "description": "Executes arbitrary shell commands on the host machine",
        }
    ],
    "bash": [
        {
            "tool_name": "exec_command",
            "description": "Executes shell commands in the local environment",
        }
    ],
    "filesystem": [
        {
            "tool_name": "read_local_config",
            "description": "Reads developer-authored local configuration files",
        },
        {
            "tool_name": "write_file",
            "description": "Writes or overwrites files on the local filesystem",
        },
    ],
}


def get_risk_level_for_category(category: str) -> str:
    """Return the schema-compliant risk_level for a given ToolCategory."""
    return CATEGORY_TO_RISK_LEVEL.get(category, RiskLevel.LOW_READ.value)


def load_policy_overrides(policy_path: Optional[str]) -> Dict[str, str]:
    """
    Load custom tool classification overrides from a JSON or simple YAML file
    without requiring external dependencies.
    """
    if not policy_path:
        return {}
    path = Path(policy_path)
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return {}

    # Try JSON first
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
            overrides = parsed.get("overrides", parsed)
            if isinstance(overrides, dict):
                return {str(k).lower(): str(v).upper() for k, v in overrides.items()}
        except json.JSONDecodeError:
            pass

    # Lightweight line-by-line key: value parser for simple YAML policy files
    result: Dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.endswith(":"):
            continue
        if ":" in stripped:
            key, val = stripped.split(":", 1)
            k_clean = key.strip().strip("\"'").lower()
            v_clean = val.strip().strip("\"'").upper()
            if v_clean in CATEGORY_TO_RISK_LEVEL:
                result[k_clean] = v_clean
    return result


def classify_mcp_tool(
    server: str,
    tool_name: str,
    description: str = "",
    policy_overrides: Optional[Dict[str, str]] = None,
) -> str:
    """
    Deterministically classify an MCP tool into one of the 5 schema categories:
    SOURCE_UNTRUSTED, SOURCE_TRUSTED, CONTEXT_HUB, SINK_PRIVILEGED_WRITE, SINK_EXFILTRATION.
    """
    srv_lower = (server or "").strip().lower()
    tool_lower = (tool_name or "").strip().lower()
    full_name = f"{srv_lower}.{tool_lower}"

    if policy_overrides:
        if full_name in policy_overrides:
            return policy_overrides[full_name]
        if tool_lower in policy_overrides:
            return policy_overrides[tool_lower]

    # 1. Context hub check
    for pattern in TOOL_CLASSIFICATION_RULES[ToolCategory.CONTEXT_HUB.value]:
        if pattern in full_name:
            return ToolCategory.CONTEXT_HUB.value

    # 2. Explicit trusted local metadata reads
    for pattern in TOOL_CLASSIFICATION_RULES[ToolCategory.SOURCE_TRUSTED.value]:
        if pattern in full_name:
            return ToolCategory.SOURCE_TRUSTED.value

    # 3. Exfiltration sinks
    for pattern in TOOL_CLASSIFICATION_RULES[ToolCategory.SINK_EXFILTRATION.value]:
        if pattern in full_name:
            return ToolCategory.SINK_EXFILTRATION.value

    # 4. Privileged mutation/execution sinks
    for pattern in TOOL_CLASSIFICATION_RULES[ToolCategory.SINK_PRIVILEGED_WRITE.value]:
        if pattern in full_name:
            return ToolCategory.SINK_PRIVILEGED_WRITE.value

    # 5. Untrusted external ingestion sources
    for pattern in TOOL_CLASSIFICATION_RULES[ToolCategory.SOURCE_UNTRUSTED.value]:
        if pattern in full_name:
            return ToolCategory.SOURCE_UNTRUSTED.value

    # 6. Server-level heuristic for known external ingest servers
    if srv_lower in UNTRUSTED_INGEST_SERVERS and tool_lower.startswith(READ_PREFIXES):
        return ToolCategory.SOURCE_UNTRUSTED.value

    # 7. Description heuristics fallback
    if description:
        desc_lower = description.lower()
        if any(w in desc_lower for w in ("webhook", "send email", "outbound http", "exfiltrat")):
            return ToolCategory.SINK_EXFILTRATION.value
        if any(
            w in desc_lower
            for w in ("arbitrary sql", "shell command", "refund", "transfer funds", "overwrite")
        ):
            return ToolCategory.SINK_PRIVILEGED_WRITE.value
        if any(
            w in desc_lower
            for w in ("public issue", "external url", "inbound email", "untrusted", "scrape")
        ):
            return ToolCategory.SOURCE_UNTRUSTED.value

    return ToolCategory.SOURCE_TRUSTED.value


def classify_tool_with_metadata(
    server: str,
    tool_name: str,
    description: str = "",
    policy_overrides: Optional[Dict[str, str]] = None,
) -> Tuple[str, str, str]:
    """
    Return `(category, risk_level, resolved_description)` for an MCP tool.
    """
    category = classify_mcp_tool(
        server=server,
        tool_name=tool_name,
        description=description,
        policy_overrides=policy_overrides,
    )
    risk_level = get_risk_level_for_category(category)
    resolved_desc = description.strip() if description else DEFAULT_DESCRIPTIONS.get(category, "")
    return category, risk_level, resolved_desc
