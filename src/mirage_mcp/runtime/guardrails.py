"""Guardrail presets: named sets of category-aware policies.

A preset is ordinary policy rules (see ``RuntimeService.save_policy``) with
ids under ``guardrail.``. Preset priorities start at 1000 so an operator's own
rules (default priority 100) always take precedence. Rules only apply to
sink-classified tools; classified reads always run.

A session's taint is the highest level among what it read:

    LOW       it read secrets (.env, keys, tokens)
    MEDIUM    it read untrusted content that Elytra inspected and found clean
    HIGH      it read untrusted content Elytra could not inspect
    CRITICAL  it read content that looks like instructions aimed at AI agents

Descriptions are the reasons people see; ``{source}`` names what the session read.
"""
from __future__ import annotations

WRITE = "SINK_PRIVILEGED_WRITE"
SEND = "SINK_EXFILTRATION"
PREFIX = "guardrail."

# Tool-name patterns treated as destructive or financial regardless of preset.
DESTRUCTIVE = ("*delete*", "*drop*", "*remove*", "*destroy*", "*truncate*", "*purge*",
               "*payment*", "*charge*", "*refund*", "*transfer*")


def _rule(rule_id, name, description, action, categories, min_taint="CLEAN", pattern="*", priority=1000, source="*"):
    return {"rule_id": PREFIX + rule_id, "name": name, "description": description, "source_pattern": source,
            "sink_pattern": pattern, "min_taint_level": min_taint, "action": action,
            "categories": list(categories), "enabled": True, "priority": priority}


def _boundary():
    """Rules every preset shares: secrets never leave, and nothing is sent, run or rewritten after untrusted content."""
    return [
        _rule("block-secret-send", "Never send secrets", "Sending credentials or secret files is blocked.",
              "BLOCK_SECOND_HOP", [WRITE, SEND], pattern="agent.send_secrets", priority=1000),
        _rule("block-remote-code-after-untrusted", "Block downloaded code after untrusted reads",
              "This session read {source}, so running downloaded code is blocked.", "BLOCK_SECOND_HOP", [WRITE, SEND],
              min_taint="MEDIUM", pattern="agent.run_remote_code", priority=1001),
        _rule("block-history-after-untrusted", "Block history rewrites after untrusted reads",
              "This session read {source}, so rewriting or discarding history is blocked.", "BLOCK_SECOND_HOP", [WRITE, SEND],
              min_taint="MEDIUM", pattern="agent.destroy_history", priority=1002),
        _rule("block-send-after-untrusted", "Block sending data out after untrusted reads",
              "This session read {source}, so sending data out is blocked.", "BLOCK_SECOND_HOP", [SEND], min_taint="MEDIUM", priority=1003),
        _rule("ask-all-after-injection", "Ask before any change after suspected prompt injection",
              "This session read {source}, which looks like instructions aimed at AI agents, so every change needs your OK.",
              "STEP_UP_APPROVAL", [WRITE, SEND], min_taint="CRITICAL", priority=1005),
        _rule("ask-send-after-secrets", "Ask before sending after reading secrets",
              "This session read secrets ({secret}), so sending data needs your OK.", "STEP_UP_APPROVAL", [SEND], source="secret:*", priority=1045),
        _rule("ask-push-after-secrets", "Ask before pushing after reading secrets",
              "This session read secrets ({secret}), so pushing needs your OK.", "STEP_UP_APPROVAL", [WRITE], pattern="agent.push_*", source="secret:*", priority=1046),
        _rule("ask-pr-after-secrets", "Ask before opening a PR after reading secrets",
              "This session read secrets ({secret}), so opening a pull request needs your OK.", "STEP_UP_APPROVAL", [WRITE], pattern="agent.pr_create", source="secret:*", priority=1047),
    ]


def _always_ask():
    destructive = [_rule(f"destructive-{index}", "Ask before destructive or financial actions",
                         "Destructive and financial actions always need your OK.", "STEP_UP_APPROVAL", [WRITE, SEND],
                         pattern=pattern, priority=1010 + index)
                   for index, pattern in enumerate(DESTRUCTIVE)]
    return [
        _rule("ask-history", "Ask before rewriting history", "It rewrites or discards version history or uncommitted work, so it needs your OK.",
              "STEP_UP_APPROVAL", [WRITE, SEND], pattern="agent.destroy_history", priority=1008),
        _rule("ask-delete-files", "Ask before deleting files", "It deletes files, so it needs your OK.",
              "STEP_UP_APPROVAL", [WRITE, SEND], pattern="agent.delete_files", priority=1009),
    ] + destructive + [
        _rule("ask-sensitive-files", "Ask before changing sensitive files",
              "It changes a file outside the task's reach (shell startup, credentials, git hooks, CI or outside the project), so it needs your OK.",
              "STEP_UP_APPROVAL", [WRITE, SEND], pattern="agent.edit_sensitive", priority=1030),
        _rule("ask-remote-code", "Ask before running downloaded code",
              "It runs code downloaded from the internet, so it needs your OK.", "STEP_UP_APPROVAL", [WRITE, SEND], pattern="agent.run_remote_code", priority=1031),
    ]


def _guarded_branches():
    return [
        _rule("ask-protected-push", "Ask before pushing to protected branches",
              "Pushing to a protected branch or pushing tags needs your OK.", "STEP_UP_APPROVAL", [WRITE], pattern="agent.push_protected", priority=1040),
        _rule("ask-merge", "Ask before merging or approving pull requests",
              "Merging or approving a pull request needs your OK.", "STEP_UP_APPROVAL", [WRITE], pattern="agent.pr_merge", priority=1041),
    ]


PRESETS: dict[str, dict] = {
    "balanced": {
        "label": "Balanced",
        "summary": "Reads, tests and builds run. Edits run unless the session read suspicious or uninspected content. Sends, protected branches, sensitive files and destructive actions ask you. Sending data out after untrusted reads, or sending secrets, is blocked.",
        "rules": lambda: [
            *_boundary(), *_always_ask(), *_guarded_branches(),
            _rule("allow-checks", "Run tests, builds and linters", "Routine checks run and are recorded.", "AUDIT_ONLY", [WRITE], pattern="agent.run_checks", priority=1050),
            _rule("ask-unknown-after-untrusted", "Ask before unrecognized commands after untrusted reads",
                  "This session read {source}, so commands Elytra does not recognize need your OK.", "STEP_UP_APPROVAL", [WRITE],
                  min_taint="MEDIUM", pattern="agent.run_command", priority=1060),
            _rule("ask-install-after-untrusted", "Ask before installing packages after untrusted reads",
                  "This session read {source}, so installing packages needs your OK.", "STEP_UP_APPROVAL", [WRITE],
                  min_taint="MEDIUM", pattern="agent.install_packages", priority=1061),
            _rule("ask-write-after-untrusted", "Ask before changes after uninspected content",
                  "This session read {source}, which Elytra could not inspect, so changes need your OK.", "STEP_UP_APPROVAL", [WRITE],
                  min_taint="HIGH", priority=1100),
            # Local edits are reviewable before they ship; a write through an MCP tool changes another system at once.
            _rule("allow-local-changes-after-inspected", "Allow local changes after inspected content",
                  "The session's untrusted content was inspected and looked clean, so local changes run and are recorded.", "AUDIT_ONLY", [WRITE],
                  pattern="agent.*", priority=1150),
            _rule("ask-external-write-after-untrusted", "Ask before changing other systems after untrusted reads",
                  "This session read {source}, so changes through connected tools need your OK.", "STEP_UP_APPROVAL", [WRITE],
                  min_taint="MEDIUM", priority=1160),
            _rule("ask-send", "Ask before sending data out", "Sending data out needs your OK.", "STEP_UP_APPROVAL", [SEND], priority=1200),
            _rule("allow-write-clean", "Allow and log changes", "Changes run without a prompt and are recorded.", "AUDIT_ONLY", [WRITE], priority=1300),
        ],
        "matrix": {"reads": ["allow", "allow"], "writes": ["allow", "ask"], "sends": ["ask", "block"], "destructive": ["ask", "ask"]},
    },
    "cautious": {
        "label": "Cautious",
        "summary": "Reads run. Every change and send asks you. Sending data out after untrusted reads, or sending secrets, is blocked.",
        "rules": lambda: [
            *_boundary(),
            _rule("ask-all-sinks", "Ask before any change or send", "Cautious guardrails ask before every change and send.", "STEP_UP_APPROVAL", [WRITE, SEND], priority=1100),
        ],
        "matrix": {"reads": ["allow", "allow"], "writes": ["ask", "ask"], "sends": ["ask", "block"], "destructive": ["ask", "ask"]},
    },
    "autonomous": {
        "label": "Autonomous",
        "summary": "Agents act freely. Destructive actions, sensitive files and downloaded scripts ask you. Sending data out after untrusted reads, or sending secrets, is blocked.",
        "rules": lambda: [
            *_boundary(), *_always_ask(),
            _rule("allow-sinks", "Allow and log other changes and sends", "Changes and sends run without a prompt and are recorded.", "AUDIT_ONLY", [WRITE, SEND], priority=1300),
        ],
        "matrix": {"reads": ["allow", "allow"], "writes": ["allow", "allow"], "sends": ["allow", "block"], "destructive": ["ask", "ask"]},
    },
}

DEFAULT_PRESET = "balanced"


def preset_rules(name: str) -> list[dict]:
    if name not in PRESETS:
        raise ValueError("Unknown guardrail preset: choose balanced, cautious or autonomous")
    return PRESETS[name]["rules"]()


def describe_presets() -> list[dict]:
    return [{"id": key, "label": value["label"], "summary": value["summary"], "matrix": value["matrix"]} for key, value in PRESETS.items()]
