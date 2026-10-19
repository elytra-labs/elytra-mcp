"""Guardrail presets: named sets of category-aware policies.

A preset is ordinary policy rules (see ``RuntimeService.save_policy``) with
ids under ``guardrail.``. Preset priorities start at 1000 so an operator's own
rules (default priority 100) always take precedence. Rules only apply to
sink-classified tools; classified reads always run.
"""
from __future__ import annotations

WRITE = "SINK_PRIVILEGED_WRITE"
SEND = "SINK_EXFILTRATION"
PREFIX = "guardrail."

# Tool-name patterns treated as destructive or financial regardless of preset.
DESTRUCTIVE = ("*delete*", "*drop*", "*remove*", "*destroy*", "*truncate*", "*purge*",
               "*payment*", "*charge*", "*refund*", "*transfer*")


def _rule(rule_id, name, description, action, categories, min_taint="CLEAN", pattern="*", priority=1000):
    return {"rule_id": PREFIX + rule_id, "name": name, "description": description, "source_pattern": "*",
            "sink_pattern": pattern, "min_taint_level": min_taint, "action": action,
            "categories": list(categories), "enabled": True, "priority": priority}


def _block_exfiltration():
    return _rule("block-send-after-untrusted", "Block sending data out after untrusted reads",
                 "A run that read untrusted content cannot send data to an external destination.",
                 "BLOCK_SECOND_HOP", [SEND], min_taint="HIGH", priority=1000)


def _destructive(action="STEP_UP_APPROVAL"):
    return [_rule(f"destructive-{index}", "Ask before destructive or financial actions",
                  f"Tools matching {pattern} always need an exact-call decision.", action, [WRITE, SEND],
                  pattern=pattern, priority=1010 + index)
            for index, pattern in enumerate(DESTRUCTIVE)]


PRESETS: dict[str, dict] = {
    "balanced": {
        "label": "Balanced",
        "summary": "Reads run. Writes run and are logged in a clean session. Writes after untrusted reads, sends, and destructive actions ask you. Sending data out after untrusted reads is blocked.",
        "rules": lambda: [
            _block_exfiltration(),
            *_destructive(),
            _rule("ask-write-after-untrusted", "Ask before writes after untrusted reads",
                  "Writes need a decision once the run has read untrusted content.", "STEP_UP_APPROVAL", [WRITE], min_taint="HIGH", priority=1100),
            _rule("ask-send", "Ask before sending data out", "Sends to external destinations need a decision.", "STEP_UP_APPROVAL", [SEND], priority=1200),
            _rule("allow-write-clean", "Allow and log writes in a clean session", "Writes run without a prompt while the run has read no untrusted content.", "AUDIT_ONLY", [WRITE], priority=1300),
        ],
        "matrix": {"reads": ["allow", "allow"], "writes": ["allow", "ask"], "sends": ["ask", "block"], "destructive": ["ask", "ask"]},
    },
    "cautious": {
        "label": "Cautious",
        "summary": "Reads run. Every write and send asks you. Sending data out after untrusted reads is blocked.",
        "rules": lambda: [
            _block_exfiltration(),
            _rule("ask-all-sinks", "Ask before any write or send", "Every write and send needs an exact-call decision.", "STEP_UP_APPROVAL", [WRITE, SEND], priority=1100),
        ],
        "matrix": {"reads": ["allow", "allow"], "writes": ["ask", "ask"], "sends": ["ask", "block"], "destructive": ["ask", "ask"]},
    },
    "autonomous": {
        "label": "Autonomous",
        "summary": "Agents act freely. Only destructive or financial actions ask you, and sending data out after untrusted reads is blocked.",
        "rules": lambda: [
            _block_exfiltration(),
            *_destructive(),
            _rule("allow-sinks", "Allow and log other writes and sends", "Writes and sends run without a prompt and are recorded.", "AUDIT_ONLY", [WRITE, SEND], priority=1300),
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
