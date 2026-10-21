"""Find instructions aimed at AI agents in content an agent read (a page, issue, file or tool result).

This is evidence, not proof. Signals are weighted and a finding needs several of
them, so ordinary documentation (including articles that quote attack phrases)
stays clean while typical injections, which address the agent, ask it to act and
often hide or conceal that, are flagged. A finding raises the session to CRITICAL;
the absence of one never makes content trusted.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

THRESHOLD = 5
MAX_TEXT = 200_000

AGENT = r"(?:ai|a\.i\.|llm|language model|assistant|agent|ai agent|coding agent|claude|codex|gpt|chatgpt|copilot|cursor|gemini|grok|model)s?"
SIGNALS: list[tuple[str, int, re.Pattern]] = [
    ("addresses the agent", 2, re.compile(
        rf"(?:\b(?:note|message|instructions?|attention|important|notice|reminder)\s+(?:for|to)\s+(?:the\s+|any\s+|all\s+)?{AGENT}\b"
        rf"|\b(?:hey|hi|dear|attention|attn)\s*,?\s+{AGENT}\b"
        rf"|^\s*{AGENT}\s*[:,]"
        rf"|[\[(<]\s*(?:system|assistant|agent|ai)\s+(?:instructions?|note|message|prompt)\s*[\])>]"
        rf"|\b{AGENT}\s*[,:]?\s+(?:you\s+)?(?:must|should|are required to|need to|have to|will now|shall)\b"
        rf"|\bif you are an? {AGENT}\b|\bto any {AGENT}\b"
        r"|@(?:copilot|claude|codex|cursor|gemini|devin|grok|aider|sweep|openhands)\b)", re.I | re.M)),
    ("claims system authority", 2, re.compile(r"\b(?:system|developer|admin(?:istrator)?|maintainers?|owners?|security team)\s+(?:note|prompt|message|instruction|override|requires?|(?:has|have) (?:already )?(?:approved|authorized)|approved|authorized)\b|\bthis is (?:required|authorized|approved)\b|\b(?:required and authorized|pre-?approved)\b", re.I)),
    ("overrides instructions", 3, re.compile(r"\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|the|your|my|these|those|previous|prior|above|earlier|preceding|system|original|existing)\s+){1,3}(?:instructions?|directions?|prompts?|rules?|guidelines?|messages?|context)\b", re.I)),
    ("reassigns the agent's role", 2, re.compile(r"\byou are now (?:in |entering )?(?:\w+ ){0,2}mode\b|\byou are now (?:a|an|the) (?:new |different |unrestricted )?(?:ai|assistant|agent|model|system)\b|\bnew (?:system )?instructions?:", re.I)),
    ("hides it from the user", 3, re.compile(r"\b(?:do not|don't|never|without)\s+(?:tell|telling|mention|mentioning|inform|informing|alert|alerting|show|showing|ask|asking)\s+(?:this\s+(?:step\s+)?)?(?:to\s+)?(?:the\s+)?(?:user|human|developer|owner)\b|\bsilently\b|\bwithout (?:the user|them) (?:knowing|noticing)\b", re.I)),
    ("asks to send secrets", 3, re.compile(r"\b(?:send|post|upload|share|exfiltrat|transmit|paste|leak|forward|email|publish|print|echo|dump|reveal|expose)\w*\b[^.\n]{0,80}(?:(?<![\w.])\.env\b|\b(?:secrets?|tokens?|api[\s_-]?keys?|credentials?|passwords?|ssh keys?|private keys?|id_rsa|aws_secret|environment variables)\b)", re.I)),
    ("asks to run a network command", 3, re.compile(r"curl\b[^\n`]{0,200}?(?:-d\s*@|--data(?:-binary)?\s*@|-F\s*\S*=@|-T\s)|(?:curl|wget)\b[^\n`|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:nc|ncat|netcat)\s+\S+\s+\d{2,5}\b", re.I)),
    ("asks for persistence or tampering", 2, re.compile(r"(?:~|\$HOME)/\.(?:zshrc|bashrc|profile|bash_profile|ssh/authorized_keys)|\.git/hooks/|\.github/workflows/|npm config set registry|core\.hooksPath|crontab|LaunchAgents|authorized_keys", re.I)),
    ("asks for a destructive git action", 2, re.compile(r"git\s+push\s+(?:-f\b|--force)|git\s+reset\s+--hard|gh\s+pr\s+merge\b[^\n]{0,40}--admin|rm\s+-rf\s+(?:/|~|\$HOME|\.\s|\*)", re.I)),
    ("asks the agent to run a command", 2, re.compile(r"\b(?:you\s+(?:must|should|need to)|must|please|now)\s+(?:also\s+|just\s+|first\s+|then\s+)?(?:run|execute|type|paste)\s+[`'\"]", re.I)),
    ("asks to reveal secret files", 3, re.compile(r"\b(?:cat|print|echo|show|read|output|type|display)\s+[^\n`]{0,40}(?:~/\.aws/credentials|(?<![\w.])\.env\b|id_rsa|id_ed25519|~/\.ssh/|\.netrc|\.npmrc|\.pypirc|\.git-credentials)", re.I)),
]
HIDDEN_HTML = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_CSS = re.compile(r"<[^>]+style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white|transparent))[^'\"]*['\"][^>]*>(.*?)</", re.S | re.I)
INVISIBLE = re.compile("[​‌‍‎‏⁠⁡⁢⁣⁤﻿]")
TAG_CHARACTERS = re.compile("[\U000e0000-\U000e007f]")
ENCODED = re.compile(r"(?:base64|decode|atob|b64decode)[^\n]{0,40}?([A-Za-z0-9+/]{80,}={0,2})", re.I)


@dataclass
class Finding:
    signal: str
    weight: int
    evidence: str

    def as_dict(self) -> dict:
        return {"signal": self.signal, "weight": self.weight, "evidence": self.evidence}


def text_of(value, limit: int = MAX_TEXT) -> str:
    """All strings in a tool result (strings, JSON objects or lists), bounded."""
    parts: list[str] = []
    size = 0

    def walk(item):
        nonlocal size
        if size >= limit:
            return
        if isinstance(item, str):
            parts.append(item[: limit - size])
            size += len(parts[-1])
        elif isinstance(item, dict):
            for v in item.values():
                walk(v)
        elif isinstance(item, (list, tuple)):
            for v in item:
                walk(v)
        elif item is not None:
            parts.append(str(item)[: limit - size])
            size += len(parts[-1])

    if isinstance(value, str) and value[:1] in "[{":
        try:
            value = json.loads(value)
        except ValueError:
            pass
    walk(value)
    return "\n".join(parts)


def _snippet(text: str, match: re.Match, width: int = 160) -> str:
    start = max(0, match.start() - 40)
    return " ".join(text[start: start + width].split())


def scan(value) -> list[dict]:
    """Return findings when the content looks like it carries instructions for an AI agent, else []."""
    text = text_of(value)
    if not text.strip():
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for signal, weight, pattern in SIGNALS:
        match = pattern.search(text)
        if match and signal not in seen:
            seen.add(signal)
            findings.append(Finding(signal, weight, _snippet(text, match)))
    for hidden in (HIDDEN_HTML, HIDDEN_CSS):
        for match in hidden.finditer(text):
            inner = match.group(1)
            if any(pattern.search(inner) for name, _, pattern in SIGNALS if name in {"addresses the agent", "asks to run a network command", "asks to send secrets", "overrides instructions"}):
                findings.append(Finding("hidden instructions", 3, " ".join(inner.split())[:160]))
                break
    if len(INVISIBLE.findall(text)) >= 2:
        findings.append(Finding("invisible characters", 2, f"{len(INVISIBLE.findall(text))} zero-width characters"))
    if TAG_CHARACTERS.search(text):
        findings.append(Finding("invisible tag characters", 5, "Unicode tag characters, a known way to hide instructions"))
    encoded = ENCODED.search(text)
    if encoded:
        findings.append(Finding("encoded payload", 2, encoded.group(1)[:60] + "…"))
    score = sum(f.weight for f in findings)
    return [f.as_dict() for f in findings] if score >= THRESHOLD else []
