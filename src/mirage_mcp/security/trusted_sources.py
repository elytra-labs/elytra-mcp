"""Web sources whose content is official documentation or a package registry.

Reads from these do not mark an agent session as having read untrusted content,
unless Elytra's content inspection finds instructions aimed at AI agents in what
was returned. Issues, pull requests, wikis, forums, gists and arbitrary sites are
never on this list. People add their own entries with `elytra trust-domain`.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

# host, or host + path prefix. Kept short on purpose: official docs and registries only.
DEFAULT_TRUSTED = (
    "docs.python.org", "peps.python.org", "packaging.python.org", "pypi.org/project/", "pypi.org/pypi/",
    "developer.mozilla.org", "nodejs.org/api/", "nodejs.org/docs/", "nodejs.org/en/docs/", "docs.npmjs.com",
    "www.npmjs.com/package/", "npmjs.com/package/", "registry.npmjs.org", "crates.io/crates/", "docs.rs", "doc.rust-lang.org",
    "pkg.go.dev", "go.dev/doc/", "go.dev/ref/", "docs.github.com", "react.dev", "nextjs.org/docs", "vuejs.org/guide/",
    "vuejs.org/api/", "angular.dev", "svelte.dev/docs", "tailwindcss.com/docs", "kubernetes.io/docs/", "docs.docker.com",
    "docs.aws.amazon.com", "cloud.google.com/docs/", "learn.microsoft.com", "docs.djangoproject.com", "flask.palletsprojects.com",
    "fastapi.tiangolo.com", "docs.pydantic.dev", "numpy.org/doc/", "pandas.pydata.org/docs/", "docs.astral.sh",
    "www.typescriptlang.org/docs/", "typescriptlang.org/docs/", "eslint.org/docs/", "vite.dev", "vitejs.dev", "jestjs.io/docs/",
    "vitest.dev", "playwright.dev/docs/", "guides.rubyonrails.org", "api.rubyonrails.org", "ruby-doc.org", "docs.oracle.com/javase/",
    "kotlinlang.org/docs/", "developer.apple.com/documentation/", "developer.android.com/reference/", "www.postgresql.org/docs/",
    "postgresql.org/docs/", "dev.mysql.com/doc/", "redis.io/docs/", "docs.sqlalchemy.org", "www.sqlite.org/lang", "git-scm.com/docs/",
    "developer.hashicorp.com", "docs.gitlab.com", "docs.pytest.org", "docs.celeryq.dev", "www.prisma.io/docs/", "nodejs.org/dist/",
)

USER_FILE = Path.home() / ".elytra" / "trusted-domains.json"


def _normalize(entry: str) -> str:
    entry = entry.strip().lower()
    if "://" in entry:
        parts = urlsplit(entry)
        entry = parts.netloc + parts.path
    return entry.rstrip("/") if "/" not in entry.rstrip("/") else entry


def user_entries(path: Path | None = None) -> list[str]:
    try:
        value = json.loads((path or USER_FILE).read_text())
    except (OSError, ValueError):
        return []
    return [_normalize(e) for e in value.get("trusted", []) if isinstance(e, str) and e.strip()] if isinstance(value, dict) else []


def is_trusted_url(url: str, extra: list[str] | None = None) -> bool:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        return False
    host = parts.hostname.lower()
    target = host + (parts.path or "/")
    for entry in (*DEFAULT_TRUSTED, *(extra if extra is not None else user_entries())):
        entry = _normalize(entry)
        if "/" in entry:
            if target.startswith(entry if entry.endswith("/") else entry + "/") or target.rstrip("/") == entry.rstrip("/"):
                return True
        elif host == entry:  # Exact hosts only: a subdomain of a docs site may be a different publisher.
            return True
    return False


def describe(url: str, limit: int = 120) -> str:
    """A bounded, query-free label for a URL: host and path."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url[:limit]
    label = (parts.hostname or "") + (parts.path or "")
    return (label or url)[:limit]
