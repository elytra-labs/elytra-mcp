"""Facts about the agent's working directory that classification needs: the branch and the project root.

Each lookup is one short `git` call, made only when a decision depends on it
(a push without an explicit branch, a file path outside the working directory).
"""
from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path

DEFAULT_PROTECTED = ("main", "master", "trunk", "production", "prod", "stable", "release", "release/*", "release-*", "hotfix/*")
TEMP_ROOTS = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")


def _git(cwd: str, *args: str) -> str | None:
    if not cwd or not os.path.isdir(cwd):
        return None
    try:
        result = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def current_branch(cwd: str) -> str | None:
    """The checked-out branch, or None when unknown or detached."""
    branch = _git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
    return None if branch in {None, "HEAD"} else branch


def project_root(cwd: str) -> str:
    return _git(cwd, "rev-parse", "--show-toplevel") or cwd


def is_protected(branch: str | None, patterns=DEFAULT_PROTECTED) -> bool:
    """Unknown branches count as protected: a push Elytra cannot place gets the stricter rule."""
    if not branch:
        return True
    name = branch.removeprefix("refs/heads/")
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def is_temp(path: str) -> bool:
    tmp = os.environ.get("TMPDIR", "")
    return path.startswith(TEMP_ROOTS) or bool(tmp) and path.startswith(tmp.rstrip("/") + "/")


def inside(path: str, root: str) -> bool:
    try:
        Path(path).resolve(strict=False).relative_to(Path(root).resolve(strict=False))
        return True
    except ValueError:
        return False
