"""Loopback gateway access. Browser pairing never exposes the owner credential."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from http.cookies import SimpleCookie


DEFAULT_HOME = Path.home() / ".elytra"
DEFAULT_TOKEN_FILE = DEFAULT_HOME / "control-plane.token"


def load_owner_token(path: Path = DEFAULT_TOKEN_FILE) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Owner credential must not be a symbolic link")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Owner credential must be a regular file owned by this user")
        if info.st_mode & 0o077:
            raise ValueError("Owner credential permissions must be 0600")
        token = path.read_text().strip()
        if len(token) < 32:
            raise ValueError("Owner credential is invalid; replace it to rotate access")
        return token
    with os.fdopen(fd, "w") as stream:
        token = secrets.token_urlsafe(48)
        stream.write(token + "\n")
    return token


class LocalAccess:
    def __init__(self, token_file: Path | str = DEFAULT_TOKEN_FILE, owner_token: str | None = None):
        self.owner_token = owner_token or load_owner_token(Path(token_file))
        self._pairings: dict[str, float] = {}
        self._sessions: dict[str, float] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def is_owner(self, authorization: str = "", cookie: str = "") -> bool:
        if authorization.startswith("Bearer "):
            return secrets.compare_digest(authorization[7:], self.owner_token)
        try:
            cookies = SimpleCookie(cookie)
            item = cookies.get("elytra_session")
            if item:
                with self._lock:
                    key = self._digest(item.value)
                    expiry = self._sessions.get(key, 0)
                    if expiry > time.time():
                        return True
                    self._sessions.pop(key, None)
        except Exception:
            pass
        return False

    def create_pairing(self) -> str:
        with self._lock:
            now = time.time()
            self._pairings = {key: exp for key, exp in self._pairings.items() if exp > now}
            self._sessions = {key: exp for key, exp in self._sessions.items() if exp > now}
            code = secrets.token_urlsafe(32)
            self._pairings[self._digest(code)] = now + 300
            return code

    def redeem(self, code: str) -> str:
        with self._lock:
            expiry = self._pairings.pop(self._digest(code), 0)
            if expiry <= time.time():
                raise ValueError("Pairing code is invalid, expired, or already used. Run elytra connect --open.")
            token = secrets.token_urlsafe(32)
            self._sessions[self._digest(token)] = time.time() + 8 * 3600
            return token

    def logout(self, cookie: str) -> None:
        try:
            item = SimpleCookie(cookie).get("elytra_session")
            if item:
                with self._lock:
                    self._sessions.pop(self._digest(item.value), None)
        except Exception:
            pass
