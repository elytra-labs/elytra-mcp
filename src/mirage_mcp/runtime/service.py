"""Durable local authorization boundary, independent of transport and demo data.

Every tool dispatch follows evaluate -> claim -> complete. A claim is committed
before dispatch and is never retried: after a crash its outcome is UNCERTAIN.
This is at-most-once dispatch, not an exactly-once external side-effect guarantee.

Policy order is ascending explicit priority (default 100), then rule_id. The
first matching enabled rule wins. Schema and classification checks always win
over policies, approvals and grants. Taint is run-scoped supporting evidence;
the service does not infer user authorization from prompt or tool output text.
"""

from __future__ import annotations

import fnmatch
import functools
import errno
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mirage_mcp.catalog import load_catalog, suggested_category
from mirage_mcp.runtime.guardrails import DEFAULT_PRESET, PREFIX as GUARDRAIL_PREFIX, describe_presets, preset_rules
from mirage_mcp.security.schema_guard import SchemaPinGuard
from mirage_mcp.security.secret_guard import SecretRedactor, RedactionResult


class RuntimeAuthorizationError(PermissionError):
    """Invalid credentials or an expired/ended run."""


class RuntimeConflictError(RuntimeError):
    """A one-time transition was already performed or became invalid."""


class RuntimeValidationError(ValueError):
    """Unsupported or oversized input."""


CATEGORIES = {"SOURCE_TRUSTED", "SOURCE_UNTRUSTED", "SINK_PRIVILEGED_WRITE", "SINK_EXFILTRATION", "UNKNOWN"}
SINKS = {"SINK_PRIVILEGED_WRITE", "SINK_EXFILTRATION"}
ACTIONS = {"BLOCK_SECOND_HOP", "STEP_UP_APPROVAL", "REDACT_AND_ALLOW", "AUDIT_ONLY"}
LEVELS = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_PAYLOAD = 1024 * 1024
# Host sessions stay open while their agent keeps calling tools.
HOST_SESSION_IDLE_SECONDS = 12 * 3600
EXPLICIT_APPROVAL_WINDOW = 120
DEFAULT_HOST_APPROVAL_WINDOW = 600
MAX_APPROVAL_WINDOW = 1800


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise RuntimeValidationError("A finite, JSON-serializable payload is required") from exc
    if len(raw.encode("utf-8")) > MAX_PAYLOAD:
        raise RuntimeValidationError("Payload exceeds the 1 MiB limit")
    return raw


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise RuntimeValidationError(f"{label} must be a nonempty string of at most 256 characters")
    return value


def _atomic(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        events = []
        with self._lock:
            if self._closed:
                raise RuntimeConflictError("Runtime is closed")
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                result = method(self, *args, **kwargs)
                if outer:
                    self._conn.commit()
                    events, self._pending_events = self._pending_events, []
            except Exception:
                if outer:
                    self._conn.rollback()
                    self._pending_events = []
                raise
            finally:
                self._depth -= 1
        if self._event_callback:
            for event in events:
                try:
                    self._event_callback(event)
                except Exception:
                    # Telemetry delivery must never undo a durable authorization.
                    pass
        return result
    return call


class RuntimeService:
    """One service instance owns a database and all runs across MCP servers.

    The HTTP owner boundary must guard create_run, classifications,
    acknowledge_schema, save_policy, and resolve_approval. A scoped run token
    may register metadata, evaluate, claim, complete, cancel, and finish only
    its own run. Tokens, raw arguments, raw outputs, and grant argument values
    are never persisted. Pending previews are redacted and erased on finish.
    """

    def __init__(self, db_path: str | Path, event_callback=None):
        self._lock = threading.RLock()
        self._depth = 0
        self._closed = False
        self._event_callback = event_callback
        self._pending_events: list[dict] = []
        self._redactor = SecretRedactor()
        self._permit_key = secrets.token_bytes(32)
        self._started = time.monotonic()
        self._last_prune = 0.0
        self._process_lock_fd = None
        self._conn = None
        try:
            self._open_storage(str(db_path))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _private_file(path: Path, label: str) -> int:
        """Open/create a private regular file without following its symlink."""
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        if not hasattr(os, "O_NOFOLLOW"):
            raise RuntimeValidationError("Private runtime storage requires POSIX no-follow file support")
        try:
            fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR}:
                raise RuntimeValidationError(f"{label} must be a private regular file, not a symlink or directory") from None
            raise
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise RuntimeValidationError(f"{label} must be a regular file owned by this user with no hard links")
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise RuntimeValidationError(f"{label} permissions must be 0600")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _open_storage(self, path: str):
        if path != ":memory:":
            import fcntl
            candidate = Path(path).absolute()
            candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Resolve directory aliases, but never resolve the database itself:
            # its final component is checked with O_NOFOLLOW below.
            parent = candidate.parent.resolve()
            for directory in (parent, *parent.parents):
                directory_info = directory.stat()
                unsafe_write = bool(directory_info.st_mode & 0o022)
                trusted_temporary = directory_info.st_uid == 0 and bool(directory_info.st_mode & stat.S_ISVTX)
                if directory_info.st_uid not in {os.getuid(), 0} or (unsafe_write and not trusted_temporary):
                    raise RuntimeValidationError("Runtime directory ancestors must be owned by this user/root and not writable by others")
            candidate = parent / candidate.name
            lock_fd = self._private_file(Path(str(candidate) + ".lock"), "Runtime lock")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(lock_fd)
                raise RuntimeConflictError("Another Elytra service already owns this database") from None
            except BaseException:
                os.close(lock_fd)
                raise
            self._process_lock_fd = lock_fd
            # Acquire the service lock before opening/mutating the database or
            # invalidating runs during recovery. Keep the sidecar inode after
            # release so another process cannot acquire a different lock inode.
            database_fd = self._private_file(candidate, "Runtime database")
            os.close(database_fd)
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(str(candidate) + suffix)
                if os.path.lexists(sidecar):
                    sidecar_fd = self._private_file(sidecar, "Runtime SQLite sidecar")
                    os.close(sidecar_fd)
            path = str(candidate)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._conn.execute("PRAGMA secure_delete=ON")
        for name in ("runs", "tools", "calls", "approvals", "policies", "events", "meta", "hosts"):
            self._conn.execute(f"CREATE TABLE IF NOT EXISTS rt_{name} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
        # A service restart cannot safely reconstruct in-flight tool outcomes.
        with self._conn:
            for run in self._all("runs"):
                if run["status"] == "ACTIVE":
                    run.update(status="INTERRUPTED", finished_at=_now(), grants=[])
                    self._put("runs", run["run_id"], run)
            for call in self._all("calls"):
                if call["status"] == "CLAIMED":
                    call.update(status="UNCERTAIN", reason="Service restarted after dispatch claim; external outcome is unknown")
                elif call["status"] in {"READY", "PENDING", "APPROVED"}:
                    call.update(status="INVALIDATED", reason="Service restarted")
                call.pop("arguments_preview", None)
                self._put("calls", call["key"], call)
            for approval in self._all("approvals"):
                if approval["status"] in {"PENDING", "APPROVED"}:
                    approval.update(status="INVALIDATED", reason="Service restarted", resolved_at=_now())
                approval["arguments_preview"] = {}
                self._put("approvals", approval["approval_id"], approval)
            if not self._get("meta", "policy_version"):
                self._put("meta", "policy_version", {"version": 1})
            self._prune()

    def _get(self, table: str, key: str) -> dict | None:
        row = self._conn.execute(f"SELECT data FROM rt_{table} WHERE id=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def _all(self, table: str) -> list[dict]:
        return [json.loads(row[0]) for row in self._conn.execute(f"SELECT data FROM rt_{table}")]

    def _put(self, table: str, key: str, value: dict):
        self._conn.execute(f"INSERT INTO rt_{table}(id,data) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (key, json.dumps(value, separators=(",", ":"), allow_nan=False)))

    def _version(self) -> int:
        return self._get("meta", "policy_version")["version"]

    def _redact(self, payload: Any):
        # Redact keys as well as values, including common secret field names.
        sensitive = {"password", "passwd", "token", "accesstoken", "refreshtoken", "apikey", "secret", "authorization", "privatekey", "clientsecret", "runtoken", "permit", "awssecretaccesskey", "secretaccesskey", "secretkey", "credential", "credentials"}
        fields_redacted = 0
        def private(key):
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            return normalized in sensitive or normalized.endswith(("password", "passwd", "apikey", "accesstoken", "refreshtoken", "secretkey", "clientsecret"))
        def walk(item):
            nonlocal fields_redacted
            if isinstance(item, dict):
                output = {}
                for key, value in item.items():
                    cleaned_key, found, _ = self._redactor.redact_text(str(key))
                    fields_redacted += found
                    if private(key):
                        fields_redacted += 1
                        output[cleaned_key] = "[ELYTRA_REDACTED]"
                    else:
                        output[cleaned_key] = walk(value)
                return output
            if isinstance(item, list):
                return [walk(v) for v in item]
            return item
        result = self._redactor.redact(walk(payload))
        return RedactionResult(result.redacted_payload, result.secrets_found + fields_redacted, result.secret_types + (["SENSITIVE_FIELD"] if fields_redacted else []))

    def _redact_metadata(self, payload: Any):
        # A property named password/token in JSON Schema is a declaration,
        # not a credential value. Preserve schema structure while sanitizing
        # recognized secret strings in descriptions/defaults/extension data.
        def walk(value):
            if isinstance(value, dict):
                return {self._redactor.redact_text(str(key))[0]: walk(item) for key, item in value.items()}
            if isinstance(value, list):
                return [walk(item) for item in value]
            return value
        return self._redactor.redact(walk(payload)).redacted_payload

    def _run(self, run_id: str, run_token: str) -> dict:
        run = self._get("runs", _identifier(run_id, "run_id"))
        supplied = hashlib.sha256(str(run_token).encode()).hexdigest()
        if not run or not hmac.compare_digest(run["token_hash"], supplied):
            raise RuntimeAuthorizationError("Invalid run credentials")
        if run["status"] != "ACTIVE" or run["expires_at_epoch"] <= time.time():
            raise RuntimeAuthorizationError("Run has ended or expired")
        return run

    def _public_run(self, run: dict) -> dict:
        return {key: value for key, value in run.items() if key not in {"token_hash", "grants"}}

    @_atomic
    def validate_run(self, run_id: str, run_token: str) -> dict:
        return self._public_run(self._run(run_id, run_token))

    def _tool_key(self, server_id, tool_name):
        return _canonical([_identifier(server_id, "server_id"), _identifier(tool_name, "tool_name")])

    def _call_key(self, run_id, call_id):
        return _canonical([run_id, _identifier(call_id, "call_id")])

    def _permit(self, call: dict) -> str:
        binding = [call["key"], call["arguments_hash"], call["schema_hash"], call["policy_version"], call["expires_at_epoch"]]
        return hmac.new(self._permit_key, _canonical(binding).encode(), hashlib.sha256).hexdigest()

    def _valid_binding(self, call: dict) -> bool:
        tool = self._get("tools", self._tool_key(call["server_id"], call["tool_name"]))
        return bool(tool and tool["status"] == "VERIFIED" and tool["category"] != "UNKNOWN" and tool["category"] == call["category"]
                    and tool["sha256_hash"] == call["schema_hash"] and self._version() == call["policy_version"]
                    and call["expires_at_epoch"] > time.time())

    def _event(self, call: dict, decision: str, *, direction="client->server", secrets_redacted=0):
        category = call["category"]
        event = {
            "event_id": "evt_" + uuid.uuid4().hex, "timestamp": _now(), "timestamp_epoch": time.time(),
            "session_id": call["run_id"], "run_id": call["run_id"], "call_id": call["call_id"],
            "server_id": call["server_id"], "tool_name": call["tool_name"], "direction": direction,
            "jsonrpc_method": "tools/call", "tool_role": "sink" if category in SINKS else "source" if category.startswith("SOURCE_") else "neutral",
            "category": category, "decision": decision, "rule_id": call.get("rule_id"), "reason": call["reason"],
            "eval_latency_ms": call.get("eval_latency_ms", 0.0), "taint_level": call.get("taint_level", "CLEAN"),
            "source_lineage": call.get("source_lineage", []), "secrets_redacted": secrets_redacted,
            "arguments_preview": {}, "policy_version": call["policy_version"], "schema_hash": call["schema_hash"],
            "execution_status": call["status"], "notify": call.get("notify", True),
        }
        self._put("events", event["event_id"], event)
        self._pending_events.append(event)
        # Enforce the count limit with SQLite row order without parsing the
        # complete telemetry history on every tool dispatch.
        self._conn.execute("DELETE FROM rt_events WHERE rowid <= (SELECT rowid FROM rt_events ORDER BY rowid DESC LIMIT 1 OFFSET 10000)")
        if time.monotonic() - self._last_prune >= 60:
            self._prune()
        return event

    def _prune(self):
        self._last_prune = time.monotonic()
        cutoff = time.time() - 7 * 86400
        events = sorted(self._all("events"), key=lambda e: e["timestamp_epoch"], reverse=True)
        for event in events[10000:] + [e for e in events[:10000] if e["timestamp_epoch"] < cutoff]:
            self._conn.execute("DELETE FROM rt_events WHERE id=?", (event["event_id"],))
        for run in self._all("runs"):
            expired = run["expires_at_epoch"] <= time.time()
            if run["status"] == "ACTIVE" and expired:
                run.update(status="EXPIRED", finished_at=_now(), grants=[])
                self._put("runs", run["run_id"], run)
            if run["status"] != "ACTIVE" and run["created_at_epoch"] < cutoff:
                self._conn.execute("DELETE FROM rt_runs WHERE id=?", (run["run_id"],))
        for table, id_field in (("approvals", "approval_id"), ("calls", "key")):
            for record in self._all(table):
                if record.get("created_at_epoch", time.time()) < cutoff:
                    self._conn.execute(f"DELETE FROM rt_{table} WHERE id=?", (record[id_field],))

    @_atomic
    def create_run(self, intent: str, grants: list[dict] | None = None, ttl_seconds: int = 3600) -> dict:
        if not isinstance(intent, str) or not intent.strip() or len(intent) > 4096:
            raise RuntimeValidationError("A nonempty intent of at most 4096 characters is required")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not math.isfinite(ttl_seconds) or not 1 <= ttl_seconds <= 86400:
            raise RuntimeValidationError("Run TTL must be between 1 and 86400 seconds")
        if grants is None:
            grants = []
        if not isinstance(grants, list) or len(grants) > 100:
            raise RuntimeValidationError("At most 100 explicit grants are allowed")
        normalized = []
        for grant in grants:
            if not isinstance(grant, dict) or set(grant) - {"server_id", "tool_name", "arguments"} or "arguments" not in grant:
                raise RuntimeValidationError("Grant requires server_id, tool_name and exact arguments")
            item = {"server_id": _identifier(grant.get("server_id"), "server_id"), "tool_name": _identifier(grant.get("tool_name"), "tool_name")}
            if not isinstance(grant["arguments"], dict):
                raise RuntimeValidationError("Grant arguments must be an object")
            item["arguments_hash"] = _hash(grant["arguments"])
            normalized.append(item)
        run_id, token = "run_" + uuid.uuid4().hex, secrets.token_urlsafe(32)
        now = time.time()
        run = {"run_id": run_id, "token_hash": hashlib.sha256(token.encode()).hexdigest(),
               "intent": self._redact(intent).redacted_payload, "grants": normalized, "status": "ACTIVE",
               "created_at": _now(), "created_at_epoch": now, "expires_at_epoch": now + ttl_seconds,
               "call_count": 0, "untrusted_sources": [], "coverage": "EXPLICIT_RUN", "approval_window": EXPLICIT_APPROVAL_WINDOW}
        self._put("runs", run_id, run)
        return {**self._public_run(run), "run_token": token}

    @_atomic
    def list_runs(self) -> list[dict]:
        self._prune()
        return [self._public_run(r) for r in sorted(self._all("runs"), key=lambda r: r["created_at_epoch"], reverse=True)]

    @_atomic
    def finish_run(self, run_id: str, run_token: str, status="COMPLETED") -> dict:
        run = self._run(run_id, run_token)
        if status not in {"COMPLETED", "CANCELLED", "FAILED"}:
            raise RuntimeValidationError("Run status must be COMPLETED, CANCELLED or FAILED")
        run.update(status=status, finished_at=_now(), grants=[])
        self._put("runs", run_id, run)
        for call in self._all("calls"):
            if call["run_id"] != run_id:
                continue
            if call["status"] in {"READY", "PENDING", "APPROVED"}:
                self._cancel(call, "Run finished")
            elif call["status"] == "CLAIMED":
                call.update(status="UNCERTAIN", completed_at=_now(),
                            reason="Run ended before a claimed call reported completion; inspect the destination before retrying")
                self._put("calls", call["key"], call)
                self._event(call, "EXECUTION_UNCERTAIN")
        return self._public_run(run)

    @_atomic
    def register_tools(self, run_id: str, run_token: str, server_id: str, tools: list, classifications: dict | None = None) -> list[dict]:
        self._run(run_id, run_token)
        _identifier(server_id, "server_id")
        if not isinstance(tools, list) or len(tools) > 1000:
            raise RuntimeValidationError("At most 1000 tool definitions are allowed")
        _canonical(tools)
        if classifications is not None and (not isinstance(classifications, dict) or any(c not in CATEGORIES for c in classifications.values())):
            raise RuntimeValidationError("Unknown operator classification")
        records = []
        authority_changed = False
        names = set()
        known = {self._tool_key(t["server_id"], t["tool_name"]): t for t in self._all("tools")}
        accepted_catalog = (self._get("meta", "catalog_servers") or {}).get("servers", {})
        for definition in tools:
            if not isinstance(definition, dict):
                raise RuntimeValidationError("Each tool definition must be an object")
            name = _identifier(definition.get("name"), "tool_name")
            if not isinstance(definition.get("description", ""), str):
                raise RuntimeValidationError("Tool description must be a string")
            if not isinstance(definition.get("inputSchema", definition.get("input_schema", {})), dict):
                raise RuntimeValidationError("Tool input schema must be an object")
            if not isinstance(definition.get("outputSchema", {}), dict):
                raise RuntimeValidationError("Tool output schema must be an object")
            if name in names:
                raise RuntimeValidationError("Duplicate tool name")
            names.add(name)
            key = self._tool_key(server_id, name)
            previous = self._get("tools", key)
            # Include annotations, output schema and extension metadata. The
            # legacy guard's narrow digest omits those exposed surfaces.
            digest = _hash(definition)
            suspicious = SchemaPinGuard.scan_for_poisoning({"description": _canonical(definition)})
            pinned = previous["sha256_hash"] if previous else digest
            review_required = bool(previous and previous.get("requires_review"))
            status = "POISON_SUSPECTED" if suspicious else "DRIFT_DETECTED" if digest != pinned or review_required else "VERIFIED"
            category = previous["category"] if previous else "UNKNOWN"
            authority_changed = authority_changed or bool(previous and (previous["observed_sha256_hash"] != digest or previous["status"] != status))
            classified_by = previous.get("classified_by") if previous else None
            # Classification cannot silently acknowledge drift or poison.
            if classifications and name in classifications and status == "VERIFIED":
                category = classifications[name]
                classified_by = "operator"
                authority_changed = authority_changed or bool(previous and previous["category"] != category)
            elif category == "UNKNOWN" and status == "VERIFIED" and server_id in accepted_catalog:
                # The operator accepted this server's catalog entry; only listed tools are classified.
                suggestion = suggested_category(accepted_catalog[server_id], name)
                if suggestion:
                    category, classified_by = suggestion, "catalog:" + accepted_catalog[server_id]
            record = {"server_id": server_id, "tool_name": name, "sha256_hash": pinned,
                      "observed_sha256_hash": digest, "category": category, "status": status,
                      "pinned_at": previous["pinned_at"] if previous else _now(), "last_verified_at": _now(),
                      "description_preview": self._redact(str(definition.get("description", ""))[:240]).redacted_payload,
                      "description": self._redact_metadata(definition.get("description", "")),
                      "schema": self._redact_metadata(definition.get("inputSchema", definition.get("input_schema", {}))),
                      "tool_definition": self._redact_metadata(definition),
                      "suspicious_patterns": suspicious, "drift_summary": ", ".join(suspicious) if suspicious else "Tool schema changed; owner review required" if status == "DRIFT_DETECTED" else None,
                      "available": status == "VERIFIED" and category != "UNKNOWN", "present": True, "requires_review": review_required,
                      "classified_by": classified_by}
            known[key] = record
            if len(known) > 1000 or len(json.dumps(list(known.values())).encode("utf-8")) > 4 * 1024 * 1024:
                raise RuntimeValidationError("Tool registry limit reached (1000 tools / 4 MiB redacted review metadata)")
            self._put("tools", key, record)
            records.append(record)
        for key, previous in known.items():
            if previous["server_id"] == server_id and previous["tool_name"] not in names and previous.get("present", True):
                previous.update(status="DRIFT_DETECTED", available=False, present=False, requires_review=True,
                                drift_summary="Tool removed from the current server inventory; reappearance requires owner review")
                self._put("tools", key, previous)
                authority_changed = True
        if authority_changed:
            self._bump_version("Operator changed tool classification")
        return records

    @_atomic
    def list_tools(self) -> list[dict]:
        return sorted(self._all("tools"), key=lambda t: (t["server_id"], t["tool_name"]))

    @_atomic
    def list_pins(self) -> list[dict]:
        return sorted(self._all("tools"), key=lambda t: (t["server_id"], t["tool_name"]))

    @_atomic
    def acknowledge_schema(self, server_id: str, tool_name: str, sha256_hash: str, category: str) -> dict:
        if category not in CATEGORIES:
            raise RuntimeValidationError("Unknown operator classification")
        key = self._tool_key(server_id, tool_name)
        record = self._get("tools", key)
        if not record or record["observed_sha256_hash"] != sha256_hash:
            raise RuntimeConflictError("Schema hash does not match the currently observed tool")
        if record["status"] == "POISON_SUSPECTED":
            raise RuntimeConflictError("Suspicious tool metadata must be corrected before exposure")
        if not record.get("present", True):
            raise RuntimeConflictError("Tool is absent from the current server inventory")
        record.update(sha256_hash=sha256_hash, category=category, status="VERIFIED", pinned_at=_now(), drift_summary=None, available=category != "UNKNOWN", requires_review=False, classified_by="operator")
        self._put("tools", key, record)
        # Reclassification changes authority even if schema did not change.
        self._bump_version("Operator changed schema/classification")
        return record

    def _match_policy(self, run: dict, server_id: str, tool_name: str, level: str, category: str | None = None) -> dict | None:
        sources = run["untrusted_sources"] or ["*"]
        target = server_id + "." + tool_name
        policies = sorted(self._all("policies"), key=lambda p: (p["priority"], p["rule_id"]))
        for policy in policies:
            if policy.get("categories") and category not in policy["categories"]:
                continue
            if policy["enabled"] and LEVELS[level] >= LEVELS[policy["min_taint_level"]] and fnmatch.fnmatchcase(target, policy["sink_pattern"]) and any(fnmatch.fnmatchcase(source, policy["source_pattern"]) for source in sources):
                policy["hit_count"] += 1
                self._put("policies", policy["rule_id"], policy)
                return policy
        return None

    def _decision(self, call: dict) -> dict:
        status = call["status"]
        if status in {"READY", "APPROVED", "PENDING"} and not self._valid_binding(call):
            expired = call["expires_at_epoch"] <= time.time()
            self._cancel(call, "Authorization expired" if expired else "Schema, classification or policy changed", status="EXPIRED" if expired else "INVALIDATED")
            status = call["status"]
        decision = "ALLOW" if status in {"READY", "APPROVED"} and self._valid_binding(call) else "STEP_UP" if status == "PENDING" and self._valid_binding(call) else "BLOCK"
        output = {"run_id": call["run_id"], "call_id": call["call_id"], "decision": decision, "status": status,
                  "reason": call["reason"], "approval_id": call.get("approval_id"), "policy_version": call["policy_version"],
                  "schema_hash": call["schema_hash"], "expires_at_epoch": call["expires_at_epoch"], "rule_id": call.get("rule_id")}
        if decision == "ALLOW":
            output["permit"] = self._permit(call)
        return output

    @_atomic
    def get_call(self, run_id: str, run_token: str, call_id: str) -> dict:
        self._run(run_id, run_token)
        call = self._get("calls", self._call_key(run_id, call_id))
        if not call:
            raise RuntimeValidationError("Unknown call_id for this run")
        return self._decision(call)

    @_atomic
    def evaluate(self, run_id: str, run_token: str, server_id: str, tool_name: str, arguments: dict, call_id: str, notify: bool = True) -> dict:
        started = time.perf_counter()
        run = self._run(run_id, run_token)
        if not isinstance(arguments, dict):
            raise RuntimeValidationError("Tool arguments must be an object")
        if run.get("coverage") == "HOST_SESSION":
            run["expires_at_epoch"] = max(run["expires_at_epoch"], time.time() + HOST_SESSION_IDLE_SECONDS)
        arguments_hash = _hash(arguments)
        key = self._call_key(run_id, call_id)
        existing = self._get("calls", key)
        if existing:
            if existing["arguments_hash"] != arguments_hash or existing["server_id"] != server_id or existing["tool_name"] != tool_name:
                raise RuntimeConflictError("call_id is already bound to different arguments or tool")
            return self._decision(existing)
        if run["call_count"] >= 1000:
            raise RuntimeValidationError("Run reached the 1000-call limit")
        tool = self._get("tools", self._tool_key(server_id, tool_name))
        category = tool["category"] if tool else "UNKNOWN"
        call = {"key": key, "call_id": call_id, "run_id": run_id, "server_id": server_id, "tool_name": tool_name,
                "arguments_hash": arguments_hash, "schema_hash": tool["sha256_hash"] if tool else "", "policy_version": self._version(),
                "category": category, "created_at": _now(), "created_at_epoch": time.time(), "expires_at_epoch": min(time.time() + run.get("approval_window", EXPLICIT_APPROVAL_WINDOW), run["expires_at_epoch"]),
                "source_lineage": list(run["untrusted_sources"]), "taint_level": "HIGH" if run["untrusted_sources"] else "CLEAN", "rule_id": None,
                "notify": bool(notify)}
        reason, status, event_decision = "Tool is unknown; operator classification required", "BLOCKED", "BLOCK_SECOND_HOP"
        if tool and tool["status"] != "VERIFIED":
            reason, event_decision = "Tool schema is not verified: " + tool["status"], "SCHEMA_DRIFT_BLOCK"
        elif tool and category != "UNKNOWN":
            if category.startswith("SOURCE_"):
                reason, status, event_decision = "Operator-classified source read", "READY", "ALLOW"
            else:
                granted = any(g["server_id"] == server_id and g["tool_name"] == tool_name and g.get("arguments_hash") == arguments_hash for g in run["grants"])
                policy = self._match_policy(run, server_id, tool_name, call["taint_level"], category)
                action = policy["action"] if policy else None
                call["rule_id"] = policy["rule_id"] if policy else None
                if action == "BLOCK_SECOND_HOP":
                    reason = "Blocked by operator policy"
                elif action == "STEP_UP_APPROVAL":
                    reason, status, event_decision = "Operator policy requires approval for this exact action", "PENDING", "STEP_UP_REQUIRED"
                elif granted or action in {"REDACT_AND_ALLOW", "AUDIT_ONLY"}:
                    reason, status, event_decision = "Explicit operator grant" if granted else "Explicit operator policy", "READY", "ALLOW"
                else:
                    reason, status, event_decision = "Untrusted input preceded this action; approval required" if run["untrusted_sources"] else "Consequential action requires explicit authorization", "PENDING", "STEP_UP_REQUIRED"
        call.update(reason=reason, status=status, eval_latency_ms=round((time.perf_counter() - started) * 1000, 4))
        if status == "PENDING":
            approval_id = "apr_" + uuid.uuid4().hex
            call["approval_id"] = approval_id
            preview = self._redact(arguments).redacted_payload
            preview_text = json.dumps(preview, ensure_ascii=False)
            preview_truncated = len(preview_text.encode("utf-8")) > 16384
            if preview_truncated:
                preview = {"_preview_truncated": True, "_redacted_json_prefix": preview_text[:12000], "_arguments_sha256": arguments_hash}
            approval = {"approval_id": approval_id, "created_at": call["created_at"], "created_at_epoch": call["created_at_epoch"],
                        "run_id": run_id, "session_id": run_id, "call_id": call_id, "server_id": server_id, "tool_name": tool_name,
                        "rule_id": call["rule_id"] or "default-approval", "risk_score": 80 if run["untrusted_sources"] else 50,
                        "taint_lineage": call["source_lineage"], "arguments_preview": preview, "reason": reason, "status": "PENDING",
                        "arguments_hash": arguments_hash, "schema_hash": call["schema_hash"], "policy_version": call["policy_version"],
                        "expires_at_epoch": call["expires_at_epoch"], "resolved_at": None, "resolved_by": None, "arguments_preview_truncated": preview_truncated}
            self._put("approvals", approval_id, approval)
        self._put("calls", key, call)
        run["call_count"] += 1
        self._put("runs", run_id, run)
        self._event(call, event_decision)
        return self._decision(call)

    @_atomic
    def resolve_approval(self, approval_id: str, status: str, actor="local-user") -> dict:
        if status not in {"APPROVED", "DENIED"}:
            raise RuntimeValidationError("Approval status must be APPROVED or DENIED")
        approval = self._get("approvals", _identifier(approval_id, "approval_id"))
        if not approval or approval["status"] != "PENDING":
            raise RuntimeConflictError("Approval is no longer pending")
        if status == "APPROVED" and approval.get("arguments_preview_truncated"):
            raise RuntimeConflictError("Arguments exceed the safe review size; deny or create an exact owner grant")
        call = self._get("calls", self._call_key(approval["run_id"], approval["call_id"]))
        run = self._get("runs", approval["run_id"])
        if not run or run["status"] != "ACTIVE" or run["expires_at_epoch"] <= time.time() or not call or call["status"] != "PENDING" or not self._valid_binding(call):
            raise RuntimeConflictError("Approval expired or its run, schema or policy changed")
        approval.update(status=status, resolved_at=_now(), resolved_by=self._redact(str(actor)[:256]).redacted_payload)
        call.update(status="APPROVED" if status == "APPROVED" else "DENIED", reason="Owner approved exact action" if status == "APPROVED" else "Owner denied action")
        if status == "DENIED":
            approval["arguments_preview"] = {}
        self._put("approvals", approval_id, approval)
        self._put("calls", call["key"], call)
        self._event(call, "ALLOW" if status == "APPROVED" else "BLOCK_SECOND_HOP")
        # Scoped clients poll evaluate with the same call_id to retrieve permit.
        return self._approval_view(approval, call)

    @_atomic
    def claim_execution(self, run_id: str, run_token: str, call_id: str, permit: str, arguments: dict) -> dict:
        run = self._run(run_id, run_token)
        key = self._call_key(run_id, call_id)
        call = self._get("calls", key)
        if not call or call["status"] not in {"READY", "APPROVED"}:
            raise RuntimeConflictError("Call is not authorized or was already claimed")
        if not isinstance(arguments, dict) or _hash(arguments) != call["arguments_hash"]:
            raise RuntimeConflictError("Arguments differ from the evaluated action")
        if not self._valid_binding(call) or not hmac.compare_digest(self._permit(call), str(permit)):
            raise RuntimeConflictError("Permit expired or its schema/policy changed")
        call.update(status="CLAIMED", claimed_at=_now())
        self._put("calls", key, call)
        if call.get("approval_id"):
            approval = self._get("approvals", call["approval_id"])
            approval.update(status="CONSUMED", consumed_at=_now(), arguments_preview={})
            self._put("approvals", approval["approval_id"], approval)
        # Conservatively mark the run before dispatch, even if the read later
        # fails/cancels. This closes evaluate-before-source-completion races.
        if call["category"] == "SOURCE_UNTRUSTED":
            source = call["server_id"] + "." + call["tool_name"]
            if source not in run["untrusted_sources"]:
                run["untrusted_sources"].append(source)
                self._put("runs", run_id, run)
            self._invalidate_clean_permits(run_id, except_key=key)
        cleaned = self._redact(arguments)
        self._event(call, "ALLOW", secrets_redacted=cleaned.secrets_found)
        return {"run_id": run_id, "call_id": call_id, "status": "CLAIMED", "server_id": call["server_id"], "tool_name": call["tool_name"], "arguments": cleaned.redacted_payload}

    def _invalidate_clean_permits(self, run_id: str, except_key: str):
        # A source may be claimed between sink evaluation and sink dispatch.
        # Re-evaluation requires a fresh call_id and sees the current lineage.
        for other in self._all("calls"):
            if other["run_id"] == run_id and other["key"] != except_key and other["category"] in SINKS and other["status"] in {"READY", "PENDING", "APPROVED"} and other["taint_level"] == "CLEAN":
                self._cancel(other, "Untrusted source was dispatched after this authorization", status="INVALIDATED")

    @_atomic
    def complete_execution(self, run_id: str, run_token: str, call_id: str, result: Any, is_error=False) -> Any:
        self._run(run_id, run_token)
        _canonical(result)
        key = self._call_key(run_id, call_id)
        call = self._get("calls", key)
        if not call or call["status"] != "CLAIMED":
            raise RuntimeConflictError("Only a claimed call can complete, once")
        cleaned = self._redact(result)
        call.update(status="FAILED" if is_error else "COMPLETED", completed_at=_now(), reason="Tool execution failed" if is_error else "Tool execution completed")
        self._put("calls", key, call)
        self._event(call, "TAINT_PROPAGATE" if call["category"] == "SOURCE_UNTRUSTED" else "ALLOW", direction="server->client", secrets_redacted=cleaned.secrets_found)
        return cleaned.redacted_payload

    @_atomic
    def mark_uncertain(self, run_id: str, run_token: str, call_id: str, reason="Transport ended after dispatch") -> dict:
        self._run(run_id, run_token)
        call = self._get("calls", self._call_key(run_id, call_id))
        if not call or call["status"] != "CLAIMED":
            raise RuntimeConflictError("Only a claimed call can have an uncertain external outcome")
        call.update(status="UNCERTAIN", reason=self._redact(str(reason)[:1024]).redacted_payload, completed_at=_now())
        self._put("calls", call["key"], call)
        self._event(call, "EXECUTION_UNCERTAIN")
        return self._decision(call)

    def _cancel(self, call: dict, reason: str, status="CANCELLED"):
        call.update(status=status, reason=reason)
        self._put("calls", call["key"], call)
        if call.get("approval_id"):
            approval = self._get("approvals", call["approval_id"])
            if approval and approval["status"] in {"PENDING", "APPROVED"}:
                approval.update(status=status, arguments_preview={}, resolved_at=_now(), reason=reason)
                self._put("approvals", approval["approval_id"], approval)

    @_atomic
    def cancel_call(self, run_id: str, run_token: str, call_id: str) -> dict:
        self._run(run_id, run_token)
        call = self._get("calls", self._call_key(run_id, call_id))
        if not call or call["status"] not in {"READY", "PENDING", "APPROVED"}:
            raise RuntimeConflictError("Dispatched or finished calls cannot be cancelled or retried")
        self._cancel(call, "Run client cancelled action")
        self._event(call, "BLOCK_SECOND_HOP")
        return self._decision(call)

    def _approval_view(self, approval: dict, call: dict | None = None) -> dict:
        if call is None:
            call = self._get("calls", self._call_key(approval["run_id"], approval["call_id"]))
        return {**approval,
                "expires_at": datetime.fromtimestamp(approval["expires_at_epoch"], timezone.utc).isoformat(),
                "execution_status": call["status"] if call else "INVALIDATED"}

    @_atomic
    def list_approvals(self, status=None) -> list[dict]:
        for approval in self._all("approvals"):
            if approval["status"] in {"PENDING", "APPROVED"}:
                call = self._get("calls", self._call_key(approval["run_id"], approval["call_id"]))
                run = self._get("runs", approval["run_id"])
                # Preserve terminal cancellation/denial states instead of
                # relabeling them expired when their old deadline passes.
                if call and call["status"] not in {"PENDING", "APPROVED"}:
                    terminal = call["status"]
                    approval.update(status="CONSUMED" if terminal in {"CLAIMED", "COMPLETED", "FAILED", "UNCERTAIN"} else terminal,
                                    arguments_preview={}, resolved_at=approval.get("resolved_at") or _now())
                    self._put("approvals", approval["approval_id"], approval)
                elif not call or not self._valid_binding(call) or not run or run["status"] != "ACTIVE" or run["expires_at_epoch"] <= time.time():
                    expired = approval["expires_at_epoch"] <= time.time() or bool(run and run["expires_at_epoch"] <= time.time())
                    terminal = "EXPIRED" if expired else "INVALIDATED"
                    if call:
                        self._cancel(call, "Authorization expired" if expired else "Run, schema or policy changed", status=terminal)
                    else:
                        approval.update(status=terminal, arguments_preview={}, resolved_at=_now())
                        self._put("approvals", approval["approval_id"], approval)
        return [self._approval_view(a) for a in sorted(self._all("approvals"), key=lambda a: a["created_at_epoch"], reverse=True) if status is None or a["status"] == status]

    LINK_BINDING = ("run_id", "call_id", "server_id", "tool_name", "arguments_hash", "schema_hash", "policy_version")

    @_atomic
    def link_snapshot(self) -> list[dict]:
        """Pending approvals as redacted summaries for a linked account: never results, tokens or full arguments."""
        summaries = []
        for approval in self.list_approvals("PENDING"):
            if approval.get("arguments_preview_truncated"):
                continue  # Too large to review safely away from the machine; decide it locally.
            run = self._get("runs", approval["run_id"]) or {}
            summaries.append({
                "local_approval_id": approval["approval_id"],
                "binding": {**{key: approval[key] for key in self.LINK_BINDING}, "expires_at_epoch": approval["expires_at_epoch"]},
                "summary": {"agent": str(run.get("host_label") or "Python integration")[:80], "reason": str(approval.get("reason", ""))[:500],
                            "arguments_preview": approval["arguments_preview"], "created_at": approval["created_at"], "risk_score": approval.get("risk_score")},
            })
        return summaries[:30]

    @_atomic
    def apply_remote_decision(self, payload: dict) -> dict:
        """Apply a verified decision from a linked account. The approval must still be pending with the exact binding.

        The first decision wins: a local approval or denial made earlier leaves this one with nothing to resolve.
        """
        decision = payload.get("decision")
        if decision not in {"APPROVED", "DENIED"}:
            raise RuntimeValidationError("Remote decision must be APPROVED or DENIED")
        command_key = "link-command:" + _identifier(payload.get("command_id"), "command_id")
        if self._get("meta", command_key):
            return {"status": "ALREADY_APPLIED"}
        approval = self._get("approvals", _identifier(payload.get("approval_id"), "approval_id"))
        if not approval or approval["status"] != "PENDING":
            raise RuntimeConflictError("Approval is no longer pending")
        if any(payload.get(key) != approval.get(key) for key in self.LINK_BINDING):
            raise RuntimeConflictError("Remote decision does not match the held action")
        result = self.resolve_approval(approval["approval_id"], decision, actor="linked account")
        now = time.time()
        self._put("meta", command_key, {"created_at_epoch": now})
        for row in self._conn.execute("SELECT id,data FROM rt_meta WHERE id LIKE 'link-command:%'").fetchall():
            if json.loads(row[1]).get("created_at_epoch", 0) < now - 86400:
                self._conn.execute("DELETE FROM rt_meta WHERE id=?", (row[0],))
        return result

    def _bump_version(self, reason: str):
        self._put("meta", "policy_version", {"version": self._version() + 1})
        for call in self._all("calls"):
            if call["status"] in {"READY", "PENDING", "APPROVED"}:
                self._cancel(call, reason, status="INVALIDATED")

    @_atomic
    def get_policies(self) -> list[dict]:
        return sorted(self._all("policies"), key=lambda p: (p["priority"], p["rule_id"]))

    @_atomic
    def save_policy(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise RuntimeValidationError("Policy must be an object")
        _canonical(payload)
        rule_id = _identifier(payload.get("rule_id") or "policy_" + uuid.uuid4().hex, "rule_id")
        previous = self._get("policies", rule_id) or {}
        rule = {"rule_id": rule_id, "name": str(payload.get("name", previous.get("name", rule_id)))[:256],
                "description": str(payload.get("description", previous.get("description", "")))[:4096],
                "source_pattern": payload.get("source_pattern", previous.get("source_pattern", "*")),
                "sink_pattern": payload.get("sink_pattern", previous.get("sink_pattern", "*")),
                "min_taint_level": payload.get("min_taint_level", previous.get("min_taint_level", "HIGH")),
                "action": payload.get("action", previous.get("action", "STEP_UP_APPROVAL")),
                "enabled": payload.get("enabled", previous.get("enabled", True)),
                "priority": payload.get("priority", previous.get("priority", 100)), "hit_count": previous.get("hit_count", 0),
                "categories": payload.get("categories", previous.get("categories", []))}
        if rule["action"] not in ACTIONS or rule["min_taint_level"] not in LEVELS or not isinstance(rule["enabled"], bool):
            raise RuntimeValidationError("Unknown policy action, taint level or enabled value")
        if isinstance(rule["priority"], bool) or not isinstance(rule["priority"], int) or not 0 <= rule["priority"] <= 10000:
            raise RuntimeValidationError("Policy priority must be an integer between 0 and 10000")
        for field in ("source_pattern", "sink_pattern"):
            _identifier(rule[field], field)
        categories = rule["categories"]
        if not isinstance(categories, list) or len(categories) > 4 or len(set(categories)) != len(categories) or any(c not in CATEGORIES - {"UNKNOWN"} for c in categories):
            raise RuntimeValidationError("Policy categories must be distinct known tool categories")
        rule = self._redact(rule).redacted_payload
        self._put("policies", rule_id, rule)
        self._bump_version("Operator changed policy")
        return {**rule, "policy_version": self._version()}

    # Host sessions -----------------------------------------------------------
    # A host credential belongs to one agent host (for example Claude Code). It
    # can only open or resume host-session runs; it cannot approve, classify or
    # change policy. A session groups the MCP servers that one host process
    # launched, so untrusted context carries across them but never across
    # separate host processes.

    def _public_host(self, host: dict) -> dict:
        return {key: value for key, value in host.items() if key != "token_hash"}

    @_atomic
    def create_host_credential(self, label: str, kind: str, approval_window: int = DEFAULT_HOST_APPROVAL_WINDOW) -> dict:
        label = _identifier(label, "label")[:80]
        kind = _identifier(kind, "kind")[:40]
        if isinstance(approval_window, bool) or not isinstance(approval_window, int) or not 30 <= approval_window <= MAX_APPROVAL_WINDOW:
            raise RuntimeValidationError(f"Approval window must be between 30 and {MAX_APPROVAL_WINDOW} seconds")
        host_id, token = "host_" + uuid.uuid4().hex[:20], secrets.token_urlsafe(32)
        host = {"host_id": host_id, "label": self._redact(label).redacted_payload, "kind": kind,
                "token_hash": hashlib.sha256(token.encode()).hexdigest(), "approval_window": approval_window,
                "created_at": _now(), "revoked_at": None}
        self._put("hosts", host_id, host)
        return {**self._public_host(host), "host_token": token}

    @_atomic
    def list_hosts(self) -> list[dict]:
        hosts = sorted(self._all("hosts"), key=lambda h: h["created_at"])
        runs = self._all("runs")
        now = time.time()
        for host in hosts:
            host["active_sessions"] = sum(1 for r in runs if r.get("host_id") == host["host_id"] and r["status"] == "ACTIVE" and r["expires_at_epoch"] > now)
        return [self._public_host(h) for h in hosts]

    @_atomic
    def revoke_host(self, host_id: str) -> dict:
        host = self._get("hosts", _identifier(host_id, "host_id"))
        if not host:
            raise RuntimeValidationError("Unknown host")
        host["revoked_at"] = host["revoked_at"] or _now()
        self._put("hosts", host_id, host)
        for run in self._all("runs"):
            if run.get("host_id") == host_id and run["status"] == "ACTIVE":
                run.update(status="CANCELLED", finished_at=_now(), grants=[])
                self._put("runs", run["run_id"], run)
                for call in self._all("calls"):
                    if call["run_id"] == run["run_id"] and call["status"] in {"READY", "PENDING", "APPROVED"}:
                        self._cancel(call, "Host credential revoked")
        return self._public_host(host)

    def _host(self, host_id: str, host_token: str) -> dict:
        host = self._get("hosts", _identifier(host_id, "host_id"))
        supplied = hashlib.sha256(str(host_token).encode()).hexdigest()
        if not host or not hmac.compare_digest(host["token_hash"], supplied) or host["revoked_at"]:
            raise RuntimeAuthorizationError("Invalid or revoked host credential")
        return host

    @staticmethod
    def _session_token(host_token: str, run_id: str) -> str:
        # Derived per run, so the service never stores it and every proxy of the session can recompute it.
        return hmac.new(str(host_token).encode(), run_id.encode(), hashlib.sha256).hexdigest()

    @_atomic
    def open_host_session(self, host_id: str, host_token: str, session_key: str) -> dict:
        host = self._host(host_id, host_token)
        if not isinstance(session_key, str) or not re.fullmatch(r"[0-9a-f]{16,64}", session_key):
            raise RuntimeValidationError("Session key must be 16-64 lowercase hex characters")
        mapping_key = "host_session:" + host_id + ":" + session_key
        mapping = self._get("meta", mapping_key)
        run = self._get("runs", mapping["run_id"]) if mapping else None
        now = time.time()
        if run and run["status"] == "ACTIVE" and run["expires_at_epoch"] > now:
            run["expires_at_epoch"] = max(run["expires_at_epoch"], now + HOST_SESSION_IDLE_SECONDS)
            self._put("runs", run["run_id"], run)
        else:
            run_id = "run_" + uuid.uuid4().hex
            token = self._session_token(host_token, run_id)
            run = {"run_id": run_id, "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                   "intent": f"{host['label']} session", "grants": [], "status": "ACTIVE",
                   "created_at": _now(), "created_at_epoch": now, "expires_at_epoch": now + HOST_SESSION_IDLE_SECONDS,
                   "call_count": 0, "untrusted_sources": [], "coverage": "HOST_SESSION",
                   "host_id": host_id, "host_label": host["label"], "host_kind": host["kind"],
                   "approval_window": host["approval_window"]}
            self._put("runs", run_id, run)
            self._put("meta", mapping_key, {"run_id": run_id, "created_at": _now()})
        return {**self._public_run(run), "run_token": self._session_token(host_token, run["run_id"])}

    # Guardrails and catalog ---------------------------------------------------

    @_atomic
    def delete_policy(self, rule_id: str) -> dict:
        rule_id = _identifier(rule_id, "rule_id")
        if not self._get("policies", rule_id):
            raise RuntimeValidationError("Unknown policy")
        self._conn.execute("DELETE FROM rt_policies WHERE id=?", (rule_id,))
        self._bump_version("Operator removed a policy")
        return {"rule_id": rule_id, "deleted": True, "policy_version": self._version()}

    @_atomic
    def apply_guardrail_preset(self, preset: str) -> dict:
        rules = preset_rules(preset)
        for policy in self._all("policies"):
            if policy["rule_id"].startswith(GUARDRAIL_PREFIX):
                self._conn.execute("DELETE FROM rt_policies WHERE id=?", (policy["rule_id"],))
        for rule in rules:
            self.save_policy(rule)
        self._put("meta", "guardrails", {"preset": preset, "applied_at": _now()})
        self._bump_version("Guardrail preset changed")
        return self.guardrails()

    @_atomic
    def guardrails(self) -> dict:
        state = self._get("meta", "guardrails") or {"preset": None, "applied_at": None}
        custom = [p for p in self._all("policies") if not p["rule_id"].startswith(GUARDRAIL_PREFIX)]
        return {**state, "default": DEFAULT_PRESET, "presets": describe_presets(), "custom_rules": len(custom)}

    @_atomic
    def accept_catalog_server(self, server_id: str, catalog_id: str) -> dict:
        server_id = _identifier(server_id, "server_id")
        if catalog_id not in load_catalog():
            raise RuntimeValidationError("Unknown catalog entry")
        state = self._get("meta", "catalog_servers") or {"servers": {}}
        state["servers"][server_id] = catalog_id
        self._put("meta", "catalog_servers", state)
        # Apply to tools already registered and still unclassified.
        for tool in self._all("tools"):
            if tool["server_id"] == server_id and tool["category"] == "UNKNOWN" and tool["status"] == "VERIFIED":
                suggestion = suggested_category(catalog_id, tool["tool_name"])
                if suggestion:
                    tool.update(category=suggestion, available=True, classified_by="catalog:" + catalog_id)
                    self._put("tools", self._tool_key(server_id, tool["tool_name"]), tool)
        return {"servers": state["servers"]}

    @_atomic
    def catalog_servers(self) -> dict:
        return {"servers": (self._get("meta", "catalog_servers") or {"servers": {}})["servers"],
                "catalog": {key: {"label": value["label"], "note": value.get("note"), "tools": len(value["tools"])} for key, value in load_catalog().items()}}

    # Agent hooks ----------------------------------------------------------------

    @_atomic
    def install_builtin_actions(self) -> list[dict]:
        """Register Elytra's fixed agent actions (shell, edits, web) as classified tools.

        These definitions ship with Elytra and describe action classes, not an
        external server's claims, so the operator installs them already classified.
        """
        from mirage_mcp.hooks.classify import ACTIONS, SERVER
        records = []
        for name, (category, description) in ACTIONS.items():
            definition = {"name": name, "description": description, "inputSchema": {"type": "object"}}
            digest = _hash(definition)
            key = self._tool_key(SERVER, name)
            previous = self._get("tools", key)
            record = {"server_id": SERVER, "tool_name": name, "sha256_hash": digest, "observed_sha256_hash": digest,
                      "category": category, "status": "VERIFIED", "pinned_at": previous["pinned_at"] if previous else _now(),
                      "last_verified_at": _now(), "description_preview": description, "description": description,
                      "schema": definition["inputSchema"], "tool_definition": definition, "suspicious_patterns": [],
                      "drift_summary": None, "available": True, "present": True, "requires_review": False,
                      "classified_by": "elytra-builtin"}
            changed = not previous or previous["category"] != category or previous["sha256_hash"] != digest
            self._put("tools", key, record)
            records.append(record)
            if changed and previous:
                self._bump_version("Built-in agent actions updated")
        return records

    @_atomic
    def observe_tool(self, run_id: str, run_token: str, server_id: str, tool_name: str) -> dict:
        """Record one MCP tool seen through an agent hook, without touching the server's other tools."""
        self._run(run_id, run_token)
        server_id, tool_name = _identifier(server_id, "server_id"), _identifier(tool_name, "tool_name")
        from mirage_mcp.hooks.classify import SERVER
        if server_id == SERVER:
            raise RuntimeValidationError("The built-in agent actions cannot be redefined")
        key = self._tool_key(server_id, tool_name)
        existing = self._get("tools", key)
        if existing:
            return existing
        definition = {"name": tool_name, "description": "Observed through an agent hook; the tool schema was not available", "inputSchema": {}}
        digest = _hash(definition)
        accepted = (self._get("meta", "catalog_servers") or {}).get("servers", {})
        suggestion = suggested_category(accepted[server_id], tool_name) if server_id in accepted else None
        record = {"server_id": server_id, "tool_name": tool_name, "sha256_hash": digest, "observed_sha256_hash": digest,
                  "category": suggestion or "UNKNOWN", "status": "VERIFIED", "pinned_at": _now(), "last_verified_at": _now(),
                  "description_preview": definition["description"], "description": definition["description"], "schema": {},
                  "tool_definition": definition, "suspicious_patterns": [], "drift_summary": None,
                  "available": bool(suggestion), "present": True, "requires_review": False,
                  "classified_by": ("catalog:" + accepted[server_id]) if suggestion else None, "observed_via": "hook"}
        self._put("tools", key, record)
        return record

    @_atomic
    def list_events(self, limit=200) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise RuntimeValidationError("Event limit must be between 1 and 10000")
        self._prune()
        return sorted(self._all("events"), key=lambda e: e["timestamp_epoch"], reverse=True)[:limit]

    def _overview(self):
        events = self._all("events")
        calls = self._all("calls")
        runs = {r["run_id"]: r for r in self._all("runs")}
        latencies = sorted(c["eval_latency_ms"] for c in calls)
        pending = sum(c["status"] == "PENDING" and self._valid_binding(c) and runs.get(c["run_id"], {}).get("status") == "ACTIVE" and runs[c["run_id"]]["expires_at_epoch"] > time.time() for c in calls)
        return {"status": "ELEVATED_THREAT" if pending else "OPERATIONAL", "uptime_seconds": int(time.monotonic() - self._started),
                "active_sessions": sum(r["status"] == "ACTIVE" and r["expires_at_epoch"] > time.time() for r in runs.values()),
                "total_events": len(calls), "telemetry_events": len(events),
                "blocked_second_hops": sum(c["status"] in {"BLOCKED", "DENIED"} and bool(c["source_lineage"]) for c in calls),
                "tainted_ingests": sum(c["category"] == "SOURCE_UNTRUSTED" and c["status"] in {"CLAIMED", "COMPLETED", "FAILED", "UNCERTAIN"} for c in calls),
                "clean_passes": sum(c["status"] in {"CLAIMED", "COMPLETED"} and not c["source_lineage"] for c in calls), "pending_approvals": pending,
                "schema_pins_verified": sum(t["status"] == "VERIFIED" and t["category"] != "UNKNOWN" for t in self._all("tools")),
                "schema_drifts_blocked": len({(e["run_id"], e["call_id"]) for e in events if e["decision"] == "SCHEMA_DRIFT_BLOCK"}),
                "secrets_redacted_total": sum(e["secrets_redacted"] for e in events),
                "mean_eval_ms": round(sum(latencies) / len(latencies), 4) if latencies else 0,
                "p99_eval_ms": latencies[min(len(latencies)-1, int(len(latencies)*.99))] if latencies else 0,
                "attack_block_rate_pct": None, "false_positive_rate_pct": None,
                "mode": "live", "policy_version": self._version(), "coverage": "EXPLICIT_RUN"}

    @_atomic
    def overview(self) -> dict:
        self._prune()
        return self._overview()

    @_atomic
    def topology(self) -> dict:
        events = sorted(self._all("events"), key=lambda e: e["timestamp_epoch"])
        tools, nodes, edges = self._all("tools"), [], []
        calls = self._all("calls")
        for tool in tools:
            relevant = [c for c in calls if c["server_id"] == tool["server_id"] and c["tool_name"] == tool["tool_name"]]
            nodes.append({"id": "mcp:" + tool["server_id"] + ":" + tool["tool_name"], "label": tool["tool_name"],
                          "role": "sink" if tool["category"] in SINKS else "source", "server_id": tool["server_id"],
                          "risk_score": 80 if tool["category"] in SINKS else 40 if tool["category"] == "SOURCE_UNTRUSTED" else 0,
                          "tainted": any(c["category"] == "SOURCE_UNTRUSTED" and c["status"] in {"CLAIMED", "COMPLETED", "FAILED", "UNCERTAIN"} for c in relevant),
                          "taint_level": "HIGH" if tool["category"] == "SOURCE_UNTRUSTED" else "CLEAN", "blocked_count": sum(c["status"] == "BLOCKED" for c in relevant),
                          "call_count": len(relevant), "category": tool["category"], "description": tool["description_preview"], "schema_hash": tool["sha256_hash"]})
        # Observed cross-server lineage only; potential edges are not fabricated.
        for call in calls:
            if call["category"] not in SINKS:
                continue
            for index, source in enumerate(call["source_lineage"]):
                server, _, name = source.partition(".")
                edges.append({"id": call["call_id"] + ":" + str(index) + ":" + call["run_id"], "source": "mcp:" + server + ":" + name,
                              "target": "mcp:" + call["server_id"] + ":" + call["tool_name"], "edge_type": "blocked_hop" if call["status"] in {"BLOCKED", "DENIED", "INVALIDATED", "CANCELLED"} else "sink_call",
                              "status": "STEP_UP_PENDING" if call["status"] == "PENDING" else "BLOCKED" if call["status"] in {"BLOCKED", "DENIED", "INVALIDATED", "CANCELLED"} else "ALLOWED",
                              "rule_id": call.get("rule_id"), "reason": call["reason"], "timestamp": call["created_at"], "run_id": call["run_id"]})
        overview = self._overview()
        return {"schema_version": "1.0", "generated_at": _now(), "session_id": "explicit-runs", "stats": {
                    "total_events": len(calls), "tainted_nodes": sum(n["tainted"] for n in nodes), "blocked_calls": sum(c["status"] in {"BLOCKED", "DENIED"} for c in calls),
                    "allowed_calls": sum(c["status"] in {"CLAIMED", "COMPLETED"} for c in calls), "mean_eval_ms": overview["mean_eval_ms"], "p99_eval_ms": overview["p99_eval_ms"],
                    "step_up_pending": overview["pending_approvals"], "schema_pins_verified": overview["schema_pins_verified"]}, "nodes": nodes, "edges": edges, "mode": "live", "coverage": "EXPLICIT_RUN"}

    @_atomic
    def health_summary(self) -> dict:
        return {"status": "ok", "mode": "live", "coverage": "EXPLICIT_RUN", "policy_version": self._version(),
                "retention_days": 7, "event_limit": 10000, "payload_limit_bytes": MAX_PAYLOAD, "calls_per_run_limit": 1000,
                "dispatch_guarantee": "at-most-once; outcome uncertain after crash", "generic_host_coverage": "inventory only",
                "tool_registry_limit": 1000, "tool_metadata_limit_bytes": 4 * 1024 * 1024, "approval_preview_limit_bytes": 16384}

    def close(self):
        with self._lock:
            if not self._closed:
                try:
                    if self._conn is not None:
                        self._conn.close()
                finally:
                    self._closed = True
                    if self._process_lock_fd is not None:
                        import fcntl
                        fd, self._process_lock_fd = self._process_lock_fd, None
                        try:
                            fcntl.flock(fd, fcntl.LOCK_UN)
                        finally:
                            os.close(fd)
