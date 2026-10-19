"""Personal link: approve this machine's held actions from another device.

The local runtime, its database, presets and hooks stay authoritative. The link uploads
redacted summaries of pending approvals and applies signed decisions that match a held
action exactly. It never uploads tool results or credentials, and losing the connection
never allows anything: the action keeps waiting for a local decision.
"""
from __future__ import annotations
import threading
import time
from .client import CloudClient, CloudError, EnvelopeVerifier

IDLE_SECONDS = 900  # A held action wakes the link at once; the idle check only keeps "last seen" fresh.
PENDING_SECONDS = 4


class LinkedConnector:
    def __init__(self, runtime, credentials):
        self.runtime = runtime
        self.origin = credentials['origin']
        self.client = CloudClient(credentials['origin'], credentials['device_id'], credentials['device_secret'])
        self.verifier = EnvelopeVerifier(credentials['signing_keys'], credentials['workspace_id'], credentials['device_id'])
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self.last_sync = None
        self.last_error = None
        self.applied = 0
        self.rejected = 0

    def notify(self, event=None):
        self._wake.set()

    def sync_once(self):
        approvals = self.runtime.link_snapshot()
        response = self.client.request('/devices/link-sync', {'approvals': approvals})
        for envelope in response.get('decisions', [])[:30]:
            # Only a signed, unexpired decision for this device and account is ever applied.
            try:
                payload = self.verifier.verify(envelope, 'approval')
            except (CloudError, KeyError, TypeError):
                self.rejected += 1
                continue
            try:
                self.runtime.apply_remote_decision(payload)
                self.applied += 1
            except (PermissionError, ValueError, RuntimeError):
                pass  # Already decided locally, expired, or no longer the same action.
        self.last_sync, self.last_error = time.time(), None
        return bool(approvals)

    def status(self):
        return {'linked': True, 'origin': self.origin, 'connected': self.last_error is None and self.last_sync is not None,
                'last_sync': self.last_sync, 'last_error': self.last_error, 'decisions_applied': self.applied}

    def _run(self):
        retry = 3
        while not self._stop.is_set():
            began = time.monotonic()
            try:
                pending = self.sync_once()
                retry = 3
                delay = PENDING_SECONDS if pending else IDLE_SECONDS
            except (CloudError, KeyError, TypeError):
                self.last_error = 'Account link unavailable; held actions still wait for a local decision'
                delay = retry
                retry = min(120, retry * 2)
            self._wake.wait(delay)
            self._wake.clear()
            self._stop.wait(max(0, 2 - (time.monotonic() - began)))

    def start(self):
        if self._thread:
            return
        self._thread = threading.Thread(target=self._run, name='elytra-link', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=20)
