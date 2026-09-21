"""``AuditClient``: the one object a customer constructs.

SPEC §14 (registration), §23 (runtime identity), §24 (exclusive ownership and
the runtime serialization lock), §39–§40 (durable queue), §44 (permanent
failure), §45–§47 (failure modes), §48 (local failure log).

The runtime lock serialises event construction, canonicalisation, hashing,
signing, the SQLite append and the in-memory head update, plus identity
mutation. It is never held across an HTTP request or a business call.
"""

from __future__ import annotations

import os
import threading
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sealstack.decorator import CONTINUE, RAISE, ActionContext
from sealstack.decorator import track as _track
from sealstack.events import (
    AuditFailure,
    FailureLog,
    build_event,
    log_error,
    log_warning,
    new_uuid,
)
from sealstack.identity import DirectoryLock, Identity
from sealstack.queue import EventQueue, PendingEvent
from sealstack.signing import canonicalize, now_timestamp, sha256_hash
from sealstack.uploader import Uploader

DEFAULT_BASE_URL = "https://api.sealstack.com"
DEFAULT_QUEUE_WARNING_THRESHOLD = 10000
DEFAULT_FAILURE_LOG_MAX_BYTES = 10 * 1024 * 1024
FAILURE_MODES = (CONTINUE, RAISE)
STATE_DIR_ENV_VAR = "SEALSTACK_STATE_DIR"

_LIVE_CLIENTS: weakref.WeakSet[AuditClient] = weakref.WeakSet()


class AuditClient:
    """A single live owner of one local state directory (§24)."""

    def __init__(
        self,
        api_key: str,
        agent_name: str,
        base_url: str | None = None,
        state_dir: Path | str | None = None,
        environment: str = "development",
        failure_mode: str = CONTINUE,
        queue_warning_threshold: int = DEFAULT_QUEUE_WARNING_THRESHOLD,
        failure_log_max_bytes: int = DEFAULT_FAILURE_LOG_MAX_BYTES,
        upload_interval: float = 1.0,
        upload_timeout: float = 30.0,
        max_upload_delay: float = 60.0,
    ) -> None:
        if failure_mode not in FAILURE_MODES:
            raise ValueError(f"failure_mode must be one of {FAILURE_MODES}")
        self.failure_mode = failure_mode
        self.agent_name = agent_name
        self.queue_warning_threshold = int(queue_warning_threshold)
        self.base_url = (base_url or os.environ.get("SEALSTACK_API_URL") or DEFAULT_BASE_URL)
        env_state_dir = os.environ.get(STATE_DIR_ENV_VAR)
        self.state_dir = (
            Path(state_dir)
            if state_dir is not None
            else Path(env_state_dir) if env_state_dir else Path.home() / ".sealstack" / agent_name
        )

        # Held for every append and every identity mutation.
        self._runtime_lock = threading.RLock()
        self._closed = False
        self._forked = False
        self._signing_blocked_reason: str | None = None
        self._head_sequence = 0
        self._head_hash: str | None = None

        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        self.failure_log = FailureLog(self.state_dir, failure_log_max_bytes)

        # §24: exclusive ownership before identity, queue, keys or uploader.
        self._directory_lock = DirectoryLock(self.state_dir)
        self._directory_lock.acquire()
        self.identity: Identity | None = None
        self.queue: EventQueue | None = None
        self._uploader: Uploader | None = None
        try:
            self.identity = Identity(
                self.state_dir,
                agent_name=agent_name,
                environment=environment,
                base_url=self.base_url,
                api_key=api_key,
            )
            self.identity.ensure_registered()
            self.queue = EventQueue(self.state_dir)
            #: §23: a runtime never survives a process restart.
            self.runtime_id = new_uuid()
            self._uploader = Uploader(
                self.state_dir,
                api_key=api_key,
                base_url=self.base_url,
                client=self,
                timeout=upload_timeout,
                max_delay=max_upload_delay,
                interval=upload_interval,
            )
            _LIVE_CLIENTS.add(self)
            self._uploader.start()
        except BaseException:
            self._release_resources()
            raise

    # -- instrumentation API (§25) ----------------------------------------

    def track(
        self,
        action: str | Callable[..., Any] | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Callable[..., Any]:
        """Decorate a sync or async function as one audited action."""
        return _track(self, action, resource_type, resource_id, metadata)

    def action(
        self,
        name: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ActionContext:
        """Audit a manual block, with either ``with`` or ``async with``."""
        return ActionContext(self, name, resource_type, resource_id, metadata)

    # -- runtime state -----------------------------------------------------

    @property
    def runtime_lock(self) -> threading.RLock:
        """The §24 runtime serialization lock."""
        return self._runtime_lock

    @property
    def signing_blocked(self) -> bool:
        return self._signing_blocked_reason is not None

    @property
    def agent_key_id(self) -> str | None:
        """The key ID this runtime signs with, or ``None`` when unregistered."""
        return None if self.identity is None else self.identity.agent_key_id

    @property
    def key_fingerprint(self) -> str | None:
        """The registered fingerprint of the active agent key (§16)."""
        return None if self.identity is None else self.identity.key_fingerprint

    def block_signing(self, reason: str) -> None:
        """Stop creating signed events for this runtime until restart (§44)."""
        with self._runtime_lock:
            if self._signing_blocked_reason is None:
                self._signing_blocked_reason = reason
                log_warning(
                    "sealstack: signing blocked for runtime %s (%s); a process restart is "
                    "required to start a new runtime",
                    getattr(self, "runtime_id", "-"),
                    reason,
                )

    # -- append protocol (§39) ---------------------------------------------

    def append_event(
        self,
        *,
        event_type: str,
        action_id: str,
        action_name: str,
        resource: dict[str, str | None] | None,
        input_digest: dict[str, Any],
        output_digest: dict[str, Any] | None,
        error_type: str | None,
        metadata: dict[str, Any],
    ) -> None:
        """Construct, sign and durably append one event, then advance the head.

        Raises :class:`AuditFailure` unless the row is known to be committed.
        """
        with self._runtime_lock:
            identity, queue = self._require_signable()
            sequence = self._head_sequence + 1
            event = build_event(
                event_id=new_uuid(),
                organisation_id=str(identity.organisation_id),
                agent_id=identity.agent_id,
                agent_key_id=str(identity.agent_key_id),
                runtime_id=self.runtime_id,
                sequence=sequence,
                previous_event_hash=self._head_hash,
                event_type=event_type,
                action_id=action_id,
                action_name=action_name,
                occurred_at=now_timestamp(),
                resource=resource,
                input_digest=input_digest,
                output_digest=output_digest,
                error_type=error_type,
                metadata=metadata,
            )
            raw = canonicalize(event)
            event_hash = sha256_hash(raw)
            pending = PendingEvent(
                event_id=str(event["event_id"]),
                runtime_id=self.runtime_id,
                sequence=sequence,
                event_json=raw.decode("utf-8"),
                event_hash=event_hash,
                signature=identity.sign(raw),
                created_at=now_timestamp(),
            )
            result = queue.append(pending)
            if result.committed:
                self._head_sequence, self._head_hash = result.head or (sequence, event_hash)
                self._warn_when_queue_is_large(queue)
                return
            if result.blocked:
                self.block_signing("ambiguous_append")
                raise AuditFailure(
                    "audit_storage_failure: append outcome could not be established"
                ) from result.error
            raise AuditFailure("audit_storage_failure: append did not commit") from result.error

    def _require_signable(self) -> tuple[Identity, EventQueue]:
        if self._closed:
            raise AuditFailure("signing_blocked: client is closed")
        if self._forked:
            raise AuditFailure("signing_blocked: inherited client invalidated by fork")
        if self._signing_blocked_reason is not None:
            raise AuditFailure(f"signing_blocked: {self._signing_blocked_reason}")
        identity, queue = self.identity, self.queue
        if identity is None or queue is None:  # pragma: no cover - constructor guarantees both
            raise AuditFailure("signing_blocked: client is not initialised")
        if not identity.can_sign and not identity.ensure_registered():
            raise AuditFailure(f"signing_blocked: {identity.blocked_reason}")
        return identity, queue

    def _warn_when_queue_is_large(self, queue: EventQueue) -> None:
        """Warn above the configured threshold; rows are never dropped (§40)."""
        try:
            unresolved = queue.count_unresolved()
        except Exception as exc:  # noqa: BLE001 - counting must not fail an append
            log_error("sealstack: could not measure the audit queue: %s", exc)
            return
        if unresolved > self.queue_warning_threshold:
            log_warning(
                "sealstack: %d unresolved audit events exceed queue_warning_threshold=%d "
                "in %s; no rows are deleted",
                unresolved,
                self.queue_warning_threshold,
                self.state_dir,
            )

    # -- diagnostics (§48) -------------------------------------------------

    def diagnose(self, action_name: str | None, error: BaseException) -> None:
        """Emit best-effort diagnostics for an audit failure; never raises."""
        cause = error.__cause__ if error.__cause__ is not None else error
        log_error(
            "sealstack: audit failure for action %s: %s: %s",
            action_name or "-",
            type(cause).__name__,
            cause,
        )
        identity = self.identity
        self.failure_log.record(
            agent_id=None if identity is None else identity.agent_id,
            runtime_id=getattr(self, "runtime_id", None),
            action_name=action_name,
            error=cause,
        )

    # -- shutdown (§24) ----------------------------------------------------

    def close(self) -> None:
        """Stop local work, close the queue and release the directory lock."""
        if self._closed:
            return
        self._closed = True
        _LIVE_CLIENTS.discard(self)
        self._release_resources()

    def _release_resources(self) -> None:
        if self._uploader is not None:
            try:
                self._uploader.stop()
            except BaseException as exc:  # noqa: BLE001 - shutdown is best effort
                log_error("sealstack: uploader shutdown failed: %s", exc)
        if self.queue is not None:
            self.queue.close()
        self._directory_lock.release()

    def _invalidate_after_fork(self) -> None:
        """Refuse queue, signer and uploader use in a forked child (§24)."""
        self._forked = True
        self._closed = True
        self._signing_blocked_reason = "forked_child"
        if self._uploader is not None:
            self._uploader.halt("forked_child")
        self._directory_lock.abandon()

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown ordering
        try:
            if not getattr(self, "_closed", True):
                self.close()
        except BaseException:  # noqa: BLE001, S110 - finalisers must stay silent
            pass


def _invalidate_inherited_clients() -> None:
    """``after_in_child`` fork hook: inherited clients may never be used (§24)."""
    for client in list(_LIVE_CLIENTS):
        try:
            client._invalidate_after_fork()
        except BaseException:  # noqa: BLE001, S110 - a child must still run
            pass
    _LIVE_CLIENTS.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_invalidate_inherited_clients)


__all__ = ["AuditClient", "AuditFailure"]
