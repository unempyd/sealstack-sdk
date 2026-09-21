"""Canonical signed-event construction, SDK failure types and local diagnostics.

SPEC §27 (lifecycle), §28 (event types), §30–§31 (digests), §33 (closed
``Event`` record), §45–§47 (failure modes), §48–§50 (local failure log).

Every diagnostic path here is best effort: a broken logging handler or an
unwritable failure log must never change a business outcome (§46–§47).
"""

from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import Any, Final
from uuid import uuid4

from sealstack.signing import (
    UNSUPPORTED_DIGEST,
    canonicalize,
    digest,
    is_supported,
    now_timestamp,
)

EVENT_SCHEMA_VERSION: Final[int] = 1
METADATA_MAX_BYTES: Final[int] = 16384

ACTION_STARTED: Final[str] = "action.started"
ACTION_COMPLETED: Final[str] = "action.completed"
ACTION_FAILED: Final[str] = "action.failed"

#: Field order is irrelevant to JCS but fixed here for readable stored rows.
EVENT_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "event_id",
    "organisation_id",
    "agent_id",
    "agent_key_id",
    "runtime_id",
    "sequence",
    "previous_event_hash",
    "event_type",
    "action_id",
    "action_name",
    "occurred_at",
    "resource",
    "input_digest",
    "output_digest",
    "error_type",
    "metadata",
)


class AuditFailure(Exception):
    """The SDK could not create, sign or durably store audit evidence.

    Raised out of ``@audit.track``/``audit.action`` only when
    ``failure_mode="raise"``; in ``continue`` mode it is caught, reported
    through the local diagnostics and the business call proceeds (§45–§47).
    """


def new_uuid() -> str:
    """Return a fresh lowercase hyphenated UUIDv4 string (§33)."""
    return str(uuid4())


def error_type_of(exc: BaseException) -> str:
    """Return the qualified exception class name recorded in ``error_type``.

    Only the class name is ever recorded; exception text is never signed or
    uploaded (§33, §49).
    """
    cls = type(exc)
    return f"{cls.__module__}.{cls.__qualname__}"


def input_digest_for_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Digest a decorated call's raw binding, computed before execution (§33).

    Defaults are not bound and positional/keyword spellings stay distinct.
    """
    return digest({"args": list(args), "kwargs": dict(kwargs)})


def resource_field(
    resource_type: str | None, resource_id: str | None
) -> dict[str, str | None] | None:
    """Build the §33 ``Resource`` value, or ``None`` when both parts are absent.

    Values must already be strings; identifiers are never stringified.
    """
    if resource_type is None and resource_id is None:
        return None
    for value in (resource_type, resource_id):
        if value is not None and not isinstance(value, str):
            raise AuditFailure("invalid_resource: resource values must be strings or null")
    return {"type": resource_type, "id": resource_id}


def metadata_snapshot(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Capture and validate the per-invocation metadata snapshot (§33).

    A deep copy is taken so that later mutation by the business function cannot
    change what the terminal event commits to.
    """
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise AuditFailure("invalid_metadata: metadata must be an object")
    snapshot = copy.deepcopy(metadata)
    if not is_supported(snapshot):
        raise AuditFailure("invalid_metadata: value outside the §30 profile")
    if len(canonicalize(snapshot)) > METADATA_MAX_BYTES:
        raise AuditFailure("invalid_metadata: canonical metadata exceeds 16384 bytes")
    return snapshot


def build_event(
    *,
    event_id: str,
    organisation_id: str,
    agent_id: str,
    agent_key_id: str,
    runtime_id: str,
    sequence: int,
    previous_event_hash: str | None,
    event_type: str,
    action_id: str,
    action_name: str,
    occurred_at: str,
    resource: dict[str, str | None] | None,
    input_digest: dict[str, Any],
    output_digest: dict[str, Any] | None,
    error_type: str | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the closed §33 ``Event`` record with every null made explicit."""
    event = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": event_id,
        "organisation_id": organisation_id,
        "agent_id": agent_id,
        "agent_key_id": agent_key_id,
        "runtime_id": runtime_id,
        "sequence": sequence,
        "previous_event_hash": previous_event_hash,
        "event_type": event_type,
        "action_id": action_id,
        "action_name": action_name,
        "occurred_at": occurred_at,
        "resource": resource,
        "input_digest": input_digest,
        "output_digest": output_digest,
        "error_type": error_type,
        "metadata": metadata,
    }
    assert tuple(event) == EVENT_FIELDS  # closed record; no field may drift
    return event


LOGGER: Final[logging.Logger] = logging.getLogger("sealstack")


def log_error(message: str, *args: Any) -> None:
    """Emit ``logging.ERROR`` without ever letting the handler break a caller."""
    try:
        LOGGER.error(message, *args)
    except BaseException:  # noqa: BLE001, S110 - diagnostics must never propagate
        pass


def log_warning(message: str, *args: Any) -> None:
    """Emit a high-severity local warning, suppressing handler failures."""
    try:
        LOGGER.warning(message, *args)
    except BaseException:  # noqa: BLE001, S110 - diagnostics must never propagate
        pass


def escape_controls(text: str) -> str:
    """Escape every C0 control character and DEL as ``\\xHH`` (§48).

    This is what keeps one failure record on exactly one physical line.
    """
    parts: list[str] = []
    for character in text:
        code = ord(character)
        parts.append(f"\\x{code:02X}" if code < 32 or code == 127 else character)
    return "".join(parts)


class FailureLog:
    """The local, never-uploaded ``audit_sdk_failures.log`` (§48–§50).

    One physical line per record, at most two files ever retained.
    """

    FILENAME: Final[str] = "audit_sdk_failures.log"
    MESSAGE_LIMIT: Final[int] = 512

    def __init__(self, state_dir: Path | str, max_bytes: int = 10 * 1024 * 1024) -> None:
        self.path = Path(state_dir) / self.FILENAME
        self.backup = self.path.with_name(self.FILENAME + ".1")
        self.max_bytes = int(max_bytes)

    def record(
        self,
        *,
        agent_id: str | None,
        runtime_id: str | None,
        action_name: str | None,
        error: BaseException,
    ) -> None:
        """Append one diagnostic record; never raises."""
        try:
            self._write(self._format(agent_id, runtime_id, action_name, error))
        except BaseException:  # noqa: BLE001, S110 - diagnostics must never propagate
            pass

    def _format(
        self,
        agent_id: str | None,
        runtime_id: str | None,
        action_name: str | None,
        error: BaseException,
    ) -> str:
        fields = (
            now_timestamp(),
            agent_id or "-",
            runtime_id or "-",
            action_name or "-",
            error_type_of(error),
            str(error)[: self.MESSAGE_LIMIT],
        )
        return " | ".join(escape_controls(field) for field in fields) + "\n"

    def _write(self, record: str) -> None:
        raw = record.encode("utf-8")
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        if size and size + len(raw) > self.max_bytes:
            os.replace(self.path, self.backup)
        with open(self.path, "ab") as handle:
            handle.write(raw)


__all__ = [
    "ACTION_COMPLETED",
    "ACTION_FAILED",
    "ACTION_STARTED",
    "EVENT_SCHEMA_VERSION",
    "METADATA_MAX_BYTES",
    "UNSUPPORTED_DIGEST",
    "AuditFailure",
    "FailureLog",
    "build_event",
    "error_type_of",
    "escape_controls",
    "input_digest_for_call",
    "log_error",
    "log_warning",
    "metadata_snapshot",
    "new_uuid",
    "resource_field",
]
