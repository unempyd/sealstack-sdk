"""Durable local SQLite audit queue.

SPEC §39 (queue layout, PRAGMAs, append/acknowledge protocol), §40 (capacity),
§43–§44 (retry classification and permanent-failure propagation).

``sqlite3`` is imported at module level and ``sqlite3.connect`` is resolved as a
module attribute at call time so that every connection this module opens is
observable at the dependency boundary.
"""

from __future__ import annotations

import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from sealstack.events import AuditFailure

QUEUE_FILENAME: Final[str] = "audit_queue.db"
TABLE: Final[str] = "audit_queue"

PENDING: Final[str] = "pending"
UPLOADED: Final[str] = "uploaded"
FAILED_RETRYABLE: Final[str] = "failed_retryable"
FAILED_PERMANENT: Final[str] = "failed_permanent"
UNRESOLVED: Final[tuple[str, str]] = (PENDING, FAILED_RETRYABLE)

BUSY_TIMEOUT_MS: Final[int] = 5000

_SCHEMA: Final[str] = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    event_id TEXT NOT NULL UNIQUE,
    runtime_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    server_receipt TEXT,
    last_error TEXT,
    restart_required INTEGER NOT NULL DEFAULT 0,
    UNIQUE(runtime_id, sequence)
)
"""

_INSERT: Final[str] = f"""
INSERT INTO {TABLE} (
    event_id, runtime_id, sequence, event_json, event_hash, signature,
    state, attempt_count, created_at, acknowledged_at, server_receipt,
    last_error, restart_required
) VALUES (?, ?, ?, ?, ?, ?, '{PENDING}', 0, ?, NULL, NULL, NULL, 0)
"""


@dataclass(frozen=True, slots=True)
class PendingEvent:
    """The immutable bytes of one signed event awaiting durable storage."""

    event_id: str
    runtime_id: str
    sequence: int
    event_json: str
    event_hash: str
    signature: str
    created_at: str


@dataclass(frozen=True, slots=True)
class AppendResult:
    """Outcome of one §39 append attempt.

    ``committed`` rows may advance the in-memory runtime head. ``blocked``
    means the commit outcome could not be established, so further signing for
    this runtime must stop rather than guess the next sequence.
    """

    committed: bool
    blocked: bool = False
    head: tuple[int, str] | None = None
    error: BaseException | None = None


def _storage_failure(message: str, cause: BaseException | None = None) -> AuditFailure:
    failure = AuditFailure(f"audit_storage_failure: {message}")
    if cause is not None:
        failure.__cause__ = cause
    return failure


def connect(path: Path | str) -> sqlite3.Connection:
    """Open a queue connection with the §39 durability settings verified."""
    connection = sqlite3.connect(
        str(path),
        isolation_level=None,
        check_same_thread=False,
        timeout=BUSY_TIMEOUT_MS / 1000,
    )
    try:
        connection.row_factory = sqlite3.Row
        _configure(connection)
    except BaseException:
        try:
            connection.close()
        except BaseException:  # noqa: BLE001, S110 - the open error is the real one
            pass
        raise
    return connection


def _configure(connection: sqlite3.Connection) -> None:
    """Apply and verify the required PRAGMAs on a freshly opened connection."""
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    required: list[tuple[str, Any]] = [
        ("journal_mode", "wal"),
        ("synchronous", 2),
        ("busy_timeout", BUSY_TIMEOUT_MS),
    ]
    if sys.platform == "darwin":
        connection.execute("PRAGMA fullfsync=ON")
        connection.execute("PRAGMA checkpoint_fullfsync=ON")
        required += [("fullfsync", 1), ("checkpoint_fullfsync", 1)]
    for name, expected in required:
        row = connection.execute(f"PRAGMA {name}").fetchone()
        observed = None if row is None else row[0]
        if isinstance(expected, str):
            observed = str(observed).lower()
        if observed != expected:
            raise _storage_failure(f"PRAGMA {name}={observed!r}, required {expected!r}")


class EventQueue:
    """One connection onto ``audit_queue.db``.

    Each owner (the runtime writer, the uploader thread) holds its own
    instance; SQLite serialises them through WAL and ``busy_timeout``.
    """

    def __init__(self, state_dir: Path | str) -> None:
        self.path = Path(state_dir) / QUEUE_FILENAME
        self._connection = connect(self.path)
        try:
            self._connection.execute(_SCHEMA)
        except sqlite3.Error as exc:  # pragma: no cover - creation is trivially stable
            self.close()
            raise _storage_failure(f"cannot create queue schema: {exc}", exc) from exc

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        try:
            self._connection.close()
        except BaseException:  # noqa: BLE001, S110 - closing must never fail a caller
            pass

    def _discard_connection(self) -> None:
        """Drop a connection whose transaction outcome is unknown."""
        self.close()

    def _reopen(self) -> None:
        self._connection = connect(self.path)

    def _rollback_quietly(self) -> None:
        try:
            self._connection.execute("ROLLBACK")
        except BaseException:  # noqa: BLE001, S110 - a failed rollback adds nothing
            pass

    # -- append (§39) ------------------------------------------------------

    def append(self, event: PendingEvent) -> AppendResult:
        """Durably append one signed event, reporting the exact commit outcome."""
        parameters = (
            event.event_id,
            event.runtime_id,
            event.sequence,
            event.event_json,
            event.event_hash,
            event.signature,
            event.created_at,
        )
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except BaseException as exc:  # noqa: BLE001 - any failure is a definite failure
            self._rollback_quietly()
            return AppendResult(committed=False, error=exc)
        try:
            self._connection.execute(_INSERT, parameters)
        except BaseException as exc:  # noqa: BLE001 - any failure is a definite failure
            self._rollback_quietly()
            return AppendResult(committed=False, error=exc)
        try:
            self._connection.execute("COMMIT")
        except BaseException as exc:  # noqa: BLE001 - the outcome is now ambiguous
            return self._reconcile_ambiguous_commit(event, exc)
        return AppendResult(committed=True)

    def _reconcile_ambiguous_commit(
        self, event: PendingEvent, exc: BaseException
    ) -> AppendResult:
        """Resolve an unknown commit result by inspecting the reopened queue (§39).

        The attempted event bytes and the runtime lock are retained by the
        caller; a conflicting or unreadable row blocks further signing rather
        than guessing whether the sequence was consumed.
        """
        self._discard_connection()
        try:
            self._reopen()
            row = self._connection.execute(
                f"SELECT event_json, event_hash, signature FROM {TABLE} WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
        except BaseException as reopen_error:  # noqa: BLE001 - never guess
            return AppendResult(committed=False, blocked=True, error=reopen_error)
        if row is None:
            return AppendResult(committed=False, error=exc)
        stored = (row["event_json"], row["event_hash"], row["signature"])
        if stored != (event.event_json, event.event_hash, event.signature):
            return AppendResult(committed=False, blocked=True, error=exc)
        try:
            head = self.head(event.runtime_id)
        except BaseException as head_error:  # noqa: BLE001 - never guess
            return AppendResult(committed=False, blocked=True, error=head_error)
        if head is None:  # cannot happen once the row is present, but never guess
            return AppendResult(committed=False, blocked=True, error=exc)
        return AppendResult(committed=True, head=head)

    def head(self, runtime_id: str) -> tuple[int, str] | None:
        """Return ``(sequence, event_hash)`` of the highest committed row."""
        row = self._connection.execute(
            f"SELECT sequence, event_hash FROM {TABLE} WHERE runtime_id = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (runtime_id,),
        ).fetchone()
        if row is None:
            return None
        return int(row["sequence"]), str(row["event_hash"])

    def count_unresolved(self) -> int:
        """Count rows that are neither uploaded nor permanently failed (§40)."""
        row = self._connection.execute(
            f"SELECT count(*) FROM {TABLE} WHERE state IN (?, ?)", UNRESOLVED
        ).fetchone()
        return int(row[0])

    # -- upload selection (§41) --------------------------------------------

    def select_upload_batch(self) -> list[dict[str, Any]]:
        """Lowest unresolved row per eligible runtime, in sequence order.

        Runtimes holding a permanent failure or a row that requires a restart
        are skipped entirely: their chain cannot progress until a new runtime
        is created (§44).
        """
        blocked = {
            row["runtime_id"]
            for row in self._connection.execute(
                f"SELECT DISTINCT runtime_id FROM {TABLE} "
                "WHERE state = ? OR (restart_required = 1 AND state IN (?, ?))",
                (FAILED_PERMANENT, *UNRESOLVED),
            )
        }
        batch: dict[str, dict[str, Any]] = {}
        for row in self._connection.execute(
            f"SELECT * FROM {TABLE} WHERE state IN (?, ?) ORDER BY runtime_id, sequence",
            UNRESOLVED,
        ):
            runtime_id = row["runtime_id"]
            if runtime_id in blocked or runtime_id in batch:
                continue
            batch[runtime_id] = dict(row)
        return list(batch.values())

    def has_row(self, runtime_id: str, sequence: int) -> bool:
        row = self._connection.execute(
            f"SELECT 1 FROM {TABLE} WHERE runtime_id = ? AND sequence = ?",
            (runtime_id, sequence),
        ).fetchone()
        return row is not None

    # -- state transitions -------------------------------------------------

    def acknowledge(self, event_id: str, receipt_json: str, acknowledged_at: str) -> None:
        """Store the receipt and mark ``uploaded`` in one transaction (§39/§43)."""
        self._transaction(
            (
                (
                    f"UPDATE {TABLE} SET state = ?, server_receipt = ?, acknowledged_at = ?, "
                    "last_error = NULL WHERE event_id = ? AND state IN (?, ?)"
                ),
                (UPLOADED, receipt_json, acknowledged_at, event_id, *UNRESOLVED),
            )
        )

    def mark_retryable(
        self, event_ids: list[str], last_error: str, restart_required: bool = False
    ) -> None:
        """Retain signed bytes, count the attempt and schedule a later retry (§43)."""
        if not event_ids:
            return
        statements = [
            (
                (
                    f"UPDATE {TABLE} SET state = ?, attempt_count = attempt_count + 1, "
                    "last_error = ?, restart_required = max(restart_required, ?) "
                    "WHERE event_id = ? AND state IN (?, ?)"
                ),
                (
                    FAILED_RETRYABLE,
                    last_error,
                    1 if restart_required else 0,
                    event_id,
                    *UNRESOLVED,
                ),
            )
            for event_id in event_ids
        ]
        self._transaction(*statements)

    def mark_permanent(self, event_id: str, runtime_id: str, sequence: int, reason: str) -> None:
        """Fail one row permanently and strand its unresolved descendants (§44)."""
        self._transaction(
            (
                (
                    f"UPDATE {TABLE} SET state = ?, last_error = ?, restart_required = 1 "
                    "WHERE event_id = ?"
                ),
                (FAILED_PERMANENT, reason, event_id),
            ),
            (
                (
                    f"UPDATE {TABLE} SET state = ?, last_error = ?, restart_required = 1 "
                    "WHERE runtime_id = ? AND sequence > ? AND state IN (?, ?)"
                ),
                (
                    FAILED_PERMANENT,
                    f"stranded_after:{event_id}",
                    runtime_id,
                    sequence,
                    *UNRESOLVED,
                ),
            ),
        )

    def _transaction(self, *statements: tuple[str, tuple[Any, ...]]) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            for sql, parameters in statements:
                self._connection.execute(sql, parameters)
            self._connection.execute("COMMIT")
        except BaseException as exc:
            self._rollback_quietly()
            raise _storage_failure(str(exc), exc) from exc


__all__ = [
    "FAILED_PERMANENT",
    "FAILED_RETRYABLE",
    "PENDING",
    "QUEUE_FILENAME",
    "UNRESOLVED",
    "UPLOADED",
    "AppendResult",
    "EventQueue",
    "PendingEvent",
    "connect",
]
