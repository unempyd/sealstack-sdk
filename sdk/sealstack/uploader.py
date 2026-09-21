"""Background upload of durable queue rows to the ingestion API.

SPEC §41 (ordering), §42 (statuses), §43 (retry classification), §44 (retry
behaviour and permanent-failure propagation), §92–§93 (batch API).

``httpx`` is imported at module level and ``httpx.post`` is resolved as a
module attribute at call time so every request is observable at the dependency
boundary. No upload ever holds the runtime lock across an HTTP request.
"""

from __future__ import annotations

import json
import random
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import httpx

from sealstack.events import log_error, log_warning
from sealstack.queue import EventQueue
from sealstack.signing import b64url_decode, is_hash, now_timestamp

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from sealstack.client import AuditClient

ACCEPTED_STATUSES: Final[frozenset[str]] = frozenset({"accepted", "duplicate"})
RETRYABLE_STATUSES: Final[frozenset[str]] = frozenset({"missing_previous"})
PERMANENT_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "conflict",
        "invalid_signature",
        "invalid_hash",
        "unknown_agent",
        "agent_revoked",
        "organisation_mismatch",
        "revoked_key",
        "retired_key",
        "invalid_chain",
        "invalid_schema",
        "invalid_timestamp",
    }
)
KNOWN_STATUSES: Final[frozenset[str]] = (
    ACCEPTED_STATUSES | RETRYABLE_STATUSES | PERMANENT_STATUSES
)

RECEIPT_SCHEMA_VERSION: Final[int] = 2
SIGNATURE_BYTES: Final[int] = 64
BATCH_PATH: Final[str] = "/v1/events/batch"


class Uploader:
    """Uploads one event per runtime per attempt and classifies the outcome."""

    def __init__(
        self,
        state_dir: Path | str,
        *,
        api_key: str,
        base_url: str,
        client: AuditClient,
        timeout: float = 30.0,
        max_delay: float = 60.0,
        interval: float = 1.0,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._api_key = api_key
        self._url = base_url.rstrip("/") + BATCH_PATH
        self._client = client
        self._timeout = timeout
        self._max_delay = max_delay
        self._interval = interval
        self._delay = interval
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._queue: EventQueue | None = None
        #: Set when automatic uploading must stop until the process restarts.
        self._stopped = False

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Run ``upload_once`` on a daemon thread until :meth:`stop`."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="sealstack-uploader", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop and join the upload thread, then close its queue connection."""
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=10)
        with self._lock:
            if self._queue is not None:
                self._queue.close()
                self._queue = None

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.upload_once()
            except BaseException as exc:  # noqa: BLE001 - the thread must survive
                log_error("sealstack: upload attempt failed: %s", exc)
            if self._stop_event.wait(self._delay):
                return

    # -- one attempt -------------------------------------------------------

    def upload_once(self) -> None:
        """Make at most one upload attempt for at most one event per runtime."""
        with self._lock:
            if self._stopped or self._stop_event.is_set():
                return
            queue = self._open_queue()
            batch = queue.select_upload_batch()
            if not batch:
                return
            self._attempt(queue, batch)

    def _open_queue(self) -> EventQueue:
        if self._queue is None:
            self._queue = EventQueue(self._state_dir)
        return self._queue

    def _attempt(self, queue: EventQueue, batch: list[dict[str, Any]]) -> None:
        body = {
            "events": [
                {
                    "event": json.loads(row["event_json"]),
                    "event_hash": row["event_hash"],
                    "signature": row["signature"],
                }
                for row in batch
            ]
        }
        try:
            response = httpx.post(
                self._url,
                json=body,
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=self._timeout,
                follow_redirects=False,
            )
        except BaseException as exc:  # noqa: BLE001 - every transport failure retries
            self._retry(queue, batch, f"network:{type(exc).__name__}")
            return
        self._classify(queue, batch, response)

    def _classify(
        self, queue: EventQueue, batch: list[dict[str, Any]], response: httpx.Response
    ) -> None:
        status = getattr(response, "status_code", None)
        if status == 200:
            self._apply_results(queue, batch, response)
            return
        if status in (408, 429) or (isinstance(status, int) and 500 <= status <= 599):
            self._retry(queue, batch, f"http_{status}", self._retry_after(response))
            return
        if status == 413:
            if len(batch) > 1:
                self._attempt(queue, batch[: len(batch) // 2])
            else:
                self._strand(queue, batch[0], "http_413")
            return
        if status == 400 and _is_top_level_invalid_schema(response):
            for row in batch:
                self._strand(queue, row, "invalid_schema")
            return
        # HTTP 401/403 and every other 3xx/4xx: retain evidence, stop uploading.
        self._retry(queue, batch, f"http_{status}")
        self.halt(f"http_{status}")

    # -- 200 OK results (§42/§43) -----------------------------------------

    def _apply_results(
        self, queue: EventQueue, batch: list[dict[str, Any]], response: httpx.Response
    ) -> None:
        results = _batch_results(response, len(batch))
        if results is None:
            self._retry(queue, batch, "malformed_response")
            return
        for index, (row, result) in enumerate(zip(batch, results)):
            if not _is_correlated(result, index, row["event_id"]):
                self._retry(queue, batch, "uncorrelated_response")
                return
        self._reset_backoff()
        for row, result in zip(batch, results):
            self._apply_result(queue, row, result)

    def _apply_result(
        self, queue: EventQueue, row: dict[str, Any], result: dict[str, Any]
    ) -> None:
        status = str(result["status"])
        if status in ACCEPTED_STATUSES:
            receipt = result.get("receipt")
            if _receipt_binds(
                receipt, row, self._client.agent_key_id, self._client.key_fingerprint
            ):
                queue.acknowledge(
                    row["event_id"],
                    json.dumps(receipt, ensure_ascii=False),
                    now_timestamp(),
                )
            else:
                self._retry(queue, [row], f"{status}:unusable_receipt")
            return
        if status == "missing_previous":
            self._handle_missing_previous(queue, row)
            return
        self._strand(queue, row, status)

    def _handle_missing_previous(self, queue: EventQueue, row: dict[str, Any]) -> None:
        """Retry the earlier local predecessor first, or stop this runtime (§44)."""
        sequence = int(row["sequence"])
        repairable = sequence == 1 or queue.has_row(row["runtime_id"], sequence - 1)
        queue.mark_retryable([row["event_id"]], "missing_previous", not repairable)
        if not repairable:
            log_error(
                "sealstack: event %s reports missing_previous but local sequence %s is "
                "absent; runtime %s requires a restart",
                row["event_id"],
                sequence - 1,
                row["runtime_id"],
            )
            self._client.diagnose(
                None,
                RuntimeError(f"missing_previous_unrepairable:{row['event_id']}"),
            )

    # -- state transitions -------------------------------------------------

    def _retry(
        self,
        queue: EventQueue,
        batch: list[dict[str, Any]],
        reason: str,
        retry_after: float | None = None,
    ) -> None:
        queue.mark_retryable([row["event_id"] for row in batch], reason)
        self._grow_backoff(retry_after)

    def _strand(self, queue: EventQueue, row: dict[str, Any], reason: str) -> None:
        """Propagate one permanent failure through its runtime (§44).

        The runtime lock is taken only now, around the local transaction, and
        never across the HTTP request that produced this outcome.
        """
        with self._client.runtime_lock:
            queue.mark_permanent(
                row["event_id"], row["runtime_id"], int(row["sequence"]), reason
            )
            if row["runtime_id"] == self._client.runtime_id:
                self._client.block_signing(f"permanent_upload_failure:{reason}")
        log_error(
            "sealstack: event %s permanently failed (%s); descendants stranded",
            row["event_id"],
            reason,
        )

    def halt(self, reason: str) -> None:
        """Stop automatic uploads until the process restarts (§43)."""
        self._stopped = True
        log_warning(
            "sealstack: automatic uploads stopped (%s); events remain durable and "
            "retryable after the endpoint or credentials are corrected",
            reason,
        )

    # -- backoff -----------------------------------------------------------

    def _reset_backoff(self) -> None:
        self._delay = self._interval

    def _grow_backoff(self, retry_after: float | None = None) -> None:
        if retry_after is not None:
            self._delay = min(max(retry_after, self._interval), self._max_delay)
            return
        grown = min(max(self._delay * 2, self._interval), self._max_delay)
        self._delay = min(grown + random.uniform(0, self._interval), self._max_delay)

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        try:
            value = response.headers.get("Retry-After")
        except BaseException:  # noqa: BLE001 - armed responses may lack headers
            return None
        if value is None:
            return None
        try:
            return float(int(str(value).strip()))
        except ValueError:
            return None


def _batch_results(response: httpx.Response, expected: int) -> list[Any] | None:
    try:
        payload = response.json()
    except BaseException:  # noqa: BLE001 - an unreadable body acknowledges nothing
        return None
    if not isinstance(payload, dict):
        return None
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != expected:
        return None
    return results


def _is_correlated(result: Any, index: int, event_id: str) -> bool:
    return (
        isinstance(result, dict)
        and type(result.get("index")) is int
        and result["index"] == index
        and result.get("event_id") == event_id
        and result.get("status") in KNOWN_STATUSES
    )


def _receipt_binds(
    receipt: Any,
    row: dict[str, Any],
    active_key_id: str | None,
    active_fingerprint: str | None,
) -> bool:
    """Check the receipt's cross-links against the stored event before acking (§43)."""
    if not isinstance(receipt, dict) or not _is_base64url64(receipt.get("signature")):
        return False
    body = receipt.get("body")
    if not isinstance(body, dict):
        return False
    try:
        event = json.loads(row["event_json"])
    except ValueError:  # pragma: no cover - stored bytes are always canonical JSON
        return False
    return (
        body.get("schema_version") == RECEIPT_SCHEMA_VERSION
        and body.get("event_id") == row["event_id"]
        and body.get("event_hash") == row["event_hash"]
        and body.get("organisation_id") == event.get("organisation_id")
        and body.get("agent_id") == event.get("agent_id")
        and body.get("agent_key_id") == event.get("agent_key_id")
        and _fingerprint_binds(body, event, active_key_id, active_fingerprint)
    )


def _fingerprint_binds(
    body: dict[str, Any],
    event: dict[str, Any],
    active_key_id: str | None,
    active_fingerprint: str | None,
) -> bool:
    """The receipt binds the registered agent-key fingerprint (§87).

    For an event signed with the key that is active now, the bound fingerprint
    must equal the one held locally. A row signed by an earlier key — a queue
    retained across a rotation — keeps only the format check, because the SDK
    no longer holds that key's fingerprint and must not strand its evidence.
    """
    claimed = body.get("agent_key_fingerprint")
    if not is_hash(claimed):
        return False
    if active_fingerprint is not None and event.get("agent_key_id") == active_key_id:
        return bool(claimed == active_fingerprint)
    return True


def _is_base64url64(value: Any) -> bool:
    """§33 Base64url64: decode to 64 bytes and re-encode to the same string."""
    if not isinstance(value, str):
        return False
    try:
        b64url_decode(value, SIGNATURE_BYTES)
    except ValueError:
        return False
    return True


def _is_top_level_invalid_schema(response: httpx.Response) -> bool:
    try:
        payload = response.json()
    except BaseException:  # noqa: BLE001 - an unreadable 400 body is not the contract
        return False
    return bool(payload == {"error": "invalid_schema"})


__all__ = [
    "ACCEPTED_STATUSES",
    "KNOWN_STATUSES",
    "PERMANENT_STATUSES",
    "Uploader",
]
