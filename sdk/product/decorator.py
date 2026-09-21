"""The instrumentation API: ``@audit.track()`` and ``with audit.action(...)``.

SPEC §25 (API surface), §27 (lifecycle), §33 (digest capture), §46–§47 (the
failure-mode algorithm).

The rules that matter here: the business function runs exactly once, its
original result or exception is always what the caller sees, and no terminal
event is ever written for an action whose start was not durably committed.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, Self

from product.events import (
    ACTION_COMPLETED,
    ACTION_FAILED,
    ACTION_STARTED,
    UNSUPPORTED_DIGEST,
    AuditFailure,
    error_type_of,
    input_digest_for_call,
    metadata_snapshot,
    new_uuid,
    resource_field,
)
from product.signing import digest

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from product.client import AuditClient

RAISE: str = "raise"
CONTINUE: str = "continue"


class _Invocation:
    """One instrumented action: a start attempt, then a best-effort terminal."""

    __slots__ = (
        "_action_id",
        "_action_name",
        "_client",
        "_input_digest",
        "_metadata",
        "_metadata_argument",
        "_resource",
        "_resource_id",
        "_resource_type",
        "_started",
    )

    def __init__(
        self,
        client: AuditClient,
        action_name: str,
        resource_type: str | None,
        resource_id: str | None,
        metadata: dict[str, Any] | None,
        input_digest: dict[str, Any],
    ) -> None:
        self._client = client
        self._action_name = action_name
        self._action_id = new_uuid()
        self._input_digest = input_digest
        self._resource_type = resource_type
        self._resource_id = resource_id
        self._metadata_argument = metadata
        self._resource: dict[str, str | None] | None = None
        self._metadata: dict[str, Any] = {}
        self._started = False

    def begin(self) -> None:
        """Durably append ``action.started`` (§47).

        On failure the diagnostics are emitted best effort and, in
        ``failure_mode="raise"``, ``AuditFailure`` is raised before the business
        function can execute.
        """
        try:
            self._resource = resource_field(self._resource_type, self._resource_id)
            self._metadata = metadata_snapshot(self._metadata_argument)
            self._append(ACTION_STARTED, output_digest=None, error_type=None)
        except Exception as exc:
            self._client.diagnose(self._action_name, exc)
            if self._client.failure_mode == RAISE:
                raise _as_audit_failure(exc) from exc
            return
        self._started = True

    def complete(self, result: Any) -> None:
        """Best-effort ``action.completed`` carrying the output digest."""
        self._terminal(ACTION_COMPLETED, digest(result), None)

    def complete_opaque(self) -> None:
        """Best-effort ``action.completed`` for a manual context (§31)."""
        self._terminal(ACTION_COMPLETED, None, None)

    def fail(self, error: BaseException) -> None:
        """Best-effort ``action.failed``; only the error class is recorded."""
        self._terminal(ACTION_FAILED, None, error_type_of(error))

    def _terminal(
        self, event_type: str, output_digest: dict[str, Any] | None, error_type: str | None
    ) -> None:
        if not self._started:
            return
        try:
            self._append(event_type, output_digest=output_digest, error_type=error_type)
        except Exception as exc:  # noqa: BLE001 - a terminal failure only gets logged
            self._client.diagnose(self._action_name, exc)

    def _append(
        self,
        event_type: str,
        *,
        output_digest: dict[str, Any] | None,
        error_type: str | None,
    ) -> None:
        self._client.append_event(
            event_type=event_type,
            action_id=self._action_id,
            action_name=self._action_name,
            resource=self._resource,
            input_digest=self._input_digest,
            output_digest=output_digest,
            error_type=error_type,
            metadata=self._metadata,
        )


def _as_audit_failure(exc: Exception) -> AuditFailure:
    if isinstance(exc, AuditFailure):
        return exc
    return AuditFailure(f"audit_creation_error: {error_type_of(exc)}")


class ActionContext:
    """The manual instrumentation block returned by ``audit.action(...)``.

    Usable with both ``with`` and ``async with``; the body is opaque, so the
    input digest is ``unsupported`` and a completed output is null (§31).
    """

    __slots__ = ("_invocation",)

    def __init__(
        self,
        client: AuditClient,
        name: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._invocation = _Invocation(
            client, name, resource_type, resource_id, metadata, UNSUPPORTED_DIGEST
        )

    def __enter__(self) -> Self:
        self._invocation.begin()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        if kind is None:
            self._invocation.complete_opaque()
        else:
            self._invocation.fail(value if value is not None else kind())
        return False

    async def __aenter__(self) -> Self:
        return self.__enter__()

    async def __aexit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        return self.__exit__(kind, value, tb)


def track(
    client: AuditClient,
    action: str | Callable[..., Any] | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Callable[..., Any]:
    """Return the decorator described in §25, for sync and ``async def``."""

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        name = action if isinstance(action, str) else _default_action_name(function)

        def prepare(args: tuple[Any, ...], kwargs: dict[str, Any]) -> _Invocation:
            return _Invocation(
                client, name, resource_type, resource_id, metadata,
                input_digest_for_call(args, kwargs),
            )

        if inspect.iscoroutinefunction(function):

            @functools.wraps(function)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                invocation = prepare(args, kwargs)
                invocation.begin()
                try:
                    result = await function(*args, **kwargs)
                except BaseException as error:
                    invocation.fail(error)
                    raise
                invocation.complete(result)
                return result

            return async_wrapper

        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            invocation = prepare(args, kwargs)
            invocation.begin()
            try:
                result = function(*args, **kwargs)
            except BaseException as error:
                invocation.fail(error)
                raise
            invocation.complete(result)
            return result

        return wrapper

    if callable(action):  # bare @audit.track usage
        function, action = action, None
        return decorate(function)
    return decorate


def _default_action_name(function: Callable[..., Any]) -> str:
    return f"{function.__module__}.{function.__qualname__}"


__all__ = ["CONTINUE", "RAISE", "ActionContext", "track"]
