"""A minimal reference implementation of the SealStack ingestion API.

It exists so that a user of this SDK can register an agent, upload signed
events, receive counter-signed receipts and verify them offline with
``product verify`` without the hosted service.

It is not the hosted service and it is not a production server. One tenant,
one bearer key, SQLite storage, no dashboard, no OIDC, no sponsor or grant
context, no agent-key rotation and no service-key rotation. Every
cryptographic primitive comes from ``product.signing``, so the receipt bytes
are produced by the same code the offline verifier checks.

Run it with::

    SEALSTACK_REF_API_KEY=... uvicorn server:app --app-dir reference-server
"""

from __future__ import annotations

import datetime as _datetime
import os
import sqlite3
import stat
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from product.signing import (
    MAX_SAFE,
    PUBLIC_KEY_LENGTH,
    SEED_LENGTH,
    SIGNATURE_LENGTH,
    b64url_decode,
    b64url_encode,
    canonicalize,
    fingerprint,
    generate_seed,
    is_hash,
    is_nonempty_text,
    is_supported,
    is_text,
    is_uuid,
    parse_timestamp,
    public_key_from_seed,
    sha256_hash,
    sign,
    strict_loads,
    verify,
)

__all__ = ["Config", "app", "create_app", "initialise", "load_config"]

ALGORITHM: Final[str] = "Ed25519"
ENVIRONMENTS: Final[tuple[str, ...]] = ("development", "staging", "production")
EVENT_TYPES: Final[tuple[str, ...]] = ("action.started", "action.completed", "action.failed")
METADATA_LIMIT: Final[int] = 16384
MAX_BATCH_EVENTS: Final[int] = 500
MAX_BATCH_BYTES: Final[int] = 4194304
CLOCK_SKEW_SECONDS: Final[int] = 300
DEFAULT_DATABASE: Final[str] = "./sealstack-ref.sqlite"
DEFAULT_SEED_FILE: Final[str] = "./sealstack-ref-service.seed"

_EVENT_KEYS: Final[tuple[str, ...]] = (
    "schema_version", "event_id", "organisation_id", "agent_id", "agent_key_id",
    "runtime_id", "sequence", "previous_event_hash", "event_type", "action_id",
    "action_name", "occurred_at", "resource", "input_digest", "output_digest",
    "error_type", "metadata",
)
_UUID_FIELDS: Final[tuple[str, ...]] = (
    "event_id", "organisation_id", "agent_id", "agent_key_id", "runtime_id", "action_id",
)
_ENVELOPE_KEYS: Final[tuple[str, ...]] = ("event", "event_hash", "signature")
_DIGEST_KEYS: Final[tuple[str, ...]] = ("algorithm", "value", "status")
_RESOURCE_KEYS: Final[tuple[str, ...]] = ("type", "id")

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS service_keys (
    key_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, public_key TEXT NOT NULL,
    valid_from TEXT NOT NULL, valid_until TEXT);
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, environment TEXT NOT NULL,
    status TEXT NOT NULL, created_at TEXT NOT NULL,
    registration_fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_keys (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, algorithm TEXT NOT NULL,
    public_key TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE (agent_id, fingerprint));
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, agent_key_id TEXT NOT NULL,
    runtime_id TEXT NOT NULL, sequence INTEGER NOT NULL, previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE, signature TEXT NOT NULL,
    canonical_event BLOB NOT NULL, occurred_at TEXT NOT NULL, received_at TEXT NOT NULL,
    UNIQUE (agent_id, runtime_id, sequence));
CREATE TABLE IF NOT EXISTS receipts (
    event_id TEXT PRIMARY KEY, service_key_id TEXT NOT NULL, received_at TEXT NOT NULL,
    receipt_json BLOB NOT NULL, receipt_signature TEXT NOT NULL);
"""


class ApiError(Exception):
    """A client-visible failure rendered as ``{"error": code}``."""

    def __init__(self, status_code: int, error: str) -> None:
        super().__init__(f"{status_code} {error}")
        self.status_code = status_code
        self.error = error


class SchemaError(ValueError):
    """The candidate is not a structurally valid event envelope."""


@dataclass(frozen=True)
class Config:
    """Everything the reference server reads from its environment."""

    database: Path
    api_key: str
    seed_file: Path


def load_config() -> Config:
    """Resolve the three ``SEALSTACK_REF_*`` settings, or fail loudly."""
    api_key = os.environ.get("SEALSTACK_REF_API_KEY", "")
    if not api_key:
        raise RuntimeError("SEALSTACK_REF_API_KEY must be set to the one bearer key")
    seed_file = os.environ.get("SEALSTACK_REF_SERVICE_SEED_FILE") or DEFAULT_SEED_FILE
    return Config(
        database=Path(os.environ.get("SEALSTACK_REF_DB") or DEFAULT_DATABASE),
        api_key=api_key,
        seed_file=Path(seed_file),
    )


# -- storage ----------------------------------------------------------------


@contextmanager
def _connect(config: Config) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(str(config.database), isolation_level=None, timeout=10.0)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        yield connection
    finally:
        connection.close()


def _service_time(moment: _datetime.datetime) -> str:
    """Render a moment as a ServiceTime: UTC with exactly six fractional digits."""
    return moment.astimezone(_datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _now() -> _datetime.datetime:
    return _datetime.datetime.now(tz=_datetime.UTC)


def _read_seed(path: Path) -> bytes:
    """Read the base64url service seed, creating a 0600 file on first start."""
    if path.exists():
        return b64url_decode(path.read_text(encoding="ascii").strip(), SEED_LENGTH)
    seed = generate_seed()
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IRUSR | stat.S_IWUSR
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(b64url_encode(seed))
        handle.flush()
        os.fsync(handle.fileno())
    print(f"reference server: wrote a new service signing seed to {path} (mode 0600)")
    return seed


def _meta(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    if row is not None:
        return str(row["value"])
    value = str(uuid4())
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (key, value))
    return value


def initialise(config: Config) -> tuple[str, str, bytes]:
    """Create the schema, the single organisation and the one service key.

    Returns ``(organisation_id, service_key_id, service_seed)``.
    """
    seed = _read_seed(config.seed_file)
    public = b64url_encode(public_key_from_seed(seed))
    with _connect(config) as conn:
        conn.executescript(_SCHEMA)
        organisation_id = _meta(conn, "organisation_id")
        row = conn.execute(
            "SELECT key_id, public_key FROM service_keys ORDER BY valid_from, key_id"
        ).fetchone()
        if row is None:
            key_id = f"service-{uuid4()}"
            conn.execute(
                "INSERT INTO service_keys (key_id, algorithm, public_key, valid_from,"
                " valid_until) VALUES (?, ?, ?, ?, NULL)",
                (key_id, ALGORITHM, public, _service_time(_now())),
            )
            return organisation_id, key_id, seed
        if str(row["public_key"]) != public:
            raise RuntimeError(
                f"{config.seed_file} does not hold the seed for the service key "
                f"{row['key_id']} already recorded in {config.database}"
            )
        return organisation_id, str(row["key_id"]), seed


# -- validation -------------------------------------------------------------


def _closed(value: Any, keys: tuple[str, ...], what: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(keys):
        raise SchemaError(f"{what} is not a closed record with exactly {sorted(keys)}")
    record: dict[str, Any] = value
    return record


def _check_digest(value: Any, what: str) -> None:
    record = _closed(value, _DIGEST_KEYS, what)
    available = (
        record["algorithm"] == "sha256"
        and is_hash(record["value"])
        and record["status"] == "available"
    )
    unsupported = (
        record["algorithm"] is None
        and record["value"] is None
        and record["status"] == "unsupported"
    )
    if not (available or unsupported):
        raise SchemaError(f"{what} is not a valid Digest record")


def _check_resource(value: Any, what: str) -> None:
    if value is None:
        return
    record = _closed(value, _RESOURCE_KEYS, what)
    for name in _RESOURCE_KEYS:
        if record[name] is not None and not is_text(record[name]):
            raise SchemaError(f"{what}.{name} is not Text or null")
    if record["type"] is None and record["id"] is None:
        raise SchemaError(f"{what} requires at least one non-null member")


def _check_lifecycle(record: dict[str, Any]) -> None:
    """Enforce the field combinations each event type allows."""
    event_type, output, error_type = (
        record["event_type"], record["output_digest"], record["error_type"]
    )
    if error_type is not None and not is_nonempty_text(error_type):
        raise SchemaError("event.error_type is not nonempty Text or null")
    if event_type == "action.started" and not (output is None and error_type is None):
        raise SchemaError("event: started events require null output and error")
    if event_type == "action.completed" and error_type is not None:
        raise SchemaError("event: completed events require a null error type")
    if event_type == "action.failed" and not (output is None and error_type is not None):
        raise SchemaError("event: failed events require null output and an error type")


def _validate_event(value: Any) -> dict[str, Any]:
    record = _closed(value, _EVENT_KEYS, "event")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise SchemaError("event.schema_version must be the integer 1")
    for name in _UUID_FIELDS:
        if not is_uuid(record[name]):
            raise SchemaError(f"event.{name} is not a lowercase hyphenated UUID")

    sequence, previous = record["sequence"], record["previous_event_hash"]
    if type(sequence) is not int or not 1 <= sequence <= MAX_SAFE:
        raise SchemaError("event.sequence must be an integer in [1, MAX_SAFE]")
    if previous is not None and not is_hash(previous):
        raise SchemaError("event.previous_event_hash is not a sha256 hash")
    if (sequence == 1) != (previous is None):
        raise SchemaError("event: sequence 1 requires a null predecessor hash")

    if record["event_type"] not in EVENT_TYPES:
        raise SchemaError("event.event_type is not a known event type")
    if not is_nonempty_text(record["action_name"]):
        raise SchemaError("event.action_name is not nonempty Text")
    if parse_timestamp(record["occurred_at"]) is None:
        raise SchemaError("event.occurred_at is not a valid Timestamp")

    _check_resource(record["resource"], "event.resource")
    _check_digest(record["input_digest"], "event.input_digest")
    if record["output_digest"] is not None:
        _check_digest(record["output_digest"], "event.output_digest")
    _check_lifecycle(record)

    metadata = record["metadata"]
    if type(metadata) is not dict or not is_supported(metadata):
        raise SchemaError("event.metadata is not an object within the value profile")
    if len(canonicalize(metadata)) > METADATA_LIMIT:
        raise SchemaError(f"event.metadata exceeds {METADATA_LIMIT} canonical bytes")
    return record


def _validate_envelope(candidate: Any) -> dict[str, Any]:
    envelope = _closed(candidate, _ENVELOPE_KEYS, "envelope")
    event = _validate_event(envelope["event"])
    if not is_hash(envelope["event_hash"]):
        raise SchemaError("envelope.event_hash is not a sha256 hash")
    try:
        b64url_decode(envelope["signature"], SIGNATURE_LENGTH)
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"envelope.signature is not canonical base64url: {exc}") from exc
    return event


def _candidate_event_id(candidate: Any) -> str | None:
    if type(candidate) is not dict or type(candidate.get("event")) is not dict:
        return None
    event_id = candidate["event"].get("event_id")
    return str(event_id) if is_uuid(event_id) else None


# -- registration and key listing -------------------------------------------


def _registered_fingerprint(body: Any) -> str:
    """Validate a registration body and return the key fingerprint it commits to."""
    if type(body) is not dict:
        raise ApiError(400, "invalid_schema")
    allowed = {"agent_id", "name", "environment", "public_key", "key_fingerprint"}
    required = {"agent_id", "name", "environment", "public_key"}
    if not required <= set(body) or not set(body) <= allowed:
        raise ApiError(400, "invalid_schema")
    if not is_uuid(body["agent_id"]) or not is_nonempty_text(body["name"]):
        raise ApiError(400, "invalid_schema")
    if body["environment"] not in ENVIRONMENTS:
        raise ApiError(400, "invalid_schema")
    if type(body["public_key"]) is not str:
        raise ApiError(400, "invalid_schema")
    try:
        public_raw = b64url_decode(body["public_key"], PUBLIC_KEY_LENGTH)
    except ValueError as exc:
        raise ApiError(400, "invalid_public_key") from exc

    computed = fingerprint(public_raw)
    claimed = body.get("key_fingerprint")
    if claimed is not None:
        if not is_hash(claimed):
            raise ApiError(400, "invalid_schema")
        if claimed != computed:
            raise ApiError(400, "fingerprint_mismatch")
    return computed


def _register_agent(
    conn: sqlite3.Connection, organisation_id: str, body: Any
) -> tuple[dict[str, str], int]:
    """Register an agent and its first key. Idempotent for the same key."""
    key_fingerprint = _registered_fingerprint(body)
    agent_id, now = str(body["agent_id"]), _service_time(_now())
    existing = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()

    if existing is None:
        key_id = str(uuid4())
        conn.execute(
            "INSERT INTO agents (id, name, environment, status, created_at,"
            " registration_fingerprint) VALUES (?, ?, ?, 'active', ?, ?)",
            (agent_id, str(body["name"]), str(body["environment"]), now, key_fingerprint),
        )
        conn.execute(
            "INSERT INTO agent_keys (id, agent_id, algorithm, public_key, fingerprint,"
            " status, created_at) VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (key_id, agent_id, ALGORITHM, body["public_key"], key_fingerprint, now),
        )
        status = 201
    else:
        # A reused agent id with a different key is another agent's identity.
        if str(existing["registration_fingerprint"]) != key_fingerprint:
            raise ApiError(409, "active_key_conflict")
        if str(existing["status"]) != "active":
            raise ApiError(409, "unknown_agent")
        key = conn.execute(
            "SELECT id, status FROM agent_keys WHERE agent_id = ? AND fingerprint = ?",
            (agent_id, key_fingerprint),
        ).fetchone()
        if key is None:
            raise ApiError(500, "internal_error")
        if str(key["status"]) != "active":
            raise ApiError(409, f"key_{key['status']}")
        key_id, status = str(key["id"]), 200

    return {
        "organisation_id": organisation_id,
        "agent_id": agent_id,
        "key_id": key_id,
        "key_fingerprint": key_fingerprint,
    }, status


def _list_keys(conn: sqlite3.Connection, agent_id: str) -> dict[str, list[dict[str, str]]]:
    if not is_uuid(agent_id):
        raise ApiError(404, "unknown_agent")
    if conn.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone() is None:
        raise ApiError(404, "unknown_agent")
    rows = conn.execute(
        "SELECT id, fingerprint, status FROM agent_keys WHERE agent_id = ?"
        " ORDER BY created_at, id",
        (agent_id,),
    ).fetchall()
    return {
        "keys": [
            {
                "key_id": str(row["id"]),
                "key_fingerprint": str(row["fingerprint"]),
                "status": str(row["status"]),
            }
            for row in rows
        ]
    }


def _verification_keys(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    rows = conn.execute(
        "SELECT key_id, algorithm, public_key, valid_from, valid_until FROM service_keys"
        " ORDER BY valid_from, key_id"
    ).fetchall()
    return {
        "keys": [
            {
                "key_id": str(row["key_id"]),
                "algorithm": str(row["algorithm"]),
                "public_key": str(row["public_key"]),
                "valid_from": str(row["valid_from"]),
                "valid_until": row["valid_until"],
            }
            for row in rows
        ]
    }


# -- ingestion --------------------------------------------------------------


@dataclass(frozen=True)
class _Outcome:
    status: str
    receipt: dict[str, Any] | None = None


def _stored_receipt(conn: sqlite3.Connection, event_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT receipt_json, receipt_signature FROM receipts WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if row is None:
        return None
    body: Any = strict_loads(bytes(row["receipt_json"]).decode("utf-8"))
    return {"body": body, "signature": str(row["receipt_signature"])}


def _duplicate(
    conn: sqlite3.Connection, event_id: str, canonical: bytes, claimed: str, signature: str
) -> _Outcome | None:
    """Resolve a replay: the original receipt bytes, or a conflict. Never a new receipt."""
    row = conn.execute(
        "SELECT canonical_event, event_hash, signature FROM events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if row is None:
        return None
    identical = (
        bytes(row["canonical_event"]) == canonical
        and claimed == str(row["event_hash"])
        and b64url_decode(signature, SIGNATURE_LENGTH)
        == b64url_decode(str(row["signature"]), SIGNATURE_LENGTH)
    )
    if not identical:
        return _Outcome("conflict")
    receipt = _stored_receipt(conn, event_id)
    if receipt is None:
        raise ApiError(500, "internal_error")
    return _Outcome("duplicate", receipt)


def _check_chain(
    conn: sqlite3.Connection, event: dict[str, Any], computed_hash: str
) -> _Outcome | None:
    """Enforce per-runtime sequence uniqueness and the predecessor hash link."""
    agent, runtime = str(event["agent_id"]), str(event["runtime_id"])
    sequence = int(event["sequence"])
    if sequence > 1:
        predecessor = conn.execute(
            "SELECT event_hash FROM events WHERE agent_id = ? AND runtime_id = ?"
            " AND sequence = ?",
            (agent, runtime, sequence - 1),
        ).fetchone()
        if predecessor is None:
            return _Outcome("missing_previous")
        if str(predecessor["event_hash"]) != event["previous_event_hash"]:
            return _Outcome("invalid_chain")
    occupant = conn.execute(
        "SELECT event_id FROM events WHERE agent_id = ? AND runtime_id = ? AND sequence = ?",
        (agent, runtime, sequence),
    ).fetchone()
    if occupant is not None and str(occupant["event_id"]) != str(event["event_id"]):
        return _Outcome("invalid_chain")
    collision = conn.execute(
        "SELECT 1 FROM events WHERE event_hash = ?", (computed_hash,)
    ).fetchone()
    return _Outcome("conflict") if collision is not None else None


def _receipt_body(
    event: dict[str, Any],
    *,
    organisation_id: str,
    event_hash: str,
    key_fingerprint: str,
    received_at: str,
    service_key_id: str,
) -> dict[str, Any]:
    """Build the closed receipt body.

    This deployment records no sponsor and no capability grant, so every
    context field carries the explicit null the format defines for their
    absence. Nothing here is invented.
    """
    return {
        "schema_version": 2,
        "event_id": str(event["event_id"]),
        "event_hash": event_hash,
        "organisation_id": organisation_id,
        "agent_id": str(event["agent_id"]),
        "agent_key_id": str(event["agent_key_id"]),
        "agent_key_fingerprint": key_fingerprint,
        "agent_sponsor_id": None,
        "sponsor_user_id_snapshot": None,
        "grant_id": None,
        "capabilities_snapshot": None,
        "received_at": received_at,
        "service_key_id": service_key_id,
        "sponsor": None,
        "grant": None,
    }


def _ingest(
    conn: sqlite3.Connection,
    candidate: Any,
    *,
    organisation_id: str,
    service_key_id: str,
    seed: bytes,
) -> tuple[str | None, _Outcome]:
    """Process one batch candidate. Per-candidate problems are statuses, not errors."""
    try:
        event = _validate_envelope(candidate)
    except SchemaError:
        return _candidate_event_id(candidate), _Outcome("invalid_schema")

    event_id = str(event["event_id"])
    canonical = canonicalize(event)
    computed_hash = sha256_hash(canonical)
    claimed_hash, signature = str(candidate["event_hash"]), str(candidate["signature"])
    occurred_at = parse_timestamp(event["occurred_at"])
    if occurred_at is None:  # pragma: no cover - _validate_event already checked
        return event_id, _Outcome("invalid_schema")

    if str(event["organisation_id"]) != organisation_id:
        return event_id, _Outcome("organisation_mismatch")
    duplicate = _duplicate(conn, event_id, canonical, claimed_hash, signature)
    if duplicate is not None:
        return event_id, duplicate

    agent = conn.execute(
        "SELECT status FROM agents WHERE id = ?", (str(event["agent_id"]),)
    ).fetchone()
    if agent is None:
        return event_id, _Outcome("unknown_agent")
    if str(agent["status"]) != "active":
        return event_id, _Outcome("agent_revoked")

    received = _now()
    key = conn.execute(
        "SELECT public_key, fingerprint, status FROM agent_keys"
        " WHERE agent_id = ? AND id = ?",
        (str(event["agent_id"]), str(event["agent_key_id"])),
    ).fetchone()
    if key is None:
        return event_id, _Outcome("invalid_signature")
    if str(key["status"]) != "active":
        return event_id, _Outcome(f"{key['status']}_key")

    if occurred_at > received + _datetime.timedelta(seconds=CLOCK_SKEW_SECONDS):
        return event_id, _Outcome("invalid_timestamp")
    if computed_hash != claimed_hash:
        return event_id, _Outcome("invalid_hash")
    public_raw = b64url_decode(str(key["public_key"]), PUBLIC_KEY_LENGTH)
    if not verify(public_raw, signature, canonical):
        return event_id, _Outcome("invalid_signature")

    chain = _check_chain(conn, event, computed_hash)
    if chain is not None:
        return event_id, chain

    received_at = _service_time(received)
    body = _receipt_body(
        event,
        organisation_id=organisation_id,
        event_hash=computed_hash,
        key_fingerprint=str(key["fingerprint"]),
        received_at=received_at,
        service_key_id=service_key_id,
    )
    receipt_bytes = canonicalize(body)
    receipt_signature = sign(seed, receipt_bytes)
    conn.execute(
        "INSERT INTO events (event_id, agent_id, agent_key_id, runtime_id, sequence,"
        " previous_event_hash, event_hash, signature, canonical_event, occurred_at,"
        " received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event_id, str(event["agent_id"]), str(event["agent_key_id"]),
            str(event["runtime_id"]), int(event["sequence"]), event["previous_event_hash"],
            computed_hash, signature, canonical, str(event["occurred_at"]), received_at,
        ),
    )
    conn.execute(
        "INSERT INTO receipts (event_id, service_key_id, received_at, receipt_json,"
        " receipt_signature) VALUES (?, ?, ?, ?, ?)",
        (event_id, service_key_id, received_at, receipt_bytes, receipt_signature),
    )
    return event_id, _Outcome("accepted", {"body": body, "signature": receipt_signature})


# -- application ------------------------------------------------------------


class _State:
    """Process state resolved once, when the application starts."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.config: Config | None = None
        self.organisation_id = ""
        self.service_key_id = ""
        self.seed = b""

    def start(self) -> None:
        config = load_config()
        self.organisation_id, self.service_key_id, self.seed = initialise(config)
        self.config = config

    def require(self, request: Request) -> Config:
        """Return the live configuration once the bearer key has been checked."""
        config = self.config
        if config is None:  # pragma: no cover - start-up always runs first
            raise ApiError(503, "service_unavailable")
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or value.strip() != config.api_key:
            raise ApiError(401, "unauthorized")
        return config


def _json_body(body: bytes) -> Any:
    try:
        return strict_loads(body.decode("utf-8"))
    except Exception as exc:
        raise ApiError(400, "invalid_schema") from exc


def create_app() -> FastAPI:
    """Build the reference application. Configuration is read at start-up."""
    state = _State()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        state.start()
        yield

    application = FastAPI(
        title="SealStack reference server",
        description="A minimal single-tenant reference implementation. Not the hosted service.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @application.exception_handler(ApiError)
    def _api_error(_request: Request, exc: Exception) -> JSONResponse:
        error = exc if isinstance(exc, ApiError) else ApiError(500, "internal_error")
        return JSONResponse({"error": error.error}, status_code=error.status_code)

    @application.exception_handler(StarletteHTTPException)
    @application.exception_handler(RequestValidationError)
    def _routing_error(_request: Request, _exc: Exception) -> JSONResponse:
        """Every unrouted path, method and unusable path parameter is a 404."""
        return JSONResponse({"error": "not_found"}, status_code=404)

    @application.post("/v1/agents/register")
    async def register(request: Request) -> JSONResponse:
        config = state.require(request)
        body = _json_body(await request.body())
        with state.lock, _connect(config) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                payload, status = _register_agent(conn, state.organisation_id, body)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        return JSONResponse(payload, status_code=status)

    @application.get("/v1/agents/{agent_id}/keys")
    async def list_keys(agent_id: str, request: Request) -> JSONResponse:
        config = state.require(request)
        with state.lock, _connect(config) as conn:
            return JSONResponse(_list_keys(conn, agent_id))

    @application.get("/v1/verification-keys")
    async def verification_keys(request: Request) -> JSONResponse:
        config = state.require(request)
        with state.lock, _connect(config) as conn:
            return JSONResponse(_verification_keys(conn))

    @application.post("/v1/events/batch")
    async def events_batch(request: Request) -> JSONResponse:
        config = state.require(request)
        raw = await request.body()
        if len(raw) > MAX_BATCH_BYTES:
            raise ApiError(413, "payload_too_large")
        parsed = _json_body(raw)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("events"), list):
            raise ApiError(400, "invalid_schema")
        candidates: list[Any] = parsed["events"]
        if len(candidates) > MAX_BATCH_EVENTS:
            raise ApiError(413, "payload_too_large")

        results: list[dict[str, Any]] = []
        for index, candidate in enumerate(candidates):
            # One transaction per candidate: a batch is never all-or-nothing.
            with state.lock, _connect(config) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    event_id, outcome = _ingest(
                        conn,
                        candidate,
                        organisation_id=state.organisation_id,
                        service_key_id=state.service_key_id,
                        seed=state.seed,
                    )
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                conn.execute("COMMIT" if outcome.status == "accepted" else "ROLLBACK")
            results.append(
                {
                    "index": index,
                    "event_id": event_id,
                    "status": outcome.status,
                    "receipt": outcome.receipt,
                }
            )
        return JSONResponse({"results": results})

    return application


app = create_app()
