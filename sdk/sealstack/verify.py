"""Offline evidence-bundle verifier (SPEC §118, §121–§124).

Pure and offline: this module performs no network access, reads no files and
imports nothing from the SealStack runtime except :mod:`sealstack.signing`.  The
caller supplies the bundle and trust-file *text*; parsing happens here so that
parse failures are classified with the same exit codes as everything else.
"""

from __future__ import annotations

import datetime as _datetime
from dataclasses import dataclass, field
from typing import Any, NoReturn

from sealstack.signing import (
    MAX_SAFE,
    PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
    b64url_decode,
    canonicalize,
    fingerprint,
    is_hash,
    is_nonempty_text,
    is_supported,
    is_text,
    is_uuid,
    parse_timestamp,
    sha256_hash,
    strict_loads,
    verify,
)

__all__ = ["LIMITATIONS", "Result", "validate_bundle_document", "verify_bundle"]

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_UNVERIFIABLE = 2

#: Byte-exact §124 limitations block required by §121 in every bundle.
LIMITATIONS = (
    "This receipt verifies cryptographic relationships between the\n"
    "included data, registered keys and service receipt.\n"
    "\n"
    "It does not independently prove:\n"
    "\n"
    "• that an external real-world action occurred;\n"
    "• that logged inputs or outputs were truthful;\n"
    "• that the agent host was uncompromised;\n"
    "• that the private key was never stolen;\n"
    "• that uninstrumented actions did not occur;\n"
    "• the legal identity of a human sponsor;\n"
    "• that the sponsor personally authorised this individual action;\n"
    "• legal liability;\n"
    "• regulatory compliance."
)

_LABEL_WIDTH = 25
_BUNDLE_LABEL = "Evidence bundle"
_RECEIPT_LABEL = "Service receipt"

_METADATA_LIMIT = 16384

_EVENT_KEYS = (
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
_ENVELOPE_KEYS = ("event", "event_hash", "signature")
_BUNDLE_KEYS = (
    "schema_version",
    "event_envelope",
    "agent_public_key",
    "service_receipt",
    "service_public_key_metadata",
    "limitations",
    "predecessor",
)
_RECEIPT_KEYS = ("body", "signature")
_BODY_KEYS = (
    "schema_version",
    "event_id",
    "event_hash",
    "organisation_id",
    "agent_id",
    "agent_key_id",
    "agent_key_fingerprint",
    "agent_sponsor_id",
    "sponsor_user_id_snapshot",
    "grant_id",
    "capabilities_snapshot",
    "received_at",
    "service_key_id",
    "sponsor",
    "grant",
)
_SPONSOR_KEYS = (
    "id",
    "organisation_id",
    "agent_id",
    "user_id",
    "valid_from",
    "valid_until",
    "created_by_user_id",
)
_GRANT_KEYS = (
    "id",
    "organisation_id",
    "agent_id",
    "sponsor_id",
    "capabilities",
    "valid_from",
    "valid_until",
    "created_at",
    "created_by_user_id",
)
_KEY_METADATA_KEYS = ("key_id", "algorithm", "public_key", "valid_from", "valid_until")
_TRUST_KEY_KEYS = _KEY_METADATA_KEYS
_DIGEST_KEYS = ("algorithm", "value", "status")
_RESOURCE_KEYS = ("type", "id")
_EVENT_TYPES = ("action.started", "action.completed", "action.failed")


@dataclass
class Result:
    """Outcome of one verification run."""

    exit_code: int
    lines: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


class _Reject(Exception):
    """Internal control-flow signal carrying an exit code and a report label."""

    def __init__(self, code: int, label: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.label = label
        self.reason = reason


def _invalid(reason: str, label: str = _BUNDLE_LABEL) -> NoReturn:
    raise _Reject(EXIT_INVALID, label, reason)


def _unknown(reason: str, label: str = _RECEIPT_LABEL) -> NoReturn:
    raise _Reject(EXIT_UNVERIFIABLE, label, reason)


def _line(label: str, status: str, detail: str | None = None) -> str:
    text = f"{label + ':':<{_LABEL_WIDTH}}{status}"
    return f"{text} — {detail}" if detail else text


# --------------------------------------------------------------------------
# Structural helpers
# --------------------------------------------------------------------------


def _closed(value: Any, keys: tuple[str, ...], what: str) -> dict[str, Any]:
    """Require a closed record: an object with exactly ``keys``."""
    if type(value) is not dict:
        _invalid(f"{what} is not a JSON object")
    record: dict[str, Any] = value
    missing = sorted(set(keys) - set(record))
    unexpected = sorted(set(record) - set(keys))
    if missing or unexpected:
        _invalid(f"{what} field set invalid (missing={missing}, unexpected={unexpected})")
    return record


def _exact_int(value: Any) -> bool:
    """True for a genuine int; booleans never satisfy integer fields (§33)."""
    return type(value) is int


def _uuid(value: Any, what: str) -> None:
    if not is_uuid(value):
        _invalid(f"{what} is not a lowercase hyphenated UUID")


def _hash(value: Any, what: str) -> None:
    if not is_hash(value):
        _invalid(f"{what} is not a sha256 hash")


def _service_time(value: Any, what: str) -> _datetime.datetime:
    parsed = parse_timestamp(value, service=True)
    if parsed is None:
        _invalid(f"{what} is not a ServiceTime timestamp")
    return parsed


def _optional_service_time(value: Any, what: str) -> _datetime.datetime | None:
    return None if value is None else _service_time(value, what)


def _base64url(value: Any, length: int, what: str) -> bytes:
    try:
        return b64url_decode(value, length)
    except ValueError as exc:
        _invalid(f"{what} is not canonical base64url of {length} bytes: {exc}")


def _capabilities(value: Any, what: str) -> list[str]:
    if type(value) is not list:
        _invalid(f"{what} is not an array")
    members: list[str] = value
    for item in members:
        if not is_nonempty_text(item):
            _invalid(f"{what} contains a value that is not nonempty Text")
    if len(set(members)) != len(members):
        _invalid(f"{what} contains duplicate values")
    return members


def _digest(value: Any, what: str) -> None:
    _closed(value, _DIGEST_KEYS, what)
    available = (
        value["algorithm"] == "sha256"
        and is_hash(value["value"])
        and value["status"] == "available"
    )
    unsupported = (
        value["algorithm"] is None
        and value["value"] is None
        and value["status"] == "unsupported"
    )
    if not (available or unsupported):
        _invalid(f"{what} is not a valid Digest record")


def _resource(value: Any, what: str) -> None:
    if value is None:
        return
    _closed(value, _RESOURCE_KEYS, what)
    for name in _RESOURCE_KEYS:
        item = value[name]
        if item is not None and not is_text(item):
            _invalid(f"{what}.{name} is not Text or null")
    if value["type"] is None and value["id"] is None:
        _invalid(f"{what} requires at least one non-null member")


# --------------------------------------------------------------------------
# Schema validation (§33, §87, §121)
# --------------------------------------------------------------------------


def _validate_event(event: Any, what: str) -> None:
    _closed(event, _EVENT_KEYS, what)

    if not _exact_int(event["schema_version"]) or event["schema_version"] != 1:
        _invalid(f"{what}.schema_version must be the integer 1")

    for name in ("event_id", "organisation_id", "agent_id", "agent_key_id",
                 "runtime_id", "action_id"):
        _uuid(event[name], f"{what}.{name}")

    sequence = event["sequence"]
    if not _exact_int(sequence) or not 1 <= sequence <= MAX_SAFE:
        _invalid(f"{what}.sequence must be an integer in [1, {MAX_SAFE}]")

    previous = event["previous_event_hash"]
    if previous is not None:
        _hash(previous, f"{what}.previous_event_hash")
    if (sequence == 1) != (previous is None):
        _invalid(f"{what}: sequence 1 requires a null predecessor hash and vice versa")

    event_type = event["event_type"]
    if event_type not in _EVENT_TYPES:
        _invalid(f"{what}.event_type is not a known event type")

    if not is_nonempty_text(event["action_name"]):
        _invalid(f"{what}.action_name is not nonempty Text")

    if parse_timestamp(event["occurred_at"]) is None:
        _invalid(f"{what}.occurred_at is not a valid Timestamp")

    _resource(event["resource"], f"{what}.resource")
    _digest(event["input_digest"], f"{what}.input_digest")

    output = event["output_digest"]
    if output is not None:
        _digest(output, f"{what}.output_digest")

    error_type = event["error_type"]
    if error_type is not None and not is_nonempty_text(error_type):
        _invalid(f"{what}.error_type is not nonempty Text or null")

    # §33 event-type field combinations.
    if event_type == "action.started" and not (output is None and error_type is None):
        _invalid(f"{what}: started events require null output and error")
    if event_type == "action.completed" and error_type is not None:
        _invalid(f"{what}: completed events require a null error type")
    if event_type == "action.failed" and not (output is None and error_type is not None):
        _invalid(f"{what}: failed events require null output and a non-null error type")

    metadata = event["metadata"]
    if type(metadata) is not dict or not is_supported(metadata):
        _invalid(f"{what}.metadata is not an object satisfying the §30 profile")
    if len(canonicalize(metadata)) > _METADATA_LIMIT:
        _invalid(f"{what}.metadata exceeds {_METADATA_LIMIT} canonical bytes")


def _validate_envelope(envelope: Any, what: str) -> None:
    _closed(envelope, _ENVELOPE_KEYS, what)
    _validate_event(envelope["event"], f"{what}.event")
    _hash(envelope["event_hash"], f"{what}.event_hash")
    _base64url(envelope["signature"], SIGNATURE_LENGTH, f"{what}.signature")


def _validate_context(body: dict[str, Any], what: str) -> None:
    sponsor = body["sponsor"]
    if sponsor is not None:
        _closed(sponsor, _SPONSOR_KEYS, f"{what}.sponsor")
        for name in ("id", "organisation_id", "agent_id", "user_id",
                     "created_by_user_id"):
            _uuid(sponsor[name], f"{what}.sponsor.{name}")
        _service_time(sponsor["valid_from"], f"{what}.sponsor.valid_from")
        _optional_service_time(sponsor["valid_until"], f"{what}.sponsor.valid_until")

    grant = body["grant"]
    if grant is not None:
        _closed(grant, _GRANT_KEYS, f"{what}.grant")
        for name in ("id", "organisation_id", "agent_id", "sponsor_id",
                     "created_by_user_id"):
            _uuid(grant[name], f"{what}.grant.{name}")
        _capabilities(grant["capabilities"], f"{what}.grant.capabilities")
        _service_time(grant["valid_from"], f"{what}.grant.valid_from")
        _optional_service_time(grant["valid_until"], f"{what}.grant.valid_until")
        _service_time(grant["created_at"], f"{what}.grant.created_at")

    # §87 nullness: root snapshots exist exactly when their record does.
    if sponsor is None:
        if body["agent_sponsor_id"] is not None or body["sponsor_user_id_snapshot"] is not None:
            _invalid(f"{what}: null sponsor requires null sponsor root fields")
    else:
        _uuid(body["agent_sponsor_id"], f"{what}.agent_sponsor_id")
        _uuid(body["sponsor_user_id_snapshot"], f"{what}.sponsor_user_id_snapshot")

    if grant is None:
        if body["grant_id"] is not None or body["capabilities_snapshot"] is not None:
            _invalid(f"{what}: null grant requires null grant root fields")
    else:
        _uuid(body["grant_id"], f"{what}.grant_id")
        _capabilities(body["capabilities_snapshot"], f"{what}.capabilities_snapshot")


def _validate_receipt_body(body: Any, what: str) -> None:
    _closed(body, _BODY_KEYS, what)
    if not _exact_int(body["schema_version"]) or body["schema_version"] != 2:
        _invalid(f"{what}.schema_version must be the integer 2")
    for name in ("event_id", "organisation_id", "agent_id", "agent_key_id"):
        _uuid(body[name], f"{what}.{name}")
    _hash(body["event_hash"], f"{what}.event_hash")
    _hash(body["agent_key_fingerprint"], f"{what}.agent_key_fingerprint")
    _service_time(body["received_at"], f"{what}.received_at")
    if not is_nonempty_text(body["service_key_id"]):
        _invalid(f"{what}.service_key_id is not nonempty Text")
    _validate_context(body, what)


def _validate_key_metadata(metadata: Any, what: str) -> None:
    _closed(metadata, _KEY_METADATA_KEYS, what)
    if not is_nonempty_text(metadata["key_id"]):
        _invalid(f"{what}.key_id is not nonempty Text")
    if metadata["algorithm"] != "Ed25519":
        _invalid(f"{what}.algorithm must be Ed25519")
    _base64url(metadata["public_key"], PUBLIC_KEY_LENGTH, f"{what}.public_key")
    _service_time(metadata["valid_from"], f"{what}.valid_from")
    _optional_service_time(metadata["valid_until"], f"{what}.valid_until")


def _validate_bundle(bundle: Any, what: str, allow_predecessor: bool) -> None:
    _closed(bundle, _BUNDLE_KEYS, what)
    if not _exact_int(bundle["schema_version"]) or bundle["schema_version"] != 2:
        _invalid(f"{what}.schema_version must be the integer 2")
    _validate_envelope(bundle["event_envelope"], f"{what}.event_envelope")
    _base64url(bundle["agent_public_key"], PUBLIC_KEY_LENGTH, f"{what}.agent_public_key")
    receipt = _closed(bundle["service_receipt"], _RECEIPT_KEYS, f"{what}.service_receipt")
    _validate_receipt_body(receipt["body"], f"{what}.service_receipt.body")
    _base64url(receipt["signature"], SIGNATURE_LENGTH, f"{what}.service_receipt.signature")
    _validate_key_metadata(
        bundle["service_public_key_metadata"], f"{what}.service_public_key_metadata"
    )
    if bundle["limitations"] != LIMITATIONS:
        _invalid(f"{what}.limitations is not the exact §124 limitations text")

    predecessor = bundle["predecessor"]
    if predecessor is None:
        return
    if not allow_predecessor:
        _invalid(f"{what}.predecessor must itself have a null predecessor")
    _validate_bundle(predecessor, f"{what}.predecessor", allow_predecessor=False)


# --------------------------------------------------------------------------
# Receipt version gate (§121, §122) — unsupported versions are UNKNOWN/2
# --------------------------------------------------------------------------


def _check_receipt_version(bundle: Any, what: str) -> None:
    if type(bundle) is not dict:
        return
    receipt = bundle.get("service_receipt")
    if type(receipt) is not dict:
        return
    body = receipt.get("body")
    if type(body) is not dict or "schema_version" not in body:
        return
    version = body["schema_version"]
    if _exact_int(version) and version != 2:
        _unknown(
            f"{what} carries receipt schema version {version}; "
            "only receipt schema version 2 can be verified"
        )


# --------------------------------------------------------------------------
# Trust file (§90, §122)
# --------------------------------------------------------------------------


def _load_trust(trust_text: str | None) -> dict[str, dict[str, Any]]:
    if trust_text is None:
        _unknown("no trusted-service-keys file was supplied")
    try:
        trust = strict_loads(trust_text)
    except ValueError as exc:
        _unknown(f"trusted-service-keys file is not strictly parsable JSON: {exc}")
    if type(trust) is not dict or type(trust.get("keys")) is not list:
        _unknown("trusted-service-keys file is not a {\"keys\": [...]} document")

    resolved: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(trust["keys"]):
        where = f"trust file key[{index}]"
        if type(entry) is not dict or set(entry) != set(_TRUST_KEY_KEYS):
            _unknown(f"{where} is not a well-formed service-key entry")
        if not is_nonempty_text(entry["key_id"]):
            _unknown(f"{where}.key_id is not nonempty Text")
        if entry["algorithm"] != "Ed25519":
            _unknown(f"{where}.algorithm must be Ed25519")
        try:
            raw = b64url_decode(entry["public_key"], PUBLIC_KEY_LENGTH)
        except ValueError as exc:
            _unknown(f"{where}.public_key is not a valid 32-byte encoding: {exc}")
        if parse_timestamp(entry["valid_from"], service=True) is None:
            _unknown(f"{where}.valid_from is not a ServiceTime timestamp")
        if entry["valid_until"] is not None and (
            parse_timestamp(entry["valid_until"], service=True) is None
        ):
            _unknown(f"{where}.valid_until is not a ServiceTime timestamp or null")
        if entry["key_id"] in resolved:
            _unknown(f"trust file contains duplicate key_id {entry['key_id']!r}")
        resolved[entry["key_id"]] = {"entry": entry, "public_raw": raw}
    return resolved


# --------------------------------------------------------------------------
# Binding checks (§122)
# --------------------------------------------------------------------------


def _verify_core(
    bundle: dict[str, Any], trust: dict[str, dict[str, Any]], what: str
) -> dict[str, Any]:
    """Apply the trust, signature and binding checks to one bundle."""
    envelope = bundle["event_envelope"]
    event = envelope["event"]
    receipt = bundle["service_receipt"]
    body = receipt["body"]
    metadata = bundle["service_public_key_metadata"]

    # Trust anchor: resolve ONLY by the signed body's service_key_id.
    trusted = trust.get(body["service_key_id"])
    if trusted is None:
        _unknown(
            f"{what}: service key {body['service_key_id']!r} is not in the trust file"
        )

    # Bundle-supplied metadata is descriptive and must match the trusted entry.
    if metadata["key_id"] != trusted["entry"]["key_id"]:
        _invalid(f"{what}: bundle key metadata key_id does not match the trusted key")
    if metadata["key_id"] != body["service_key_id"]:
        _invalid(f"{what}: bundle key metadata key_id does not match the signed body")
    if metadata["algorithm"] != trusted["entry"]["algorithm"]:
        _invalid(f"{what}: bundle key metadata algorithm does not match the trusted key")
    if b64url_decode(metadata["public_key"], PUBLIC_KEY_LENGTH) != trusted["public_raw"]:
        _invalid(f"{what}: bundle key metadata public key does not match the trusted key")

    # Service signature over JCS(ReceiptBodyV2) using the trusted key.
    try:
        body_bytes = canonicalize(body)
    except Exception as exc:  # noqa: BLE001 - any JCS failure is invalid evidence
        _invalid(f"{what}: receipt body is not canonicalisable: {exc}")
    if not verify(trusted["public_raw"], receipt["signature"], body_bytes):
        _invalid(f"{what}: service receipt signature does not verify", _RECEIPT_LABEL)

    # Event hash recomputation.
    try:
        event_bytes = canonicalize(event)
    except Exception as exc:  # noqa: BLE001 - any JCS failure is invalid evidence
        _invalid(f"{what}: event is not canonicalisable: {exc}")
    computed = sha256_hash(event_bytes)
    if computed != envelope["event_hash"]:
        _invalid(f"{what}: recomputed event hash differs from the envelope", "Event hash")
    if computed != body["event_hash"]:
        _invalid(f"{what}: recomputed event hash differs from the receipt", "Event hash")

    for name in ("event_id", "organisation_id", "agent_id", "agent_key_id"):
        if body[name] != event[name]:
            _invalid(f"{what}: receipt {name} does not bind the event")

    agent_public_raw = b64url_decode(bundle["agent_public_key"], PUBLIC_KEY_LENGTH)
    if fingerprint(agent_public_raw) != body["agent_key_fingerprint"]:
        _invalid(
            f"{what}: supplied agent public key does not match the receipt fingerprint",
            "Agent key fingerprint",
        )
    if not verify(agent_public_raw, envelope["signature"], event_bytes):
        _invalid(f"{what}: agent signature does not verify", "Agent signature")

    _verify_context(event, body, what)
    parsed_event: dict[str, Any] = event
    return parsed_event


def _verify_context(event: dict[str, Any], body: dict[str, Any], what: str) -> None:
    occurred_at = parse_timestamp(event["occurred_at"])
    if occurred_at is None:  # already rejected by _validate_event
        _invalid(f"{what}.occurred_at is not a valid Timestamp")
    sponsor = body["sponsor"]
    grant = body["grant"]

    if sponsor is not None:
        if body["agent_sponsor_id"] != sponsor["id"]:
            _invalid(f"{what}: agent_sponsor_id does not equal sponsor.id")
        if body["sponsor_user_id_snapshot"] != sponsor["user_id"]:
            _invalid(f"{what}: sponsor_user_id_snapshot does not equal sponsor.user_id")
        if sponsor["organisation_id"] != event["organisation_id"]:
            _invalid(f"{what}: sponsor organisation does not match the event")
        if sponsor["agent_id"] != event["agent_id"]:
            _invalid(f"{what}: sponsor agent does not match the event")
        if not _contains(sponsor, occurred_at):
            _invalid(f"{what}: sponsor interval does not contain occurred_at")
    elif body["agent_sponsor_id"] is not None or body["sponsor_user_id_snapshot"] is not None:
        _invalid(f"{what}: null sponsor requires null sponsor root fields")

    if grant is not None:
        if body["grant_id"] != grant["id"]:
            _invalid(f"{what}: grant_id does not equal grant.id")
        if body["capabilities_snapshot"] != grant["capabilities"]:
            _invalid(f"{what}: capabilities_snapshot does not equal grant.capabilities")
        if sponsor is None:
            _invalid(f"{what}: a grant requires a sponsor snapshot")
        if grant["sponsor_id"] != sponsor["id"]:
            _invalid(f"{what}: grant.sponsor_id does not equal sponsor.id")
        if grant["organisation_id"] != event["organisation_id"]:
            _invalid(f"{what}: grant organisation does not match the event")
        if grant["agent_id"] != event["agent_id"]:
            _invalid(f"{what}: grant agent does not match the event")
        if not _within(grant, sponsor):
            _invalid(f"{what}: grant interval is not within the sponsor interval")
        if not _contains(grant, occurred_at):
            _invalid(f"{what}: grant interval does not contain occurred_at")
        if event["action_name"] not in grant["capabilities"]:
            _invalid(f"{what}: action_name is not a member of grant.capabilities")
    elif body["grant_id"] is not None or body["capabilities_snapshot"] is not None:
        _invalid(f"{what}: null grant requires null grant root fields")


def _contains(record: dict[str, Any], moment: _datetime.datetime) -> bool:
    """Half-open interval test: valid_from <= moment < valid_until."""
    start = parse_timestamp(record["valid_from"], service=True)
    end = parse_timestamp(record["valid_until"], service=True)
    if start is None or moment < start:
        return False
    return end is None or moment < end


def _within(grant: dict[str, Any], sponsor: dict[str, Any]) -> bool:
    """True when the grant interval lies inside the sponsor interval."""
    grant_from = parse_timestamp(grant["valid_from"], service=True)
    sponsor_from = parse_timestamp(sponsor["valid_from"], service=True)
    if grant_from is None or sponsor_from is None or grant_from < sponsor_from:
        return False
    sponsor_until = parse_timestamp(sponsor["valid_until"], service=True)
    if sponsor_until is None:
        return True
    grant_until = parse_timestamp(grant["valid_until"], service=True)
    return grant_until is not None and grant_until <= sponsor_until


def _verify_link(bundle: dict[str, Any], event: dict[str, Any],
                 predecessor_event: dict[str, Any]) -> None:
    label = "Runtime chain link"
    for name in ("organisation_id", "agent_id", "runtime_id"):
        if predecessor_event[name] != event[name]:
            _invalid(f"predecessor {name} does not match the event", label)
    if predecessor_event["sequence"] != event["sequence"] - 1:
        _invalid("predecessor sequence is not N-1", label)
    predecessor_hash = bundle["predecessor"]["event_envelope"]["event_hash"]
    if predecessor_hash != event["previous_event_hash"]:
        _invalid("predecessor hash does not equal previous_event_hash", label)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def verify_bundle(bundle_text: str, trust_text: str | None) -> Result:
    """Verify an evidence bundle offline and return a :class:`Result`.

    Exit codes follow §123: ``0`` valid, ``1`` invalid, ``2``
    incomplete/unverifiable.
    """
    try:
        try:
            bundle = strict_loads(bundle_text)
        except ValueError as exc:
            _invalid(f"evidence bundle is not strictly parsable JSON: {exc}")

        if type(bundle) is not dict:
            _invalid("evidence bundle is not a JSON object")
        version = bundle.get("schema_version")
        if not _exact_int(version) or version != 2:
            _invalid("evidence bundle schema_version must be the integer 2")

        # Unsupported receipt versions are UNKNOWN before any schema verdict.
        _check_receipt_version(bundle, "bundle")
        if type(bundle.get("predecessor")) is dict:
            _check_receipt_version(bundle["predecessor"], "predecessor bundle")

        _validate_bundle(bundle, "bundle", allow_predecessor=True)
        trust = _load_trust(trust_text)

        event = _verify_core(bundle, trust, "bundle")
        predecessor = bundle["predecessor"]
        if predecessor is None:
            chain = _line("Runtime chain", "NOT VERIFIED", "predecessor absent")
        else:
            predecessor_event = _verify_core(predecessor, trust, "predecessor bundle")
            _verify_link(bundle, event, predecessor_event)
            chain = "Runtime chain link: VALID"
    except _Reject as reject:
        return Result(reject.code, _failure_lines(reject))

    return Result(
        EXIT_VALID,
        [
            _line("Event hash", "VALID"),
            _line("Agent signature", "VALID"),
            _line("Agent key fingerprint", "VALID"),
            _line("Service receipt", "VALID"),
            chain,
        ],
    )


def validate_bundle_document(bundle: object) -> None:
    """Structurally validate a parsed evidence bundle (§121), nothing more.

    Public wrapper over the internal schema check so other modules (the
    format exporters) validate a bundle exactly as ``verify_bundle`` does
    instead of duplicating the record rules.  No trust file, no signature
    verification: this answers "is this a well-formed bundle?" only.  Raises
    ``ValueError`` describing the first violation.
    """
    try:
        _validate_bundle(bundle, "bundle", allow_predecessor=True)
    except _Reject as reject:
        raise ValueError(reject.reason) from None


def _failure_lines(reject: _Reject) -> list[str]:
    status = "INVALID" if reject.code == EXIT_INVALID else "UNKNOWN"
    lines = []
    if reject.label != _BUNDLE_LABEL:
        lines.append(_line(reject.label, status, reject.reason))
    lines.append(_line(_BUNDLE_LABEL, status, reject.reason))
    return lines
