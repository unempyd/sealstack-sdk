"""External-format exports of a SealStack evidence bundle (SDK only).

Three targets, one signed artifact per SealStack event:

* AERF v0.1.0-draft.1 (Agent Evidence Receipt Format), signature hex Ed25519
  over the ASCII-escaped sorted-compact canonical payload.
* Agent Receipt Protocol v0.5.0, a W3C Verifiable Credential secured with an
  Ed25519Signature2020 proof over RFC 8785 bytes.
* The noa SCITT profile (draft-noa-scitt-ai-agent-receipt-01), bare receipt
  form. No COSE envelope is produced, so no SCITT Signed Statement is
  registered.

The three builders are pure functions of ``(bundle, mapping, seed)`` plus an
explicit export time, so tests call them without the CLI. Nothing here reads
files, opens sockets or mutates an identity; the CLI does the I/O.

Two modes. In ``subset`` mode (no mapping) a field whose semantics SealStack
does not record is OMITTED, never guessed and never written as null, and the
artifact is labelled non-conformant naming exactly those fields. In ``full``
mode the operator's mapping file supplies those semantics; a gap is an error,
never a silent fall back to subset.
"""

from __future__ import annotations

import base64
import datetime as _datetime
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Final, NamedTuple, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from product.signing import SEED_LENGTH, canonicalize, public_key_from_seed
from product.verify import validate_bundle_document

__all__ = [
    "AERF_VERSION",
    "AGENT_RECEIPTS_VERSION",
    "BUILDERS",
    "FORMATS",
    "NOA_ENVELOPE_LINE",
    "NOA_MESSAGE_PREFIX",
    "NOA_SPEC",
    "Export",
    "ExportError",
    "Labels",
    "build_aerf",
    "build_agent_receipt",
    "build_noa",
    "load_bundle",
    "load_mapping",
    "public_key_pem",
]

AERF_VERSION: Final[str] = "v0.1.0-draft.1"
AGENT_RECEIPTS_VERSION: Final[str] = "0.5.0"
NOA_SPEC: Final[str] = "noa.receipt/0.1"
NOA_DRAFT: Final[str] = "draft-noa-scitt-ai-agent-receipt-01"
NOA_MESSAGE_PREFIX: Final[bytes] = b"NOA-Receipt-v0.1-sig:"
NOA_ENVELOPE_LINE: Final[str] = (
    "envelope: bare receipt (no COSE; SCITT registration not produced)"
)

FORMATS: Final[tuple[str, ...]] = ("aerf", "agent-receipts", "scitt")

#: Default artifact suffix per format (the CLI derives ``--out`` from it).
ARTIFACT_SUFFIX: Final[dict[str, str]] = {
    "aerf": "aerf",
    "agent-receipts": "agent-receipt",
    "scitt": "noa",
}

AERF_ACTION_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_:.\-]{1,128}", re.ASCII)

AGENT_RECEIPT_CONTEXT: Final[list[str]] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentreceipts.ai/context/v2",
]

_RISK_LEVELS: Final[tuple[str, ...]] = ("low", "medium", "high", "critical")
_NOA_PRINCIPALS: Final[tuple[str, ...]] = ("HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM")
_NOA_RISK_CLASSES: Final[tuple[str, ...]] = (
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "IRREVERSIBLE",
)

_OUTCOME_STATUS: Final[dict[str, str]] = {
    "action.started": "pending",
    "action.completed": "success",
    "action.failed": "failure",
}
_NOA_VERDICT: Final[dict[str, str]] = {
    "action.started": "ALLOWED",
    "action.completed": "EXECUTED",
    "action.failed": "FAILED",
}

_BASE58_ALPHABET: Final[str] = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)
_ED25519_MULTICODEC: Final[bytes] = b"\xed\x01"

CHAIN_SET: Final[str] = "set"
CHAIN_GENESIS: Final[str] = "genesis"
CHAIN_NO_PREDECESSOR: Final[str] = "no predecessor evidence"


def _chain_line(state: str, field: str, genesis_form: str) -> str:
    """The printed chain line, naming the target format's own field.

    ``genesis_form`` is how the target format records genesis: AERF omits the
    field, the other two write an explicit null.
    """
    if state == CHAIN_SET:
        return f"{field} set"
    if state == CHAIN_GENESIS:
        return f"{field} {genesis_form} (genesis)"
    return f"{field} omitted ({CHAIN_NO_PREDECESSOR})"


class ExportError(Exception):
    """A usage, mapping or identity error: the CLI turns this into exit 2."""


@dataclass(frozen=True)
class Labels:
    """What the CLI prints and what the companion object records."""

    format_line: str
    mode: str
    missing_fields: tuple[str, ...]
    signing_key: str
    chain: str
    chain_line: str
    embedded_evidence: bool
    notes: tuple[str, ...] = ()

    @property
    def conformant(self) -> bool:
        return not self.missing_fields

    @property
    def mode_line(self) -> str:
        if self.conformant:
            return f"mode: {self.mode}"
        return (
            f"mode: {self.mode} (non-conformant): missing "
            + ", ".join(self.missing_fields)
        )


class Export(NamedTuple):
    """One built artifact, its companion object (if any) and its labels."""

    artifact: dict[str, Any]
    companion: dict[str, Any] | None
    labels: Labels


# --------------------------------------------------------------------------
# Small typed accessors over an already validated bundle
# --------------------------------------------------------------------------


def _object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExportError(f"{what} is not a JSON object")
    record: dict[str, Any] = value
    return record


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ExportError(f"{what} is not a string")
    return value


def _integer(value: Any, what: str) -> int:
    if type(value) is not int:
        raise ExportError(f"{what} is not an integer")
    return value


def _event_of(bundle: dict[str, Any]) -> dict[str, Any]:
    return _object(_object(bundle["event_envelope"], "event_envelope")["event"], "event")


def _receipt_body(bundle: dict[str, Any]) -> dict[str, Any]:
    receipt = _object(bundle["service_receipt"], "service_receipt")
    return _object(receipt["body"], "service_receipt.body")


def _predecessor_of(bundle: dict[str, Any]) -> dict[str, Any] | None:
    predecessor = bundle.get("predecessor")
    return None if predecessor is None else _object(predecessor, "predecessor")


def _digest_value(digest: Any) -> str | None:
    """The ``sha256:...`` value of an available Digest, else ``None``."""
    if not isinstance(digest, dict):
        return None
    record: dict[str, Any] = digest
    if record.get("status") != "available":
        return None
    value = record.get("value")
    return value if isinstance(value, str) else None


# --------------------------------------------------------------------------
# Canonicalisation, hashing and key material
# --------------------------------------------------------------------------


def aerf_canonical(value: Any) -> bytes:
    """AERF v0.1 canonical JSON: sorted, compact, ASCII escaped (SPEC 5.1)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha512_hex(raw: bytes) -> str:
    return hashlib.sha512(raw).hexdigest()


def aerf_key_id(public_raw: bytes) -> str:
    """AERF key_id: the first 16 hex characters of SHA-256(raw public key)."""
    return _sha256_hex(public_raw)[:16]


def public_key_pem(seed: bytes) -> bytes:
    """The SPKI PEM (RFC 8410) of the public key for ``seed``."""
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return private.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def _sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def _base58btc(raw: bytes) -> str:
    """Bitcoin-alphabet base58 of ``raw`` (no dependency, no checksum)."""
    number = int.from_bytes(raw, "big")
    digits: list[str] = []
    while number > 0:
        number, remainder = divmod(number, 58)
        digits.append(_BASE58_ALPHABET[remainder])
    leading = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading + "".join(reversed(digits))


def did_key(public_raw: bytes) -> str:
    """The did:key identifier of a raw 32-byte Ed25519 public key."""
    return "did:key:z" + _base58btc(_ED25519_MULTICODEC + public_raw)


def _check_seed(seed: bytes) -> bytes:
    if len(seed) != SEED_LENGTH:
        raise ExportError(f"signing seed must be {SEED_LENGTH} bytes")
    return seed


def export_timestamp(now: _datetime.datetime | None = None) -> str:
    """Export time as UTC, seconds precision, ``Z`` suffix."""
    moment = now if now is not None else _datetime.datetime.now(_datetime.UTC)
    return moment.astimezone(_datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Input documents
# --------------------------------------------------------------------------


def load_bundle(text: str) -> dict[str, Any]:
    """Parse and structurally validate an evidence bundle.

    Raises ``ValueError`` when the document is not a valid bundle; the CLI
    turns that into exit 1 without writing anything.
    """
    document = json.loads(text)
    validate_bundle_document(document)
    bundle: dict[str, Any] = document
    return bundle


_MAPPING_SECTIONS: Final[dict[str, tuple[str, ...]]] = {
    "aerf": ("plan_id_source", "actions"),
    "agent_receipts": ("actions",),
    "noa": ("agent", "actions"),
}
_ACTION_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "aerf": ("in_policy", "policy_reason", "action"),
    "agent_receipts": ("type", "risk_level"),
    "noa": ("riskClass", "reversible", "canonical"),
}


def load_mapping(text: str) -> dict[str, Any]:
    """Parse and strictly validate a mapping file; unknown keys are errors."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ExportError(f"mapping file is not valid JSON: {exc}") from None
    mapping = _object(document, "mapping file")
    unknown = sorted(set(mapping) - set(_MAPPING_SECTIONS))
    if unknown:
        raise ExportError(f"mapping file has unknown top-level keys: {unknown}")
    for name, allowed in _MAPPING_SECTIONS.items():
        if name not in mapping:
            continue
        section = _object(mapping[name], f"mapping.{name}")
        extra = sorted(set(section) - set(allowed))
        if extra:
            raise ExportError(f"mapping.{name} has unknown keys: {extra}")
        _validate_mapping_section(name, section)
    return mapping


def _validate_mapping_section(name: str, section: dict[str, Any]) -> None:
    if name == "aerf" and "plan_id_source" in section:
        source = section["plan_id_source"]
        if source != "action_id":
            raise ExportError(
                "mapping.aerf.plan_id_source must be the literal \"action_id\": "
                "SealStack records no plan, so using the action invocation id as "
                "plan_id is the operator's explicit choice"
            )
    if name == "noa" and "agent" in section:
        agent = _object(section["agent"], "mapping.noa.agent")
        extra = sorted(set(agent) - {"principal", "sandboxed"})
        if extra:
            raise ExportError(f"mapping.noa.agent has unknown keys: {extra}")
        if "principal" in agent and agent["principal"] not in _NOA_PRINCIPALS:
            raise ExportError(
                f"mapping.noa.agent.principal must be one of {list(_NOA_PRINCIPALS)}"
            )
        if "sandboxed" in agent and not isinstance(agent["sandboxed"], bool):
            raise ExportError("mapping.noa.agent.sandboxed must be a boolean")
    actions = section.get("actions")
    if actions is None:
        return
    for action_name, entry in _object(actions, f"mapping.{name}.actions").items():
        where = f"mapping.{name}.actions[{action_name!r}]"
        record = _object(entry, where)
        extra = sorted(set(record) - set(_ACTION_FIELDS[name]))
        if extra:
            raise ExportError(f"{where} has unknown keys: {extra}")
        _validate_action_entry(name, record, where)


def _validate_action_entry(name: str, entry: dict[str, Any], where: str) -> None:
    if name == "aerf":
        if "in_policy" in entry and not isinstance(entry["in_policy"], bool):
            raise ExportError(f"{where}.in_policy must be a boolean")
        for field in ("policy_reason", "action"):
            if field in entry and not isinstance(entry[field], str):
                raise ExportError(f"{where}.{field} must be a string")
        if "action" in entry and not AERF_ACTION_RE.fullmatch(entry["action"]):
            raise ExportError(
                f"{where}.action must match ^[A-Za-z0-9_:.-]{{1,128}}$"
            )
    elif name == "agent_receipts":
        if "type" in entry and not isinstance(entry["type"], str):
            raise ExportError(f"{where}.type must be a string")
        if "risk_level" in entry and entry["risk_level"] not in _RISK_LEVELS:
            raise ExportError(f"{where}.risk_level must be one of {list(_RISK_LEVELS)}")
    else:
        if "riskClass" in entry and entry["riskClass"] not in _NOA_RISK_CLASSES:
            raise ExportError(
                f"{where}.riskClass must be one of {list(_NOA_RISK_CLASSES)}"
            )
        if "reversible" in entry and not isinstance(entry["reversible"], bool):
            raise ExportError(f"{where}.reversible must be a boolean")
        if "canonical" in entry and not isinstance(entry["canonical"], str):
            raise ExportError(f"{where}.canonical must be a string")


def _section(mapping: dict[str, Any] | None, name: str) -> dict[str, Any] | None:
    if mapping is None or name not in mapping:
        return None
    return _object(mapping[name], f"mapping.{name}")


def _action_entry(section: dict[str, Any] | None, action_name: str) -> dict[str, Any]:
    """The mapping entry for ``action_name``, or the operator's ``default``."""
    if section is None:
        return {}
    actions = section.get("actions")
    if actions is None:
        return {}
    table = _object(actions, "mapping actions")
    entry = table.get(action_name, table.get("default"))
    return {} if entry is None else _object(entry, "mapping action entry")


def _required(
    entry: dict[str, Any], field: str, action_name: str, where: str
) -> Any:
    if field not in entry:
        raise ExportError(
            f"mapping has no {where}.{field} for action {action_name!r}"
        )
    return entry[field]


# --------------------------------------------------------------------------
# AERF v0.1.0-draft.1
# --------------------------------------------------------------------------


def _aerf_evidence(
    bundle: dict[str, Any], mode: str, missing: tuple[str, ...], notes: tuple[str, ...]
) -> dict[str, Any]:
    """The native SealStack evidence, embedded whole in the AERF receipt."""
    envelope = _object(bundle["event_envelope"], "event_envelope")
    event = _event_of(bundle)
    body = _receipt_body(bundle)
    return {
        "format": "sealstack/v1",
        "event_type": event["event_type"],
        "event": event,
        "event_hash": envelope["event_hash"],
        "agent_signature": envelope["signature"],
        "agent_public_key": bundle["agent_public_key"],
        "agent_key_fingerprint": body["agent_key_fingerprint"],
        "received_at": body["received_at"],
        "service_receipt": bundle["service_receipt"],
        "service_public_key_metadata": bundle["service_public_key_metadata"],
        "sealstack_export": {
            "mode": mode,
            "missing_fields": list(missing),
            "notes": list(notes),
        },
    }


def _aerf_payload(
    bundle: dict[str, Any], mapping: dict[str, Any] | None, key_id: str
) -> tuple[dict[str, Any], tuple[str, ...], str]:
    """Build one unsigned AERF payload, its missing fields and its chain state."""
    event = _event_of(bundle)
    action_name = _text(event["action_name"], "action_name")
    section = _section(mapping, "aerf")
    entry = _action_entry(section, action_name)
    missing: list[str] = []
    notes: list[str] = []

    payload: dict[str, Any] = {
        "id": event["event_id"],
        "type": "notarised_evidence",
        "agent": event["agent_id"],
        "session_id": event["runtime_id"],
        "observed_at": event["occurred_at"],
        "key_id": key_id,
    }

    if AERF_ACTION_RE.fullmatch(action_name):
        payload["action"] = action_name
    elif "action" in entry:
        payload["action"] = entry["action"]
        notes.append(
            f"action was mapped to {entry['action']!r}; the SealStack action name "
            f"{action_name!r} is outside the AERF charset"
        )
    else:
        payload["action"] = action_name
        missing.append("action (outside the AERF charset, emitted verbatim)")

    if mapping is None:
        missing.extend(("plan_id", "in_policy", "policy_reason"))
    else:
        if section is None or "plan_id_source" not in section:
            raise ExportError(
                "mapping has no aerf.plan_id_source; SealStack records no plan, so "
                "full mode requires the operator to choose \"action_id\" explicitly"
            )
        if AERF_ACTION_RE.fullmatch(action_name) is None and "action" not in entry:
            raise ExportError(
                f"mapping has no aerf.actions.action alias for action "
                f"{action_name!r}, which is outside the AERF charset"
            )
        payload["plan_id"] = event["action_id"]
        payload["in_policy"] = _required(entry, "in_policy", action_name, "aerf.actions")
        payload["policy_reason"] = _required(
            entry, "policy_reason", action_name, "aerf.actions"
        )
        notes.append(
            "plan_id carries the SealStack action invocation id by operator mapping; "
            "SealStack records no plan receipt"
        )

    output_value = _digest_value(event.get("output_digest"))
    if output_value is not None:
        payload["output_hash"] = output_value.removeprefix("sha256:")

    sequence = _integer(event["sequence"], "sequence")
    predecessor = _predecessor_of(bundle)
    if sequence == 1:
        chain = CHAIN_GENESIS
    elif predecessor is None:
        chain = CHAIN_NO_PREDECESSOR
        missing.append("previous_receipt_hash")
    else:
        chain = CHAIN_SET
        previous, _, _ = _aerf_payload(predecessor, mapping, key_id)
        payload["previous_receipt_hash"] = _sha256_hex(aerf_canonical(previous))

    mode = "subset" if mapping is None else "full"
    payload["evidence"] = _aerf_evidence(bundle, mode, tuple(missing), tuple(notes))
    payload["evidence_hash_sha512"] = _sha512_hex(aerf_canonical(payload["evidence"]))
    return payload, tuple(missing), chain


def build_aerf(
    bundle: dict[str, Any],
    mapping: dict[str, Any] | None,
    seed: bytes,
    *,
    now: _datetime.datetime | None = None,
) -> Export:
    """Build a signed AERF v0.1.0-draft.1 receipt for the bundle's event.

    The native evidence is embedded in the ``evidence`` object, which AERF
    defines for exactly that purpose, so no companion file is written.
    """
    del now  # AERF carries observed_at only; no export time is recorded.
    _check_seed(seed)
    key_id = aerf_key_id(public_key_from_seed(seed))
    payload, missing, chain = _aerf_payload(bundle, mapping, key_id)
    payload["signature"] = _sign(seed, aerf_canonical(payload)).hex()
    labels = Labels(
        format_line=f"aerf {AERF_VERSION}",
        mode="subset" if mapping is None else "full",
        missing_fields=missing,
        signing_key=key_id,
        chain=chain,
        chain_line=_chain_line(chain, "previous_receipt_hash", "omitted"),
        embedded_evidence=True,
        notes=(
            (
                "no RFC 3161 timestamp is produced: SealStack has no timestamp "
                "authority, which the AERF production profile requires"
            ),
        ),
    )
    return Export(payload, None, labels)


# --------------------------------------------------------------------------
# Agent Receipt Protocol v0.5.0
# --------------------------------------------------------------------------


def _agent_receipt_principal(body: dict[str, Any], event: dict[str, Any]) -> dict[str, str]:
    sponsor = body.get("sponsor")
    if isinstance(sponsor, dict):
        snapshot: dict[str, Any] = sponsor
        return {
            "id": "urn:uuid:" + _text(snapshot["user_id"], "sponsor.user_id"),
            "type": "HumanPrincipal",
        }
    return {
        "id": "urn:uuid:" + _text(event["organisation_id"], "organisation_id"),
        "type": "OrganizationPrincipal",
    }


def _agent_receipt_action(
    event: dict[str, Any], entry: dict[str, Any], mapping: dict[str, Any] | None
) -> tuple[dict[str, Any], list[str]]:
    action_name = _text(event["action_name"], "action_name")
    action: dict[str, Any] = {
        "id": "act_" + _text(event["action_id"], "action_id"),
        "timestamp": event["occurred_at"],
    }
    missing: list[str] = []
    if mapping is None:
        missing.extend(("action.type", "action.risk_level"))
    else:
        action["type"] = _required(entry, "type", action_name, "agent_receipts.actions")
        action["risk_level"] = _required(
            entry, "risk_level", action_name, "agent_receipts.actions"
        )

    resource = event.get("resource")
    if isinstance(resource, dict):
        record: dict[str, Any] = resource
        target = {
            key: value
            for key, value in (("system", record["type"]), ("resource", record["id"]))
            if value is not None
        }
        if target:
            action["target"] = target

    parameters_hash = _digest_value(event.get("input_digest"))
    if parameters_hash is not None:
        action["parameters_hash"] = parameters_hash
    return action, missing


def _agent_receipt_outcome(event: dict[str, Any]) -> dict[str, Any]:
    event_type = _text(event["event_type"], "event_type")
    outcome: dict[str, Any] = {"status": _OUTCOME_STATUS[event_type]}
    if event_type == "action.failed":
        outcome["error"] = event["error_type"]
    response_hash = _digest_value(event.get("output_digest"))
    if response_hash is not None:
        outcome["response_hash"] = response_hash
    return outcome


def _agent_receipt_authorization(body: dict[str, Any]) -> dict[str, Any] | None:
    grant = body.get("grant")
    if not isinstance(grant, dict):
        return None
    snapshot: dict[str, Any] = grant
    authorization: dict[str, Any] = {
        "scopes": snapshot["capabilities"],
        "granted_at": snapshot["valid_from"],
        "grant_ref": snapshot["id"],
    }
    if snapshot["valid_until"] is not None:
        authorization["expires_at"] = snapshot["valid_until"]
    return authorization


def _agent_receipt_credential(
    bundle: dict[str, Any], mapping: dict[str, Any] | None, issued_at: str, did: str
) -> tuple[dict[str, Any], tuple[str, ...], str]:
    """Build one unsigned Agent Receipt credential, its gaps and chain state."""
    event = _event_of(bundle)
    body = _receipt_body(bundle)
    entry = _action_entry(_section(mapping, "agent_receipts"), _text(
        event["action_name"], "action_name"))
    action, missing = _agent_receipt_action(event, entry, mapping)

    subject: dict[str, Any] = {
        "principal": _agent_receipt_principal(body, event),
        "action": action,
        "outcome": _agent_receipt_outcome(event),
    }
    authorization = _agent_receipt_authorization(body)
    if authorization is not None:
        subject["authorization"] = authorization

    sequence = _integer(event["sequence"], "sequence")
    predecessor = _predecessor_of(bundle)
    chain_id = event["runtime_id"]
    if sequence == 1:
        chain = CHAIN_GENESIS
        subject["chain"] = {
            "chain_id": chain_id,
            "sequence": sequence,
            "previous_receipt_hash": None,
        }
    elif predecessor is None:
        chain = CHAIN_NO_PREDECESSOR
        missing.append("chain")
    else:
        chain = CHAIN_SET
        previous, _, _ = _agent_receipt_credential(predecessor, mapping, issued_at, did)
        subject["chain"] = {
            "chain_id": chain_id,
            "sequence": sequence,
            "previous_receipt_hash": "sha256:" + _sha256_hex(canonicalize(previous)),
        }

    credential: dict[str, Any] = {
        "@context": list(AGENT_RECEIPT_CONTEXT),
        "id": "urn:receipt:" + _text(event["event_id"], "event_id"),
        "type": ["VerifiableCredential", "AgentReceipt"],
        "version": AGENT_RECEIPTS_VERSION,
        "issuer": {"id": did, "type": "AIAgent", "session_id": chain_id},
        "issuanceDate": issued_at,
        "credentialSubject": subject,
    }
    return credential, tuple(missing), chain


def build_agent_receipt(
    bundle: dict[str, Any],
    mapping: dict[str, Any] | None,
    seed: bytes,
    *,
    now: _datetime.datetime | None = None,
) -> Export:
    """Build a signed Agent Receipt Protocol v0.5.0 verifiable credential.

    The protocol has no slot for a second party's receipt, so the native
    SealStack bundle is written beside the artifact as a companion object
    rather than smuggled into undeclared credential fields.
    """
    _check_seed(seed)
    public_raw = public_key_from_seed(seed)
    did = did_key(public_raw)
    issued_at = export_timestamp(now)
    credential, missing, chain = _agent_receipt_credential(bundle, mapping, issued_at, did)
    signature = _sign(seed, canonicalize(credential))
    credential["proof"] = {
        "type": "Ed25519Signature2020",
        "created": issued_at,
        "verificationMethod": did + "#" + did.removeprefix("did:key:"),
        "proofPurpose": "assertionMethod",
        "proofValue": "u" + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }
    labels = Labels(
        format_line=f"agent-receipts v{AGENT_RECEIPTS_VERSION}",
        mode="subset" if mapping is None else "full",
        missing_fields=missing,
        signing_key=did,
        chain=chain,
        chain_line=(
            "chain object omitted (" + CHAIN_NO_PREDECESSOR + ")"
            if chain == CHAIN_NO_PREDECESSOR
            else _chain_line(chain, "previous_receipt_hash", "null")
        ),
        embedded_evidence=False,
        notes=(
            (
                "no trusted_timestamp is produced: SealStack has no timestamp "
                "authority"
            ),
        ),
    )
    return Export(credential, _companion(bundle, labels), labels)


# --------------------------------------------------------------------------
# noa SCITT profile, bare receipt form
# --------------------------------------------------------------------------


def _noa_receipt(
    bundle: dict[str, Any], mapping: dict[str, Any] | None
) -> tuple[dict[str, Any], tuple[str, ...], str]:
    """Build one unsigned noa bare receipt (no chain.hash, no sig.value)."""
    event = _event_of(bundle)
    action_name = _text(event["action_name"], "action_name")
    section = _section(mapping, "noa")
    entry = _action_entry(section, action_name)
    missing: list[str] = []

    agent: dict[str, Any] = {"id": event["agent_id"]}
    governance: dict[str, Any] = {
        "mode": "off",
        "verdict": _NOA_VERDICT[_text(event["event_type"], "event_type")],
    }
    action: dict[str, Any] = {"id": action_name, "canonical": action_name}

    if mapping is None:
        missing.extend(
            ("agent.principal", "action.riskClass", "action.reversible",
             "governance.sandboxed")
        )
    else:
        agent_section = _object(
            section["agent"] if section is not None and "agent" in section else {},
            "mapping.noa.agent",
        )
        if "principal" not in agent_section:
            raise ExportError("mapping has no noa.agent.principal")
        if "sandboxed" not in agent_section:
            raise ExportError("mapping has no noa.agent.sandboxed")
        agent["principal"] = agent_section["principal"]
        governance["sandboxed"] = agent_section["sandboxed"]
        if agent["principal"] == "SANDBOX_SIM" and governance["sandboxed"] is not True:
            raise ExportError(
                "mapping.noa: governance.sandboxed must be true when "
                "agent.principal is SANDBOX_SIM"
            )
        action["riskClass"] = _required(entry, "riskClass", action_name, "noa.actions")
        action["reversible"] = _required(entry, "reversible", action_name, "noa.actions")
        if "canonical" in entry:
            action["canonical"] = entry["canonical"]

    params_hash = _digest_value(event.get("input_digest"))
    if params_hash is not None:
        action["paramsHash"] = params_hash
    else:
        missing.append("action.paramsHash")

    sequence = _integer(event["sequence"], "sequence")
    predecessor = _predecessor_of(bundle)
    chain: dict[str, Any] = {"seq": sequence - 1}
    if sequence == 1:
        chain_state = CHAIN_GENESIS
        chain["prevHash"] = None
    elif predecessor is None:
        chain_state = CHAIN_NO_PREDECESSOR
        missing.append("chain.prevHash")
    else:
        chain_state = CHAIN_SET
        chain["prevHash"] = _noa_chain_hash(predecessor, mapping)

    receipt: dict[str, Any] = {
        "spec": NOA_SPEC,
        "id": event["event_id"],
        "ts": event["occurred_at"],
        "scope": {"chain": event["runtime_id"], "tenant": event["organisation_id"]},
        "agent": agent,
        "action": action,
        "governance": governance,
        "chain": chain,
        "sig": {"alg": "ed25519", "kid": event["agent_key_id"]},
    }
    return receipt, tuple(missing), chain_state


def noa_hash_input(receipt: dict[str, Any]) -> bytes:
    """RFC 8785 bytes of the receipt without ``chain.hash`` and ``sig.value``.

    ``sig.alg`` and ``sig.kid`` stay in the hash input; producer and verifier
    call this same function so the two can never drift.
    """
    stripped = dict(receipt)
    for member, dropped in (("chain", "hash"), ("sig", "value")):
        part = stripped.get(member)
        if isinstance(part, dict):
            copy: dict[str, Any] = dict(part)
            copy.pop(dropped, None)
            stripped[member] = copy
    return canonicalize(stripped)


def _noa_chain_hash(bundle: dict[str, Any], mapping: dict[str, Any] | None) -> str:
    receipt, _, _ = _noa_receipt(bundle, mapping)
    return "sha256:" + _sha256_hex(noa_hash_input(receipt))


def noa_message(hash_input: bytes) -> bytes:
    """The signed message: the 21 octet prefix plus raw SHA-256(HASH-INPUT)."""
    return NOA_MESSAGE_PREFIX + hashlib.sha256(hash_input).digest()


def build_noa(
    bundle: dict[str, Any],
    mapping: dict[str, Any] | None,
    seed: bytes,
    *,
    now: _datetime.datetime | None = None,
) -> Export:
    """Build a signed noa bare receipt (draft-noa-scitt-ai-agent-receipt-01).

    Only the bare form is produced. The COSE envelope required for SCITT
    Signed Statement registration is out of scope, so no registration
    happens and no CBOR or COSE dependency is added.
    """
    del now  # The bare receipt records the event time only.
    _check_seed(seed)
    receipt, missing, chain_state = _noa_receipt(bundle, mapping)
    hash_input = noa_hash_input(receipt)
    receipt["chain"]["hash"] = "sha256:" + _sha256_hex(hash_input)
    signature = _sign(seed, noa_message(hash_input))
    receipt["sig"]["value"] = base64.b64encode(signature).decode("ascii")
    labels = Labels(
        format_line=f"scitt {NOA_SPEC} ({NOA_DRAFT})",
        mode="subset" if mapping is None else "full",
        missing_fields=missing,
        signing_key=_text(receipt["sig"]["kid"], "sig.kid"),
        chain=chain_state,
        chain_line=_chain_line(chain_state, "prevHash", "null"),
        embedded_evidence=False,
        notes=(
            (
                "bare receipt form only: no COSE envelope is built, so no SCITT "
                "Signed Statement is registered"
            ),
        ),
    )
    return Export(receipt, _companion(bundle, labels), labels)


# --------------------------------------------------------------------------
# Companion object
# --------------------------------------------------------------------------


def _companion(bundle: dict[str, Any], labels: Labels) -> dict[str, Any]:
    """The native bundle beside an artifact whose format cannot embed it."""
    return {
        "format": "sealstack/v1",
        "sealstack_export": {
            "target_format": labels.format_line,
            "mode": labels.mode,
            "missing_fields": list(labels.missing_fields),
            "notes": list(labels.notes),
        },
        "bundle": bundle,
    }


class Builder(Protocol):
    """The shared shape of the three format builders."""

    def __call__(
        self,
        bundle: dict[str, Any],
        mapping: dict[str, Any] | None,
        seed: bytes,
        *,
        now: _datetime.datetime | None = None,
    ) -> Export: ...


BUILDERS: Final[dict[str, Builder]] = {
    "aerf": build_aerf,
    "agent-receipts": build_agent_receipt,
    "scitt": build_noa,
}
