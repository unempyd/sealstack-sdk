"""Shared cryptographic and canonicalisation primitives (SPEC §16, §30, §33–§35).

This module is the single source of truth for the SDK's value profile, JCS
canonicalisation, hashing, base64url encoding, Ed25519 signing/verification,
strict JSON parsing and strict timestamp parsing.  It performs no I/O and
opens no sockets at import time.
"""

from __future__ import annotations

import base64
import datetime as _datetime
import hashlib
import json
import math
import os
import re
from decimal import Decimal, InvalidOperation
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "BASE64URL_RE",
    "HASH_RE",
    "MAX_SAFE",
    "PUBLIC_KEY_LENGTH",
    "SEED_LENGTH",
    "SIGNATURE_LENGTH",
    "TIMESTAMP_RE",
    "UNSUPPORTED_DIGEST",
    "UUID_RE",
    "b64url_decode",
    "b64url_encode",
    "canonicalize",
    "digest",
    "event_hash",
    "fingerprint",
    "generate_seed",
    "is_hash",
    "is_nonempty_text",
    "is_supported",
    "is_text",
    "is_uuid",
    "now_timestamp",
    "parse_timestamp",
    "public_key_from_seed",
    "sha256_hash",
    "sign",
    "strict_loads",
    "verify",
]

# §30: the bounded V1 value profile.
MAX_SAFE = 9007199254740991

SEED_LENGTH = 32
PUBLIC_KEY_LENGTH = 32
SIGNATURE_LENGTH = 64

HASH_RE = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.ASCII
)
TIMESTAMP_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z", re.ASCII
)
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)

UNSUPPORTED_DIGEST: dict[str, Any] = {
    "algorithm": None,
    "value": None,
    "status": "unsupported",
}


# --------------------------------------------------------------------------
# Canonicalisation and hashing (§34)
# --------------------------------------------------------------------------


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 (JCS) serialisation of ``value``.

    Callers SHOULD check :func:`is_supported` first; ``rfc8785`` raises for
    values outside the profile, but it does not enforce the §30 bounds.
    """
    return rfc8785.dumps(value)


def sha256_hash(raw: bytes) -> str:
    """Return ``sha256:<64 lowercase hex digits>`` for ``raw`` (§33 ``Hash``)."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def event_hash(event: Any) -> str:
    """Return the §34 event hash: ``Hash(SHA256(JCS(event)))``."""
    return sha256_hash(canonicalize(event))


# --------------------------------------------------------------------------
# base64url (§33 Base64urlN)
# --------------------------------------------------------------------------


def b64url_encode(raw: bytes) -> str:
    """Encode ``raw`` as unpadded RFC 4648 URL-safe base64."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str, length: int) -> bytes:
    """Decode a canonical unpadded base64url string of exactly ``length`` bytes.

    Raises ``ValueError`` unless the text uses only the URL-safe alphabet,
    decodes to exactly ``length`` bytes, and re-encodes to the same string
    (rejecting padding, non-canonical trailing bits and alternate alphabets).
    """
    if not isinstance(text, str) or not BASE64URL_RE.fullmatch(text):
        raise ValueError("not canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:  # binascii.Error and friends
        raise ValueError("undecodable base64url") from exc
    if len(raw) != length:
        raise ValueError(f"expected {length} bytes, got {len(raw)}")
    if b64url_encode(raw) != text:
        raise ValueError("non-canonical base64url encoding")
    return raw


# --------------------------------------------------------------------------
# Ed25519 (§15, §16, §34)
# --------------------------------------------------------------------------


def generate_seed() -> bytes:
    """Return a fresh 32-byte Ed25519 private seed."""
    return os.urandom(SEED_LENGTH)


def public_key_from_seed(seed: bytes) -> bytes:
    """Return the raw 32-byte Ed25519 public key for ``seed``."""
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def fingerprint(public_raw: bytes) -> str:
    """Return the §16 agent-key fingerprint of a raw 32-byte public key."""
    return sha256_hash(public_raw)


def sign(seed: bytes, raw: bytes) -> str:
    """Sign ``raw`` with the Ed25519 private ``seed``; return base64url."""
    return b64url_encode(Ed25519PrivateKey.from_private_bytes(seed).sign(raw))


def verify(public_raw: bytes, signature_b64: str, raw: bytes) -> bool:
    """Verify an Ed25519 signature; return ``False`` on any failure."""
    try:
        signature = b64url_decode(signature_b64, SIGNATURE_LENGTH)
    except ValueError:
        return False
    try:
        public = Ed25519PublicKey.from_public_bytes(public_raw)
    except Exception:  # noqa: BLE001 - any unusable key is a verification failure
        return False
    try:
        public.verify(signature, raw)
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 - any verification error is a failure
        return False
    return True


# --------------------------------------------------------------------------
# Value profile (§30)
# --------------------------------------------------------------------------


def _is_encodable_str(value: str) -> bool:
    """True when the string contains no unpaired surrogate code points."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _supported(value: Any, seen: frozenset[int]) -> bool:
    if value is None or value is True or value is False:
        return True
    if type(value) is int:
        return -MAX_SAFE <= value <= MAX_SAFE
    if type(value) is float:
        return math.isfinite(value) and abs(value) <= MAX_SAFE
    if type(value) is str:
        return _is_encodable_str(value)
    if type(value) is list:
        if id(value) in seen:
            return False
        nested = seen | {id(value)}
        return all(_supported(item, nested) for item in value)
    if type(value) is dict:
        if id(value) in seen:
            return False
        nested = seen | {id(value)}
        for key, item in value.items():
            if type(key) is not str or not _is_encodable_str(key):
                return False
            if not _supported(item, nested):
                return False
        return True
    return False


def is_supported(value: Any) -> bool:
    """Return ``True`` when ``value`` lies inside the §30 value profile.

    Bools are not integers here, tuples are not arrays, non-string keys,
    ``Decimal``, NaN, infinities, out-of-range numbers, lone surrogates,
    cycles and arbitrary objects are all unsupported.  No coercion,
    ``str()``, ``repr()`` or Unicode normalisation is performed.
    """
    return _supported(value, frozenset())


def digest(value: Any) -> dict[str, Any]:
    """Return the §30/§31 digest record for ``value``."""
    if not is_supported(value):
        return dict(UNSUPPORTED_DIGEST)
    try:
        raw = canonicalize(value)
    except Exception:  # noqa: BLE001 - anything JCS cannot encode is unsupported
        return dict(UNSUPPORTED_DIGEST)
    return {"algorithm": "sha256", "value": sha256_hash(raw), "status": "available"}


# --------------------------------------------------------------------------
# Strict JSON parsing (§30, §33)
# --------------------------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise ValueError(f"unsupported JSON constant: {name}")


def _parse_int(token: str) -> int:
    value = int(token)
    if not -MAX_SAFE <= value <= MAX_SAFE:
        raise ValueError(f"integer out of range: {token}")
    return value


def _parse_float(token: str) -> float:
    try:
        exact = Decimal(token)
    except InvalidOperation as exc:
        raise ValueError(f"invalid numeric token: {token}") from exc
    if not exact.is_finite():
        raise ValueError(f"non-finite numeric token: {token}")
    if abs(exact) > MAX_SAFE:
        raise ValueError(f"numeric token out of range: {token}")
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"numeric token overflows binary64: {token}")
    if value == 0.0 and exact != 0:
        raise ValueError(f"numeric token underflows to zero: {token}")
    if abs(value) > MAX_SAFE:
        raise ValueError(f"numeric value out of range: {token}")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON property: {key!r}")
        result[key] = value
    return result


def strict_loads(text: str) -> Any:
    """Parse JSON without defaulting, coercing or accepting duplicates.

    Rejects duplicate object properties, ``NaN``/``Infinity``, integers
    outside ±MAX_SAFE and numeric tokens that overflow or underflow binary64.
    Raises ``ValueError`` (``json.JSONDecodeError`` is a subclass) on any
    violation.
    """
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
        parse_int=_parse_int,
        parse_float=_parse_float,
    )


# --------------------------------------------------------------------------
# Timestamps (§33)
# --------------------------------------------------------------------------


def parse_timestamp(text: Any, service: bool = False) -> _datetime.datetime | None:
    """Parse a §33 ``Timestamp`` (or ``ServiceTime`` when ``service``).

    Returns an aware UTC ``datetime``, or ``None`` when ``text`` is not
    exactly of the accepted form.  Nothing is normalised: ``+00:00``,
    lowercase ``t``/``z``, surrounding whitespace, more than six fractional
    digits and unpadded components are all rejected.
    """
    if type(text) is not str:
        return None
    match = TIMESTAMP_RE.fullmatch(text)
    if match is None:
        return None
    year, month, day, hour, minute, second, fraction = match.groups()
    if service and (fraction is None or len(fraction) != 6):
        return None
    microsecond = int(fraction.ljust(6, "0")) if fraction else 0
    try:
        return _datetime.datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            microsecond,
            tzinfo=_datetime.UTC,
        )
    except ValueError:
        # Year 0000, month 13, 30 February, hour 24, leap second, ...
        return None


def now_timestamp() -> str:
    """Return the current UTC time as a six-fraction-digit §33 Timestamp."""
    return _datetime.datetime.now(_datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


# --------------------------------------------------------------------------
# Small shared predicates
# --------------------------------------------------------------------------


def is_hash(value: Any) -> bool:
    """True when ``value`` is a §33 ``Hash``."""
    return type(value) is str and HASH_RE.fullmatch(value) is not None


def is_uuid(value: Any) -> bool:
    """True when ``value`` is a lowercase hyphenated UUID string."""
    return type(value) is str and UUID_RE.fullmatch(value) is not None


def is_text(value: Any) -> bool:
    """True when ``value`` is a §33 ``Text`` (a §30-supported string)."""
    return type(value) is str and _is_encodable_str(value)


def is_nonempty_text(value: Any) -> bool:
    """True when ``value`` is a nonempty §33 ``Text``."""
    return is_text(value) and value != ""
