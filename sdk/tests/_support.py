"""Independent cryptographic oracle: canonicalisation, digests and re-signing."""
import copy

import rfc8785
from _fixture_source import AGENT_SEED, SERVICE_SEED, hash_bytes, sign


def jcs(value):
    return rfc8785.dumps(value)


def digest(value):
    return {"algorithm": "sha256", "value": hash_bytes(jcs(value)), "status": "available"}


UNSUPPORTED = {"algorithm": None, "value": None, "status": "unsupported"}


def resign_event(bundle, seed=AGENT_SEED):
    envelope = bundle["event_envelope"]
    raw = jcs(envelope["event"])
    envelope.update(event_hash=hash_bytes(raw), signature=sign(raw, seed))
    return bundle


def resign_receipt(bundle, seed=SERVICE_SEED):
    receipt = bundle["service_receipt"]
    receipt["signature"] = sign(jcs(receipt["body"]), seed)
    return bundle


def rebind(bundle):
    """Create a test-controlled, validly signed candidate (not an acceptance oracle)."""
    resign_event(bundle)
    event = bundle["event_envelope"]["event"]
    body = bundle["service_receipt"]["body"]
    for key in ("event_id", "organisation_id", "agent_id", "agent_key_id"):
        body[key] = event[key]
    body["event_hash"] = bundle["event_envelope"]["event_hash"]
    return resign_receipt(bundle)


def clone(value):
    return copy.deepcopy(value)
