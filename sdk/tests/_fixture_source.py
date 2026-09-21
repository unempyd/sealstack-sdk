"""Independent, deterministic golden-vector derivation; never imports product.

Run with ``python -m tests._fixture_source`` to print (not overwrite) vectors.
The chosen vector contains only ASCII keys and integral JSON numbers, so
stdlib compact/sorted JSON coincides with JCS without using product's encoder.
These seeds are PUBLIC TEST DATA and must never be used outside tests.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

AGENT_SEED = bytes(range(32))
SERVICE_SEED = bytes(range(32, 64))
ATTACKER_SEED = bytes(range(64, 96))
TIME = "2026-01-02T03:04:05.000000Z"
START = "2026-01-01T00:00:00.000000Z"
LIMITATIONS = """This receipt verifies cryptographic relationships between the
included data, registered keys and service receipt.

It does not independently prove:

• that an external real-world action occurred;
• that logged inputs or outputs were truthful;
• that the agent host was uncompromised;
• that the private key was never stolen;
• that uninstrumented actions did not occur;
• the legal identity of a human sponsor;
• that the sponsor personally authorised this individual action;
• legal liability;
• regulatory compliance."""


def uid(n):
    return f"00000000-0000-4000-8000-{n:012x}"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_bytes(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def ascii_jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def sign(raw, seed=AGENT_SEED):
    return b64(Ed25519PrivateKey.from_private_bytes(seed).sign(raw))


def derive():
    event = dict(schema_version=1, event_id=uid(1), organisation_id=uid(2),
                 agent_id=uid(3), agent_key_id=uid(4), runtime_id=uid(5),
                 sequence=1, previous_event_hash=None, event_type="action.started",
                 action_id=uid(6), action_name="invoice.create", occurred_at=TIME,
                 resource=None, input_digest=dict(algorithm="sha256",
                 value=hash_bytes(b'{"args":[],"kwargs":{}}'), status="available"),
                 output_digest=None, error_type=None, metadata={"source": "golden"})
    event_bytes = ascii_jcs(event)
    sponsor = dict(id=uid(7), organisation_id=uid(2), agent_id=uid(3),
                   user_id=uid(8), valid_from=START, valid_until=None,
                   created_by_user_id=uid(8))
    grant = dict(id=uid(9), organisation_id=uid(2), agent_id=uid(3), sponsor_id=uid(7),
                 capabilities=["invoice.create", "invoice.read"], valid_from=START,
                 valid_until=None, created_at=START, created_by_user_id=uid(8))
    receipt = dict(schema_version=2, event_id=uid(1), event_hash=hash_bytes(event_bytes),
                   organisation_id=uid(2), agent_id=uid(3), agent_key_id=uid(4),
                   agent_key_fingerprint=hash_bytes(public(AGENT_SEED)),
                   agent_sponsor_id=uid(7), sponsor_user_id_snapshot=uid(8),
                   grant_id=uid(9), capabilities_snapshot=grant["capabilities"],
                   received_at=TIME, service_key_id="service-golden-v1",
                   sponsor=sponsor, grant=grant)
    receipt_bytes = ascii_jcs(receipt)
    key = dict(key_id="service-golden-v1", algorithm="Ed25519",
               public_key=b64(public(SERVICE_SEED)), valid_from=START, valid_until=None)
    bundle = dict(schema_version=2,
                  event_envelope=dict(event=event, event_hash=hash_bytes(event_bytes),
                                      signature=sign(event_bytes)),
                  agent_public_key=b64(public(AGENT_SEED)),
                  service_receipt=dict(body=receipt, signature=sign(receipt_bytes, SERVICE_SEED)),
                  service_public_key_metadata=key, limitations=LIMITATIONS, predecessor=None)
    return dict(fixture=dict(canonical_event_utf8=event_bytes.decode(),
                             canonical_receipt_utf8=receipt_bytes.decode(), bundle=bundle),
                trust={"keys": [key]})


if __name__ == "__main__":
    print(json.dumps(derive(), ensure_ascii=False, indent=2))
