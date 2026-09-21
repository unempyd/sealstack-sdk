# SealStack Receipt Format, version 1

This document defines the receipt format SealStack emits. It is not a submitted standard. Other formats (AERF, Agent Receipts, noa) are supported via export.

Scope: the signed event record, its canonical encoding, the hash chain, the
counter-signed receipt, the evidence bundle, and the offline verification
procedure. Every section is implementable from this document alone. Nothing
here depends on a particular server, storage system, dashboard or hosted
service. Section 12 lists the places where the format as currently produced by
the SealStack SDK still assumes a registry or receipt issuer; those are the
interoperability gaps.

Key words: MUST, MUST NOT, SHALL, MAY are used as in RFC 2119.

## 1. Roles and terms

- Agent: a program that performs actions. It holds an Ed25519 private key and
  signs one Event per lifecycle transition of each action.
- Runtime: one process lifetime of an Agent. Every runtime has a fresh
  `runtime_id` and its own hash chain starting at sequence 1.
- Registry: the party that assigns `organisation_id`, `agent_id` binding and
  `agent_key_id` to an Agent key. In SealStack this is the ingestion service.
  This document only requires that these identifiers are UUIDs that the
  Issuer later repeats in its receipt.
- Issuer: the party that counter-signs an accepted Event with its own Ed25519
  key, producing a Receipt. In SealStack this is the ingestion service.
- Verifier: any party holding an evidence bundle and a trust file who checks
  the relationships defined in Section 10. The Verifier performs no network
  access.

## 2. Primitive types

```text
UUID         = lowercase hyphenated UUID string
               (8-4-4-4-12 lowercase hexadecimal); Agent-generated IDs are UUIDv4
Hash         = "sha256:" followed by exactly 64 lowercase hexadecimal digits
Base64urlN   = unpadded RFC 4648 URL-safe base64 of exactly N bytes;
               decoding then re-encoding MUST reproduce the supplied string
               byte for byte (alphabet A-Z a-z 0-9 - _ only, no padding)
Timestamp    = UTC Gregorian date-time "YYYY-MM-DDTHH:MM:SS[.d{1,6}]Z",
               years 0001..9999, a real calendar date, HH < 24, MM < 60,
               SS < 60 (no leap seconds), one to six fractional digits,
               uppercase T and Z, no offset form, no surrounding whitespace
ServiceTime  = Timestamp rendered with exactly six fractional digits
Text         = a Unicode string with no unpaired surrogate code points
Digest       = {"algorithm":"sha256","value":Hash,"status":"available"}
             | {"algorithm":null,"value":null,"status":"unsupported"}
Resource     = {"type":Text|null,"id":Text|null} with at least one non-null
```

All records in this document are closed: every listed field is required,
null is written explicitly where allowed, and any additional property makes
the record invalid.

## 3. Value profile

The value profile bounds every JSON value that is digested, placed in
`metadata`, or included in a signed record.

```text
MAX_SAFE = 9007199254740991

Supported:
  null
  true, false
  strings satisfying Text
  integers in [-MAX_SAFE, MAX_SAFE] (booleans are not integers)
  finite IEEE 754 binary64 numbers with abs(value) <= MAX_SAFE
  arrays of supported values, finite and acyclic
  objects with unique Text keys and supported values

Unsupported: anything else, including larger integers or floats, NaN,
infinities, non-string keys, cyclic structures, and host-language objects.
```

Producers MUST NOT coerce unsupported values (no stringification, no
`repr`, no Unicode normalisation, no large-number-to-string conversion). An
unsupported value is represented by the unsupported Digest.

Parsers MUST reject JSON with duplicate object properties anywhere in the
document. Numeric tokens MUST be validated before conversion to binary64:
integer tokens outside [-MAX_SAFE, MAX_SAFE] are invalid, and non-integer
tokens are invalid when their exact decimal magnitude exceeds MAX_SAFE,
when they overflow binary64, or when a nonzero token converts to zero.
Negative zero canonicalises to `0`.

## 4. Digests

```text
digest(value):
    if value is outside the value profile:
        return {"algorithm":null,"value":null,"status":"unsupported"}
    return {"algorithm":"sha256",
            "value": "sha256:" + lowercase_hex(SHA-256(JCS(value))),
            "status":"available"}
```

The output Digest of an action is `null` when no output was captured. A
captured output whose value is JSON `null` has an available digest of the
canonical bytes `null`. Digests are commitments, not anonymisation: low
entropy values can be brute forced from their hash.

## 5. Event schema (schema_version 1)

```text
Event = {
  "schema_version": 1,
  "event_id": UUID,
  "organisation_id": UUID,
  "agent_id": UUID,
  "agent_key_id": UUID,
  "runtime_id": UUID,
  "sequence": integer in [1, MAX_SAFE],
  "previous_event_hash": Hash|null,
  "event_type": "action.started"|"action.completed"|"action.failed",
  "action_id": UUID,
  "action_name": nonempty Text,
  "occurred_at": Timestamp,
  "resource": Resource|null,
  "input_digest": Digest,
  "output_digest": Digest|null,
  "error_type": nonempty Text|null,
  "metadata": object within the value profile, len(JCS(metadata)) <= 16384
}
```

Structural rules:

- `schema_version` and `sequence` MUST be JSON integers; booleans and
  numeric strings are invalid.
- `sequence` = 1 requires `previous_event_hash` = null; `sequence` > 1
  requires a Hash.
- `action.started` requires `output_digest` = null and `error_type` = null.
- `action.completed` requires `error_type` = null; `output_digest` MAY be
  null (no output captured) or a Digest.
- `action.failed` requires `output_digest` = null and a nonempty
  `error_type`.
- All events of one action share `action_id`, `action_name`, `resource`,
  `input_digest` and `metadata`.
- `error_type` is a type name only. Error messages and stack traces MUST NOT
  appear in the event.
- `occurred_at` is the Agent's claimed time and is not independently trusted.

Lifecycle: each action produces `action.started` followed by exactly one of
`action.completed` or `action.failed`. A started event without a terminal
event means the action is incomplete; no party may synthesise a terminal
event on the Agent's behalf.

Input binding used by the SealStack SDK: for an instrumented function call
the input digest is `digest({"args": [positional values], "kwargs": {named
values}})`, computed before execution and reused unchanged for the terminal
event. Manual contexts use the unsupported Digest as input and null as
completed output. Other producers MAY define other input bindings; the
binding is not part of the signed format.

## 6. Canonical JSON

Canonical bytes of any record are its RFC 8785 JSON Canonicalization Scheme
serialisation (JCS):

- UTF-8 output, no insignificant whitespace.
- Object properties sorted by the UTF-16 code units of their names.
- Numbers serialised per ECMAScript Number.prototype.toString, which is why
  the value profile is restricted to binary64-exact values.
- Strings escaped per RFC 8785 Section 3.2.2.2.

Consumers MUST parse strictly (Section 3) and then canonicalise the parsed
value themselves. A transmitted hash is never trusted without recomputation.
Consumers MUST NOT insert defaults, strip unknown properties, or normalise
strings, timestamps or UUIDs before canonicalising.

## 7. Hashing and signatures

```text
canonical_event = JCS(event)
event_hash      = "sha256:" + lowercase_hex(SHA-256(canonical_event))
signature       = Base64url64(Ed25519.sign(agent_private_key, canonical_event))

EventEnvelope   = {"event": Event, "event_hash": Hash, "signature": Base64url64}
```

- The signature is Ed25519 (RFC 8032, pure Ed25519, no prehash) over the
  canonical event bytes, never over the digest.
- Keys are raw 32-byte Ed25519 public keys encoded as Base64url32. A public
  key that does not decode to exactly 32 bytes, or that the Ed25519
  implementation rejects, is invalid.
- Key fingerprint: `"sha256:" + lowercase_hex(SHA-256(raw 32-byte public
  key))`.
- Signature encoding MUST be canonical Base64url64: exactly 86 characters
  from the URL-safe alphabet, decoding to 64 bytes and re-encoding to the same
  string.
- One private key signs for one `agent_key_id`. The Agent MUST NOT sign
  before it holds the `agent_key_id` and `organisation_id` that the Issuer
  will bind in receipts.

## 8. Hash chain

Each runtime is one chain:

- The first event of a runtime has `sequence` 1 and `previous_event_hash`
  null.
- Every later event carries `sequence` = previous sequence + 1 and
  `previous_event_hash` = the `event_hash` of the immediately preceding event
  of the same runtime.
- Sequence numbers are assigned under a single serialisation lock per
  runtime, and an event's bytes, hash and signature are computed exactly once;
  retries re-send the stored bytes unchanged.
- A restarted process starts a new runtime; it never continues a previous
  runtime's chain.

Properties: changing any event changes its hash and breaks every later
link; deleting an interior event creates a sequence and hash gap. The chain
alone does not prevent deletion of the final tail event of a runtime; the
Issuer's receipt and the sequence accounting of the consumer address that.

## 9. Receipt (receipt schema_version 2)

A Receipt is the Issuer's signed acknowledgement of one accepted Event. It
binds the event hash, the Agent's registered key fingerprint, and the
organisational context the Issuer associated at acceptance.

```text
ReceiptBodyV2 = {
  "schema_version": 2,
  "event_id": UUID,
  "event_hash": Hash,
  "organisation_id": UUID,
  "agent_id": UUID,
  "agent_key_id": UUID,
  "agent_key_fingerprint": Hash,
  "agent_sponsor_id": UUID|null,
  "sponsor_user_id_snapshot": UUID|null,
  "grant_id": UUID|null,
  "capabilities_snapshot": array of distinct nonempty Text|null,
  "received_at": ServiceTime,
  "service_key_id": nonempty Text,
  "sponsor": null | {
    "id": UUID, "organisation_id": UUID, "agent_id": UUID, "user_id": UUID,
    "valid_from": ServiceTime, "valid_until": ServiceTime|null,
    "created_by_user_id": UUID
  },
  "grant": null | {
    "id": UUID, "organisation_id": UUID, "agent_id": UUID, "sponsor_id": UUID,
    "capabilities": array of distinct nonempty Text,
    "valid_from": ServiceTime, "valid_until": ServiceTime|null,
    "created_at": ServiceTime, "created_by_user_id": UUID
  }
}

receipt_bytes     = JCS(ReceiptBodyV2)
receipt_signature = Base64url64(Ed25519.sign(issuer_private_key, receipt_bytes))
Receipt           = {"body": ReceiptBodyV2, "signature": Base64url64}
```

Nullness rules: when `sponsor` is null, `agent_sponsor_id` and
`sponsor_user_id_snapshot` are null; when `grant` is null, `grant_id` and
`capabilities_snapshot` are null; otherwise the root fields equal
`sponsor.id`, `sponsor.user_id`, `grant.id` and `grant.capabilities`. A grant
requires a sponsor. Intervals are half-open `[valid_from, valid_until)`; a
null `valid_until` is unbounded.

The sponsor and grant records are context snapshots recorded by the Issuer at
acceptance. They assert association, not approval of the individual action.
An Issuer that tracks no such context emits null for all of them; a Receipt
with null context is fully valid.

`received_at` is the Issuer's acceptance time. `service_key_id` names the
Issuer key used for the signature; the key itself is never resolved from the
Receipt or the bundle (Section 10.2).

## 10. Evidence bundle and verification

### 10.1 Evidence bundle (bundle schema_version 2)

```text
EvidenceBundle = {
  "schema_version": 2,
  "event_envelope": EventEnvelope,
  "agent_public_key": Base64url32,
  "service_receipt": Receipt,
  "service_public_key_metadata": {
    "key_id": nonempty Text, "algorithm": "Ed25519",
    "public_key": Base64url32,
    "valid_from": ServiceTime, "valid_until": ServiceTime|null
  },
  "limitations": the exact text in Section 11,
  "predecessor": null | EvidenceBundle for the previous event of the same
                 runtime, whose own "predecessor" MUST be null
}
```

The bundle's key metadata is descriptive. It MUST match the trusted entry
(Section 10.2) but it can never add a trusted key or override one.

### 10.2 Trust file

The Verifier is given, out of band and over a channel it trusts
independently of any bundle, a trust file:

```text
TrustFile = {"keys": [
  {"key_id": nonempty Text, "algorithm": "Ed25519", "public_key": Base64url32,
   "valid_from": ServiceTime, "valid_until": ServiceTime|null}, ...
]}
```

Key IDs MUST be unique. Retired Issuer keys remain in the file so historical
receipts stay verifiable. Validity timestamps are descriptive; they do not
invalidate a historical signature.

### 10.3 Verification procedure

Inputs: bundle text, trust file text (may be absent). Output: one of the
statuses VALID, INVALID, UNKNOWN and an exit code 0, 1 or 2. INCOMPLETE is an
action level status (a started event with no terminal event) and is not
produced for a single bundle.

```text
1. Parse the bundle with the strict parser (Section 3).
   Failure, non-object, or bundle.schema_version != 2      -> INVALID, 1
2. If service_receipt.body.schema_version is an integer other than 2
   (also for a supplied predecessor)                       -> UNKNOWN, 2
3. Validate every closed record exactly (Sections 2, 5, 7, 9, 10.1),
   including the value profile of metadata, Base64url canonicality,
   Timestamp and ServiceTime forms, event-type field combinations,
   the limitations text, and predecessor nesting depth       -> INVALID, 1
4. Load the trust file. Absent file, unparsable file, wrong shape,
   duplicate key_id, or any entry failing its record rules   -> UNKNOWN, 2
   Resolve body.service_key_id ONLY in the trust file; absent -> UNKNOWN, 2
5. Require bundle metadata key_id == body.service_key_id, and metadata
   key_id, algorithm and raw public key bytes equal to the trusted
   entry                                                     -> INVALID, 1
6. Verify the Issuer signature over JCS(body) with the trusted key
                                                             -> INVALID, 1
7. Recompute Hash(SHA-256(JCS(event))); require it equal to
   envelope.event_hash and to body.event_hash                -> INVALID, 1
8. Require body.event_id, organisation_id, agent_id, agent_key_id to
   equal the event's fields                                  -> INVALID, 1
9. Require Hash(SHA-256(raw agent_public_key)) ==
   body.agent_key_fingerprint                                -> INVALID, 1
10. Verify the Agent signature over JCS(event) with that public key
                                                             -> INVALID, 1
11. Context:
    if sponsor present: agent_sponsor_id == sponsor.id,
      sponsor_user_id_snapshot == sponsor.user_id,
      sponsor.organisation_id and agent_id equal the event's,
      sponsor.valid_from <= occurred_at < sponsor.valid_until (if set)
    else: agent_sponsor_id and sponsor_user_id_snapshot are null
    if grant present: grant_id == grant.id,
      capabilities_snapshot == grant.capabilities (ordered equality),
      sponsor present and grant.sponsor_id == sponsor.id,
      grant.organisation_id and agent_id equal the event's,
      grant.valid_from >= sponsor.valid_from and, when sponsor.valid_until
      is set, grant.valid_until is set and <= sponsor.valid_until,
      grant.valid_from <= occurred_at < grant.valid_until (if set),
      event.action_name is an exact member of grant.capabilities
    else: grant_id and capabilities_snapshot are null
    Any failure                                              -> INVALID, 1
12. Predecessor, when supplied: apply steps 2 to 11 to it with the same
    trust file, then require equal organisation_id, agent_id and
    runtime_id, predecessor.sequence == event.sequence - 1, and
    predecessor envelope.event_hash == event.previous_event_hash
                                                             -> INVALID, 1
13. Otherwise VALID, 0. Report the chain as NOT VERIFIED when no
    predecessor was supplied; report "Runtime chain link: VALID" when the
    supplied link verified. Never infer chain history that was not
    supplied.
```

Reference report lines produced by the SealStack verifier:

```text
Event hash:              VALID
Agent signature:         VALID
Agent key fingerprint:   VALID
Service receipt:         VALID
Runtime chain:           NOT VERIFIED, predecessor absent
```

Exit codes: 0 cryptographically valid for the supplied evidence; 1 invalid;
2 incomplete or unverifiable.

## 11. Limitations text

Every evidence bundle carries this text verbatim in `limitations`; a
mismatch is a schema failure.

```text
This receipt verifies cryptographic relationships between the
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
• regulatory compliance.
```

## 12. Test vector

Public test seeds (never use them outside tests):

```text
agent seed   = bytes 0x00..0x1f   (32 bytes)
issuer seed  = bytes 0x20..0x3f   (32 bytes)
agent public key  = A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
issuer public key = Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc
agent fingerprint = sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c
```

Canonical event bytes:

```text
{"action_id":"00000000-0000-4000-8000-000000000006","action_name":"invoice.create","agent_id":"00000000-0000-4000-8000-000000000003","agent_key_id":"00000000-0000-4000-8000-000000000004","error_type":null,"event_id":"00000000-0000-4000-8000-000000000001","event_type":"action.started","input_digest":{"algorithm":"sha256","status":"available","value":"sha256:97fcdad9fe31227a9ec60e519ff7635ac71941c55b77e585c908db1fa6406030"},"metadata":{"source":"golden"},"occurred_at":"2026-01-02T03:04:05.000000Z","organisation_id":"00000000-0000-4000-8000-000000000002","output_digest":null,"previous_event_hash":null,"resource":null,"runtime_id":"00000000-0000-4000-8000-000000000005","schema_version":1,"sequence":1}
```

```text
event_hash = sha256:210dac98941ac0bbc38eab7f6dd8bbb5fd5cca6bf8da03a1c05892ef0e34a233
signature  = m_ifXERnt9MnkduS1RKVBxTtXX4EcqfremBkeDipPqHzYu0vjRE3nDQ1rEvVuO8yTFhTJcCwbPxXN0q9qrjqAw
input_digest value above = digest of the canonical bytes {"args":[],"kwargs":{}}
```

The complete bundle, receipt bytes and trust file for this vector are in
`sdk/tests/fixtures/receipt-v1.json` and `sdk/tests/fixtures/service-keys.json` of the
SealStack repository; the receipt signature there is
`vthOyW4G1c_sqIzM9V8TJ8UkflctDrDXfKM8x7BDyq3Hq9BXVJm9dpk50mflSGt8I--fU_OI31HzHKaiP-wfBQ`
with `service_key_id` `service-golden-v1`.

## 13. Interoperability gaps

Places where the format as produced today still assumes the SealStack
registry or Issuer. Each is a candidate for a future revision of this
document.

1. `organisation_id` and `agent_key_id` are assigned by the registry at
   registration and the Agent MUST NOT sign before activation. A producer
   without a registry has no defined way to mint them. A revision could allow
   self-assigned identifiers with the fingerprint as the key identity.
2. A bundle without a Receipt cannot reach VALID: the procedure returns
   UNKNOWN at step 4. There is no defined verification level for an
   Agent-signed event alone (hash, signature and chain without an Issuer).
3. The trust file is the Issuer's key list (`/v1/verification-keys` in
   SealStack). The format defines its shape but not how an Issuer publishes
   it or how a Verifier authenticates it.
4. `received_at` is Issuer time with no defined clock discipline; the
   future-skew rule (5 minutes) that gates acceptance is an Issuer policy,
   not part of the format.
5. The sponsor and grant records model SealStack's organisational context
   (users, memberships, capability grants). Other Issuers must either emit
   null context or reproduce these exact records; there is no extension
   point.
6. `error_type` and the input binding `{"args": [...], "kwargs": {...}}` are
   Python-shaped. The format only requires Text and a Digest, so other
   producers are conformant, but cross-language consumers cannot interpret
   the digest without knowing the producer's binding.
7. `action_name` capability matching is exact string equality against the
   Issuer's grant; the format defines no namespace for action names.
8. The `limitations` text is mandatory and fixed. Localisation or an
   Issuer-specific text is a schema failure.
9. Receipt schema_version 2 and bundle schema_version 2 are the only
   supported versions; version negotiation is undefined.
10. Key rotation of the Agent key (predecessor key retirement, ingestion
    grace) is an Issuer lifecycle rule. Bundles signed by a retired Agent key
    verify exactly as before; the format itself carries no key state.
