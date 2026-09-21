# Compatibility

What SealStack emits, which external receipt formats it can produce, how each
export is built, and what was verified. Facts only. Version 0.1.3.

## Native format

SealStack emits, per action event:

- An Event (schema_version 1, SPEC-RECEIPT.md Section 5): 17 closed fields, RFC 8785
  canonical bytes, `event_hash` = `sha256:` plus SHA-256 of those bytes,
  Ed25519 signature over the bytes, encoded base64url without padding.
- A second-party service receipt (schema_version 2, SPEC-RECEIPT.md Section 9): the ingestion
  service's Ed25519 signature over the RFC 8785 bytes of a body that binds the
  event id and hash, the organisation, agent and key ids, the registered
  key fingerprint, the receive time (`received_at`), and the sponsor and
  capability-grant snapshots the service associated at acceptance. It is a
  counter-signature by the receiving service, not an independent third party.
- An evidence bundle (schema_version 2, SPEC-RECEIPT.md Section 10.1) carrying both, the agent
  public key, the service key metadata, the SPEC-RECEIPT.md Section 11 limitations text and,
  optionally, the predecessor event's bundle.

The offline verifier (`sealstack verify`) accepts only this bundle. Internal
reference: SPEC-RECEIPT.md.

## External formats produced

| Format | Exact version targeted | Command | Verification performed |
| --- | --- | --- | --- |
| AERF, Agent Evidence Receipt Format | v0.1.0-draft.1 (tag `v0.1.0-draft.1` of github.com/aerf-spec/aerf) | `sealstack export --format aerf` | External: the AERF Go reference verifier built from the v0.1.0-draft.1 tag and from the repository main branch (v0.2.0-draft.1); full-mode artifact exits 0, a tampered copy exits 1. |
| Agent Receipt Protocol | 0.5.0 (agentreceipts.ai, `@context` `https://agentreceipts.ai/context/v2`) | `sealstack export --format agent-receipts` | External: the `obsigna` Python package (its build on this machine reports protocol 0.6.0 and context v3; its `verify_raw` and `verify_receipt` accepted the 0.5.0 artifact and rejected a tampered copy). Internal: RFC 8785 bytes without `proof`, Ed25519, previous-hash recomputation. |
| noa profile, draft-noa-scitt-ai-agent-receipt-01 | `noa.receipt/0.1`, bare receipt form | `sealstack export --format scitt` | Internal specification-derived test only (closed member set, enumerations, `chain.hash` recomputation, the 21-octet `NOA-Receipt-v0.1-sig:` prefix plus raw SHA-256 message, Ed25519, canonical base64). No external or reference verifier was run. |

SealStack does not consume any of these formats. `sealstack verify` reads only
the native bundle.

## Signing location

Every export is a new signature by the agent's Ed25519 key, because none of
the three formats signs the same bytes as the native event. The export runs
in the SDK on the customer's machine, reading the key from the local identity
directory (`--state-dir`, under the same exclusive lock the SDK uses) or from
a seed file (`--signing-key`). The server never receives or accesses the agent
private key and takes no part in the export.

## Modes

`subset` (default): fields whose semantics SealStack does not record are
omitted. No placeholder, default or null is written in their place. The
artifact is labelled non-conformant on stdout and in the artifact's companion
record with the exact list of missing fields.

`full` (`--mapping PATH`): the operator supplies the missing semantics per
action name in a JSON mapping file. Any action without an entry, or any value
outside the target enumeration, stops the export with exit code 2 and writes
nothing. An `actions.default` entry is honoured only when the operator's file
contains one.

Mapping keys required for full mode:

| Format | Required from the operator |
| --- | --- |
| AERF | `aerf.actions.<name>.in_policy` (boolean), `aerf.actions.<name>.policy_reason` (string), `aerf.plan_id_source` (must be the literal `"action_id"`: the operator's decision to use the action invocation id as `plan_id`), and `aerf.actions.<name>.action` (a conformant alias) only when the SealStack action name violates `^[A-Za-z0-9_:.\-]{1,128}$`. |
| Agent Receipts | `agent_receipts.actions.<name>.type` (a taxonomy value, `unknown`, or a reverse-domain custom type) and `.risk_level` (`low`, `medium`, `high`, `critical`). |
| noa | `noa.agent.principal` (`HUMAN`, `SERVICE`, `POLICY`, `SANDBOX_SIM`), `noa.agent.sandboxed` (boolean, must be true for `SANDBOX_SIM`), `noa.actions.<name>.riskClass` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `IRREVERSIBLE`), `.reversible` (boolean), optional `.canonical`. |

An example mapping is at sdk/tests/fixtures/mapping-full.json.

## Native evidence with every artifact

- AERF: embedded in the receipt's `evidence` object, which the format defines
  as a producer-defined JSON object. `evidence` carries the event, its hash and
  agent signature, the agent public key and fingerprint, the receive time, the
  service receipt, the service key metadata, and a `sealstack_export` record
  (mode, missing fields, notes).
- Agent Receipts and noa: written as a companion file `<artifact>.sealstack.json`
  holding the native bundle verbatim plus the same `sealstack_export` record.
  Neither format defines an extension slot for it: the noa receipt is a closed
  object that rejects unknown members, and the Agent Receipt schema does not
  declare an extension point for foreign evidence. Adding undeclared fields
  would make the artifacts non-conformant, so the evidence travels beside them.

## Field mappings

### AERF v0.1.0-draft.1

| AERF field | Source | Notes |
| --- | --- | --- |
| `id` | `event.event_id` | |
| `type` | `"notarised_evidence"` | |
| `plan_id` | `event.action_id` in full mode only | SealStack has no plan; omitted in subset. |
| `agent` | `event.agent_id` | |
| `action` | `event.action_name` verbatim | Full mode substitutes the operator's alias when the name is outside the AERF charset; subset emits it verbatim and labels the artifact non-conformant if it violates the pattern. Never transliterated. |
| `in_policy`, `policy_reason` | mapping (full) | Omitted in subset. |
| `evidence_hash_sha512` | SHA-512 of the canonical `evidence` object | AERF canonicalisation. |
| `evidence` | native evidence, see above | |
| `observed_at` | `event.occurred_at` unchanged | ISO 8601 with `Z`. |
| `key_id` | first 16 hex characters of SHA-256 of the raw 32-byte agent public key | Confirmed against the reference example: the raw key reproduces its `key_id`, the DER form does not. |
| `signature` | Ed25519 over the canonical payload without `signature` and `timestamp`, lowercase hex | |
| `previous_receipt_hash` | SHA-256 of the predecessor's canonical payload | Only when the bundle carries predecessor evidence; omitted at sequence 1; omitted and labelled when sequence > 1 without predecessor evidence. |
| `output_hash` | `output_digest.value` without the `sha256:` prefix | Only when the digest is available. |
| `session_id` | `event.runtime_id` | |
| `timestamp`, `plan_signature`, `policy_hash`, `session_trajectory`, `reasoning_hash`, `compliance_tags` | never emitted | SealStack has no source; no timestamp authority. |

Canonical form: sorted keys, compact separators, ASCII-escaped strings,
numbers as written (the v0.1.0-draft.1 rule). The verifier on the AERF main
branch canonicalises non-ASCII strings differently (raw UTF-8); an artifact
whose `evidence` contains non-ASCII text verifies under the v0.1.0-draft.1
verifier and fails under the main-branch verifier. The golden fixture is
ASCII and passes both. The public key is written beside the artifact as SPKI
PEM.

### Agent Receipt Protocol 0.5.0

One credential per SealStack event.

| Field | Source | Notes |
| --- | --- | --- |
| `@context` | `["https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v2"]` | |
| `id` | `"urn:receipt:" + event_id` | |
| `type` | `["VerifiableCredential", "AgentReceipt"]` | |
| `version` | `"0.5.0"` | |
| `issuer.id` | `did:key` of the agent public key (multicodec `0xed01`, base58btc) | Deterministic from the key; no registry involved. |
| `issuer.type`, `issuer.session_id` | `"AIAgent"`, `runtime_id` | |
| `issuanceDate`, `proof.created` | export time | |
| `credentialSubject.principal` | sponsor user id as `urn:uuid:` with type `HumanPrincipal` when the service receipt carries a sponsor snapshot; otherwise the organisation id as `urn:uuid:` with type `OrganizationPrincipal` | |
| `credentialSubject.action.id` | `"act_" + action_id` | |
| `credentialSubject.action.type`, `.risk_level` | mapping (full) | Omitted in subset. |
| `credentialSubject.action.timestamp` | `occurred_at` | |
| `credentialSubject.action.target.system`, `.resource` | `resource.type`, `resource.id` | Only present members. |
| `credentialSubject.action.parameters_hash` | `input_digest.value` | Only when available; same RFC 8785 construction on both sides. |
| `credentialSubject.outcome.status` | `pending` for started, `success` for completed, `failure` for failed | |
| `credentialSubject.outcome.error`, `.response_hash` | `error_type` (failed only), `output_digest.value` (available only) | |
| `credentialSubject.authorization` | grant snapshot: `scopes` = capabilities, `granted_at` = valid_from, `expires_at` = valid_until if set, `grant_ref` = grant id | Only when a grant snapshot exists. |
| `credentialSubject.chain` | `chain_id` = runtime_id, `sequence` = event sequence, `previous_receipt_hash` = `sha256:` plus SHA-256 of the RFC 8785 form of the predecessor credential without `proof`, `null` at sequence 1 | The chain object is omitted and labelled when sequence > 1 without predecessor evidence. |
| `proof` | `Ed25519Signature2020`, `verificationMethod` = `did:key` URL with the key fragment, `proofPurpose` `assertionMethod`, `proofValue` = `u` plus base64url of the Ed25519 signature over the RFC 8785 bytes of the credential without `proof` | |
| `intent`, `parameters_disclosure`, reversal fields, `state_change`, `delegation`, `terminal`, `trusted_timestamp` | never emitted | |

### noa.receipt/0.1 (draft-noa-scitt-ai-agent-receipt-01), bare form

One receipt per SealStack event; closed object.

| Field | Source | Notes |
| --- | --- | --- |
| `spec` | `"noa.receipt/0.1"` | |
| `id`, `ts` | `event_id`, `occurred_at` | |
| `scope.chain`, `scope.tenant` | `runtime_id`, `organisation_id` | |
| `agent.id` | `agent_id` | |
| `agent.principal` | mapping (full) | Omitted in subset. |
| `action.id`, `action.canonical` | `action_name` (canonical may be overridden by the mapping) | |
| `action.riskClass`, `action.reversible` | mapping (full) | Omitted in subset. |
| `action.paramsHash` | `input_digest.value` | Only when available; omitted and labelled otherwise. |
| `governance.mode` | `"off"` | SealStack applies no governance. |
| `governance.verdict` | `ALLOWED` for started, `EXECUTED` for completed, `FAILED` for failed | |
| `governance.sandboxed` | mapping (full) | Omitted in subset. |
| `chain.seq` | `sequence - 1` | The profile numbers from 0. |
| `chain.prevHash` | the predecessor receipt's `chain.hash`, computed from predecessor evidence; `null` at sequence 1 | Omitted and labelled when sequence > 1 without predecessor evidence. |
| `chain.hash` | `sha256:` plus SHA-256 of the RFC 8785 bytes of the receipt without `chain.hash` and `sig.value` | |
| `sig` | `alg` `"ed25519"`, `kid` = `agent_key_id`, `value` = standard base64 with padding of the Ed25519 signature over `"NOA-Receipt-v0.1-sig:"` followed by the raw SHA-256 of those bytes | |
| COSE_Sign1 envelope, SCITT Signed Statement, transparency registration | not produced | The bare form is a conformant receipt for a Receipt Verifier under the draft; the COSE envelope is required only for registration with a SCITT transparency service, which would need a CBOR/COSE dependency that the SDK dependency list does not include. |

## Receipts issued by other parties

SealStack's service receipt is a counter-signature by the receiving service
over the acceptance context at receive time. A SCITT transparency service
issues a different artifact: a receipt over a registered Signed Statement
carrying inclusion or consistency proofs from an append-only log, issued by a
party other than the producer. SealStack does not register statements with a
transparency service and does not produce SCITT receipts. No statement is
made here about mechanisms the other formats or their implementations do or
do not provide beyond what their published specifications define.

## Limitations of the exports

- Subset artifacts are not conformant to their target specification; the
  label says which required fields are absent.
- Full-mode conformance depends on the operator's mapping being truthful;
  SealStack does not evaluate policy, classify actions or assess risk.
- The AERF and Agent Receipts production profiles expect RFC 3161 trusted
  timestamps; none is produced.
- Chain fields are set only when predecessor evidence is in the bundle.

## Package name change in 0.1.3

From 0.1.3 the SDK imports as `sealstack` and the command is `sealstack`; `product`
remains a working alias for both, resolving to the same module objects. The SDK's
logger is named `sealstack` (it was `product` before 0.1.3); a logging
configuration that named the old logger must be updated to see the records.
