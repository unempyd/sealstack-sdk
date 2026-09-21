# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through either channel:

- Email: SealStack@icloud.com
- GitHub private vulnerability reporting: https://github.com/unempyd/sealstack-sdk/security/advisories/new

Do not open a public issue for a security problem. Include the affected
component (SDK, reference server, verifier), a reproduction, and the impact
you observed. You will receive an acknowledgement, and a fix or a decision,
before any public disclosure.

## Scope

- `sdk/product`: the Python SDK, local identity file, SQLite queue, uploader,
  the offline verifier (`product verify`) and the exporters (`product export`).
- `reference-server/`: the single-tenant reference server. It exists so the
  SDK can be exercised end to end without the hosted service; it is not the
  hosted service and is not hardened for a reachable deployment.

Reports about the hosted SealStack service are welcome through the same
channels; that code is not in this repository.

## Trust assumptions

The product assumes the customer host that runs the SDK is not compromised,
the agent private key is not stolen, and the operator provisions service
verification keys over an independently trusted channel. It does not assume
the network, the service database, or the exported bundle are trusted; those
are covered by signatures and hashes.

## What V1 defends against

- Modification, reordering or deletion of accepted events inside a runtime
  chain, detected by hash-chain and signature verification.
- Forged events for a registered agent without its private key.
- Forged or altered service receipts without the service signing key.
- Replay of an accepted event: it is answered as a duplicate with the
  original receipt, never re-accepted.

## What V1 does not defend against

- A compromised agent host or a stolen agent private key signing false
  events. Revocation stops new ingestion; it does not retract history.
- Deletion of the final tail event of a runtime before upload.
- Untruthful inputs or outputs: digests commit to values, they do not
  attest to them.
- Uninstrumented actions.
- Compromise of the service signing key.

## Known limitations in this release

- Agent key rotation is disabled in the SDK and CLI in V1.
- The reference server is single-process and single-tenant, has no key
  rotation, revocation or retirement, and keeps its signing seed in a file.
  Run it on a private network for evaluation only.

## Supported versions

The latest tagged release on `main` receives security fixes.
