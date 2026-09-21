# Reference server

A minimal implementation of the four SDK-facing endpoints, so that you can run
the SDK end to end without the hosted service: register an agent, upload signed
events, receive counter-signed receipts, and verify them offline with
`sealstack verify`.

**This is not the hosted service and it is not a production server.** It exists
to make the receipt format reproducible on your own machine. It has one tenant,
one bearer key, SQLite storage, no dashboard, no OIDC, no user accounts, no
sponsor or capability-grant context, no agent-key rotation and no service-key
rotation. Do not put it on a network you do not control, and do not treat its
receipts as evidence from an independent party: it signs with a key that sits
on the same machine as the agent.

## Running it

The reference server is not part of the PyPI package: `pip install sealstack`
does not install it. Clone this repository and run it from the checkout.

```sh
git clone https://github.com/unempyd/sealstack-sdk
cd sealstack-sdk
pip install -e ".[reference-server]"
SEALSTACK_REF_API_KEY=pick-a-long-random-string \
    uvicorn server:app --app-dir reference-server --host 127.0.0.1 --port 8000
```

Then point the SDK at it:

```sh
export SEALSTACK_API_URL=http://127.0.0.1:8000
export AUDIT_API_KEY=pick-a-long-random-string
```

## Configuration

| Variable | Meaning | Default |
| --- | --- | --- |
| `SEALSTACK_REF_API_KEY` | The one bearer key accepted on all four endpoints | required |
| `SEALSTACK_REF_DB` | SQLite database path | `./sealstack-ref.sqlite` |
| `SEALSTACK_REF_SERVICE_SEED_FILE` | File holding the base64url service signing seed. It is generated with mode 0600 on first start and the path is printed once. | `./sealstack-ref-service.seed` |

The organisation id and the service key id are generated on first start and
kept in the database. Delete the database and the seed file together; a
database whose recorded service public key does not match the seed file is
refused at start-up rather than signing with the wrong key.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/agents/register` | Register an agent and its first key. Idempotent for the same key. |
| `POST` | `/v1/events/batch` | Accept signed events and return one result per input position. |
| `GET` | `/v1/verification-keys` | The service public keys, which you save as your trust file. |
| `GET` | `/v1/agents/{agent_id}/keys` | The keys registered for one agent. |

Every other path answers `404 {"error": "not_found"}`. All four require
`Authorization: Bearer <SEALSTACK_REF_API_KEY>` and answer
`401 {"error": "unauthorized"}` without it. Request and response shapes and
error codes match the hosted API, so the unmodified SDK works against either.

`POST /v1/agents/{agent_id}/keys`, the agent-key rotation endpoint, is not
implemented here. Agent key rotation is disabled in the SDK in V1, so nothing
in this repository calls it.

## What it does and does not check

It does check, per event: the closed event schema and value profile, the
canonical JSON hash, the agent's Ed25519 signature against the registered key,
the claimed time against a five-minute future-skew allowance, the per-runtime
sequence uniqueness, and the predecessor hash for every event after the first.
An event whose predecessor has not arrived is answered `missing_previous` and
the SDK retries it; a predecessor hash that disagrees with the stored one is
answered `invalid_chain` and is permanent. A replayed event returns its
original receipt bytes and is never re-signed.

It does not implement: multi-tenancy, user accounts or sessions, sponsor and
capability-grant context (every receipt carries the explicit nulls the format
defines for their absence, and never an invented value), agent-key retirement
or revocation, service-key rotation, rate limiting, or any of the concurrency
guarantees that the hosted service gets from PostgreSQL row locks. This server
serialises its writes with one in-process lock and one SQLite transaction per
event.

## Building an evidence bundle

The SDK stores each receipt next to its event in the local durable queue
(`<state_dir>/audit_queue.db`, column `server_receipt`). An evidence bundle is
that event envelope, the agent public key from `<state_dir>/identity.json`, the
receipt, the matching entry from `/v1/verification-keys`, the limitations text
from `sealstack.verify.LIMITATIONS`, and optionally the predecessor event's
bundle. `tests/test_reference_server.py` assembles one exactly that way and
verifies it. Save `/v1/verification-keys` as your trust file and pass it to
`sealstack verify --trusted-service-keys`.

## Tests

```sh
pytest -q reference-server/tests
```

The test starts this server on a free port, drives it with a real
`AuditClient`, and asserts that `sealstack verify` exits 0 on the resulting
bundle and 1 after one field is changed.
