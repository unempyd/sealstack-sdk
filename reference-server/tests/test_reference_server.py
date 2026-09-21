"""The reference server issues receipts that ``product verify`` accepts.

The SDK is not modified or mocked anywhere here: a real ``AuditClient``
registers against a real uvicorn process on a free port, signs two actions in
one runtime, uploads them, and the receipts it stores are assembled into an
evidence bundle that the shipped offline verifier accepts and, after one
byte changes, rejects.
"""

from __future__ import annotations

import copy
import json
import socket
import sqlite3
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

import server
from product.cli import main
from product.client import AuditClient
from product.queue import QUEUE_FILENAME, TABLE
from product.signing import SEED_LENGTH, b64url_decode, canonicalize, sha256_hash, sign
from product.verify import LIMITATIONS

API_KEY = "audit_live_reference_server_test_key"
AUTH = {"Authorization": f"Bearer {API_KEY}"}
READY_TIMEOUT = 20.0
DRAIN_TIMEOUT = 60.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_until_ready(base_url: str) -> None:
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{base_url}/v1/verification-keys", headers=AUTH, timeout=2.0)
        except httpx.HTTPError:
            time.sleep(0.05)
            continue
        if response.status_code == 200:
            return
        time.sleep(0.05)
    raise AssertionError(f"reference server did not answer on {base_url}")


@pytest.fixture
def base_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Run the reference server on a free port for the duration of one test."""
    monkeypatch.setenv("SEALSTACK_REF_DB", str(tmp_path / "reference.sqlite"))
    monkeypatch.setenv("SEALSTACK_REF_API_KEY", API_KEY)
    monkeypatch.setenv("SEALSTACK_REF_SERVICE_SEED_FILE", str(tmp_path / "service.seed"))

    port = _free_port()
    running = uvicorn.Server(
        uvicorn.Config(server.create_app(), host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=running.run, name="reference-server", daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_ready(url)
        yield url
    finally:
        running.should_exit = True
        thread.join(timeout=10)


def _queue_rows(state_dir: Path) -> list[dict[str, Any]]:
    """Read the SDK's durable queue read-only, exactly as an operator could."""
    path = state_dir / QUEUE_FILENAME
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in connection.execute(f"SELECT * FROM {TABLE} ORDER BY runtime_id, sequence")
        ]
    finally:
        connection.close()


def _drain(audit: AuditClient) -> None:
    queue = audit.queue
    assert queue is not None
    deadline = time.monotonic() + DRAIN_TIMEOUT
    while time.monotonic() < deadline:
        if queue.count_unresolved() == 0:
            return
        time.sleep(0.05)
    raise AssertionError("the uploader did not drain the durable queue")


def _record_two_actions(base: str, state_dir: Path) -> None:
    audit = AuditClient(
        api_key=API_KEY,
        agent_name="reference-agent",
        base_url=base,
        state_dir=state_dir,
        upload_interval=0.05,
    )
    try:
        with audit.action("invoice.create", resource_type="invoice", resource_id="INV-1"):
            pass
        with audit.action("ledger.reconcile", resource_type="ledger", resource_id="2026-09"):
            pass
        _drain(audit)
    finally:
        audit.close()


def _trust_document(base: str) -> dict[str, Any]:
    response = httpx.get(f"{base}/v1/verification-keys", headers=AUTH, timeout=10.0)
    assert response.status_code == 200, response.text
    document: dict[str, Any] = response.json()
    return document


def _bundle(
    row: dict[str, Any],
    agent_public_key: str,
    keys: dict[str, Any],
    predecessor: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assemble the evidence bundle the offline verifier expects."""
    receipt = json.loads(str(row["server_receipt"]))
    return {
        "schema_version": 2,
        "event_envelope": {
            "event": json.loads(str(row["event_json"])),
            "event_hash": str(row["event_hash"]),
            "signature": str(row["signature"]),
        },
        "agent_public_key": agent_public_key,
        "service_receipt": receipt,
        "service_public_key_metadata": keys[receipt["body"]["service_key_id"]],
        "limitations": LIMITATIONS,
        "predecessor": predecessor,
    }


def _verify(tmp_path: Path, bundle: dict[str, Any], trust: dict[str, Any], name: str) -> int:
    bundle_path = tmp_path / f"{name}.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    trust_path = tmp_path / f"{name}-trust.json"
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    return main(["verify", str(bundle_path), "--trusted-service-keys", str(trust_path)])


def test_receipts_verify_offline(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state_dir = tmp_path / "agent"
    _record_two_actions(base_url, state_dir)

    rows = _queue_rows(state_dir)
    assert [int(row["sequence"]) for row in rows] == [1, 2, 3, 4]
    assert {str(row["state"]) for row in rows} == {"uploaded"}

    identity = json.loads((state_dir / "identity.json").read_text(encoding="utf-8"))
    agent_public_key = str(identity["active_key"]["public_key"])
    trust = _trust_document(base_url)
    keys = {str(entry["key_id"]): entry for entry in trust["keys"]}
    assert len(keys) == 1

    predecessor = _bundle(rows[2], agent_public_key, keys, None)
    bundle = _bundle(rows[3], agent_public_key, keys, predecessor)

    assert _verify(tmp_path, bundle, trust, "evidence") == 0
    report = capsys.readouterr().out
    assert "Runtime chain link" in report
    assert "INVALID" not in report

    tampered = copy.deepcopy(bundle)
    tampered["event_envelope"]["event"]["action_name"] = "invoice.delete"
    assert _verify(tmp_path, tampered, trust, "tampered") == 1


def test_receipts_bind_the_registered_key(base_url: str, tmp_path: Path) -> None:
    state_dir = tmp_path / "agent"
    _record_two_actions(base_url, state_dir)
    rows = _queue_rows(state_dir)
    identity = json.loads((state_dir / "identity.json").read_text(encoding="utf-8"))
    agent_id = str(identity["agent_id"])

    response = httpx.get(f"{base_url}/v1/agents/{agent_id}/keys", headers=AUTH, timeout=10.0)
    assert response.status_code == 200
    listed = response.json()["keys"]
    assert [entry["status"] for entry in listed] == ["active"]
    assert listed[0]["key_id"] == identity["active_key"]["key_id"]

    body = json.loads(str(rows[0]["server_receipt"]))["body"]
    assert body["schema_version"] == 2
    assert body["agent_key_fingerprint"] == identity["active_key"]["key_fingerprint"]
    assert body["organisation_id"] == identity["organisation_id"]
    assert body["sponsor"] is None
    assert body["grant"] is None
    assert body["capabilities_snapshot"] is None


def test_replayed_event_returns_the_original_receipt(base_url: str, tmp_path: Path) -> None:
    state_dir = tmp_path / "agent"
    _record_two_actions(base_url, state_dir)
    row = _queue_rows(state_dir)[0]
    envelope = {
        "event": json.loads(str(row["event_json"])),
        "event_hash": str(row["event_hash"]),
        "signature": str(row["signature"]),
    }
    response = httpx.post(
        f"{base_url}/v1/events/batch", json={"events": [envelope]}, headers=AUTH, timeout=10.0
    )
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["status"] == "duplicate"
    assert result["receipt"] == json.loads(str(row["server_receipt"]))


def test_missing_predecessor_is_reported(base_url: str, tmp_path: Path) -> None:
    """A genuinely signed event whose runtime has no sequence N-1 is retryable."""
    state_dir = tmp_path / "agent"
    _record_two_actions(base_url, state_dir)
    rows = _queue_rows(state_dir)
    identity = json.loads((state_dir / "identity.json").read_text(encoding="utf-8"))
    seed = b64url_decode(str(identity["active_key"]["private_key"]), SEED_LENGTH)

    event = json.loads(str(rows[1]["event_json"]))
    event["event_id"] = "22222222-2222-4222-8222-222222222222"
    event["runtime_id"] = "11111111-1111-4111-8111-111111111111"
    event["sequence"] = 2
    event["previous_event_hash"] = f"sha256:{'0' * 64}"
    raw = canonicalize(event)
    envelope = {"event": event, "event_hash": sha256_hash(raw), "signature": sign(seed, raw)}

    response = httpx.post(
        f"{base_url}/v1/events/batch", json={"events": [envelope]}, headers=AUTH, timeout=10.0
    )
    assert response.json()["results"][0]["status"] == "missing_previous"


def test_authentication_and_unknown_paths(base_url: str) -> None:
    unauthenticated = httpx.get(f"{base_url}/v1/verification-keys", timeout=10.0)
    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {"error": "unauthorized"}

    wrong = httpx.get(
        f"{base_url}/v1/verification-keys", headers={"Authorization": "Bearer nope"}, timeout=10.0
    )
    assert wrong.status_code == 401

    for path in ("/", "/v1/agents/00000000-0000-4000-8000-000000000001", "/app/"):
        missing = httpx.get(f"{base_url}{path}", headers=AUTH, timeout=10.0)
        assert missing.status_code == 404, path
        assert missing.json() == {"error": "not_found"}, path


def test_invalid_batch_container_is_rejected(base_url: str) -> None:
    response = httpx.post(
        f"{base_url}/v1/events/batch", content=b'{"events": 1}', headers=AUTH, timeout=10.0
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_schema"}
