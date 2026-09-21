"""External-format exports: AERF v0.1.0-draft.1, Agent Receipts v0.5.0, noa.

What each format is checked against:

* AERF: the two Go reference verifiers, run through ``$AERF_VERIFY_V01``
  (v0.1.0-draft.1) and ``$AERF_VERIFY`` (the current repository), plus an
  internal recomputation of the v0.1 canonical payload. The external runs
  skip when the environment variables are unset.
* Agent Receipts: the obsigna reference verifier, run through
  ``$OBSIGNA_PYTHON`` (skipped when unset), plus an internal RFC 8785
  recomputation of the credential without its proof.
* noa: the noa project's independent Python verifier
  (``impl-py/noa_verify.py`` in github.com/NordenSoft/noa-mandate-core), run
  through the NOA_VERIFY environment variable (skipped when unset), plus an
  internal specification-derived verifier for the bare receipt form.

Self-contained apart from two read-only inputs the brief names: the golden
bundle in ``sdk/tests/fixtures/receipt-v1.json`` and the public test seed in
``sdk/tests/_fixture_source``. Predecessor bundles are built with the same
``rebind`` helper that the SealStack source repository's acceptance suite uses.
"""

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk"))
sys.path.insert(0, str(ROOT))

from sealstack import export as export_module
from sealstack.cli import main
from sealstack.export import (
    NOA_MESSAGE_PREFIX,
    ExportError,
    build_aerf,
    build_agent_receipt,
    build_noa,
    load_mapping,
)
from sealstack.signing import public_key_from_seed

from _fixture_source import AGENT_SEED, uid
from _support import rebind

MAPPING_PATH = Path(__file__).resolve().parent / "fixtures" / "mapping-full.json"


def _golden_path() -> Path:
    """Locate the golden bundle beside this file first, then at the repository root.

    The SDK export ships the fixtures under ``sdk/tests/fixtures/``; this
    repository keeps them under ``tests/fixtures/``. The same file resolves in
    both without a copy in either tree.
    """
    local = Path(__file__).resolve().parent / "fixtures" / "receipt-v1.json"
    return local if local.exists() else ROOT / "tests" / "fixtures" / "receipt-v1.json"


GOLDEN_PATH = _golden_path()

AGENT_PUBLIC = public_key_from_seed(AGENT_SEED)

NOA_MEMBERS = {"spec", "id", "ts", "scope", "agent", "action", "governance", "chain", "sig"}
NOA_VERDICTS = {"ALLOWED", "EXECUTED", "FAILED"}
NOA_PRINCIPALS = {"HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM"}
NOA_RISK = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"}


# -- fixtures ----------------------------------------------------------------


@pytest.fixture
def bundle() -> dict[str, Any]:
    golden = json.loads(GOLDEN_PATH.read_text())
    document: dict[str, Any] = copy.deepcopy(golden["bundle"])
    return document


@pytest.fixture
def mapping() -> dict[str, Any]:
    return load_mapping(MAPPING_PATH.read_text())


@pytest.fixture
def seed_file(tmp_path: Path) -> Path:
    path = tmp_path / "agent-seed.txt"
    path.write_text(base64.urlsafe_b64encode(AGENT_SEED).rstrip(b"=").decode("ascii"))
    return path


def write_bundle(tmp_path: Path, bundle: dict[str, Any]) -> Path:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(bundle, ensure_ascii=True))
    return path


def run_cli(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str]:
    code = main(list(args))
    return code, capsys.readouterr().out


def export_cli(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    bundle: dict[str, Any],
    seed_file: Path,
    fmt: str,
    *extra: str,
) -> tuple[int, str, Path]:
    source = write_bundle(tmp_path, bundle)
    out = tmp_path / f"artifact.{fmt}.json"
    code, output = run_cli(
        capsys,
        "export",
        "--format",
        fmt,
        str(source),
        "--out",
        str(out),
        "--signing-key",
        str(seed_file),
        *extra,
    )
    return code, output, out


def predecessor_pair(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return the fixture bundle advanced to sequence 2 over its predecessor."""
    predecessor = copy.deepcopy(bundle)
    event = bundle["event_envelope"]["event"]
    event.update(
        event_id=uid(600),
        sequence=2,
        previous_event_hash=predecessor["event_envelope"]["event_hash"],
    )
    rebind(bundle)
    bundle["predecessor"] = predecessor
    return bundle


# -- internal verifiers ------------------------------------------------------


def ed25519_ok(public_raw: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def aerf_internal_verify(artifact: dict[str, Any], public_raw: bytes) -> bool:
    """AERF SPEC 10.1: strip signature and timestamp, canonicalise, verify."""
    payload = {
        key: value
        for key, value in artifact.items()
        if key not in ("signature", "timestamp")
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return ed25519_ok(public_raw, bytes.fromhex(artifact["signature"]), canonical)


def agent_receipt_internal_verify(artifact: dict[str, Any], public_raw: bytes) -> bool:
    """Recompute the RFC 8785 bytes of the credential without its proof."""
    proof = artifact["proof"]
    assert proof["type"] == "Ed25519Signature2020"
    assert proof["proofValue"].startswith("u")
    encoded = proof["proofValue"][1:]
    signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    credential = {key: value for key, value in artifact.items() if key != "proof"}
    return ed25519_ok(public_raw, signature, rfc8785.dumps(credential))


def noa_hash_input(receipt: dict[str, Any]) -> bytes:
    stripped = dict(receipt)
    stripped["chain"] = {k: v for k, v in receipt["chain"].items() if k != "hash"}
    stripped["sig"] = {k: v for k, v in receipt["sig"].items() if k != "value"}
    return rfc8785.dumps(stripped)


def noa_verify(receipt: dict[str, Any], public_raw: bytes) -> list[str]:
    """Specification-derived verifier for the noa bare receipt form.

    Implements the draft's steps for a Receipt Verifier: closed member set,
    enumerations, chain hash recomputation, the signed MESSAGE construction
    and canonical base64.  Returns the list of failures; empty means valid.
    No external noa verifier exists to run instead (see the module docstring).
    """
    failures: list[str] = []

    # 1. Closed object.
    if set(receipt) != NOA_MEMBERS:
        failures.append(f"member set is {sorted(receipt)}")

    # 2. Enumerations and value forms.
    if receipt.get("spec") != "noa.receipt/0.1":
        failures.append("spec is not noa.receipt/0.1")
    governance = receipt.get("governance", {})
    if governance.get("mode") != "off":
        failures.append("governance.mode is not off")
    if governance.get("verdict") not in NOA_VERDICTS:
        failures.append("governance.verdict is not an allowed verdict")
    if "rollbackRef" in receipt.get("action", {}) or "rollbackRef" in governance:
        failures.append("rollbackRef must never be emitted")
    if receipt.get("agent", {}).get("principal") not in NOA_PRINCIPALS:
        failures.append("agent.principal is not an allowed principal")
    if receipt.get("action", {}).get("riskClass") not in NOA_RISK:
        failures.append("action.riskClass is not an allowed risk class")
    if not isinstance(governance.get("sandboxed"), bool):
        failures.append("governance.sandboxed is not a boolean")
    if governance.get("sandboxed") is not True and (
        receipt.get("agent", {}).get("principal") == "SANDBOX_SIM"
    ):
        failures.append("SANDBOX_SIM requires governance.sandboxed true")
    if type(receipt.get("chain", {}).get("seq")) is not int:
        failures.append("chain.seq is not an integer")
    if receipt.get("sig", {}).get("alg") != "ed25519":
        failures.append("sig.alg is not ed25519")

    # 3. Chain hash recomputation.
    hash_input = noa_hash_input(receipt)
    digest = hashlib.sha256(hash_input).digest()
    if receipt["chain"].get("hash") != "sha256:" + digest.hex():
        failures.append("chain.hash does not match the recomputed hash input")

    # 4 and 5. MESSAGE construction and signature.
    value = receipt["sig"].get("value", "")
    try:
        signature = base64.b64decode(value, validate=True)
    except Exception:  # noqa: BLE001 - any decode failure is a verification failure
        failures.append("sig.value is not standard base64")
        return failures
    # 6. Canonical re-encode.
    if base64.b64encode(signature).decode("ascii") != value:
        failures.append("sig.value is not canonical padded base64")
    message = NOA_MESSAGE_PREFIX + digest
    if len(NOA_MESSAGE_PREFIX) != 21:
        failures.append("the signed prefix is not 21 octets")
    if not ed25519_ok(public_raw, signature, message):
        failures.append("sig.value does not verify over the MESSAGE")
    return failures


# -- external verifier harnesses ---------------------------------------------


def run_aerf_verifier(variable: str, artifact: Path, pem: Path) -> int:
    binary = os.environ.get(variable)
    if not binary:
        pytest.skip(f"{variable} is not set")
    result = subprocess.run(
        [binary, str(artifact), str(pem)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    print(f"{variable}: exit {result.returncode}\n{result.stdout}{result.stderr}")
    return result.returncode


def run_obsigna(artifact: Path, pem: Path) -> str:
    interpreter = os.environ.get("OBSIGNA_PYTHON")
    if not interpreter:
        pytest.skip("OBSIGNA_PYTHON is not set")
    program = (
        "import sys, obsigna;"
        "raw=open(sys.argv[1],'rb').read();"
        "pem=open(sys.argv[2]).read();"
        "print(obsigna.verify_raw(raw, pem))"
    )
    result = subprocess.run(
        [interpreter, "-c", program, str(artifact), str(pem)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def run_noa_verifier(receipts: Path, keyring: Path | None) -> tuple[int, str]:
    """Run the noa project's zero-dependency Python verifier.

    Exit codes there: 0 VALID, 1 UNVERIFIED (no keyring), 2 TAMPERED, 3 MALFORMED.
    """
    script = os.environ.get("NOA_VERIFY")
    if not script:
        pytest.skip("NOA_VERIFY is not set")
    command = [sys.executable, script, str(receipts)]
    if keyring is not None:
        command.append(str(keyring))
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    print(f"NOA_VERIFY: exit {result.returncode}\n{result.stdout}{result.stderr}")
    return result.returncode, result.stdout


def noa_keyring(tmp_path: Path, kid: str) -> Path:
    """The noa keyring form: {kid: base64(DER SPKI)} of the agent public key."""
    pem = export_module.public_key_pem(AGENT_SEED).decode("ascii")
    der = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps({kid: der}))
    return path


# -- AERF --------------------------------------------------------------------


def test_aerf_subset_omits_the_fields_sealstack_does_not_record(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(capsys, tmp_path, bundle, seed_file, "aerf")
    assert code == 0, output
    artifact = json.loads(out.read_text())

    for field in ("plan_id", "in_policy", "policy_reason"):
        assert field not in artifact
        assert field in output
    assert "mode: subset (non-conformant): missing" in output
    assert artifact["evidence"]["sealstack_export"] == {
        "mode": "subset",
        "missing_fields": ["plan_id", "in_policy", "policy_reason"],
        "notes": [],
    }


def test_aerf_subset_embeds_the_native_evidence_verbatim(
    capsys, tmp_path, bundle, seed_file
):
    original = copy.deepcopy(bundle)
    code, output, out = export_cli(capsys, tmp_path, bundle, seed_file, "aerf")
    assert code == 0, output
    evidence = json.loads(out.read_text())["evidence"]

    assert "native evidence: embedded in evidence" in output
    assert evidence["event"] == original["event_envelope"]["event"]
    assert evidence["event_hash"] == original["event_envelope"]["event_hash"]
    assert evidence["agent_signature"] == original["event_envelope"]["signature"]
    assert evidence["service_receipt"] == original["service_receipt"]
    assert evidence["agent_public_key"] == original["agent_public_key"]
    assert not (tmp_path / "artifact.aerf.json.sealstack.json").exists()


def test_aerf_full_carries_the_mapped_policy_decision(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(
        capsys, tmp_path, bundle, seed_file, "aerf", "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())

    assert "mode: full" in output
    assert "non-conformant" not in output
    assert artifact["plan_id"] == bundle["event_envelope"]["event"]["action_id"]
    assert artifact["in_policy"] is True
    assert artifact["policy_reason"] == "matched capability invoice.create"
    assert artifact["key_id"] == hashlib.sha256(AGENT_PUBLIC).hexdigest()[:16]
    assert aerf_internal_verify(artifact, AGENT_PUBLIC)


@pytest.mark.parametrize("variable", ["AERF_VERIFY_V01", "AERF_VERIFY"])
def test_aerf_full_passes_the_go_reference_verifier(
    capsys, tmp_path, bundle, seed_file, variable
):
    pem = tmp_path / "agent.pem"
    code, output, out = export_cli(
        capsys,
        tmp_path,
        bundle,
        seed_file,
        "aerf",
        "--mapping",
        str(MAPPING_PATH),
        "--public-key-out",
        str(pem),
    )
    assert code == 0, output
    assert run_aerf_verifier(variable, out, pem) == 0

    tampered = json.loads(out.read_text())
    tampered["agent"] = uid(999)
    flipped = tmp_path / "tampered.aerf.json"
    flipped.write_text(json.dumps(tampered))
    assert run_aerf_verifier(variable, flipped, pem) == 1


def test_aerf_chain_sets_previous_receipt_hash_from_the_predecessor(
    capsys, tmp_path, bundle, seed_file, mapping
):
    linked = predecessor_pair(bundle)
    code, output, out = export_cli(
        capsys, tmp_path, linked, seed_file, "aerf", "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())

    assert "chain: previous_receipt_hash set" in output
    predecessor_export = build_aerf(linked["predecessor"], mapping, AGENT_SEED)
    payload = {
        key: value
        for key, value in predecessor_export.artifact.items()
        if key not in ("signature", "timestamp")
    }
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("ascii")
    ).hexdigest()
    assert artifact["previous_receipt_hash"] == expected
    assert aerf_internal_verify(artifact, AGENT_PUBLIC)


def test_aerf_genesis_omits_previous_receipt_hash(capsys, tmp_path, bundle, seed_file):
    code, output, out = export_cli(capsys, tmp_path, bundle, seed_file, "aerf")
    assert code == 0, output
    assert "chain: previous_receipt_hash omitted (genesis)" in output
    assert "previous_receipt_hash" not in json.loads(out.read_text())


def test_aerf_without_predecessor_evidence_omits_and_labels_the_link(
    capsys, tmp_path, bundle, seed_file
):
    linked = predecessor_pair(bundle)
    linked["predecessor"] = None
    code, output, out = export_cli(capsys, tmp_path, linked, seed_file, "aerf")
    assert code == 0, output
    assert "chain: previous_receipt_hash omitted (no predecessor evidence)" in output
    assert "previous_receipt_hash" in output.splitlines()[1]
    assert "previous_receipt_hash" not in json.loads(out.read_text())


def test_aerf_never_emits_a_timestamp_or_unsupported_fields(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(
        capsys, tmp_path, bundle, seed_file, "aerf", "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())
    for field in (
        "timestamp",
        "plan_signature",
        "policy_hash",
        "session_trajectory",
        "reasoning_hash",
        "compliance_tags",
    ):
        assert field not in artifact


# -- Agent Receipt Protocol --------------------------------------------------


def test_agent_receipts_subset_omits_the_mapped_action_semantics(
    capsys, tmp_path, bundle, seed_file
):
    original = copy.deepcopy(bundle)
    code, output, out = export_cli(capsys, tmp_path, bundle, seed_file, "agent-receipts")
    assert code == 0, output
    artifact = json.loads(out.read_text())
    action = artifact["credentialSubject"]["action"]

    assert "type" not in action
    assert "risk_level" not in action
    assert "missing action.type, action.risk_level" in output
    companion = json.loads((tmp_path / "artifact.agent-receipts.json.sealstack.json").read_text())
    assert companion["bundle"] == original
    assert companion["sealstack_export"]["missing_fields"] == [
        "action.type",
        "action.risk_level",
    ]
    assert f"companion: {tmp_path / 'artifact.agent-receipts.json.sealstack.json'}" in output


def test_agent_receipts_full_carries_the_mapped_taxonomy(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(
        capsys,
        tmp_path,
        bundle,
        seed_file,
        "agent-receipts",
        "--mapping",
        str(MAPPING_PATH),
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())
    subject = artifact["credentialSubject"]

    assert "mode: full" in output
    assert subject["action"]["type"] == "financial.payment.initiate"
    assert subject["action"]["risk_level"] == "high"
    assert artifact["version"] == "0.5.0"
    assert artifact["@context"] == [
        "https://www.w3.org/ns/credentials/v2",
        "https://agentreceipts.ai/context/v2",
    ]
    assert subject["principal"] == {
        "id": "urn:uuid:" + bundle["service_receipt"]["body"]["sponsor"]["user_id"],
        "type": "HumanPrincipal",
    }
    assert subject["authorization"]["scopes"] == ["invoice.create", "invoice.read"]
    assert "expires_at" not in subject["authorization"]
    assert agent_receipt_internal_verify(artifact, AGENT_PUBLIC)


def test_agent_receipts_full_passes_the_obsigna_reference_verifier(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(
        capsys,
        tmp_path,
        bundle,
        seed_file,
        "agent-receipts",
        "--mapping",
        str(MAPPING_PATH),
    )
    assert code == 0, output
    pem = tmp_path / "agent.pem"
    pem.write_bytes(export_module.public_key_pem(AGENT_SEED))

    assert run_obsigna(out, pem) == "True"

    tampered = json.loads(out.read_text())
    tampered["credentialSubject"]["action"]["risk_level"] = "low"
    flipped = tmp_path / "tampered.json"
    flipped.write_text(json.dumps(tampered))
    assert run_obsigna(flipped, pem) == "False"


def test_agent_receipts_chain_hash_binds_the_predecessor_credential(
    capsys, tmp_path, bundle, seed_file, mapping
):
    linked = predecessor_pair(bundle)
    code, output, out = export_cli(
        capsys,
        tmp_path,
        linked,
        seed_file,
        "agent-receipts",
        "--mapping",
        str(MAPPING_PATH),
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())
    chain = artifact["credentialSubject"]["chain"]

    assert chain["sequence"] == 2
    assert "chain: previous_receipt_hash set" in output
    predecessor = build_agent_receipt(
        linked["predecessor"], mapping, AGENT_SEED
    ).artifact
    unsigned = {key: value for key, value in predecessor.items() if key != "proof"}
    assert chain["previous_receipt_hash"] == "sha256:" + hashlib.sha256(
        rfc8785.dumps(unsigned)
    ).hexdigest()
    assert agent_receipt_internal_verify(artifact, AGENT_PUBLIC)


def test_agent_receipts_genesis_writes_an_explicit_null_link(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(capsys, tmp_path, bundle, seed_file, "agent-receipts")
    assert code == 0, output
    chain = json.loads(out.read_text())["credentialSubject"]["chain"]
    assert chain == {
        "chain_id": bundle["event_envelope"]["event"]["runtime_id"],
        "sequence": 1,
        "previous_receipt_hash": None,
    }


def test_agent_receipts_without_predecessor_evidence_omits_the_chain(
    capsys, tmp_path, bundle, seed_file
):
    linked = predecessor_pair(bundle)
    linked["predecessor"] = None
    code, output, out = export_cli(capsys, tmp_path, linked, seed_file, "agent-receipts")
    assert code == 0, output
    assert "chain object omitted (no predecessor evidence)" in output
    assert "missing action.type, action.risk_level, chain" in output
    assert "chain" not in json.loads(out.read_text())["credentialSubject"]


def test_agent_receipts_never_emit_optional_fields_as_null(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(
        capsys,
        tmp_path,
        bundle,
        seed_file,
        "agent-receipts",
        "--mapping",
        str(MAPPING_PATH),
    )
    assert code == 0, output
    subject = json.loads(out.read_text())["credentialSubject"]
    nulls = [key for key, value in subject["action"].items() if value is None]
    nulls += [key for key, value in subject["outcome"].items() if value is None]
    assert nulls == []
    for field in ("intent", "delegation", "state_change", "terminal"):
        assert field not in subject
    assert "trusted_timestamp" not in subject["action"]


# -- noa (scitt) -------------------------------------------------------------


def test_noa_subset_omits_the_four_mapped_semantics(capsys, tmp_path, bundle, seed_file):
    original = copy.deepcopy(bundle)
    code, output, out = export_cli(capsys, tmp_path, bundle, seed_file, "scitt")
    assert code == 0, output
    artifact = json.loads(out.read_text())

    assert "principal" not in artifact["agent"]
    assert "riskClass" not in artifact["action"]
    assert "reversible" not in artifact["action"]
    assert "sandboxed" not in artifact["governance"]
    assert (
        "missing agent.principal, action.riskClass, action.reversible, "
        "governance.sandboxed" in output
    )
    companion = json.loads((tmp_path / "artifact.scitt.json.sealstack.json").read_text())
    assert companion["bundle"] == original
    assert export_module.NOA_ENVELOPE_LINE in output


def test_noa_full_passes_the_internal_specification_verifier(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(
        capsys, tmp_path, bundle, seed_file, "scitt", "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())

    assert "mode: full" in output
    assert artifact["agent"] == {
        "id": bundle["event_envelope"]["event"]["agent_id"],
        "principal": "SERVICE",
    }
    assert artifact["action"]["riskClass"] == "HIGH"
    assert artifact["action"]["reversible"] is False
    assert artifact["governance"] == {
        "mode": "off",
        "verdict": "ALLOWED",
        "sandboxed": False,
    }
    assert artifact["scope"] == {
        "chain": bundle["event_envelope"]["event"]["runtime_id"],
        "tenant": bundle["event_envelope"]["event"]["organisation_id"],
    }
    assert noa_verify(artifact, AGENT_PUBLIC) == []


@pytest.mark.parametrize(
    "path,value",
    [
        (("action", "riskClass"), "LOW"),
        (("governance", "verdict"), "EXECUTED"),
        (("sig", "kid"), "tampered"),
    ],
)
def test_noa_tampering_fails_the_internal_verifier(
    capsys, tmp_path, bundle, seed_file, path, value
):
    code, output, out = export_cli(
        capsys, tmp_path, bundle, seed_file, "scitt", "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())
    artifact[path[0]][path[1]] = value
    assert noa_verify(artifact, AGENT_PUBLIC) != []


def test_noa_chain_prevhash_is_the_predecessor_receipt_hash(
    capsys, tmp_path, bundle, seed_file, mapping
):
    linked = predecessor_pair(bundle)
    code, output, out = export_cli(
        capsys, tmp_path, linked, seed_file, "scitt", "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())

    assert artifact["chain"]["seq"] == 1
    assert "chain: prevHash set" in output
    predecessor = build_noa(linked["predecessor"], mapping, AGENT_SEED).artifact
    assert artifact["chain"]["prevHash"] == predecessor["chain"]["hash"]
    assert noa_verify(artifact, AGENT_PUBLIC) == []


def test_noa_full_chain_passes_the_noa_reference_verifier(tmp_path, bundle, mapping):
    linked = predecessor_pair(bundle)
    first = build_noa(linked["predecessor"], mapping, AGENT_SEED).artifact
    second = build_noa(linked, mapping, AGENT_SEED).artifact
    receipts = tmp_path / "chain.json"
    receipts.write_text(json.dumps([first, second]))
    keyring = noa_keyring(tmp_path, first["sig"]["kid"])

    code, output = run_noa_verifier(receipts, keyring)
    assert code == 0, output
    assert '"status": "VALID"' in output

    tampered = copy.deepcopy(first)
    tampered["action"]["riskClass"] = "LOW"
    flipped = tmp_path / "tampered.json"
    flipped.write_text(json.dumps([tampered]))
    code, output = run_noa_verifier(flipped, keyring)
    assert code == 2, output
    assert '"status": "TAMPERED"' in output


def test_noa_subset_is_malformed_under_the_noa_reference_verifier(tmp_path, bundle):
    """The subset artifact omits four mandatory members, exactly as its label says."""
    subset = build_noa(bundle, None, AGENT_SEED).artifact
    receipts = tmp_path / "subset.json"
    receipts.write_text(json.dumps([subset]))
    code, output = run_noa_verifier(receipts, noa_keyring(tmp_path, subset["sig"]["kid"]))
    assert code == 3, output
    assert '"status": "MALFORMED"' in output


def test_noa_without_predecessor_evidence_omits_prevhash(
    capsys, tmp_path, bundle, seed_file
):
    linked = predecessor_pair(bundle)
    linked["predecessor"] = None
    code, output, out = export_cli(
        capsys, tmp_path, linked, seed_file, "scitt", "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())
    assert "chain: prevHash omitted (no predecessor evidence)" in output
    assert "missing chain.prevHash" in output
    assert "prevHash" not in artifact["chain"]


def test_noa_message_prefix_and_hash_input_are_the_specified_ones(
    tmp_path, bundle, mapping
):
    receipt = build_noa(bundle, mapping, AGENT_SEED).artifact
    assert NOA_MESSAGE_PREFIX == b"NOA-Receipt-v0.1-sig:"
    assert len(NOA_MESSAGE_PREFIX) == 21
    hash_input = noa_hash_input(receipt)
    assert b'"hash"' not in hash_input
    assert b'"value"' not in hash_input
    assert b'"alg":"ed25519"' in hash_input
    assert receipt["chain"]["hash"] == "sha256:" + hashlib.sha256(hash_input).hexdigest()


# -- mapping gaps ------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["aerf", "agent-receipts", "scitt"])
def test_mapping_without_the_event_action_exits_two_and_writes_nothing(
    capsys, tmp_path, bundle, seed_file, fmt
):
    partial = json.loads(MAPPING_PATH.read_text())
    for section in partial.values():
        section["actions"] = {"invoice.read": next(iter(section["actions"].values()))}
    path = tmp_path / "partial-mapping.json"
    path.write_text(json.dumps(partial))

    code, output, out = export_cli(
        capsys, tmp_path, bundle, seed_file, fmt, "--mapping", str(path)
    )
    assert code == 2, output
    assert "invoice.create" in output
    assert not out.exists()
    assert not (tmp_path / f"artifact.{fmt}.json.sealstack.json").exists()


@pytest.mark.parametrize(
    "document",
    [
        {"unknown": {}},
        {"aerf": {"plan_id_source": "event_id"}},
        {"aerf": {"actions": {"invoice.create": {"in_policy": "yes"}}}},
        {"agent_receipts": {"actions": {"invoice.create": {"risk_level": "severe"}}}},
        {"noa": {"agent": {"principal": "ROBOT", "sandboxed": False}}},
        {"noa": {"actions": {"invoice.create": {"riskClass": "SEVERE"}}}},
        {"noa": {"agent": {"principal": "SERVICE", "unknown": 1}}},
    ],
)
def test_unknown_or_invalid_mapping_keys_are_refused(document):
    with pytest.raises(ExportError):
        load_mapping(json.dumps(document))


def test_sandbox_simulation_requires_the_sandboxed_flag(bundle):
    document = json.loads(MAPPING_PATH.read_text())
    document["noa"]["agent"] = {"principal": "SANDBOX_SIM", "sandboxed": False}
    mapping = load_mapping(json.dumps(document))
    with pytest.raises(ExportError) as caught:
        build_noa(bundle, mapping, AGENT_SEED)
    assert "SANDBOX_SIM" in str(caught.value)


# -- bundle validation, overwrite and identity -------------------------------


def test_an_invalid_bundle_exits_one_and_writes_nothing(capsys, tmp_path, seed_file):
    source = tmp_path / "evidence.json"
    source.write_text(json.dumps({"schema_version": 2}))
    out = tmp_path / "artifact.json"
    code, output = run_cli(
        capsys, "export", "--format", "aerf", str(source), "--out", str(out),
        "--signing-key", str(seed_file),
    )
    assert code == 1, output
    assert "invalid" in output
    assert not out.exists()


def test_export_rejects_what_the_verifier_rejects(capsys, tmp_path, seed_file):
    """A bundle text the strict parser refuses (duplicate keys) exits 1 and writes nothing."""
    source = tmp_path / "evidence.json"
    source.write_text('{"schema_version": 2, "schema_version": 2}')
    out = tmp_path / "artifact.json"
    code, output = run_cli(
        capsys, "export", "--format", "aerf", str(source), "--out", str(out),
        "--signing-key", str(seed_file),
    )
    assert code == 1, output
    assert "duplicate" in output
    assert not out.exists()


def test_existing_files_are_never_overwritten_without_force(
    capsys, tmp_path, bundle, seed_file
):
    code, output, out = export_cli(capsys, tmp_path, bundle, seed_file, "scitt")
    assert code == 0, output
    before = out.read_bytes()

    code, output, _ = export_cli(capsys, tmp_path, bundle, seed_file, "scitt")
    assert code == 2, output
    assert "--force" in output
    assert out.read_bytes() == before

    code, output, _ = export_cli(capsys, tmp_path, bundle, seed_file, "scitt", "--force")
    assert code == 0, output


def test_exactly_one_signing_source_is_required(capsys, tmp_path, bundle, seed_file):
    source = write_bundle(tmp_path, bundle)
    code, output = run_cli(capsys, "export", "--format", "aerf", str(source))
    assert code == 2, output
    assert "exactly one" in output

    code, output = run_cli(
        capsys, "export", "--format", "aerf", str(source),
        "--signing-key", str(seed_file), "--state-dir", str(tmp_path),
    )
    assert code == 2, output


def identity_document() -> dict[str, Any]:
    """A registered §18 identity holding the public test key."""
    return {
        "schema_version": 1,
        "organisation_id": uid(2),
        "agent_id": uid(3),
        "active_key": {
            "key_id": uid(4),
            "state": "active",
            "public_key": base64.urlsafe_b64encode(AGENT_PUBLIC)
            .rstrip(b"=")
            .decode("ascii"),
            "private_key": base64.urlsafe_b64encode(AGENT_SEED)
            .rstrip(b"=")
            .decode("ascii"),
            "key_fingerprint": "sha256:" + hashlib.sha256(AGENT_PUBLIC).hexdigest(),
        },
        "pending_key": None,
    }


def test_state_dir_signs_with_the_registered_identity(capsys, tmp_path, bundle):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    identity_path = state_dir / "identity.json"
    identity_path.write_text(json.dumps(identity_document()))
    identity_path.chmod(0o600)
    before = identity_path.read_bytes()

    source = write_bundle(tmp_path, bundle)
    out = tmp_path / "artifact.aerf.json"
    code, output = run_cli(
        capsys, "export", "--format", "aerf", str(source), "--out", str(out),
        "--state-dir", str(state_dir),
    )
    assert code == 0, output
    artifact = json.loads(out.read_text())
    assert artifact["key_id"] == hashlib.sha256(AGENT_PUBLIC).hexdigest()[:16]
    assert aerf_internal_verify(artifact, AGENT_PUBLIC)
    assert identity_path.read_bytes() == before


def test_state_dir_owned_by_another_sdk_is_refused(capsys, tmp_path, bundle):
    from sealstack.identity import DirectoryLock

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    identity_path = state_dir / "identity.json"
    identity_path.write_text(json.dumps(identity_document()))
    identity_path.chmod(0o600)

    owner = DirectoryLock(state_dir)
    owner.acquire()
    try:
        source = write_bundle(tmp_path, bundle)
        out = tmp_path / "artifact.aerf.json"
        code, output = run_cli(
            capsys, "export", "--format", "aerf", str(source), "--out", str(out),
            "--state-dir", str(state_dir),
        )
    finally:
        owner.release()

    assert code == 2, output
    assert "identity_in_use" in output
    assert not out.exists()


# -- output hygiene ----------------------------------------------------------


@pytest.mark.parametrize("fmt", ["aerf", "agent-receipts", "scitt"])
def test_export_output_uses_no_dash_punctuation(capsys, tmp_path, bundle, seed_file, fmt):
    code, output, out = export_cli(
        capsys, tmp_path, bundle, seed_file, fmt, "--mapping", str(MAPPING_PATH)
    )
    assert code == 0, output
    written = out.read_text()
    for forbidden in ("—", "–"):
        assert forbidden not in output
        assert forbidden not in written


@pytest.mark.parametrize("fmt", ["aerf", "agent-receipts", "scitt"])
def test_builders_are_callable_without_the_cli(bundle, mapping, fmt):
    builder = export_module.BUILDERS[fmt]
    artifact, companion, labels = builder(bundle, mapping, AGENT_SEED)
    assert isinstance(artifact, dict)
    assert labels.mode == "full"
    assert (companion is None) is labels.embedded_evidence
    subset = builder(bundle, None, AGENT_SEED)
    assert subset.labels.mode == "subset"
    assert subset.labels.missing_fields
