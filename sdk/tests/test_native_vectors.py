"""Native conformance vectors for the offline verifier (SPEC-RECEIPT.md Section 10.3).

``fixtures/native-vectors.json`` holds one positive case (the Section 12 golden
bundle) and a set of negative and unverifiable cases, each expressed as a
mutation of that bundle plus the exit code and report line Section 10.3
requires. The file is data, so another implementation can consume it without
running this test: apply the mutation to the golden bundle, verify with the
golden trust file (or none, when ``trust`` is ``null``), and compare the exit
code.

Mutation forms:

* ``{"set": {"/json/pointer": value}}`` sets the value at each pointer;
* ``{"text": "..."}`` replaces the whole bundle text (for parser-level cases);
* ``"resign": true`` re-signs the mutated bundle with the public test seeds so
  a rule behind the signature checks is exercised on its own; the value
  ``"$golden"`` stands for a copy of the golden bundle (predecessor cases).

``expect.output`` is a substring that must appear in the verifier's report.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from sealstack.cli import main
from sealstack.signing import canonicalize, sha256_hash, sign

from _fixture_source import AGENT_SEED, SERVICE_SEED

HERE = Path(__file__).resolve().parent
ROOT = HERE.resolve().parents[1]


def _fixture(name: str) -> Path:
    """Locate a Codex-owned fixture beside this file first, then at the repository root.

    The SDK export ships fixtures under ``sdk/tests/fixtures/``; this
    repository keeps the golden bundle and trust file under ``tests/fixtures/``
    (Codex-owned). The same file resolves in both without a copy in either
    tree. See sdk/tests/test_export_formats.py's identical ``_golden_path``.
    """
    local = HERE / "fixtures" / name
    return local if local.exists() else ROOT / "tests" / "fixtures" / name


GOLDEN = _fixture("receipt-v1.json")
TRUST = _fixture("service-keys.json")
VECTORS = HERE / "fixtures" / "native-vectors.json"


def _set_pointer(document: Any, pointer: str, value: Any) -> None:
    parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]
    target = document
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    last = parts[-1]
    if isinstance(target, list):
        target[int(last)] = value
    else:
        target[last] = value


def _bundle_text(case: dict[str, Any]) -> str:
    mutation = case["mutation"]
    if "text" in mutation:
        text: str = mutation["text"]
        return text
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["bundle"]
    bundle = copy.deepcopy(golden)
    for pointer, value in mutation.get("set", {}).items():
        _set_pointer(bundle, pointer, copy.deepcopy(golden) if value == "$golden" else value)
    if mutation.get("resign"):
        _resign(bundle)
    return json.dumps(bundle, ensure_ascii=False)


def _resign(bundle: dict[str, Any]) -> None:
    """Re-sign a mutated bundle with the public test seeds (Section 12)."""
    envelope = bundle["event_envelope"]
    raw = canonicalize(envelope["event"])
    envelope["event_hash"] = sha256_hash(raw)
    envelope["signature"] = sign(AGENT_SEED, raw)
    body = bundle["service_receipt"]["body"]
    for key in ("event_id", "organisation_id", "agent_id", "agent_key_id"):
        body[key] = envelope["event"][key]
    body["event_hash"] = envelope["event_hash"]
    bundle["service_receipt"]["signature"] = sign(SERVICE_SEED, canonicalize(body))


def _cases() -> list[dict[str, Any]]:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = document["cases"]
    return cases


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["id"]))
def test_native_vector(case: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(_bundle_text(case), encoding="utf-8")
    arguments = ["verify", str(bundle_path)]
    if case.get("trust", "golden") == "golden":
        arguments += ["--trusted-service-keys", str(TRUST)]
    code = main(arguments)
    report = capsys.readouterr().out
    assert code == case["expect"]["exit"], report
    assert case["expect"]["output"] in report, report


def test_standalone_golden_bundle_matches_the_fixture() -> None:
    """golden-evidence-bundle.json is the README's zero-setup file; it must stay the golden bundle."""
    standalone = json.loads((HERE / "fixtures" / "golden-evidence-bundle.json").read_text(encoding="utf-8"))
    assert standalone == json.loads(GOLDEN.read_text(encoding="utf-8"))["bundle"]


def test_limitations_fixture_is_byte_exact() -> None:
    """limitations.txt is the Section 11 text as bytes, for implementers in other languages."""
    from sealstack.verify import LIMITATIONS

    assert (HERE / "fixtures" / "limitations.txt").read_bytes() == LIMITATIONS.encode("utf-8")


def test_vector_file_covers_every_status() -> None:
    codes = {case["expect"]["exit"] for case in _cases()}
    assert codes == {0, 1, 2}
