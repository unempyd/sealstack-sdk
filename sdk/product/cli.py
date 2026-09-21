"""Console entry point for the offline verifier (SPEC §122, §123).

``product verify receipt.json --trusted-service-keys service-keys.json``
``product export --format aerf bundle.json --signing-key seed.txt``

The verifier performs no network access.  ``main`` never raises and never lets
a traceback escape: every outcome is a printed report plus an exit code.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from product import export as export_module
from product.export import ARTIFACT_SUFFIX, BUILDERS, FORMATS, Export, ExportError
from product.identity import DirectoryLock, IdentityStore
from product.signing import SEED_LENGTH, b64url_decode
from product.verify import Result, verify_bundle

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_UNVERIFIABLE = 2

_PROGRAM = "product"
_LABEL_WIDTH = 25


def _line(label: str, status: str, detail: str) -> str:
    return f"{label + ':':<{_LABEL_WIDTH}}{status} — {detail}"


def build_parser() -> argparse.ArgumentParser:
    """Build the ``product`` command-line parser."""
    parser = argparse.ArgumentParser(
        prog=_PROGRAM,
        description="SealStack agent audit tooling.",
    )
    subcommands = parser.add_subparsers(dest="command")

    verify_command = subcommands.add_parser(
        "verify", help="verify an evidence bundle offline"
    )
    verify_command.add_argument("bundle_path", help="path to the evidence bundle JSON")
    verify_command.add_argument(
        "--trusted-service-keys",
        dest="trusted_service_keys",
        default=None,
        help="path to the independently provisioned §90 trust file",
    )

    export_command = subcommands.add_parser(
        "export", help="export an evidence bundle to an external receipt format"
    )
    export_command.add_argument(
        "--format", dest="format", required=True, choices=list(FORMATS),
        help="target receipt format",
    )
    export_command.add_argument("bundle_path", help="path to the evidence bundle JSON")
    export_command.add_argument(
        "--out", dest="out", default=None, help="artifact path (default: <stem>.<format>.json)"
    )
    export_command.add_argument(
        "--public-key-out", dest="public_key_out", default=None,
        help="SPKI PEM path for the signing public key (aerf only)",
    )
    export_command.add_argument(
        "--mapping", dest="mapping", default=None,
        help="operator mapping file; its presence selects full mode",
    )
    export_command.add_argument(
        "--force", dest="force", action="store_true", help="overwrite existing files"
    )
    export_command.add_argument(
        "--state-dir", dest="state_dir", default=None,
        help="local agent state directory holding identity.json",
    )
    export_command.add_argument(
        "--signing-key", dest="signing_key", default=None,
        help="file holding a base64url 32-byte Ed25519 seed",
    )

    rotate_command = subcommands.add_parser(
        "rotate-key",
        help="rotate an agent signing key (disabled in V1; planned for v0.2)",
    )
    rotate_command.add_argument("--agent", dest="agent", required=True, help="agent id")

    return parser


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _run_verify(arguments: argparse.Namespace) -> Result:
    try:
        bundle_text = _read_text(arguments.bundle_path)
    except OSError as exc:
        return Result(
            EXIT_UNVERIFIABLE,
            [_line("Evidence bundle", "UNKNOWN", f"cannot read bundle: {exc}")],
        )
    except UnicodeDecodeError as exc:
        return Result(
            EXIT_INVALID,
            [_line("Evidence bundle", "INVALID", f"bundle is not valid UTF-8: {exc}")],
        )

    trust_path = arguments.trusted_service_keys
    trust_text = None
    if trust_path is not None:
        try:
            trust_text = _read_text(trust_path)
        except OSError as exc:
            return Result(
                EXIT_UNVERIFIABLE,
                [
                    _line(
                        "Service receipt",
                        "UNKNOWN",
                        f"cannot read trusted-service-keys file: {exc}",
                    )
                ],
            )
        except UnicodeDecodeError as exc:
            return Result(
                EXIT_UNVERIFIABLE,
                [
                    _line(
                        "Service receipt",
                        "UNKNOWN",
                        f"trusted-service-keys file is not valid UTF-8: {exc}",
                    )
                ],
            )

    return verify_bundle(bundle_text, trust_text)


# --------------------------------------------------------------------------
# export (external receipt formats)
# --------------------------------------------------------------------------


def _read_for_export(path: str, what: str) -> str:
    try:
        return _read_text(path)
    except OSError as exc:
        raise ExportError(f"cannot read {what}: {exc}") from None
    except UnicodeDecodeError:
        raise ExportError(f"{what} is not valid UTF-8") from None


def _seed_from_file(path: str) -> bytes:
    text = _read_for_export(path, "signing key file")
    try:
        return b64url_decode(text.strip(), SEED_LENGTH)
    except ValueError as exc:
        raise ExportError(
            f"signing key file does not hold a base64url {SEED_LENGTH}-byte seed: {exc}"
        ) from None


def _seed_from_state_dir(path: str) -> bytes:
    """Read the active agent key under the §24 directory lock, changing nothing."""
    directory = Path(path)
    if not directory.is_dir():
        raise ExportError(f"state directory does not exist: {path}")
    lock = DirectoryLock(directory)
    try:
        lock.acquire()
    except Exception as exc:  # noqa: BLE001 - AuditFailure carries identity_in_use
        raise ExportError(f"cannot use {path}: {exc}") from None
    try:
        document = IdentityStore(directory).read()
    except Exception as exc:  # noqa: BLE001 - permissions, version, parse failures
        raise ExportError(f"cannot read the identity: {exc}") from None
    finally:
        lock.release()

    if document is None:
        raise ExportError(f"no identity file in {path}")
    active = document.get("active_key")
    if not isinstance(active, dict) or not isinstance(active.get("private_key"), str):
        raise ExportError("the identity holds no active key, so nothing can be signed")
    try:
        return b64url_decode(active["private_key"], SEED_LENGTH)
    except ValueError as exc:
        raise ExportError(f"the identity private key is unusable: {exc}") from None


def _export_seed(arguments: argparse.Namespace) -> bytes:
    if arguments.signing_key is not None:
        return _seed_from_file(arguments.signing_key)
    state_dir: str = arguments.state_dir
    return _seed_from_state_dir(state_dir)


def _json_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")


def _export_paths(
    arguments: argparse.Namespace, built: Export, seed: bytes
) -> list[tuple[str, Path, bytes]]:
    """The (kind, path, bytes) of everything this export writes."""
    source = Path(arguments.bundle_path)
    suffix = ARTIFACT_SUFFIX[arguments.format]
    out = (
        Path(arguments.out)
        if arguments.out is not None
        else source.with_name(f"{source.stem}.{suffix}.json")
    )
    targets: list[tuple[str, Path, bytes]] = [
        ("artifact", out, _json_bytes(built.artifact))
    ]
    if arguments.format == "aerf":
        pem = (
            Path(arguments.public_key_out)
            if arguments.public_key_out is not None
            else source.with_name(f"{source.stem}.{suffix}.pem")
        )
        targets.append(("public key", pem, export_module.public_key_pem(seed)))
    if built.companion is not None:
        targets.append(
            ("companion", Path(str(out) + ".sealstack.json"), _json_bytes(built.companion))
        )
    return targets


def _write_all(targets: list[tuple[str, Path, bytes]], force: bool) -> None:
    """Refuse the whole export before writing any of it (§22 spirit)."""
    for _, path, _payload in targets:
        if path.exists() and not force:
            raise ExportError(f"refusing to overwrite {path} without --force")
    for _, path, payload in targets:
        try:
            path.write_bytes(payload)
        except OSError as exc:
            raise ExportError(f"cannot write {path}: {exc}") from None


def _export_report(
    arguments: argparse.Namespace, built: Export, targets: list[tuple[str, Path, bytes]]
) -> list[str]:
    labels = built.labels
    lines = [f"format: {labels.format_line}", labels.mode_line]
    lines.extend(f"wrote: {path}" for kind, path, _ in targets if kind != "companion")
    lines.append(f"signing key: {labels.signing_key}")
    if labels.embedded_evidence:
        lines.append("native evidence: embedded in evidence")
    else:
        companion = next(path for kind, path, _ in targets if kind == "companion")
        lines.append(f"companion: {companion}")
    lines.append(f"chain: {labels.chain_line}")
    if arguments.format == "scitt":
        lines.append(export_module.NOA_ENVELOPE_LINE)
    lines.extend(f"note: {note}" for note in labels.notes)
    return lines


def _run_export(arguments: argparse.Namespace) -> tuple[int, list[str]]:
    """Export one bundle; 0 written, 1 bundle invalid, 2 usage/IO/mapping."""
    if (arguments.state_dir is None) == (arguments.signing_key is None):
        return EXIT_UNVERIFIABLE, [
            "export: exactly one of --state-dir or --signing-key is required"
        ]
    if arguments.public_key_out is not None and arguments.format != "aerf":
        return EXIT_UNVERIFIABLE, [
            "export: --public-key-out applies to --format aerf only"
        ]

    try:
        bundle_text = _read_for_export(arguments.bundle_path, "evidence bundle")
    except ExportError as exc:
        return EXIT_UNVERIFIABLE, [f"export: {exc}"]
    try:
        bundle = export_module.load_bundle(bundle_text)
    except ValueError as exc:
        return EXIT_INVALID, [f"export: evidence bundle is invalid: {exc}"]

    try:
        mapping = (
            None
            if arguments.mapping is None
            else export_module.load_mapping(
                _read_for_export(arguments.mapping, "mapping file")
            )
        )
        seed = _export_seed(arguments)
        built = BUILDERS[arguments.format](bundle, mapping, seed)
        targets = _export_paths(arguments, built, seed)
        _write_all(targets, arguments.force)
    except ExportError as exc:
        return EXIT_UNVERIFIABLE, [f"export: {exc}"]
    return EXIT_OK, _export_report(arguments, built, targets)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a §123 exit code.  Never raises."""
    try:
        parser = build_parser()
        try:
            arguments = parser.parse_args(argv)
        except SystemExit as exit_request:
            code = exit_request.code
            return EXIT_UNVERIFIABLE if code not in (0, None) else int(code or 0)

        if arguments.command == "verify":
            result = _run_verify(arguments)
            for line in result.lines:
                print(line)
            return result.exit_code

        if arguments.command == "export":
            code, lines = _run_export(arguments)
            for line in lines:
                print(line)
            return code

        if arguments.command == "rotate-key":
            print(
                "rotate-key: agent key rotation is not available in V1; it is "
                "planned for v0.2. The server-side key registration endpoint "
                "exists but the SDK/CLI rotation flow (SPEC §71–§77) is deferred."
            )
            return EXIT_UNVERIFIABLE

        parser.print_usage()
        print("no subcommand given")
        return EXIT_UNVERIFIABLE
    except Exception as exc:  # noqa: BLE001 - never let a traceback reach the operator
        print(_line("Evidence bundle", "UNKNOWN", f"verifier error: {exc!r}"))
        return EXIT_UNVERIFIABLE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
