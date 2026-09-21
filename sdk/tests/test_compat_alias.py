"""``product`` is an alias of ``sealstack``, not a copy of it.

Before 0.1.3 the distribution published the ``product`` import name and the
``product`` console script.  Both still work.  What these tests pin down is
that they resolve to the *same* objects: a test or a caller that patches
``sealstack.uploader.httpx`` must see the change through ``product.uploader``,
and both console scripts must run the one ``main``.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import subprocess
import sys
from pathlib import Path

import pytest
import sealstack

#: Every module aliased under ``product.``.
MODULES = (
    "cli",
    "client",
    "decorator",
    "events",
    "export",
    "identity",
    "queue",
    "signing",
    "uploader",
    "verify",
)

#: Directory holding the ``sealstack`` and ``product`` packages.
SDK_DIR = str(Path(sealstack.__file__).resolve().parent.parent)


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *arguments],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
        env={"PYTHONPATH": SDK_DIR, "PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
    )


def test_top_level_names_are_the_same_objects() -> None:
    import product
    from product import AuditClient, AuditFailure

    assert AuditClient is sealstack.AuditClient
    assert AuditFailure is sealstack.AuditFailure
    assert product.AuditClient is sealstack.AuditClient


def test_from_submodule_import_is_the_same_object() -> None:
    from product.client import AuditClient
    from product.export import build_aerf
    from product.verify import verify_bundle

    assert AuditClient is sealstack.client.AuditClient
    assert build_aerf is sealstack.export.build_aerf
    assert verify_bundle is sealstack.verify.verify_bundle


def test_import_submodule_as_is_the_same_module() -> None:
    import product.queue as queue  # noqa: PLR0402
    import product.signing as signing  # noqa: PLR0402

    assert signing is sealstack.signing
    assert queue is sealstack.queue


@pytest.mark.parametrize("name", MODULES)
def test_every_module_is_one_module(name: str) -> None:
    real = importlib.import_module(f"sealstack.{name}")
    assert importlib.import_module(f"product.{name}") is real
    assert sys.modules[f"product.{name}"] is real


def test_patching_through_one_name_is_visible_through_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The acceptance suite patches ``product.uploader``; the SDK reads ``sealstack``."""
    sentinel = object()
    monkeypatch.setattr(sealstack.uploader, "httpx", sentinel)
    uploader = importlib.import_module("product.uploader")
    assert uploader.httpx is sentinel


def test_unknown_submodule_still_fails() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("product.not_a_module")
    with pytest.raises(AttributeError):
        _ = importlib.import_module("product").not_an_attribute


def test_both_console_scripts_are_declared() -> None:
    try:
        importlib.metadata.distribution("sealstack")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("sealstack is not installed as a distribution in this environment")
    scripts = {
        entry.name: entry.value
        for entry in importlib.metadata.entry_points(group="console_scripts")
        if entry.name in {"sealstack", "product"}
    }
    assert scripts == {"sealstack": "sealstack.cli:main", "product": "sealstack.cli:main"}


def test_module_entry_points_run() -> None:
    for module in ("sealstack.cli", "product.cli"):
        result = _run("-m", module, "--help")
        assert result.returncode == 0, result.stderr
        assert result.stdout.startswith("usage: sealstack "), result.stdout


def test_program_name_is_sealstack() -> None:
    assert sealstack.cli.build_parser().prog == "sealstack"
