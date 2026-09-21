"""Compatibility alias for the pre-0.1.3 import name of this SDK.

The package is ``sealstack``.  Before 0.1.3 it was imported as ``product``, so
that name keeps working and is not going away: ``from product import
AuditClient``, ``from product.client import AuditClient`` and
``import product.signing`` all resolve to the very same module, class and
function objects as their ``sealstack`` spellings.  New code should import
``sealstack``.

Identity is the point.  The modules listed in :data:`_ALIASED` are registered
in :data:`sys.modules` under their ``product.`` names rather than re-imported,
so patching ``sealstack.uploader.httpx`` is visible through
``product.uploader.httpx`` and the reverse.  ``cli`` is the one exception: it
is also a real file next to this one, so that ``python -m product.cli`` still
runs.  Importing it substitutes :mod:`sealstack.cli` for itself, so identity
holds there too.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from sealstack import AuditClient, AuditFailure, cli

#: Modules of the ``sealstack`` package aliased into :data:`sys.modules` under
#: ``product.``.  ``cli`` is deliberately absent; see the module docstring.
_ALIASED = (
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

__all__ = [
    "AuditClient",
    "AuditFailure",
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
]

#: Only ``product/cli.py`` is ever found here; every other ``product.<name>``
#: resolves through the :data:`sys.modules` entries registered below.
__path__: list[str] = [str(Path(__file__).resolve().parent)]

for _name in _ALIASED:
    _module: ModuleType = importlib.import_module(f"sealstack.{_name}")
    sys.modules[f"{__name__}.{_name}"] = _module
    globals()[_name] = _module
del _name, _module


def __getattr__(name: str) -> Any:
    """Resolve any remaining public name against :mod:`sealstack`."""
    try:
        return getattr(sys.modules["sealstack"], name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(sys.modules["sealstack"])))
