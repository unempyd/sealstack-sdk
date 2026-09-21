"""Compatibility alias for ``product.cli``; the module is :mod:`sealstack.cli`.

This file exists so that ``python -m product.cli`` keeps working.  Imported
normally it substitutes :mod:`sealstack.cli` for itself, so ``product.cli`` and
``sealstack.cli`` are one module object and ``main`` is one function.
"""

import sys

import sealstack.cli
from sealstack.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

sys.modules[__name__] = sealstack.cli
