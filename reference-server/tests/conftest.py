"""Put ``reference-server/`` on the import path so ``server`` resolves."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
