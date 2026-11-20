#!/usr/bin/env python3
"""Run the signer test suite with a clear environment report."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from redpen_signing.minisign import MinisignError, find_minisign, minisign_version  # noqa: E402


def main() -> int:
    try:
        binary = find_minisign()
        print(f"minisign: {binary} ({minisign_version(binary)})")
    except MinisignError as exc:
        print(f"minisign: unavailable ({exc}); crypto tests will be skipped")

    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"), pattern="test_*.py", top_level_dir=str(ROOT)
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
