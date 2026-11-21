"""Generate the reproducible synthetic datasets into data/.

Usage:
    python scripts/generate_data.py [--data-dir data]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.synth.generator import generate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SENTINEL AI synthetic datasets")
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    args = parser.parse_args()
    summary = generate(args.data_dir)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
