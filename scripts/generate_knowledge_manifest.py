"""Generate the knowledge-corpus integrity manifest.

Usage:
    python scripts/generate_knowledge_manifest.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "data" / "knowledge"


def main() -> int:
    files: dict[str, str] = {}
    for path in sorted(KNOWLEDGE.rglob("*.md")):
        relative = path.relative_to(KNOWLEDGE).as_posix()
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "schema_version": "1.0",
        "corpus": "sentinel-security-knowledge",
        "files": files,
    }
    target = KNOWLEDGE / "manifest.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {target} ({len(files)} documents)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
