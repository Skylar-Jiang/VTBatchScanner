"""Generate text manifests only. Sample bytes stay inside process memory."""

import argparse
import json
from pathlib import Path

from app.services.archive_inventory import inventory_zip
from app.services.inputs import preview_hashes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--hashes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    rows, errors = inventory_zip(arguments.archive.read_bytes(), b"virus")
    original_lines = [line for line in arguments.hashes.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    preview = preview_hashes(original_lines)
    unique_hashes = list(dict.fromkeys(str(row["sha256"]) for row in rows))
    manifest = {
        "method": "ZIP bytes read recursively in memory; no extraction or execution",
        "groupA": {
            "leafFiles": len(rows),
            "uniqueHashes": len(unique_hashes),
            "duplicateFiles": len(rows) - len(unique_hashes),
            "files": rows,
            "errors": errors,
            "selectionConfirmed": False,
        },
        "groupB": {
            "total": len(original_lines),
            "valid": len(preview.valid_sha256s),
            "duplicates": len(preview.duplicates),
            "invalid": len(preview.invalid),
        },
    }
    arguments.output.mkdir(parents=True, exist_ok=True)
    (arguments.output / "input-inventory.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (arguments.output / "group-b-sha256.txt").write_text("\n".join(preview.valid_sha256s) + "\n", encoding="utf-8")
    (arguments.output / "group-a-candidate-sha256.txt").write_text("\n".join(unique_hashes) + "\n", encoding="utf-8")
    print(json.dumps({"leafFiles": len(rows), "uniqueHashes": len(unique_hashes), "archiveErrors": len(errors), "groupBValid": len(preview.valid_sha256s)}))


if __name__ == "__main__":
    main()
