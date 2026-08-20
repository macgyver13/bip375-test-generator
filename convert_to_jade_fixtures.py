#!/usr/bin/env python3
"""Write Jade's BIP-375 device fixtures from a vector file built with --include jade.

Jade's device test globs psbt_sp_375_*.json in its test_data directory and loads one
case per file. Each fixture carries the case id, the base64 PSBT, the expected
validation result and, for accepted cases, the output scripts or contribution the
device should produce. Only vectors labeled jade are written.
"""

import argparse
import json
from pathlib import Path


def fixtures(vectors):
    for section in ("valid", "invalid"):
        for vector in vectors[section]:
            jade = vector.get("jade")
            if jade is None:
                continue
            fixture = {
                "id": jade["id"],
                "description": vector["description"],
                "input": {"network": "localtest", "psbt": vector["psbt"]},
                "validation_result": section,
            }
            for key in ("expected_contribution", "expected_scripts"):
                if key in jade:
                    fixture[key] = jade[key]
            yield jade["fixture"], fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("vectors", type=Path, help="vector file generated with --include jade")
    parser.add_argument("-o", "--output-dir", type=Path, required=True)
    args = parser.parse_args()

    vectors = json.loads(args.vectors.read_text())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for name, fixture in fixtures(vectors):
        with open(args.output_dir / f"psbt_sp_375_{name}.json", "w") as f:
            json.dump(fixture, f, indent=2)
            f.write("\n")
        count += 1
    print(f"Wrote {count} Jade fixtures to {args.output_dir}")


if __name__ == "__main__":
    main()
