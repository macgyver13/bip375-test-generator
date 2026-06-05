#!/usr/bin/env python3
"""
Convert bip375_test_vectors.json to the bip375.json format used by rust-psbt.

Transformation rules:
- Combine 'valid' and 'invalid' arrays (valid first) into a flat 'cases' array
- Each entry gets: description, version (hardcoded 2), supplementary.task, supplementary.psbts
- The PSBT base64 string moves from the top-level 'psbt' field into supplementary.psbts[0].base64
- supplementary.task is carried through from the source
- All other supplementary data (inputs, outputs, sp_proofs) is dropped
"""

import argparse
import json
import sys


SYNTHESIZED_CASES = [
    {
        "description": "psbt structure: duplicate PSBT_GLOBAL_SP_ECDH_SHARE with same scan key",
        "version": 2,
        "supplementary": {
            "task": "fail_deserialize",
            "psbts": [
                {
                    "base64": "",
                    "hex": "70736274ff01fb040200000001020402000000010401000105010001060100220702020202020202020202020202020202020202020202020202020202020202020221040404040404040404040404040404040404040404040404040404040404040404220702020202020202020202020202020202020202020202020202020202020202020221050505050505050505050505050505050505050505050505050505050505050505220802020202020202020202020202020202020202020202020202020202020202020240aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00",
                }
            ],
        },
    },
    {
        "description": "psbt structure: duplicate PSBT_IN_SP_ECDH_SHARE with same scan key",
        "version": 2,
        "supplementary": {
            "task": "fail_deserialize",
            "psbts": [
                {
                    "base64": "",
                    "hex": "70736274ff01fb04020000000102040200000001040101010501000106010000010e200000000000000000000000000000000000000000000000000000000000000000010f0400000000221d02020202020202020202020202020202020202020202020202020202020202020221040404040404040404040404040404040404040404040404040404040404040404221d02020202020202020202020202020202020202020202020202020202020202020221050505050505050505050505050505050505050505050505050505050505050505221e02020202020202020202020202020202020202020202020202020202020202020240aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00",
                }
            ],
        },
    },
]


def convert(src: dict) -> dict:
    cases = []
    for entry in src.get("valid", []) + src.get("invalid", []):
        cases.append(
            {
                "description": entry["description"],
                "version": 2,
                "supplementary": {
                    "task": entry["supplementary"]["task"],
                    "psbts": [{"base64": entry["psbt"], "hex": entry["supplementary"].get("hex", "")}],
                },
            }
        )
    cases.extend(SYNTHESIZED_CASES)
    return {"cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        default="bip375_test_vectors.json",
        help="Source JSON file (default: bip375_test_vectors.json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output file path (default: stdout)",
    )
    args = parser.parse_args()

    with open(args.input) as f:
        src = json.load(f)

    result = convert(src)

    output_text = json.dumps(result, indent=2) + "\n"

    if args.output == "-":
        sys.stdout.write(output_text)
    else:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"Written {len(result['cases'])} cases to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
