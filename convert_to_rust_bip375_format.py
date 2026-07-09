#!/usr/bin/env python3
"""
Convert bip375_test_vectors.json to the bip375.json format used by rust-psbt.

Transformation rules:
- Combine 'valid', 'invalid', synthesized, and 'workflows' entries into a flat 'cases' array
- Each entry gets: description (valid/invalid prefixed "valid: " or "invalid: "), version (hardcoded 2), supplementary.task, supplementary.psbts
- The PSBT base64 string moves from the top-level 'psbt' field into supplementary.psbts[0].base64
- Source expected.psbt, when present, moves to top-level expected.base64/expected.hex
- Workflow expected.tx/transaction_id, when present, are carried into top-level expected
- Workflow inputs/outputs, when present, are converted to rust-psbt-friendly OutPoint/TxOut shapes
- Workflow sign entries also carry signing_keys and sp_proofs, so the Signer role can be
  replayed: rust-psbt implements neither BIP-374 (DLEQ) nor BIP-352 (output derivation), so the
  shares, proofs and output scripts have to be supplied as data rather than derived
- Signing keys are re-encoded from raw hex to testnet WIF, the form rust-psbt's PrivateKey
  deserializes natively
- supplementary.task is carried through from the source
- All other supplementary data is dropped
"""

import argparse
import base64
import hashlib
import json
import sys


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Testnet WIF, matching the keys already used by the rust-psbt BIP-174 vectors.
WIF_PREFIX = 0xEF


def base58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58_ALPHABET[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def to_wif(secret_hex: str) -> str:
    """Encode a raw 32-byte secret key as a compressed WIF string."""
    return base58check(bytes([WIF_PREFIX]) + bytes.fromhex(secret_hex) + b"\x01")


SYNTHESIZED_CASES = [
    {
        "description": "Invalid: psbt structure: duplicate PSBT_GLOBAL_SP_ECDH_SHARE with same scan key",
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
        "description": "Invalid: psbt structure: duplicate PSBT_IN_SP_ECDH_SHARE with same scan key",
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

    def add_workflow_supplementary(case: dict, entry: dict) -> None:
        if case["supplementary"]["task"] == "update":
            input_updates = [
                workflow_input_update(row)
                for row in entry["supplementary"].get("inputs", [])
                if "non_witness_utxo" in row and "public_key" in row
            ]
            if input_updates:
                case["supplementary"]["input_updates"] = input_updates
            return

        if case["supplementary"]["task"] == "sign":
            signing_keys = [
                to_wif(row["private_key"])
                for row in entry["supplementary"].get("inputs", [])
                if row.get("private_key")
            ]
            if signing_keys:
                case["supplementary"]["signing_keys"] = signing_keys

            sp_proofs = [
                workflow_sp_proof(row) for row in entry["supplementary"].get("sp_proofs", [])
            ]
            if sp_proofs:
                case["supplementary"]["sp_proofs"] = sp_proofs

        inputs = [
            f"{row['prevout_txid']}:{row['prevout_index']}"
            for row in entry["supplementary"].get("inputs", [])
            if "prevout_txid" in row and "prevout_index" in row
        ]
        if inputs:
            case["supplementary"]["inputs"] = inputs

        outputs = [
            workflow_output(row)
            for row in entry["supplementary"].get("outputs", [])
            if "amount" in row
        ]
        if outputs:
            case["supplementary"]["outputs"] = outputs

    def workflow_input_update(row: dict) -> dict:
        return {
            "previous_tx": row["non_witness_utxo"],
            "witness": True,
            "bip32_derivation": [{"key": row["public_key"]}],
        }

    def workflow_sp_proof(row: dict) -> dict:
        proof = {
            "scan_key": row["scan_key"],
            "ecdh_share": row["ecdh_share"],
            "dleq_proof": row["dleq_proof"],
        }
        if "input_index" in row:
            proof["input_index"] = row["input_index"]
        return proof

    def workflow_output(row: dict) -> dict:
        output = {"value": row["amount"]}
        if "sp_v0_info" in row:
            output["sp_v0_info"] = row["sp_v0_info"]
        if "sp_v0_label" in row:
            output["sp_v0_label"] = row["sp_v0_label"]
        if "script" in row:
            output["script_pubkey"] = row["script"]
        return output

    def convert_entry(entry: dict, prefix: str = "", *, workflow: bool = False) -> dict:
        case = {
            "description": prefix + entry["description"],
            "version": 2,
            "supplementary": {
                "task": entry["supplementary"]["task"],
                "psbts": [{"base64": entry["psbt"], "hex": entry["supplementary"].get("hex", "")}],
            },
        }
        if case["supplementary"]["psbts"][0]["hex"] == "" and entry["psbt"] != "":
            case["supplementary"]["psbts"][0]["hex"] = base64.b64decode(entry["psbt"]).hex()
        if "expected" in entry and "psbt" in entry["expected"]:
            expected_base64 = entry["expected"]["psbt"]
            case["expected"] = {
                "base64": expected_base64,
                "hex": base64.b64decode(expected_base64).hex(),
            }
            if "transaction_id" in entry["expected"]:
                case["expected"]["transaction_id"] = entry["expected"]["transaction_id"]
            if "tx" in entry["expected"]:
                case["expected"]["tx"] = entry["expected"]["tx"]
        if workflow:
            add_workflow_supplementary(case, entry)
        return case

    cases = []
    for section in ("Valid", "Invalid"):
        for entry in src.get(section, []):
            cases.append(convert_entry(entry, f"{section}: "))
    cases.extend(SYNTHESIZED_CASES)
    for entry in src.get("workflows", []):
        cases.append(convert_entry(entry, workflow=True))
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
