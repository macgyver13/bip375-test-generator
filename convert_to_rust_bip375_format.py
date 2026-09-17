#!/usr/bin/env python3
"""
Convert bip375_test_vectors.json to the bip375.json format used by rust-psbt.

Transformation rules:
- Combine 'valid', 'invalid', synthesized, and 'workflows' entries into a flat 'cases' array
- Each entry gets description (valid/invalid prefixed "Valid: " or "Invalid: "), version
  (hardcoded 2), and a task object keyed by the source supplementary.task
- Each task payload carries the input psbt and expected result as base64 objects, without hex.
  Create has only expected; extract carries psbt, tx, and transaction_id instead of expected
- Workflow inputs/outputs, when present, are converted to rust-psbt-friendly OutPoint/TxOut shapes
- Workflow sign entries also carry signing_keys and sp_proofs, so the Signer role can be
  replayed: rust-psbt implements neither BIP-374 (DLEQ) nor BIP-352 (output derivation), so the
  shares, proofs and output scripts have to be supplied as data rather than derived
- A one-shot (non-workflow) sign-task entry gets the same treatment when its held-key inputs
  are all already signed, or when its expected.psbt differs from its psbt (the signer adds
  something), reading signing_keys/sp_proofs/outputs straight from its own supplementary (not
  trimmed like a workflow step, so nothing needs deriving from the psbt). A verify-and-hold
  snapshot (expected.psbt equals psbt, some held-key input unsigned) is left alone.
- Sign and extract entries' sp_proofs and outputs[].script_pubkey are parsed from
  expected.psbt (the generator no longer publishes them as supplementary, since they are
  derivable from the psbt bytes); output amount/label come from that scenario's create entry,
  which still carries them, since spdk_psbt exposes no output-amount getter
- Signing keys are re-encoded from raw hex to testnet WIF, the form rust-psbt's PrivateKey
  deserializes natively
- All other supplementary data is dropped
"""

import argparse
import base64
import hashlib
import json
import sys

from spdk_psbt import SilentPaymentPsbt


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
        "task": {
            "fail_deserialize": {
                "psbt": {
                    "base64": "cHNidP8B+wQCAAAAAQIEAgAAAAEEAQABBQEAAQYBACIHAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICIQQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBCIHAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICIQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBSIIAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICQKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqoA"
                }
            }
        }
    },
    {
        "description": "Invalid: psbt structure: duplicate PSBT_IN_SP_ECDH_SHARE with same scan key",
        "version": 2,
        "task": {
            "fail_deserialize": {
                "psbt": {
                    "base64": "cHNidP8B+wQCAAAAAQIEAgAAAAEEAQEBBQEAAQYBAAABDiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEPBAAAAAAiHQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiEEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQiHQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUiHgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkCqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAA=="
                }
            }
        }
    }
]


def convert(src: dict) -> dict:

    def scenario_key(description: str) -> str:
        return description.split(":", 1)[0]

    # create still carries amount/sp_v0_info/sp_v0_label unchanged (the generator
    # never trims it); sign and extract no longer do, so their output rows are
    # rebuilt from the psbt itself plus this scenario-level amount/label lookup.
    create_outputs_by_scenario = {
        scenario_key(entry["description"]): {
            row["output_index"]: row for row in entry["supplementary"].get("outputs", [])
        }
        for entry in src.get("workflows", [])
        if entry["supplementary"].get("task") == "create"
    }

    def add_workflow_supplementary(payload: dict, entry: dict) -> None:
        task = entry["supplementary"]["task"]

        if task == "update":
            input_updates = [
                workflow_input_update(row)
                for row in entry["supplementary"].get("inputs", [])
                if "non_witness_utxo" in row and "public_key" in row
            ]
            payload["input_updates"] = input_updates
            payload["output_updates"] = []
            return

        psbt = None
        if "expected" in entry and "psbt" in entry["expected"]:
            psbt = SilentPaymentPsbt.deserialize(base64.b64decode(entry["expected"]["psbt"]))

        if task == "sign":
            signing_keys = [
                to_wif(row["private_key"])
                for row in entry["supplementary"].get("inputs", [])
                if row.get("private_key")
            ]
            if signing_keys:
                payload["signing_keys"] = signing_keys

            sp_proofs = derive_sp_proofs(psbt) if psbt is not None else []
            if sp_proofs:
                payload["sp_proofs"] = sp_proofs

        inputs = [
            f"{row['prevout_txid']}:{row['prevout_index']}"
            for row in entry["supplementary"].get("inputs", [])
            if "prevout_txid" in row and "prevout_index" in row
        ]
        if inputs:
            payload["inputs"] = inputs

        if task in ("sign", "extract") and psbt is not None:
            outputs = derive_outputs(psbt, create_outputs_by_scenario.get(scenario_key(entry["description"]), {}))
        else:
            outputs = [
                workflow_output(row)
                for row in entry["supplementary"].get("outputs", [])
                if "amount" in row
            ]
        if outputs:
            payload["outputs"] = outputs

    def workflow_input_update(row: dict) -> dict:
        return {
            "previous_tx": row["non_witness_utxo"],
            "witness": True,
            "bip32_derivation": [{"key": row["public_key"]}],
        }

    def derive_sp_proofs(psbt: SilentPaymentPsbt) -> list:
        """Every ECDH share the psbt actually carries at this step, global then per-input."""
        proofs = [
            {
                "scan_key": share.scan_key.hex(),
                "ecdh_share": share.share_point.hex(),
                "dleq_proof": share.dleq_proof.hex(),
            }
            for share in psbt.get_global_ecdh_shares()
        ]
        for input_index in range(psbt.num_inputs()):
            for share in psbt.get_input_ecdh_shares(input_index):
                proofs.append({
                    "scan_key": share.scan_key.hex(),
                    "ecdh_share": share.share_point.hex(),
                    "dleq_proof": share.dleq_proof.hex(),
                    "input_index": input_index,
                })
        return proofs

    def derive_outputs(psbt: SilentPaymentPsbt, amounts_by_index: dict) -> list:
        outputs = []
        for output_index in range(psbt.num_outputs()):
            row = amounts_by_index.get(output_index)
            if row is None or "amount" not in row:
                continue
            output = {"value": row["amount"]}
            address = psbt.get_output_sp_address(output_index)
            if address is not None:
                output["sp_v0_info"] = (address.scan_key + address.spend_key).hex()
                if "sp_v0_label" in row:
                    output["sp_v0_label"] = row["sp_v0_label"]
            script = psbt.get_output_script(output_index)
            if script:
                output["script_pubkey"] = script.hex()
            outputs.append(output)
        return outputs

    def workflow_output(row: dict) -> dict:
        output = {"value": row["amount"]}
        if "sp_v0_info" in row:
            output["sp_v0_info"] = row["sp_v0_info"]
        if "sp_v0_label" in row:
            output["sp_v0_label"] = row["sp_v0_label"]
        if "script" in row:
            output["script_pubkey"] = row["script"]
        return output

    def is_drivable_one_shot_sign(entry: dict) -> bool:
        """True for a one-shot (non-workflow) sign-task vector the Signer role can
        replay: it holds a key, and either every held-key input is already signed
        in the source PSBT or expected.psbt shows the signer adding something. A
        verify-and-hold snapshot (expected.psbt equals psbt) is not."""
        supp = entry["supplementary"]
        if supp.get("task") != "sign":
            return False
        held_inputs = [row for row in supp.get("inputs", []) if row.get("private_key")]
        if not held_inputs:
            return False
        if all(row.get("signed") for row in held_inputs):
            return True
        expected = entry.get("expected", {}).get("psbt")
        return expected is not None and expected != entry["psbt"]

    def add_one_shot_sign_supplementary(payload: dict, entry: dict) -> None:
        """Unlike a workflow sign step, a one-shot sign-task vector is not
        trimmed by G3: its own supplementary already carries the signing key,
        the ECDH shares/proofs and the output scripts directly, so they can be
        passed through rather than derived from expected.psbt."""
        supp = entry["supplementary"]
        signing_keys = [
            to_wif(row["private_key"]) for row in supp.get("inputs", []) if row.get("private_key")
        ]
        if signing_keys:
            payload["signing_keys"] = signing_keys
        sp_proofs = supp.get("sp_proofs", [])
        if sp_proofs:
            payload["sp_proofs"] = sp_proofs
        outputs = [workflow_output(row) for row in supp.get("outputs", []) if "amount" in row]
        if outputs:
            payload["outputs"] = outputs

    def convert_entry(entry: dict, prefix: str = "", *, workflow: bool = False) -> dict:
        task = entry["supplementary"]["task"]
        payload = {}
        if task != "create":
            payload["psbt"] = {"base64": entry["psbt"]}
        if task == "extract" and "psbt" in entry.get("expected", {}):
            payload["tx"] = entry["expected"]["tx"]
        if workflow:
            add_workflow_supplementary(payload, entry)
        elif is_drivable_one_shot_sign(entry):
            add_one_shot_sign_supplementary(payload, entry)
        if "expected" in entry and "psbt" in entry["expected"]:
            expected = {"base64": entry["expected"]["psbt"]}
            if "transaction_id" in entry["expected"]:
                expected["transaction_id"] = entry["expected"]["transaction_id"]
            if task == "extract":
                if "transaction_id" in expected:
                    payload["transaction_id"] = expected["transaction_id"]
            else:
                payload["expected"] = expected
        case = {
            "description": prefix + entry["description"],
            "version": 2,
            "task": {task: payload},
        }
        return case

    cases = []
    for section, prefix in (("valid", "Valid: "), ("invalid", "Invalid: ")):
        for entry in src.get(section, []):
            cases.append(convert_entry(entry, prefix))
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
