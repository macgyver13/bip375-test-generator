#!/usr/bin/env python3
"""
BIP-375 Test Vector Generator

Configuration-driven system for generating test vectors with support for large PSBTs.
Organized by validation type → input/output type → complexity.
"""

import base64
from dataclasses import dataclass
from enum import Enum
import json
import hashlib
import os
from pathlib import Path
import struct
import sys
from typing import Dict, List, Optional, Any, Tuple
import yaml

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secp256k1 import GE, G
import spdk_psbt
from spdk_psbt import (
    add_raw_global_field, 
    add_raw_input_field, 
    add_raw_output_field, 
    remove_raw_input_fields_by_type, 
    SilentPaymentPsbt
)

from generator_utils import (
    PSBTKeyType,
    PrivateKey,
    PublicKey,
    Wallet,
    UTXO,
    create_witness_utxo,
    compute_bip352_output_script,
    apply_label_to_spend_key,
    sign_p2wpkh_input,
)


def _deterministic_hash(s: str) -> int:
    """Deterministic hash that is stable across Python sessions (unlike hash())."""
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:4], "big") % 1000

NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

# ============================================================================
# Pure PSBT helper functions
# ============================================================================


def _create_psbt(num_inputs: int, num_outputs: int, *, tx_modifiable: bool = False) -> SilentPaymentPsbt:
    """Create a PSBT v2 with the given number of inputs/outputs.

    Uses the Rust SilentPaymentPsbt.create() which sets standard global fields
    (VERSION, TX_VERSION, INPUT_COUNT, OUTPUT_COUNT, TX_MODIFIABLE), then
    overrides TX_MODIFIABLE to match the test scenario.
    """
    psbt = SilentPaymentPsbt.create(num_inputs, num_outputs)
    psbt.set_tx_modifiable(0x01 if tx_modifiable else 0x00)
    return psbt


def _make_raw_p2wpkh_input(
    pub_key,
    prevout_seed: str,
    amount: int = 50000,
    sequence: int = 0xFFFFFFFE,
) -> Dict[str, Any]:
    """Build a raw P2WPKH input info dict (prevout, witness script, witness UTXO)."""
    prevout_txid = hashlib.sha256(prevout_seed.encode()).digest()
    witness_script = bytes([0x00, 0x14]) + hashlib.sha256(pub_key.bytes).digest()[:20]
    witness_utxo = create_witness_utxo(amount, witness_script)
    return {
        "prevout_txid": prevout_txid,
        "witness_script": witness_script,
        "witness_utxo": witness_utxo,
        "amount": amount,
        "sequence": sequence,
    }


def _add_raw_p2wpkh_input_to_psbt(
    psbt: SilentPaymentPsbt,
    input_index: int,
    input_info: Dict[str, Any],
    pub_key,
    sighash_type: Optional[int] = None,
) -> None:
    """Add the standard P2WPKH input fields to a PSBT from an input_info dict.

    Optionally appends PSBT_IN_SIGHASH_TYPE.
    """
    add_raw_input_field(
        psbt, input_index, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", input_info["prevout_txid"]
    )
    add_raw_input_field(
        psbt, input_index, PSBTKeyType.PSBT_IN_OUTPUT_INDEX, b"", struct.pack("<I", 0)
    )
    add_raw_input_field(
        psbt, input_index, PSBTKeyType.PSBT_IN_SEQUENCE, b"", struct.pack("<I", input_info["sequence"])
    )
    add_raw_input_field(
        psbt, input_index, PSBTKeyType.PSBT_IN_WITNESS_UTXO, b"", input_info["witness_utxo"]
    )
    fake_derivation = struct.pack("<I", 0x80000000) + struct.pack("<I", input_index)
    add_raw_input_field(
        psbt, input_index, PSBTKeyType.PSBT_IN_BIP32_DERIVATION, pub_key.bytes, fake_derivation
    )
    if sighash_type is not None:
        add_raw_input_field(
            psbt, input_index, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", sighash_type)
        )


def _make_input_key_entry(
    input_index: int,
    priv_key,
    pub_key,
    input_info: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a test-vector input_keys entry dict with hex-encoded values."""
    return {
        "input_index": input_index,
        "private_key": priv_key.hex,
        "public_key": pub_key.hex,
        "prevout_txid": input_info["prevout_txid"].hex(),
        "prevout_index": 0,
        "prevout_scriptpubkey": input_info["witness_script"].hex(),
        "amount": input_info["amount"],
        "witness_utxo": input_info["witness_utxo"].hex(),
        "sequence": input_info["sequence"],
    }


def _sorted_outpoints_and_input_map(
    eligible_inputs: List[Dict],
) -> tuple:
    """Sort outpoints lexicographically (BIP-352 requirement) and build an index map.

    Returns (sorted_outpoints, outpoint_to_input) where each outpoint is a
    (txid_bytes, vout_int) tuple sorted by (txid, vout).
    """
    outpoints = [(inp["prevout_txid"], inp["prevout_index"]) for inp in eligible_inputs]
    outpoints.sort(key=lambda x: (x[0], x[1]))
    outpoint_to_input = {
        (inp["prevout_txid"], inp["prevout_index"]): inp for inp in eligible_inputs
    }
    return outpoints, outpoint_to_input


def _sum_pubkeys_in_outpoint_order(
    outpoints: List[tuple],
    outpoint_to_input: Dict,
):
    """Sum input public keys in sorted outpoint order (BIP-352 requirement)."""
    summed = None
    for outpoint in outpoints:
        pk = outpoint_to_input[outpoint]["public_key"]
        summed = pk if summed is None else summed + pk
    return summed


def _sum_ecdh_shares_for_scan_key(
    outpoints: List[tuple],
    outpoint_to_input: Dict,
    ecdh_data: Dict,
    scan_key_id: str,
) -> tuple:
    """Sum ECDH shares for one scan key in sorted outpoint order.

    Returns (summed_ecdh_point_or_None, coverage_complete) where
    coverage_complete is True only when every outpoint contributed a share.
    """
    inputs_with_ecdh: set = set()
    summed = None
    for outpoint in outpoints:
        inp = outpoint_to_input[outpoint]
        ecdh_key = (inp["input_index"], scan_key_id)
        if ecdh_key in ecdh_data:
            ecdh_result, _ = ecdh_data[ecdh_key]
            inputs_with_ecdh.add(inp["input_index"])
            summed = ecdh_result if summed is None else summed + ecdh_result
    return summed, len(inputs_with_ecdh) == len(outpoints)


# ============================================================================
# Core Data Structures
# ============================================================================


class InputType(Enum):
    P2WPKH = "p2wpkh"
    P2PKH = "p2pkh"
    P2SH_P2WPKH = "p2sh_p2wpkh"
    P2SH_MULTISIG = "p2sh_multisig"
    P2WSH_MULTISIG = "p2wsh_multisig"
    P2TR = "p2tr"


class OutputType(Enum):
    SILENT_PAYMENT = "silent_payment"
    REGULAR_P2TR = "regular_p2tr"
    REGULAR_P2WPKH = "regular_p2wpkh"


class ValidationResult(Enum):
    VALID = "valid"
    INVALID = "invalid"


@dataclass
class InputSpec:
    """Specification for creating a PSBT input"""

    input_type: InputType
    amount: int
    sequence: int = 0xFFFFFFFE
    # Type-specific parameters
    use_segwit_v2: bool = False
    multisig_threshold: Optional[int] = None
    multisig_pubkey_count: Optional[int] = None
    key_derivation_suffix: str = ""  # For deterministic key generation
    use_nums_tap_internal_key: bool = False  # For testing taproot internal key
    eligible_override: Optional[bool] = None  # Force is_eligible regardless of input type


@dataclass
class OutputSpec:
    """Specification for creating a PSBT output"""

    output_type: OutputType
    amount: int
    # Silent payment specific
    scan_key_id: Optional[str] = None  # References scan key from scenario
    spend_key_id: Optional[str] = None
    label: Optional[int] = None
    force_wrong_script: bool = False  # For testing wrong addresses
    force_k_index: Optional[int] = None
    spend_derivation_suffix: Optional[str] = None  # Override spend key per output
    # Regular output specific
    add_bip32_derivation: bool = (
        False  # Add PSBT_OUT_BIP32_DERIVATION for change identification
    )


@dataclass
class ScanKeySpec:
    """Specification for a scan/spend key pair"""

    key_id: str
    derivation_suffix: str = ""  # For deterministic generation


@dataclass
class TestScenario:
    """Complete specification for a test case"""

    description: str
    validation_result: ValidationResult
    inputs: List[InputSpec]
    outputs: List[OutputSpec]
    scan_keys: List[ScanKeySpec]
    # List of explicit validation checks to perform - all checks will be performed if empty
    #  (e.g. ["psbt_structure", "ecdh_coverage", "input_eligibility", "output_scripts"])
    checks: List[str]

    # control override for invalid tests
    missing_dleq_for_input: Optional[int] = None
    invalid_dleq_for_input: Optional[int] = None
    no_sighash_for_input: Optional[int] = None
    wrong_sighash_for_input: Optional[int] = None
    missing_ecdh_for_input: Optional[int] = None
    wrong_sp_info_size: bool = False
    missing_global_dleq: bool = False
    use_global_ecdh: Optional[List[str]] = (
        None  # list of scan key IDs to use global ECDH
    )
    use_segwit_v2_input: bool = False
    set_tx_modifiable: bool = False
    missing_sp_info_field: bool = False
    wrong_ecdh_share_size: bool = False
    wrong_dleq_proof_size: bool = False
    missing_ecdh_for_scan_key: Optional[str] = None
    missing_dleq_for_scan_key: Optional[str] = None
    invalid_dleq_for_scan_key: Optional[str] = None
    inject_ineligible_ecdh: bool = False
    force_output_script: bool = False
    strip_input_pubkeys_for_input: Optional[int] = None
    invalid_global_dleq: bool = False
    missing_ecdh_for_input_scan_key: Optional[tuple] = None  # (input_index, scan_key_id)
    force_partial_ecdh_output_script: bool = False
    skip_regular_output_script: bool = False


# ============================================================================
# Specialized Input Factories
# ============================================================================


class InputFactory:
    """Creates PSBT inputs based on specifications"""

    def __init__(self, wallet: Wallet, base_seed: str = "deterministic_test"):
        self.wallet = wallet
        self.base_seed = base_seed

    def create_input(
        self,
        spec: InputSpec,
        input_index: int,
        scenario: Optional["TestScenario"] = None,
    ) -> Dict[str, Any]:
        """Create input based on specification"""
        if scenario and scenario.use_segwit_v2_input:
            spec.use_segwit_v2 = True

        if spec.input_type == InputType.P2WPKH:
            result = self._create_p2wpkh_input(spec, input_index)
        elif spec.input_type == InputType.P2PKH:
            result = self._create_p2pkh_input(spec, input_index)
        elif spec.input_type == InputType.P2SH_P2WPKH:
            result = self._create_p2sh_p2wpkh_input(spec, input_index)
        elif spec.input_type == InputType.P2SH_MULTISIG:
            result = self._create_p2sh_multisig_input(spec, input_index)
        elif spec.input_type == InputType.P2WSH_MULTISIG:
            result = self._create_p2wsh_multisig_input(spec, input_index)
        elif spec.input_type == InputType.P2TR:
            result = self._create_p2tr_input(spec, input_index)  # TODO
        else:
            raise ValueError(f"Unknown input type: {spec.input_type}")

        if spec.eligible_override is not None:
            result["is_eligible"] = spec.eligible_override

        return result

    def _create_p2wpkh_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2WPKH input"""
        # Deterministic key generation
        key_suffix = f"{spec.key_derivation_suffix}_{input_index}"
        input_priv, input_pub = self.wallet.create_key_pair(
            "input", _deterministic_hash(key_suffix)
        )

        # Create prevout
        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_prevout_{input_index}".encode()
        ).digest()

        # Create P2WPKH script: OP_0 OP_PUSHBYTES_20 <20-byte-hash160(pubkey)>
        # Error injection: Use segwit v2 instead of v0
        segwit_version = 0x52 if spec.use_segwit_v2 else 0x00
        witness_script = (
            bytes([segwit_version, 0x14])
            + hashlib.sha256(input_pub.bytes).digest()[:20]
        )
        witness_utxo = create_witness_utxo(spec.amount, witness_script)

        return {
            "input_index": input_index,
            "input_type": InputType.P2WPKH,
            "private_key": input_priv,
            "public_key": input_pub,
            "prevout_txid": prevout_txid,
            "prevout_index": 0,
            "witness_script": witness_script,
            "witness_utxo": witness_utxo,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": True,
        }

    def _create_p2pkh_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2PKH input (BIP-352 eligible; public key exposed via BIP32_DERIVATION)"""
        key_suffix = f"{spec.key_derivation_suffix}_{input_index}"
        input_priv, input_pub = self.wallet.create_key_pair(
            "input", _deterministic_hash(key_suffix)
        )

        pubkey_hash = hashlib.new(
            "ripemd160", hashlib.sha256(input_pub.bytes).digest()
        ).digest()
        # OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        script_pubkey = bytes([0x76, 0xA9, 0x14]) + pubkey_hash + bytes([0x88, 0xAC])

        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_p2pkh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
        prevout_txid = hashlib.sha256(hashlib.sha256(prev_tx).digest()).digest()

        return {
            "input_index": input_index,
            "input_type": InputType.P2PKH,
            "private_key": input_priv,
            "public_key": input_pub,
            "prevout_txid": prevout_txid,
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "prev_tx": prev_tx,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": True,
        }

    def _create_p2sh_p2wpkh_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2SH-P2WPKH input (BIP-352 eligible wrapped segwit)"""
        key_suffix = f"{spec.key_derivation_suffix}_{input_index}"
        input_priv, input_pub = self.wallet.create_key_pair(
            "input", _deterministic_hash(key_suffix)
        )

        pubkey_hash = hashlib.new(
            "ripemd160", hashlib.sha256(input_pub.bytes).digest()
        ).digest()
        # Redeem script is the inner P2WPKH script: OP_0 <20-byte hash>
        redeem_script = bytes([0x00, 0x14]) + pubkey_hash

        redeem_script_hash = hashlib.new(
            "ripemd160", hashlib.sha256(redeem_script).digest()
        ).digest()
        # P2SH scriptPubKey: OP_HASH160 <20-byte hash> OP_EQUAL
        script_pubkey = bytes([0xA9, 0x14]) + redeem_script_hash + bytes([0x87])

        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_p2sh_p2wpkh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
        prevout_txid = hashlib.sha256(hashlib.sha256(prev_tx).digest()).digest()

        # PSBT_IN_WITNESS_UTXO for P2SH-P2WPKH uses the P2SH scriptPubKey
        witness_utxo = create_witness_utxo(spec.amount, script_pubkey)

        return {
            "input_index": input_index,
            "input_type": InputType.P2SH_P2WPKH,
            "private_key": input_priv,
            "public_key": input_pub,
            "prevout_txid": prevout_txid,
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "redeem_script": redeem_script,
            "witness_utxo": witness_utxo,
            "prev_tx": prev_tx,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": True,
        }

    def _generate_multisig_keys_and_script(
        self, spec: InputSpec, input_index: int, purpose: str
    ) -> Tuple[list, bytes]:
        """Generate multisig keys and build OP_CHECKMULTISIG script.

        Returns (keys, multisig_script) where keys is [(priv, pub), ...] and
        multisig_script is OP_M <pubs> OP_N OP_CHECKMULTISIG.
        """
        threshold = spec.multisig_threshold or 2
        pubkey_count = spec.multisig_pubkey_count or 2

        keys = []
        for i in range(pubkey_count):
            key_suffix = f"{spec.key_derivation_suffix}_{input_index}_{i}"
            priv_key, pub_key = self.wallet.create_key_pair(
                purpose, _deterministic_hash(key_suffix)
            )
            keys.append((priv_key, pub_key))

        script = bytes([0x50 + threshold])  # OP_M
        for _, pub_key in keys:
            script += bytes([0x21]) + pub_key.to_bytes_compressed()
        script += bytes([0x50 + pubkey_count, 0xAE])  # OP_N OP_CHECKMULTISIG

        return keys, script

    def _multisig_common_fields(
        self, keys: list, spec: InputSpec, input_index: int
    ) -> Dict[str, Any]:
        """Build the return-dict fields shared by P2SH and P2WSH multisig inputs."""
        return {
            "input_index": input_index,
            "private_keys": [priv for priv, _ in keys],
            "public_keys": [pub for _, pub in keys],
            "public_key": keys[0][1] if keys else None,
            "prevout_index": 0,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": False,
        }

    def _create_p2sh_multisig_input(
        self, spec: InputSpec, input_index: int
    ) -> Dict[str, Any]:
        """Create P2SH multisig input"""
        keys, redeem_script = self._generate_multisig_keys_and_script(
            spec, input_index, "multisig"
        )

        # P2SH scriptPubKey: OP_HASH160 <20-byte-hash> OP_EQUAL
        redeem_script_hash = hashlib.new(
            "ripemd160", hashlib.sha256(redeem_script).digest()
        ).digest()
        script_pubkey = bytes([0xA9, 0x14]) + redeem_script_hash + bytes([0x87])

        # Create non-witness UTXO for P2SH
        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_p2sh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prevout_txid, spec.amount, script_pubkey)

        result = self._multisig_common_fields(keys, spec, input_index)
        result.update({
            "input_type": InputType.P2SH_MULTISIG,
            "prevout_txid": hashlib.sha256(hashlib.sha256(prev_tx).digest()).digest(),
            "script_pubkey": script_pubkey,
            "redeem_script": redeem_script,
            "prev_tx": prev_tx,
        })
        return result

    def _create_p2wsh_multisig_input(
        self, spec: InputSpec, input_index: int
    ) -> Dict[str, Any]:
        """Create P2WSH multisig input"""
        keys, witness_script = self._generate_multisig_keys_and_script(
            spec, input_index, "wsh_multisig"
        )

        # P2WSH scriptPubKey: OP_0 <32-byte SHA256 hash>
        witness_script_hash = hashlib.sha256(witness_script).digest()
        script_pubkey = bytes([0x00, 0x20]) + witness_script_hash

        # Create witness UTXO
        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_p2wsh_prevout_{input_index}".encode()
        ).digest()
        witness_utxo = create_witness_utxo(spec.amount, script_pubkey)

        result = self._multisig_common_fields(keys, spec, input_index)
        result.update({
            "input_type": InputType.P2WSH_MULTISIG,
            "prevout_txid": prevout_txid,
            "script_pubkey": script_pubkey,
            "witness_script": witness_script,
            "witness_utxo": witness_utxo,
        })
        return result

    def _create_p2tr_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2TR key-path input (unsigned/WIP — no taptweak applied)."""
        key_suffix = f"{spec.key_derivation_suffix}_{input_index}"
        input_priv, input_pub = self.wallet.create_key_pair(
            "input", _deterministic_hash(key_suffix)
        )

        prevout_txid = hashlib.sha256(
            f"{self.base_seed}_p2tr_prevout_{input_index}".encode()
        ).digest()

        # Negate private key if pubkey has odd y (BIP340 even-y requirement for lift_x)
        if int(input_pub.y) % 2 != 0:
            input_priv = PrivateKey(GE.ORDER - int(input_priv))
            input_pub = PublicKey(int(input_priv) * G)

        if spec.use_nums_tap_internal_key:
            # NUMS point as taproot internal key: no private key exists, input is ineligible
            # for Silent Payments (cannot contribute an ECDH share).
            witness_script = bytes([0x51, 0x20]) + NUMS_H
            witness_utxo = create_witness_utxo(spec.amount, witness_script)
            return {
                "input_index": input_index,
                "input_type": InputType.P2TR,
                "private_key": input_priv,
                "public_key": input_pub,
                "tap_internal_key": NUMS_H,
                "prevout_txid": prevout_txid,
                "prevout_index": 0,
                "witness_script": witness_script,
                "witness_utxo": witness_utxo,
                "amount": spec.amount,
                "sequence": spec.sequence,
                "is_eligible": False,
            }

        # P2TR scriptPubKey: OP_1 (0x51) + push(32) (0x20) + 32-byte x-only key
        witness_script = bytes([0x51, 0x20]) + input_pub.bytes_xonly
        witness_utxo = create_witness_utxo(spec.amount, witness_script)

        return {
            "input_index": input_index,
            "input_type": InputType.P2TR,
            "private_key": input_priv,
            "public_key": input_pub,
            "prevout_txid": prevout_txid,
            "prevout_index": 0,
            "witness_script": witness_script,
            "witness_utxo": witness_utxo,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": True,
        }

    def _create_prev_tx(
        self, prev_input_txid: bytes, amount: int, script_pubkey: bytes
    ) -> bytes:
        """Create a previous transaction for non-witness UTXOs"""
        prev_tx = bytes([0x02, 0x00, 0x00, 0x00])  # version
        prev_tx += bytes([0x01])  # 1 input
        prev_tx += prev_input_txid  # prev txid
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # prev vout
        prev_tx += bytes([0x00])  # empty scriptSig
        prev_tx += bytes([0xFF, 0xFF, 0xFF, 0xFF])  # sequence
        prev_tx += bytes([0x01])  # 1 output
        prev_tx += struct.pack("<Q", amount)  # amount
        prev_tx += bytes([len(script_pubkey)]) + script_pubkey
        prev_tx += bytes([0x00, 0x00, 0x00, 0x00])  # locktime
        return prev_tx


# ============================================================================
# Output Factory
# ============================================================================


class OutputFactory:
    """Creates PSBT outputs based on specifications"""

    def __init__(self, wallet: Wallet):
        self.wallet = wallet

    def create_output(
        self, spec: OutputSpec, output_index: int, scan_keys: Dict[str, tuple]
    ) -> Dict[str, Any]:
        """Create output based on specification"""
        if spec.output_type == OutputType.SILENT_PAYMENT:
            return self._create_silent_payment_output(spec, output_index, scan_keys)
        elif spec.output_type == OutputType.REGULAR_P2TR:
            return self._create_regular_p2tr_output(spec, output_index)
        elif spec.output_type == OutputType.REGULAR_P2WPKH:
            return self._create_regular_p2wpkh_output(spec, output_index)
        else:
            raise ValueError(f"Unknown output type: {spec.output_type}")

    def _create_silent_payment_output(
        self, spec: OutputSpec, output_index: int, scan_keys: Dict[str, tuple]
    ) -> Dict[str, Any]:
        """Create silent payment output"""
        if not spec.scan_key_id or spec.scan_key_id not in scan_keys:
            raise ValueError("Silent payment output requires valid scan_key_id")

        scan_pub, spend_pub = scan_keys[spec.scan_key_id]

        if spec.spend_derivation_suffix is not None:
            spend_seed = _deterministic_hash(f"spend_{spec.spend_derivation_suffix}")
            _, spend_pub = self.wallet.create_key_pair("spend", spend_seed)

        return {
            "output_index": output_index,
            "output_type": OutputType.SILENT_PAYMENT,
            "amount": spec.amount,
            "scan_pubkey": scan_pub,
            "spend_pubkey": spend_pub,
            "label": spec.label,
            "force_wrong_script": spec.force_wrong_script,
            "force_k_index": spec.force_k_index,
        }

    def _create_regular_p2tr_output(
        self, spec: OutputSpec, output_index: int
    ) -> Dict[str, Any]:
        """Create regular P2TR output"""
        # Simple P2TR output for testing
        output_script = (
            bytes([0x51, 0x20])
            + hashlib.sha256(f"regular_p2tr_{output_index}".encode()).digest()
        )

        return {
            "output_index": output_index,
            "output_type": OutputType.REGULAR_P2TR,
            "amount": spec.amount,
            "script": output_script,
            "add_bip32_derivation": spec.add_bip32_derivation,
        }

    def _create_regular_p2wpkh_output(
        self, spec: OutputSpec, output_index: int
    ) -> Dict[str, Any]:
        """Create regular P2WPKH output"""
        # Simple P2WPKH output for testing
        pubkey_hash = hashlib.sha256(
            f"regular_p2wpkh_{output_index}".encode()
        ).digest()[:20]
        output_script = bytes([0x00, 0x14]) + pubkey_hash

        return {
            "output_index": output_index,
            "output_type": OutputType.REGULAR_P2WPKH,
            "amount": spec.amount,
            "script": output_script,
            "add_bip32_derivation": spec.add_bip32_derivation,
        }


# ============================================================================
# PSBT Builder
# ============================================================================


class PSBTBuilder:
    """Builds PSBTs from test scenarios"""

    def __init__(self, wallet: Wallet, base_seed: str = "deterministic_test"):
        self.wallet = wallet
        self.base_seed = base_seed
        self.input_factory = InputFactory(wallet, base_seed)
        self.output_factory = OutputFactory(wallet)

    def build_psbt(self, scenario: TestScenario) -> Dict[str, Any]:
        """Build a complete PSBT from a test scenario"""
        # Create base PSBT structure
        psbt = self._create_psbt_base(
            len(scenario.inputs), len(scenario.outputs), scenario
        )

        # Generate scan keys deterministically
        scan_keys = self._generate_scan_keys(scenario.scan_keys)

        # Create inputs
        input_data = []
        for i, input_spec in enumerate(scenario.inputs):
            input_info = self.input_factory.create_input(input_spec, i, scenario)
            input_data.append(input_info)
            self._add_input_to_psbt(psbt, input_info)

        # Create outputs
        output_data = []
        for i, output_spec in enumerate(scenario.outputs):
            output_info = self.output_factory.create_output(output_spec, i, scan_keys)
            output_data.append(output_info)

        # Compute ECDH shares for silent payment outputs
        ecdh_data = self._compute_ecdh_shares(input_data, scan_keys, scenario)

        # Add ECDH shares to PSBT (with error injection); track which inputs get signed
        signed_input_indices: set = set()
        self._add_ecdh_shares_to_psbt(psbt, ecdh_data, scenario, input_data, scan_keys, signed_input_indices)

        # Error injection: strip BIP32_DERIVATION from specified input
        if scenario.strip_input_pubkeys_for_input is not None:
            idx = scenario.strip_input_pubkeys_for_input
            remove_raw_input_fields_by_type(
                psbt, idx, PSBTKeyType.PSBT_IN_BIP32_DERIVATION
            )

        # Compute and add outputs to PSBT; collect finalized scripts for signing
        finalized_outputs = self._add_outputs_to_psbt(psbt, output_data, input_data, ecdh_data, scenario, scan_keys)

        # Auto-sign all eligible non-P2TR inputs when output scripts are complete
        if self._should_auto_sign(scenario):
            for input_info in input_data:
                if input_info.get("is_eligible", False):
                    self._sign_single_input(
                        psbt, input_info, input_data, finalized_outputs, input_info["input_index"]
                    )
                    if input_info.get("input_type") != InputType.P2TR:
                        signed_input_indices.add(input_info["input_index"])
            if not scenario.set_tx_modifiable:
                psbt.set_tx_modifiable(0x00)

        # Build result structure
        return {
            "psbt": psbt,
            "input_data": input_data,
            "output_data": output_data,
            "scan_keys": scan_keys,
            "ecdh_data": ecdh_data,
            "scenario": scenario,
            "signed_input_indices": signed_input_indices,
        }

    def _create_psbt_base(
        self, num_inputs: int, num_outputs: int, scenario: TestScenario
    ) -> SilentPaymentPsbt:
        """Create PSBT v2 base structure"""
        return _create_psbt(
            num_inputs,
            num_outputs,
            tx_modifiable=scenario.set_tx_modifiable,
        )

    def _generate_scan_keys(
        self, scan_key_specs: List[ScanKeySpec]
    ) -> Dict[str, tuple]:
        """Generate scan/spend key pairs deterministically"""
        scan_keys = {}

        for spec in scan_key_specs:
            if spec.key_id == "default":
                # Use wallet's default keys
                scan_keys[spec.key_id] = (self.wallet.scan_pub, self.wallet.spend_pub)
            else:
                # Generate deterministic keys
                seed_suffix = _deterministic_hash(
                    f"{spec.key_id}_{spec.derivation_suffix}"
                )
                _, scan_pub = self.wallet.create_key_pair("scan", seed_suffix)
                _, spend_pub = self.wallet.create_key_pair("spend", seed_suffix)
                scan_keys[spec.key_id] = (scan_pub, spend_pub)

        return scan_keys

    def _add_input_to_psbt(self, psbt: SilentPaymentPsbt, input_info: Dict[str, Any]):
        """Add input fields to PSBT based on input type"""
        idx = input_info["input_index"]
        input_type = input_info["input_type"]

        # Add common fields
        add_raw_input_field(
            psbt, idx, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", input_info["prevout_txid"]
        )
        add_raw_input_field(
            psbt,
            idx,
            PSBTKeyType.PSBT_IN_OUTPUT_INDEX,
            b"",
            struct.pack("<I", input_info["prevout_index"]),
        )
        add_raw_input_field(
            psbt,
            idx,
            PSBTKeyType.PSBT_IN_SEQUENCE,
            b"",
            struct.pack("<I", input_info["sequence"]),
        )

        if input_type == InputType.P2WPKH:
            # Add witness UTXO and BIP32 derivation
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_WITNESS_UTXO,
                b"",
                input_info["witness_utxo"],
            )
            # Add BIP32 derivation for pubkey exposure
            fake_derivation = struct.pack("<I", 0x80000000) + struct.pack(
                "<I", idx
            )  # m/0'/idx'
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_BIP32_DERIVATION,
                input_info["public_key"].bytes,
                fake_derivation,
            )

        elif input_type == InputType.P2PKH:
            # Non-witness UTXO (full prev tx) + BIP32 derivation to expose public key
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_NON_WITNESS_UTXO,
                b"",
                input_info["prev_tx"],
            )
            fake_derivation = struct.pack("<I", 0x80000000) + struct.pack("<I", idx)
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_BIP32_DERIVATION,
                input_info["public_key"].bytes,
                fake_derivation,
            )

        elif input_type == InputType.P2SH_P2WPKH:
            # Both non-witness UTXO (full prev tx) and witness UTXO (P2SH scriptPubKey),
            # plus the redeem script and BIP32 derivation to expose the public key
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_NON_WITNESS_UTXO,
                b"",
                input_info["prev_tx"],
            )
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_WITNESS_UTXO,
                b"",
                input_info["witness_utxo"],
            )
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_REDEEM_SCRIPT,
                b"",
                input_info["redeem_script"],
            )
            fake_derivation = struct.pack("<I", 0x80000000) + struct.pack("<I", idx)
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_BIP32_DERIVATION,
                input_info["public_key"].bytes,
                fake_derivation,
            )

        elif input_type == InputType.P2SH_MULTISIG:
            # Add non-witness UTXO and redeem script
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_NON_WITNESS_UTXO,
                b"",
                input_info["prev_tx"],
            )
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_REDEEM_SCRIPT,
                b"",
                input_info["redeem_script"],
            )

        elif input_type == InputType.P2WSH_MULTISIG:
            # Add witness UTXO and witness script
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_WITNESS_UTXO,
                b"",
                input_info["witness_utxo"],
            )
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_WITNESS_SCRIPT,
                b"",
                input_info["witness_script"],
            )

        elif input_type == InputType.P2TR:
            # Add witness UTXO and taproot internal key
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_WITNESS_UTXO,
                b"",
                input_info["witness_utxo"],
            )
            tap_key = input_info.get("tap_internal_key", input_info["public_key"].bytes_xonly)
            add_raw_input_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_IN_TAP_INTERNAL_KEY,
                b"",
                tap_key,
            )

    def _compute_ecdh_shares(
        self,
        input_data: List[Dict],
        scan_keys: Dict[str, tuple],
        scenario: TestScenario,
    ) -> Dict:
        """Compute ECDH shares for eligible inputs"""
        ecdh_shares = {}  # (input_idx, scan_key_id) -> (ecdh_result, dleq_proof)

        eligible_inputs = [inp for inp in input_data if inp["is_eligible"]]

        for input_info in eligible_inputs:
            input_idx = input_info["input_index"]

            # Error injection says to skip this input
            if scenario.missing_ecdh_for_input == input_idx:
                continue

            private_key = input_info["private_key"]

            for scan_key_id, (scan_pub, _) in scan_keys.items():
                # Skip ECDH for specific scan key (affects all inputs)
                if scenario.missing_ecdh_for_scan_key == scan_key_id:
                    continue

                # Skip ECDH for a specific (input, scan_key) pair only
                if (
                    scenario.missing_ecdh_for_input_scan_key is not None
                    and scenario.missing_ecdh_for_input_scan_key == (input_idx, scan_key_id)
                ):
                    continue

                # Compute ECDH share
                ecdh_result = private_key * scan_pub

                # Generate DLEQ proof (with potential Error injection)
                if (
                    scenario.invalid_dleq_for_input == input_idx
                    or scenario.invalid_dleq_for_scan_key == scan_key_id
                ):
                    # Use wrong private key for invalid proof
                    wrong_priv, _ = self.wallet.create_key_pair("wrong", 999)
                    dleq_proof = spdk_psbt.dleq_generate_proof(
                        wrong_priv.bytes, scan_pub.bytes, self.wallet.random_bytes(32)
                    )
                elif (
                    scenario.missing_dleq_for_input == input_idx
                    or scenario.missing_dleq_for_scan_key == scan_key_id
                ):
                    dleq_proof = None
                else:
                    # Normal valid proof
                    random_bytes = hashlib.sha256(
                        f"{self.base_seed}_dleq_{input_idx}_{scan_key_id}".encode()
                    ).digest()
                    dleq_proof = spdk_psbt.dleq_generate_proof(
                        private_key.bytes, scan_pub.bytes, random_bytes
                    )

                    # Error injection: Wrong DLEQ proof size
                    if scenario.wrong_dleq_proof_size:
                        dleq_proof = dleq_proof[:63]  # Truncate to wrong size

                ecdh_shares[(input_idx, scan_key_id)] = (ecdh_result, dleq_proof)

        return ecdh_shares

    def _add_ecdh_shares_to_psbt(
        self,
        psbt: SilentPaymentPsbt,
        ecdh_data: Dict,
        scenario: TestScenario,
        input_data: List[Dict],
        scan_keys: Dict[str, tuple],
        signed_input_indices: Optional[set] = None,
    ):
        """Add ECDH shares and DLEQ proofs to PSBT"""
        global_scan_keys = scenario.use_global_ecdh or []

        if global_scan_keys:
            global_ecdh = {
                k: v for k, v in ecdh_data.items() if k[1] in global_scan_keys
            }
            if global_ecdh:
                self._add_global_ecdh_shares(psbt, global_ecdh, scenario, input_data, scan_keys)

        per_input_ecdh = {
            k: v for k, v in ecdh_data.items() if k[1] not in global_scan_keys
        }
        if per_input_ecdh:
            self._add_per_input_ecdh_shares(psbt, per_input_ecdh, scenario, input_data, scan_keys, signed_input_indices)

        # Error injection: Add ECDH share for ineligible input (only when explicitly requested)
        if scenario.inject_ineligible_ecdh:
            self._inject_ineligible_input_ecdh_shares(psbt, input_data, scan_keys)

    def _find_input_info_by_index(
        self, input_data: List[Dict], input_idx: int
    ) -> Optional[Dict]:
        """Find input info by index"""
        for input_info in input_data:
            if input_info.get("input_index") == input_idx:
                return input_info
        return None

    def _add_per_input_ecdh_shares(
        self,
        psbt: SilentPaymentPsbt,
        ecdh_data: Dict,
        scenario: TestScenario,
        input_data: List[Dict],
        scan_keys: Dict[str, tuple],
        signed_input_indices: Optional[set] = None,
    ):
        """Add per-input ECDH shares"""

        # Track which inputs have been processed to add sighash type
        processed_inputs = set()

        for (input_idx, scan_key_id), (ecdh_result, dleq_proof) in ecdh_data.items():
            if scan_key_id not in scan_keys:
                continue

            scan_pub = scan_keys[scan_key_id][0]

            # Add ECDH share with potential Error injection
            ecdh_bytes = ecdh_result.to_bytes_compressed()
            if scenario.wrong_ecdh_share_size:
                ecdh_bytes = ecdh_bytes[:32]  # Wrong size: 32 instead of 33 bytes

            add_raw_input_field(
                psbt, input_idx, PSBTKeyType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_bytes
            )

            # Add DLEQ proof (if not missing due to Error injection)
            if dleq_proof is not None:
                add_raw_input_field(
                    psbt, input_idx, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, dleq_proof
                )

            # Add sighash type only once per input
            if input_idx not in processed_inputs:
                sighash_type = (
                    0x02 if scenario.wrong_sighash_for_input == input_idx else 0x01
                )
                if scenario.no_sighash_for_input == input_idx:
                    sighash_type = None  # Don't add sighash type at all
                if sighash_type:
                    add_raw_input_field(
                        psbt, input_idx, PSBTKeyType.PSBT_IN_SIGHASH_TYPE, b"", struct.pack("<I", sighash_type)
                    )

                if (
                    scenario.wrong_sighash_for_input == input_idx
                    or scenario.use_segwit_v2_input
                ):
                    # Partially sign to support correct detection at signed stage.
                    # Empty outputs: signature validity doesn't matter here.
                    input_info = self._find_input_info_by_index(input_data, input_idx)
                    if input_info and input_info.get("is_eligible", False):
                        self._sign_single_input(
                            psbt, input_info, input_data, [], input_idx
                        )
                        if signed_input_indices is not None:
                            signed_input_indices.add(input_idx)

                processed_inputs.add(input_idx)

    def _compute_global_dleq_proof(
        self, scan_key_id: str, summed_private_key, scan_pub
    ) -> bytes:
        """Compute a global DLEQ proof for a scan key using the summed private key"""
        random_bytes = hashlib.sha256(
            f"{self.base_seed}_global_dleq_{scan_key_id}".encode()
        ).digest()
        return spdk_psbt.dleq_generate_proof(
            summed_private_key.bytes, scan_pub.bytes, random_bytes
        )

    def _should_auto_sign(self, scenario: TestScenario) -> bool:
        """Return True if all eligible inputs should be signed after output scripts are set.

        Signing is appropriate only when PSBT_OUT_SCRIPT has been correctly computed
        for every silent payment output (i.e., no error injection interferes with
        script computation or validity).
        """
        return not any([
            scenario.force_output_script,
            scenario.force_partial_ecdh_output_script,
            scenario.wrong_sighash_for_input is not None,
            scenario.use_segwit_v2_input,
            scenario.missing_ecdh_for_input is not None,
            scenario.missing_ecdh_for_scan_key is not None,
            scenario.missing_ecdh_for_input_scan_key is not None,
            any(out.force_wrong_script for out in scenario.outputs),
        ])

    def _sign_single_input(
        self,
        psbt: SilentPaymentPsbt,
        input_info: Dict,
        input_data: List[Dict],
        output_data: List[Dict],
        input_idx: int,
    ):
        """Sign a single P2WPKH input and add PSBT_IN_PARTIAL_SIG as raw field.

        For error-injection tests (wrong sighash, segwit v2), output_data may be
        empty — signature correctness doesn't matter, only its presence.
        For valid test vectors, pass the real output_data so SIGHASH_ALL commits
        to the correct outputs.

        P2TR signing is not yet implemented (TODO).
        """
        input_type = input_info.get("input_type")
        if input_type == InputType.P2TR:
            # TODO: implement P2TR (Schnorr) signing
            return

        script_bytes = input_info.get(
            "witness_script", input_info.get("script_pubkey", b"")
        )
        pubkey_hash = script_bytes[2:]  # strip OP_0 + push byte

        # Build UTXO list from all inputs (needed for BIP143 sighash)
        utxos = []
        for inp in input_data:
            utxos.append(
                UTXO(
                    txid=inp["prevout_txid"].hex(),
                    vout=inp["prevout_index"],
                    amount=inp["amount"],
                    script_pubkey=inp.get(
                        "witness_script", inp.get("script_pubkey", b"")
                    ).hex(),
                    private_key=inp.get("private_key"),
                    sequence=inp.get("sequence", 0xFFFFFFFE),
                )
            )

        # Build output list for sighash commitment
        outputs = []
        for out in output_data:
            script = out.get("script", b"")
            outputs.append({
                "amount": out["amount"],
                "script_pubkey": script.hex() if isinstance(script, bytes) else script,
            })

        signature = sign_p2wpkh_input(
            private_key=int(input_info["private_key"]),
            inputs=utxos,
            outputs=outputs,
            input_index=input_idx,
            pubkey_hash=pubkey_hash,
            amount=input_info["amount"],
        )

        compressed_pubkey = input_info["public_key"].to_bytes_compressed()
        add_raw_input_field(
            psbt,
            input_idx,
            PSBTKeyType.PSBT_IN_PARTIAL_SIG,
            compressed_pubkey,
            signature,
        )

    def _add_global_ecdh_shares(
        self,
        psbt: SilentPaymentPsbt,
        ecdh_data: Dict,
        scenario: TestScenario,
        input_data: List[Dict],
        scan_keys: Dict[str, tuple],
    ):
        """Add global ECDH shares"""
        # Group by scan key and sum ECDH shares
        global_shares = {}  # scan_key_id -> summed_ecdh

        for (input_idx, scan_key_id), (ecdh_result, _) in ecdh_data.items():
            if scan_key_id not in global_shares:
                global_shares[scan_key_id] = ecdh_result
            else:
                global_shares[scan_key_id] += ecdh_result

        eligible_inputs = [inp for inp in input_data if inp.get("is_eligible", False)]

        for scan_key_id, summed_ecdh in global_shares.items():
            scan_pub = scan_keys[scan_key_id][0]

            # Add global ECDH share
            add_raw_global_field(
                psbt,
                PSBTKeyType.PSBT_GLOBAL_SP_ECDH_SHARE,
                scan_pub.bytes,
                summed_ecdh.to_bytes_compressed(),
            )

            # Add global DLEQ proof (if not missing due to Error injection)
            if not scenario.missing_global_dleq:
                # For global DLEQ, we need to prove sum of private keys
                # Sum all private keys from eligible inputs for this scan key
                summed_private_key = None

                for (input_idx, sk_id), (ecdh_result, _) in ecdh_data.items():
                    if sk_id == scan_key_id:
                        # Find the corresponding input data to get private key
                        matching = [
                            inp
                            for inp in eligible_inputs
                            if inp["input_index"] == input_idx
                        ]
                        if matching:
                            inp_priv_key = matching[0]["private_key"]
                            if summed_private_key is None:
                                summed_private_key = inp_priv_key
                            else:
                                summed_private_key = summed_private_key + inp_priv_key

                if summed_private_key is not None:
                    if scenario.invalid_global_dleq:
                        # Use wrong private key for invalid proof
                        wrong_priv, _ = self.wallet.create_key_pair("wrong", 999)
                        global_dleq_proof = self._compute_global_dleq_proof(
                            scan_key_id, wrong_priv, scan_pub
                        )
                    else:
                        global_dleq_proof = self._compute_global_dleq_proof(
                            scan_key_id, summed_private_key, scan_pub
                        )
                    add_raw_global_field(
                        psbt,
                        PSBTKeyType.PSBT_GLOBAL_SP_DLEQ,
                        scan_pub.bytes,
                        global_dleq_proof,
                    )

    def _inject_ineligible_input_ecdh_shares(
        self,
        psbt: SilentPaymentPsbt,
        input_data: List[Dict],
        scan_keys: Dict[str, tuple],
    ):
        """Error injection: Add ECDH shares for ineligible inputs"""
        for inp in input_data:
            if not inp.get("is_eligible", False):
                if scan_keys:
                    scan_key_id, (scan_pub, _) = next(iter(scan_keys.items()))
                    i = inp["input_index"]
                    # Create fake ECDH share
                    fake_ecdh_bytes = (
                        b"\x02" + hashlib.sha256(f"fake_ecdh_{i}".encode()).digest()
                    )
                    fake_dleq = b"\x00" * 64

                    add_raw_input_field(
                        psbt,
                        i,
                        PSBTKeyType.PSBT_IN_SP_ECDH_SHARE,
                        scan_pub.bytes,
                        fake_ecdh_bytes,
                    )
                    add_raw_input_field(
                        psbt, i, PSBTKeyType.PSBT_IN_SP_DLEQ, scan_pub.bytes, fake_dleq
                    )
                break

    def _add_outputs_to_psbt(
        self,
        psbt: SilentPaymentPsbt,
        output_data: List[Dict],
        input_data: List[Dict],
        ecdh_data: Dict,
        scenario: TestScenario,
        scan_keys: Dict[str, tuple],
    ) -> List[Dict]:
        """Add outputs to PSBT. Returns finalized output list for sighash computation.

        Each entry in the returned list has {"amount": int, "script_pubkey": hex_str}.
        Silent payment outputs that did not get a PSBT_OUT_SCRIPT (e.g. incomplete
        ECDH coverage) will have an empty script_pubkey.
        """
        # Track k counter per scan key (matches BIP-352 / validator behavior)
        scan_key_k_counter: Dict[bytes, int] = {}
        finalized_outputs: List[Dict] = []

        for output_info in output_data:
            idx = output_info["output_index"]
            output_type = output_info["output_type"]

            # Add amount
            add_raw_output_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_OUT_AMOUNT,
                b"",
                struct.pack("<Q", output_info["amount"]),
            )

            if output_type == OutputType.SILENT_PAYMENT:
                script = self._add_silent_payment_output(
                    psbt, output_info, input_data, ecdh_data, scenario, scan_keys, scan_key_k_counter
                )
                finalized_outputs.append({
                    "amount": output_info["amount"],
                    "script_pubkey": script.hex() if script else "",
                })
            else:
                # Regular output - add script and optional BIP32_DERIVATION
                if not scenario.skip_regular_output_script:
                    add_raw_output_field(
                        psbt, idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_info["script"]
                    )
                finalized_outputs.append({
                    "amount": output_info["amount"],
                    "script_pubkey": output_info["script"].hex(),
                })

                # Add BIP32_DERIVATION if requested (for change identification)
                if output_info.get("add_bip32_derivation", False):
                    self._add_output_bip32_derivation(psbt, idx, input_data)

        return finalized_outputs

    def _add_silent_payment_output(
        self,
        psbt: SilentPaymentPsbt,
        output_info: Dict,
        input_data: List[Dict],
        ecdh_data: Dict,
        scenario: TestScenario,
        scan_keys: Dict[str, tuple],
        scan_key_k_counter: Optional[Dict] = None,
    ) -> Optional[bytes]:
        """Add silent payment output with proper BIP-352 script computation.

        Returns the computed output script bytes, or None if no script was set.
        """
        idx = output_info["output_index"]
        scan_pub = output_info["scan_pubkey"]
        original_spend_pub = output_info["spend_pubkey"]
        output_script: Optional[bytes] = None

        # Apply BIP-352 label if specified
        spend_pub = original_spend_pub
        if output_info.get("label") is not None:
            spend_pub = self._compute_labeled_spend_key(
                original_spend_pub, output_info["label"]
            )

        if output_info["force_wrong_script"]:
            # Force wrong script for address mismatch tests
            output_script = (
                bytes([0x51, 0x20]) + hashlib.sha256(b"wrong_address").digest()
            )
            add_raw_output_field(psbt, idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script)
        else:
            # Compute proper BIP-352 script
            eligible_inputs = [
                inp for inp in input_data if inp.get("is_eligible", False)
            ]

            if eligible_inputs and ecdh_data:
                outpoints, outpoint_to_input = _sorted_outpoints_and_input_map(
                    eligible_inputs
                )
                summed_pubkey = _sum_pubkeys_in_outpoint_order(
                    outpoints, outpoint_to_input
                )
                summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

                # Find the scan key ID for this output's scan pub
                scan_key_id = None
                for key_id, (key_scan_pub, _) in scan_keys.items():
                    if key_scan_pub == scan_pub:
                        scan_key_id = key_id
                        break

                if scan_key_id:
                    summed_ecdh_share, coverage_complete = (
                        _sum_ecdh_shares_for_scan_key(
                            outpoints, outpoint_to_input, ecdh_data, scan_key_id
                        )
                    )

                    if (coverage_complete or scenario.force_partial_ecdh_output_script) and summed_ecdh_share is not None:
                        ecdh_share_bytes = summed_ecdh_share.to_bytes_compressed()
                        # k is per-scan-key (matches BIP-352 behavior)
                        scan_pub_bytes = scan_pub.to_bytes_compressed()
                        if scan_key_k_counter is not None:
                            k_index = scan_key_k_counter.get(scan_pub_bytes, 0)
                        else:
                            k_index = idx
                        # force_k_index overrides for error injection
                        if output_info["force_k_index"] is not None:
                            k_index = output_info["force_k_index"]
                        # Advance counter for next output with this scan key
                        if scan_key_k_counter is not None:
                            scan_key_k_counter[scan_pub_bytes] = scan_key_k_counter.get(scan_pub_bytes, 0) + 1
                        # Compute BIP-352 output script
                        output_script = compute_bip352_output_script(
                            outpoints=outpoints,
                            summed_pubkey_bytes=summed_pubkey_bytes,
                            ecdh_share_bytes=ecdh_share_bytes,
                            spend_pubkey_bytes=spend_pub.to_bytes_compressed(),
                            k=k_index,  # k is the output index
                        )
                        add_raw_output_field(
                            psbt, idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script
                        )
                    elif scenario.force_output_script:
                        output_script = (
                            bytes([0x51, 0x20])
                            + hashlib.sha256(b"wrong_address").digest()
                        )
                        add_raw_output_field(
                            psbt, idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_script
                        )

        # Add SP_V0_INFO field (unless Error injection says to skip it)
        if not scenario.missing_sp_info_field:
            sp_info = scan_pub.to_bytes_compressed() + spend_pub.to_bytes_compressed()
            if scenario.wrong_sp_info_size:
                sp_info = sp_info[:65]  # Wrong size (65 instead of 66)

            add_raw_output_field(psbt, idx, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)
            # Store for compute_unique_id
            output_info["_sp_info_bytes"] = sp_info

        # Add label if specified (this will create invalid PSBT if SP_V0_INFO is missing)
        if output_info.get("label") is not None:
            add_raw_output_field(
                psbt,
                idx,
                PSBTKeyType.PSBT_OUT_SP_V0_LABEL,
                b"",
                struct.pack("<I", output_info["label"]),
            )

        return output_script

    def _compute_labeled_spend_key(
        self, spend_pub, label: int
    ):
        """Compute BIP-352 labeled spend key: B_m = B_spend + hash_BIP0352/Label(b_scan || m) * G"""
        scan_priv_bytes = self.wallet.scan_priv.to_bytes(32, "big")
        return apply_label_to_spend_key(spend_pub, scan_priv_bytes, label)

    def _add_output_bip32_derivation(
        self, psbt: SilentPaymentPsbt, output_idx: int, input_data: List[Dict]
    ):
        """Add PSBT_OUT_BIP32_DERIVATION for change identification"""
        # Use the first input's public key for the derivation (common pattern)
        if input_data and "public_key" in input_data[0]:
            pubkey = input_data[0]["public_key"]

            # Create BIP32 derivation path (master_fingerprint + path)
            # Format: 4-byte fingerprint + 8-byte path (m/0/1 for change)
            master_fingerprint = struct.pack(">I", 0)  # Dummy fingerprint
            derivation_path = struct.pack(">I", 0) + struct.pack(">I", 1)  # m/0/1
            bip32_derivation_value = master_fingerprint + derivation_path

            add_raw_output_field(
                psbt,
                output_idx,
                PSBTKeyType.PSBT_OUT_BIP32_DERIVATION,
                pubkey.bytes,
                bip32_derivation_value,
            )


# ============================================================================
# Configuration-Based Test Generator
# ============================================================================


class ConfigBasedTestGenerator:
    """Generates test vectors from YAML configurations"""

    def __init__(self, base_seed: str = "bip375_deterministic_seed"):
        self.wallet = Wallet(base_seed)
        self.base_seed = base_seed
        self.builder = PSBTBuilder(self.wallet, base_seed)

    def load_test_scenarios_from_config(self, config_path: str) -> List[TestScenario]:
        """Load test scenarios from YAML configuration"""
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        scenarios = []
        for test_config in config.get("test_cases", []):
            scenario = self._parse_test_config(test_config)
            scenarios.append(scenario)

        return scenarios

    def _parse_test_config(self, config: Dict[str, Any]) -> TestScenario:
        """Parse a single test configuration into TestScenario"""
        # Parse inputs
        inputs = []
        for input_config in config.get("inputs", []):
            input_spec = InputSpec(
                input_type=InputType(input_config["type"]),
                amount=input_config.get("amount", 100000),
                sequence=input_config.get("sequence", 0xFFFFFFFE),
                multisig_threshold=input_config.get("multisig_threshold"),
                multisig_pubkey_count=input_config.get("multisig_pubkey_count"),
                key_derivation_suffix=input_config.get("key_derivation_suffix", ""),
                use_nums_tap_internal_key=input_config.get("use_nums_tap_internal_key", False),
                eligible_override=input_config.get("eligible_override"),
            )

            # Handle batch creation
            count = input_config.get("count", 1)
            for i in range(count):
                # Create unique suffix for batch inputs
                batch_spec = InputSpec(
                    input_type=input_spec.input_type,
                    amount=input_spec.amount,
                    sequence=input_spec.sequence,
                    multisig_threshold=input_spec.multisig_threshold,
                    multisig_pubkey_count=input_spec.multisig_pubkey_count,
                    key_derivation_suffix=f"{input_spec.key_derivation_suffix}_batch_{i}",
                    use_nums_tap_internal_key=input_spec.use_nums_tap_internal_key,
                    eligible_override=input_spec.eligible_override,
                )
                inputs.append(batch_spec)

        # Parse outputs
        outputs = []
        for output_config in config.get("outputs", []):
            output_spec = OutputSpec(
                output_type=OutputType(output_config["type"]),
                amount=output_config.get("amount", 95000),
                scan_key_id=output_config.get("scan_key_id"),
                spend_key_id=output_config.get("spend_key_id"),
                label=output_config.get("label"),
                force_wrong_script=output_config.get("force_wrong_script", False),
                force_k_index=output_config.get("force_k_index", None),
                spend_derivation_suffix=output_config.get("spend_derivation_suffix"),
                add_bip32_derivation=output_config.get("add_bip32_derivation", False),
            )

            # Handle batch creation
            count = output_config.get("count", 1)
            for i in range(count):
                outputs.append(output_spec)

        # Parse scan keys
        scan_keys = []
        for key_config in config.get("scan_keys", [{"key_id": "default"}]):
            scan_key_spec = ScanKeySpec(
                key_id=key_config["key_id"],
                derivation_suffix=key_config.get("derivation_suffix", ""),
            )
            scan_keys.append(scan_key_spec)

        # Parse control override
        control_override = config.get("control_override", {})

        # Parse use_global_ecdh: true -> all scan keys, list -> specific scan keys, absent -> None
        raw_global_ecdh = control_override.get("use_global_ecdh")
        if raw_global_ecdh is True:
            use_global_ecdh = [sk.key_id for sk in scan_keys]
        elif isinstance(raw_global_ecdh, list):
            use_global_ecdh = raw_global_ecdh
        else:
            use_global_ecdh = None

        return TestScenario(
            description=config["description"],
            validation_result=ValidationResult(
                config.get("validation_result", "valid")
            ),
            checks=config.get("checks", []),
            inputs=inputs,
            outputs=outputs,
            scan_keys=scan_keys,
            missing_dleq_for_input=control_override.get("missing_dleq_for_input"),
            invalid_dleq_for_input=control_override.get("invalid_dleq_for_input"),
            no_sighash_for_input=control_override.get("no_sighash_for_input"),
            wrong_sighash_for_input=control_override.get("wrong_sighash_for_input"),
            missing_ecdh_for_input=control_override.get("missing_ecdh_for_input"),
            wrong_sp_info_size=control_override.get("wrong_sp_info_size", False),
            missing_global_dleq=control_override.get("missing_global_dleq", False),
            use_global_ecdh=use_global_ecdh,
            use_segwit_v2_input=control_override.get("use_segwit_v2_input", False),
            set_tx_modifiable=control_override.get("set_tx_modifiable", False),
            missing_sp_info_field=control_override.get("missing_sp_info_field", False),
            wrong_ecdh_share_size=control_override.get("wrong_ecdh_share_size", False),
            wrong_dleq_proof_size=control_override.get("wrong_dleq_proof_size", False),
            missing_ecdh_for_scan_key=control_override.get("missing_ecdh_for_scan_key"),
            missing_dleq_for_scan_key=control_override.get("missing_dleq_for_scan_key"),
            invalid_dleq_for_scan_key=control_override.get("invalid_dleq_for_scan_key"),
            inject_ineligible_ecdh=control_override.get(
                "inject_ineligible_ecdh", False
            ),
            force_output_script=control_override.get("force_output_script", False),
            strip_input_pubkeys_for_input=control_override.get(
                "strip_input_pubkeys_for_input"
            ),
            invalid_global_dleq=control_override.get("invalid_global_dleq", False),
            missing_ecdh_for_input_scan_key=(
                (
                    control_override["missing_ecdh_for_input_scan_key"]["input_index"],
                    control_override["missing_ecdh_for_input_scan_key"]["scan_key_id"],
                )
                if control_override.get("missing_ecdh_for_input_scan_key")
                else None
            ),
            force_partial_ecdh_output_script=control_override.get(
                "force_partial_ecdh_output_script", False
            ),
            skip_regular_output_script=control_override.get(
                "skip_regular_output_script", False
            ),
        )

    # Generate test vector for a given scenario
    def generate_test_vector_from_scenario(
        self, scenario: TestScenario
    ) -> Dict[str, Any]:
        """Generate a test vector from a scenario"""
        # Build PSBT
        psbt_data = self.builder.build_psbt(scenario)
        psbt = psbt_data["psbt"]

        # Convert to GenTestVector format for compatibility
        signed_input_indices = psbt_data["signed_input_indices"]
        input_keys = []
        for inp in psbt_data["input_data"]:
            private_key = ""
            public_key = ""

            if "private_key" in inp and inp["private_key"] is not None:
                private_key = inp["private_key"].hex
                public_key = inp["public_key"].hex

            input_key = {
                "input_index": inp["input_index"],
                "private_key": private_key,
                "public_key": public_key,
                "prevout_txid": inp["prevout_txid"].hex(),
                "prevout_index": inp["prevout_index"],
                "prevout_scriptpubkey": inp.get(
                    "witness_script", inp.get("script_pubkey", b"")
                ).hex(),
                "amount": inp["amount"],
                "witness_utxo": inp.get("witness_utxo", inp.get("prev_tx", b"")).hex(),
                "sequence": inp["sequence"],
                "signed": inp["input_index"] in signed_input_indices,
            }
            input_keys.append(input_key)

        scan_keys = []
        for _, (scan_pub, spend_pub) in psbt_data["scan_keys"].items():
            scan_key = {
                "scan_pubkey": scan_pub.hex
                if hasattr(scan_pub, "hex")
                else str(scan_pub),
                "spend_pubkey": spend_pub.hex
                if hasattr(spend_pub, "hex")
                else str(spend_pub),
            }
            scan_keys.append(scan_key)

        global_scan_keys = psbt_data["scenario"].use_global_ecdh or []

        expected_ecdh_shares = []
        # Global ECDH shares: one summed entry per scan key, no input_index
        if global_scan_keys:
            global_sums = {}  # scan_key_id -> summed ecdh_result
            global_priv_sums = {}  # scan_key_id -> summed private key
            for (input_idx, scan_key_id), (ecdh_result, _) in psbt_data[
                "ecdh_data"
            ].items():
                if (
                    scan_key_id in global_scan_keys
                    and scan_key_id in psbt_data["scan_keys"]
                ):
                    if scan_key_id not in global_sums:
                        global_sums[scan_key_id] = ecdh_result
                    else:
                        global_sums[scan_key_id] += ecdh_result
                    # Sum private keys for DLEQ proof
                    for inp in psbt_data["input_data"]:
                        if inp["input_index"] == input_idx and inp.get("is_eligible"):
                            if scan_key_id not in global_priv_sums:
                                global_priv_sums[scan_key_id] = inp["private_key"]
                            else:
                                global_priv_sums[scan_key_id] = (
                                    global_priv_sums[scan_key_id] + inp["private_key"]
                                )
            for scan_key_id, summed_ecdh in global_sums.items():
                scan_pub = psbt_data["scan_keys"][scan_key_id][0]
                entry = {
                    "scan_key": scan_pub.hex
                    if hasattr(scan_pub, "hex")
                    else str(scan_pub),
                    "ecdh_result": summed_ecdh.to_bytes_compressed().hex(),
                }
                if scan_key_id in global_priv_sums and not scenario.missing_global_dleq:
                    global_dleq_proof = self.builder._compute_global_dleq_proof(
                        scan_key_id, global_priv_sums[scan_key_id], scan_pub
                    )
                    entry["dleq_proof"] = global_dleq_proof.hex()
                expected_ecdh_shares.append(entry)

        # Per-input ECDH shares: one entry per (input, scan_key), with input_index
        for (input_idx, scan_key_id), (ecdh_result, dleq_proof) in psbt_data[
            "ecdh_data"
        ].items():
            if scan_key_id in global_scan_keys:
                continue
            if scan_key_id in psbt_data["scan_keys"]:
                ecdh_share = {
                    "scan_key": psbt_data["scan_keys"][scan_key_id][0].hex
                    if hasattr(psbt_data["scan_keys"][scan_key_id][0], "hex")
                    else str(psbt_data["scan_keys"][scan_key_id][0]),
                    "ecdh_result": ecdh_result.to_bytes_compressed().hex(),
                    "dleq_proof": dleq_proof.hex() if dleq_proof else None,
                    "input_index": input_idx,
                }
                expected_ecdh_shares.append(ecdh_share)

        expected_outputs = []
        for out in psbt_data["output_data"]:
            output = {
                "output_index": out["output_index"],
                "amount": out["amount"],
                "is_silent_payment": out["output_type"] == OutputType.SILENT_PAYMENT,
            }

            if out["output_type"] == OutputType.SILENT_PAYMENT:
                scan_pub = out["scan_pubkey"]
                spend_pub = out["spend_pubkey"]
                output["sp_info"] = (scan_pub.bytes + spend_pub.bytes).hex()
                if out.get("label") is not None:
                    output["sp_label"] = out["label"]
            else:
                output["script"] = out["script"].hex()

            expected_outputs.append(output)

        test_dict = {
            "description": scenario.description,
            "psbt": base64.b64encode(psbt.serialize()).decode(),
            "input_keys": input_keys,
            "scan_keys": scan_keys,
            "expected_ecdh_shares": expected_ecdh_shares,
            "expected_outputs": expected_outputs,
        }
        if scenario.checks:
            test_dict["checks"] = scenario.checks
        return test_dict


# ============================================================================
# Test Vector Generator Section
# ============================================================================


class TestVectorGenerator:
    """Main class to generate test vectors from configurations and code based scenarios"""

    def __init__(self, seed: str = "bip375_deterministic_seed"):
        self.config_generator = ConfigBasedTestGenerator(seed)
        self.test_vectors = {
            "description": "BIP-375 Test Vectors",
            "version": "1.2",
            "notes": [
                "Generated by https://github.com/macgyver13/bip375-test-generator/",
                "Each vector includes: psbt (source of truth), supporting material (input_keys, scan_keys, expected_ecdh_shares, expected_outputs)",
                "PSBTs are base64-encoded and all that is needed to process each test vector",
                "'checks' can be used to force specific validation behavior that would otherwise be caught by a previous validation"
            ],
            "invalid": [],
            "valid": [],
        }

    def generate_all_test_vectors(self) -> Dict:
        """Generate all test vectors using configuration files"""
        # Load test configurations
        test_configs_dir = Path(__file__).parent / "test_configs"

        # Load invalid test cases
        invalid_configs = list(test_configs_dir.glob("invalid/**/*.yaml"))
        for config_file in sorted(invalid_configs):
            try:
                scenarios = self.config_generator.load_test_scenarios_from_config(
                    str(config_file)
                )
                for scenario in scenarios:
                    test_vector = (
                        self.config_generator.generate_test_vector_from_scenario(
                            scenario
                        )
                    )
                    self.test_vectors["invalid"].append(test_vector)
            except Exception as e:
                print(f"Error loading {config_file}: {str(e)}")
                import traceback

                traceback.print_exc()

        # Load valid test cases
        valid_configs = list(test_configs_dir.glob("valid/**/*.yaml"))
        for config_file in sorted(valid_configs):
            try:
                scenarios = self.config_generator.load_test_scenarios_from_config(
                    str(config_file)
                )
                for scenario in scenarios:
                    test_vector = (
                        self.config_generator.generate_test_vector_from_scenario(
                            scenario
                        )
                    )
                    self.test_vectors["valid"].append(test_vector)
            except Exception as e:
                print(f"Error loading {config_file}: {str(e)}")
                import traceback

                traceback.print_exc()

        return self.test_vectors


    def save_test_vectors(self, filename: str = "test_vectors.json"):
        """Generate and save all test vectors"""
        all_vectors = self.generate_all_test_vectors()

        with open(filename, "w") as f:
            json.dump(all_vectors, f, indent=2)

        print(
            f"Generated {len(all_vectors['invalid'])} invalid and {len(all_vectors['valid'])} valid test vectors"
        )
        print(f"Saved to {filename}")


if __name__ == "__main__":
    # Create test configs directory structure if it doesn't exist
    test_configs_dir = Path(__file__).parent / "test_configs"
    test_configs_dir.mkdir(exist_ok=True)
    (test_configs_dir / "invalid").mkdir(exist_ok=True)
    (test_configs_dir / "valid").mkdir(exist_ok=True)

    # Default: save to parent directory
    default_output = Path(__file__).parent / "bip375_test_vectors.json"

    generator = TestVectorGenerator()
    generator.save_test_vectors(str(default_output))
