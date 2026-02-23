#!/usr/bin/env python3
"""
BIP-375 Test Vector Generator

Configuration-driven system for generating test vectors with support for large PSBTs.
Organized by validation type → input/output type → complexity.
"""

import base64
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
from importlib.metadata import version
import os
from pathlib import Path
import struct
import sys
from typing import Dict, List, Optional, Any, Tuple
import yaml

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_framework.crypto.secp256k1 import GE, G
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, hash256, uint256_from_str
from test_framework.script import SIGHASH_ALL, SIGHASH_NONE, hash160
from test_framework.script_util import (
    key_to_p2pkh_script,
    keys_to_multisig_script,
    output_key_to_p2tr_script,
    program_to_witness_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
import spdk_psbt
from spdk_psbt import (
    add_raw_global_field,
    add_raw_input_field,
    add_raw_output_field,
    remove_raw_input_fields_by_type,
    SilentPaymentPsbt,
    PsbtOutput
)

print(f"Using spdk_psbt version {version('spdk_psbt')}")

from generator_utils import (
    PSBTKeyType,
    PrivateKey,
    PublicKey,
    Wallet,
    UTXO,
    compute_bip352_output_script,
    apply_label_to_spend_key,
    compute_transaction_id,
    sign_p2wpkh_input,
    sign_p2pkh_input,
    sign_p2tr_input,
    verify_receiver_detects_outputs,
    verify_no_empty_output_script_headers,
    normalize_psbt_field_order,
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


def _sorted_outpoints_and_input_map(
    all_inputs: List[Dict],
    eligible_inputs: List[Dict],
) -> tuple:
    """Sort outpoints lexicographically and build eligible input index map.

    Outpoints are from ALL inputs (BIP-352: outpoint_L is the smallest
    outpoint in the transaction). The index map only contains eligible
    inputs for pubkey/ECDH summation.
    """
    outpoints = [(inp["previous_txid"], inp["prevout_index"]) for inp in all_inputs]
    outpoints.sort(key=lambda x: (x[0], x[1]))
    outpoint_to_input = {
        (inp["previous_txid"], inp["prevout_index"]): inp for inp in eligible_inputs
    }
    return outpoints, outpoint_to_input


def _sum_pubkeys_in_outpoint_order(
    outpoints: List[tuple],
    outpoint_to_input: Dict,
):
    """Sum input public keys in sorted outpoint order (BIP-352 requirement)."""
    summed = None
    for outpoint in outpoints:
        if outpoint not in outpoint_to_input:
            continue
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
    eligible_outpoints = [op for op in outpoints if op in outpoint_to_input]
    for outpoint in eligible_outpoints:
        inp = outpoint_to_input[outpoint]
        ecdh_key = (inp["input_index"], scan_key_id)
        if ecdh_key in ecdh_data:
            ecdh_result, _ = ecdh_data[ecdh_key]
            inputs_with_ecdh.add(inp["input_index"])
            summed = ecdh_result if summed is None else summed + ecdh_result
    return summed, len(inputs_with_ecdh) == len(eligible_outpoints)


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
    skip_signing: bool = False  # Force input to remain unsigned even if eligible


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
    exclude_material: List[str] = field(default_factory=list)  # List of material fields to exclude from test vector (e.g. ["inputs", "sp_proofs", "outputs"])

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
    force_ecdh_for_input_scan_key: Optional[tuple] = None  # (input_index, scan_key_id)
    force_partial_ecdh_output_script: bool = False
    skip_regular_output_script: bool = False
    empty_regular_output_script: bool = False


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
            result = self._create_p2tr_input(spec, input_index)
        else:
            raise ValueError(f"Unknown input type: {spec.input_type}")

        if spec.eligible_override is not None:
            result["is_eligible"] = spec.eligible_override

        if spec.skip_signing:
            result["skip_signing"] = True

        return result

    def _create_p2wpkh_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2WPKH input"""
        # Deterministic key generation
        key_suffix = f"{spec.key_derivation_suffix}_{input_index}"
        input_priv, input_pub = self.wallet.create_key_pair(
            "input", _deterministic_hash(key_suffix)
        )

        # Create prevout
        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_prevout_{input_index}".encode()
        ).digest()

        # P2WPKH witness program. Error injection: use segwit v2 instead of v0.
        segwit_version = 2 if spec.use_segwit_v2 else 0
        script_pubkey = bytes(
            program_to_witness_script(segwit_version, hash160(input_pub.bytes))
        )
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
        previous_txid = hash256(prev_tx)

        witness_utxo = CTxOut(spec.amount, script_pubkey).serialize()

        return {
            "input_index": input_index,
            "input_type": InputType.P2WPKH,
            "private_key": input_priv,
            "public_key": input_pub,
            "previous_txid": previous_txid,
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "witness_utxo": witness_utxo,
            "non_witness_utxo": prev_tx,
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

        script_pubkey = bytes(key_to_p2pkh_script(input_pub.bytes))

        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_p2pkh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
        previous_txid = hash256(prev_tx)

        return {
            "input_index": input_index,
            "input_type": InputType.P2PKH,
            "private_key": input_priv,
            "public_key": input_pub,
            "previous_txid": previous_txid,
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "non_witness_utxo": prev_tx,
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

        # Redeem script is the inner P2WPKH witness program: OP_0 <20-byte hash>
        redeem_script = bytes(program_to_witness_script(0, hash160(input_pub.bytes)))
        # P2SH scriptPubKey wrapping the redeem script
        script_pubkey = bytes(script_to_p2sh_script(redeem_script))

        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_p2sh_p2wpkh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
        previous_txid = hash256(prev_tx)

        # PSBT_IN_WITNESS_UTXO for P2SH-P2WPKH uses the P2SH scriptPubKey
        witness_utxo = CTxOut(spec.amount, script_pubkey).serialize()

        return {
            "input_index": input_index,
            "input_type": InputType.P2SH_P2WPKH,
            "private_key": input_priv,
            "public_key": input_pub,
            "previous_txid": previous_txid,
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "redeem_script": redeem_script,
            "witness_utxo": witness_utxo,
            "non_witness_utxo": prev_tx,
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

        script = bytes(keys_to_multisig_script(
            [pub_key.to_bytes_compressed() for _, pub_key in keys], k=threshold
        ))

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

        # P2SH scriptPubKey wrapping the multisig redeem script
        script_pubkey = bytes(script_to_p2sh_script(redeem_script))

        # Create non-witness UTXO for P2SH
        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_p2sh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)

        result = self._multisig_common_fields(keys, spec, input_index)
        result.update({
            "input_type": InputType.P2SH_MULTISIG,
            "previous_txid": hash256(prev_tx),
            "script_pubkey": script_pubkey,
            "redeem_script": redeem_script,
            "non_witness_utxo": prev_tx,
        })
        return result

    def _create_p2wsh_multisig_input(
        self, spec: InputSpec, input_index: int
    ) -> Dict[str, Any]:
        """Create P2WSH multisig input"""
        keys, witness_script = self._generate_multisig_keys_and_script(
            spec, input_index, "wsh_multisig"
        )

        # P2WSH scriptPubKey wrapping the multisig witness script
        script_pubkey = bytes(script_to_p2wsh_script(witness_script))

        # Create witness UTXO
        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_p2wsh_prevout_{input_index}".encode()
        ).digest()
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
        previous_txid = hash256(prev_tx)

        witness_utxo = CTxOut(spec.amount, script_pubkey).serialize()

        result = self._multisig_common_fields(keys, spec, input_index)
        result.update({
            "input_type": InputType.P2WSH_MULTISIG,
            "previous_txid": previous_txid,
            "script_pubkey": script_pubkey,
            "witness_script": witness_script,
            "witness_utxo": witness_utxo,
            "non_witness_utxo": prev_tx,
        })
        return result

    def _create_p2tr_input(self, spec: InputSpec, input_index: int) -> Dict[str, Any]:
        """Create P2TR key-path input (unsigned/WIP — no taptweak applied)."""
        key_suffix = f"{spec.key_derivation_suffix}_{input_index}"
        input_priv, input_pub = self.wallet.create_key_pair(
            "input", _deterministic_hash(key_suffix)
        )

        prev_input_txid = hashlib.sha256(
            f"{self.base_seed}_p2tr_prevout_{input_index}".encode()
        ).digest()

        # Negate private key if pubkey has odd y (BIP340 even-y requirement for lift_x)
        if int(input_pub.y) % 2 != 0:
            input_priv = PrivateKey(GE.ORDER - int(input_priv))
            input_pub = PublicKey(int(input_priv) * G)

        if spec.use_nums_tap_internal_key:
            # NUMS point as taproot internal key: no private key exists, input is ineligible
            # for Silent Payments (cannot contribute an ECDH share).
            script_pubkey = bytes(output_key_to_p2tr_script(NUMS_H))
            prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
            previous_txid = hash256(prev_tx)

            witness_utxo = CTxOut(spec.amount, script_pubkey).serialize()
            return {
                "input_index": input_index,
                "input_type": InputType.P2TR,
                "private_key": input_priv,
                "public_key": input_pub,
                "tap_internal_key": NUMS_H,
                "previous_txid": previous_txid,
                "prevout_index": 0,
                "script_pubkey": script_pubkey,
                "witness_utxo": witness_utxo,
                "non_witness_utxo": prev_tx,
                "amount": spec.amount,
                "sequence": spec.sequence,
                "is_eligible": False,
            }

        # P2TR scriptPubKey: OP_1 + 32-byte x-only key
        script_pubkey = bytes(output_key_to_p2tr_script(input_pub.bytes_xonly))
        prev_tx = self._create_prev_tx(prev_input_txid, spec.amount, script_pubkey)
        previous_txid = hash256(prev_tx)
        witness_utxo = CTxOut(spec.amount, script_pubkey).serialize()

        return {
            "input_index": input_index,
            "input_type": InputType.P2TR,
            "private_key": input_priv,
            "public_key": input_pub,
            "previous_txid": previous_txid,
            "prevout_index": 0,
            "script_pubkey": script_pubkey,
            "witness_utxo": witness_utxo,
            "non_witness_utxo": prev_tx,
            "amount": spec.amount,
            "sequence": spec.sequence,
            "is_eligible": True,
        }

    def _create_prev_tx(
        self, prev_input_txid: bytes, amount: int, script_pubkey: bytes
    ) -> bytes:
        """Create a previous transaction for non-witness UTXOs"""
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = 0
        tx.vin.append(
            CTxIn(COutPoint(uint256_from_str(prev_input_txid), 0), b"", 0xFFFFFFFF)
        )
        tx.vout.append(CTxOut(amount, bytes(script_pubkey)))
        return tx.serialize_without_witness()


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
            "base_spend_pubkey": spend_pub,
            "label": spec.label,
            "force_wrong_script": spec.force_wrong_script,
            "force_k_index": spec.force_k_index,
        }

    def _create_regular_p2tr_output(
        self, spec: OutputSpec, output_index: int
    ) -> Dict[str, Any]:
        """Create regular P2TR output"""
        if spec.add_bip32_derivation:
            raise ValueError(
                "add_bip32_derivation is not supported for p2tr outputs: taproot "
                "requires PSBT_OUT_TAP_BIP32_DERIVATION (0x07), which is not implemented"
            )
        # Simple P2TR output for testing
        output_script = bytes(output_key_to_p2tr_script(
            hashlib.sha256(f"regular_p2tr_{output_index}".encode()).digest()
        ))

        return {
            "output_index": output_index,
            "output_type": OutputType.REGULAR_P2TR,
            "amount": spec.amount,
            "script": output_script,
        }

    def _create_regular_p2wpkh_output(
        self, spec: OutputSpec, output_index: int
    ) -> Dict[str, Any]:
        """Create regular P2WPKH output"""
        # Derive a real key so the scriptPubKey and any PSBT_OUT_BIP32_DERIVATION
        # describe the same output (hash160(change_pub) == witness program).
        _, change_pub = self.wallet.create_key_pair("change_p2wpkh", output_index)
        output_script = bytes(program_to_witness_script(0, hash160(change_pub.bytes)))

        return {
            "output_index": output_index,
            "output_type": OutputType.REGULAR_P2WPKH,
            "amount": spec.amount,
            "script": output_script,
            "change_pubkey": change_pub,
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

        # Auto-sign all eligible inputs when output scripts are complete
        if self._should_auto_sign(scenario):
            for input_info in input_data:
                if input_info.get("is_eligible", False) and not input_info.get("skip_signing", False):
                    self._sign_single_input(
                        psbt, input_info, input_data, finalized_outputs, input_info["input_index"]
                    )
                    signed_input_indices.add(input_info["input_index"])
            if not scenario.set_tx_modifiable:
                psbt.set_tx_modifiable(0x00)

        # Self-check valid scenarios from the receiver side (independent oracle).
        if scenario.validation_result == ValidationResult.VALID:
            verify_receiver_detects_outputs(input_data, output_data, self.scan_privs)

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
        """Generate scan/spend key pairs deterministically.

        Also records the scan private key for each scan public key in
        self.scan_privs (keyed by compressed scan pubkey bytes) so labeled
        spend keys can be computed with the correct scan key. The map is reset
        on every call since the builder is reused across scenarios.
        """
        scan_keys = {}
        self.scan_privs: Dict[bytes, PrivateKey] = {}

        for spec in scan_key_specs:
            if spec.key_id == "default":
                # Use wallet's default keys
                scan_priv, scan_pub = self.wallet.scan_priv, self.wallet.scan_pub
                scan_keys[spec.key_id] = (scan_pub, self.wallet.spend_pub)
            else:
                # Generate deterministic keys
                seed_suffix = _deterministic_hash(
                    f"{spec.key_id}_{spec.derivation_suffix}"
                )
                scan_priv, scan_pub = self.wallet.create_key_pair("scan", seed_suffix)
                _, spend_pub = self.wallet.create_key_pair("spend", seed_suffix)
                scan_keys[spec.key_id] = (scan_pub, spend_pub)

            self.scan_privs[scan_pub.to_bytes_compressed()] = scan_priv

        return scan_keys

    def _add_input_to_psbt(self, psbt: SilentPaymentPsbt, input_info: Dict[str, Any]):
        """Add input fields to PSBT based on input type"""
        idx = input_info["input_index"]
        input_type = input_info["input_type"]

        # Add common fields
        add_raw_input_field(
            psbt, idx, PSBTKeyType.PSBT_IN_PREVIOUS_TXID, b"", input_info["previous_txid"]
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
                input_info["non_witness_utxo"],
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
                input_info["non_witness_utxo"],
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
                input_info["non_witness_utxo"],
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
            k: v for k, v in ecdh_data.items()
            if k[1] not in global_scan_keys
            or (scenario.force_ecdh_for_input_scan_key is not None
                and k == scenario.force_ecdh_for_input_scan_key)
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
                    SIGHASH_NONE
                    if scenario.wrong_sighash_for_input == input_idx
                    else SIGHASH_ALL
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
                    # SIGHASH_NONE does not commit to the intentionally empty outputs.
                    # For segwit v2 tests, only the signature's presence matters.
                    if scenario.wrong_sighash_for_input == input_idx:
                        assert sighash_type == SIGHASH_NONE, (
                            "empty output_data is only valid for SIGHASH_NONE; "
                            "SIGHASH_SINGLE commits to the output at this index"
                        )
                    input_info = self._find_input_info_by_index(input_data, input_idx)
                    if input_info and input_info.get("is_eligible", False):
                        self._sign_single_input(
                            psbt,
                            input_info,
                            input_data,
                            [],
                            input_idx,
                            sighash_type=sighash_type,
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
        sighash_type: int = SIGHASH_ALL,
    ):
        """Sign a single input and add the appropriate PSBT signature field.

        For SIGHASH_NONE error-injection tests, output_data may be empty because
        the signature does not commit to outputs. For segwit v2 tests, only the
        signature's presence matters.
        For valid test vectors, pass the real output_data so the sighash commits
        to the correct outputs.
        """
        input_type = input_info.get("input_type")

        # Build UTXO list from all inputs (needed for sighash computation)
        utxos = []
        for inp in input_data:
            utxos.append(
                UTXO(
                    txid=inp["previous_txid"].hex(),
                    vout=inp["prevout_index"],
                    amount=inp["amount"],
                    script_pubkey=inp.get("script_pubkey", b"").hex(),
                    private_key=inp.get("private_key"),
                    sequence=inp.get("sequence", 0xFFFFFFFE),
                )
            )

        # Build output list for sighash commitment.
        # _add_outputs_to_psbt produces dicts with key "script_pubkey" (hex string).
        outputs = []
        for out in output_data:
            script = out.get("script_pubkey", "")
            outputs.append({
                "amount": out["amount"],
                "script_pubkey": script.hex() if isinstance(script, bytes) else script,
            })

        if input_type == InputType.P2TR:
            signature = sign_p2tr_input(
                private_key=int(input_info["private_key"]),
                inputs=utxos,
                outputs=outputs,
                input_index=input_idx,
                sighash_type=sighash_type,
            )
            add_raw_input_field(
                psbt,
                input_idx,
                PSBTKeyType.PSBT_IN_TAP_KEY_SIG,
                b"",
                signature,
            )
            return

        if input_type == InputType.P2PKH:
            # P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
            pubkey_hash = input_info["script_pubkey"][3:-2]
        elif input_type == InputType.P2SH_P2WPKH:
            # Inner P2WPKH redeem_script: OP_0 <20-byte hash>
            pubkey_hash = input_info["redeem_script"][2:]
        else:
            # P2WPKH script_pubkey: OP_0 <20-byte hash>
            pubkey_hash = input_info["script_pubkey"][2:]

        if input_type == InputType.P2PKH:
            signature = sign_p2pkh_input(
                private_key=int(input_info["private_key"]),
                inputs=utxos,
                outputs=outputs,
                input_index=input_idx,
                pubkey_hash=pubkey_hash,
                sighash_type=sighash_type,
            )
        else:
            signature = sign_p2wpkh_input(
                private_key=int(input_info["private_key"]),
                inputs=utxos,
                outputs=outputs,
                input_index=input_idx,
                pubkey_hash=pubkey_hash,
                amount=input_info["amount"],
                sighash_type=sighash_type,
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
                    scalar = int.from_bytes(hashlib.sha256(f"fake_ecdh_{i}".encode()).digest(), 'big') % GE.ORDER
                    fake_ecdh_bytes = (scalar * G).to_bytes_compressed()
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

    def _canonical_k_map(self, output_data: List[Dict]) -> Dict[int, int]:
        """Map output_index -> k per the BIP-375 canonical ordering.

        Group silent payment outputs by scan key, then within each group sort
        the codes lexicographically in ascending order to determine the k
        ordering, breaking ties (same scan and spend keys) by output index. The
        code's spend key is the labeled spend key B_m when a label is present,
        since that is the key carried in the silent payment address.
        """
        groups: Dict[bytes, List[Tuple[bytes, int]]] = {}
        for output_info in output_data:
            if output_info["output_type"] != OutputType.SILENT_PAYMENT:
                continue
            scan_pub = output_info["scan_pubkey"]
            spend_pub = output_info["base_spend_pubkey"]
            if output_info.get("label") is not None:
                spend_pub = self._compute_labeled_spend_key(
                    scan_pub, spend_pub, output_info["label"]
                )
            groups.setdefault(scan_pub.to_bytes_compressed(), []).append(
                (spend_pub.to_bytes_compressed(), output_info["output_index"])
            )

        k_map: Dict[int, int] = {}
        for entries in groups.values():
            entries.sort()  # (spend_key_bytes, output_index) ascending
            for k, (_, output_index) in enumerate(entries):
                k_map[output_index] = k
        return k_map

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
        # BIP-375 canonical k assignment: precompute output_index -> k by sorting
        # each scan-key group's codes lexicographically (tie-break by output index).
        k_map = self._canonical_k_map(output_data)
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
                    psbt, output_info, input_data, ecdh_data, scenario, scan_keys, k_map[idx]
                )
                if script:
                    output_info["script"] = script
                    add_raw_output_field(
                        psbt, idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", script
                    )
                finalized_outputs.append({
                    "amount": output_info["amount"],
                    "script_pubkey": script.hex() if script else "",
                })

            else:
                # Regular output - add script and optional BIP32_DERIVATION
                if not scenario.skip_regular_output_script:
                    if scenario.empty_regular_output_script:
                        psbt.add_outputs([
                            PsbtOutput.REGULAR(
                                amount=output_info["amount"],
                                script_pubkey=b"")
                            ]
                        )
                    else:
                        add_raw_output_field(
                            psbt, idx, PSBTKeyType.PSBT_OUT_SCRIPT, b"", output_info["script"]
                        )
                finalized_outputs.append({
                    "amount": output_info["amount"],
                    "script_pubkey": output_info["script"].hex(),
                })

                # Add BIP32_DERIVATION if requested (for change identification)
                if output_info.get("add_bip32_derivation", False):
                    self._add_output_bip32_derivation(psbt, idx, output_info)

        return finalized_outputs

    def _add_silent_payment_output(
        self,
        psbt: SilentPaymentPsbt,
        output_info: Dict,
        input_data: List[Dict],
        ecdh_data: Dict,
        scenario: TestScenario,
        scan_keys: Dict[str, tuple],
        k: int,
    ) -> Optional[bytes]:
        """Add silent payment output with proper BIP-352 script computation.

        k is the canonical BIP-375 k value for this output (see _canonical_k_map).
        Returns the computed output script bytes, or None if no script was set.
        """
        idx = output_info["output_index"]
        scan_pub = output_info["scan_pubkey"]
        base_spend_pub = output_info["base_spend_pubkey"]
        output_script: Optional[bytes] = None

        # Apply BIP-352 label if specified
        spend_pub = base_spend_pub
        if output_info.get("label") is not None:
            spend_pub = self._compute_labeled_spend_key(
                scan_pub, base_spend_pub, output_info["label"]
            )
        output_info["spend_pubkey"] = spend_pub

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
                    input_data, eligible_inputs
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
                        # k is the canonical BIP-375 value; force_k_index overrides
                        # it for error injection.
                        k_index = k
                        if output_info["force_k_index"] is not None:
                            k_index = output_info["force_k_index"]
                        # Compute BIP-352 output script
                        output_script = compute_bip352_output_script(
                            outpoints=outpoints,
                            summed_pubkey_bytes=summed_pubkey_bytes,
                            ecdh_share_bytes=ecdh_share_bytes,
                            spend_pubkey_bytes=spend_pub.to_bytes_compressed(),
                            k=k_index,
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
            output_info["sp_v0_info"] = sp_info
            if scenario.wrong_sp_info_size:
                sp_info = sp_info[:65]  # Wrong size (65 instead of 66)

            add_raw_output_field(psbt, idx, PSBTKeyType.PSBT_OUT_SP_V0_INFO, b"", sp_info)

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
        self, scan_pub, spend_pub, label: int
    ):
        """Compute BIP-352 labeled spend key: B_m = B_spend + hash_BIP0352/Label(b_scan || m) * G

        Uses the scan private key belonging to scan_pub (not the wallet default),
        so labeled spend keys are correct for non-default scan keys.
        """
        scan_priv = self.scan_privs[scan_pub.to_bytes_compressed()]
        scan_priv_bytes = scan_priv.to_bytes(32, "big")
        return PublicKey(apply_label_to_spend_key(spend_pub, scan_priv_bytes, label))

    def _add_output_bip32_derivation(
        self, psbt: SilentPaymentPsbt, output_idx: int, output_info: Dict
    ):
        """Add PSBT_OUT_BIP32_DERIVATION for change identification"""
        # Use the output's own change key so hash160(pubkey) == the witness program.
        pubkey = output_info["change_pubkey"]

        # Format: 4-byte master fingerprint + path (4 bytes per level, m/0/1).
        # The origin is a fixed test-vector placeholder (no HD master exists); no
        # BIP-375 role reads it. The pubkey above is the field's factual part.
        master_fingerprint = struct.pack(">I", 0)  # placeholder fingerprint
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
                skip_signing=input_config.get("skip_signing", False),
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
                    skip_signing=input_spec.skip_signing,
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
            exclude_material=config.get("exclude_material", []),
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
            force_ecdh_for_input_scan_key=(
                (
                    control_override["force_ecdh_for_input_scan_key"]["input_index"],
                    control_override["force_ecdh_for_input_scan_key"]["scan_key_id"],
                )
                if control_override.get("force_ecdh_for_input_scan_key")
                else None
            ),
            force_partial_ecdh_output_script=control_override.get(
                "force_partial_ecdh_output_script", False
            ),
            skip_regular_output_script=control_override.get(
                "skip_regular_output_script", False
            ),
            empty_regular_output_script=control_override.get(
                "empty_regular_output_script", False
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

            utxo_field = {"non_witness_utxo": inp["non_witness_utxo"].hex()}
            if "witness_utxo" in inp:
                utxo_field["witness_utxo"] = inp["witness_utxo"].hex()

            input_key = {
                "input_index": inp["input_index"],
                "private_key": private_key,
                "public_key": public_key,
                "prevout_txid": inp["previous_txid"][::-1].hex(),
                "prevout_index": inp["prevout_index"],
                "amount": inp["amount"],
                **utxo_field,
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
                    "ecdh_share": summed_ecdh.to_bytes_compressed().hex(),
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
                    "ecdh_share": ecdh_result.to_bytes_compressed().hex(),
                    "dleq_proof": dleq_proof.hex() if dleq_proof else None,
                    "input_index": input_idx,
                }
                expected_ecdh_shares.append(ecdh_share)

        expected_outputs = []
        for out in psbt_data["output_data"]:
            output = {
                "output_index": out["output_index"],
                "amount": out["amount"],
            }

            if out["output_type"] == OutputType.SILENT_PAYMENT:
                scan_pub = out["scan_pubkey"]
                spend_pub = out["spend_pubkey"]
                output["sp_v0_info"] = (scan_pub.bytes + spend_pub.bytes).hex()
                if out.get("label") is not None:
                    output["sp_v0_label"] = out["label"]
                if out.get("script") is not None:
                    output["script"] = out["script"].hex()
            else:
                output["script"] = out["script"].hex()

            expected_outputs.append(output)

        serialized_psbt = psbt.serialize()
        serialized_psbt = normalize_psbt_field_order(serialized_psbt)
        verify_no_empty_output_script_headers(serialized_psbt, scenario.description)
        test_dict = {
            "description": scenario.description,
            "psbt": base64.b64encode(serialized_psbt).decode(),
        }
        all_material = {
            "inputs": input_keys,
            "sp_proofs": expected_ecdh_shares,
            "outputs": expected_outputs,
        }
        for key in scenario.exclude_material:
            all_material.pop(key, None)
        if scenario.validation_result == ValidationResult.VALID:
            all_material["unique_id"] = compute_transaction_id(
                psbt_data["input_data"], psbt_data["output_data"]
            )
        test_dict["supplementary"] = all_material
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
            "version": "1.2.0",
            "notes": [
                "Generated by https://github.com/macgyver13/bip375-test-generator/",
                "Each vector includes: base64-encoded psbt and description",
                "Supplementary material (inputs, outputs, sp_proofs) is included for diagnostics and should not be used for validation",
                "'checks' overrides the validation sequence, e.g. skip structure checks to test input eligibility"
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
            except AssertionError:
                raise
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
            except AssertionError:
                raise
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
