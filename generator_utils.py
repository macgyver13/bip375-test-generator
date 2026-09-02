#!/usr/bin/env python3
"""
Utilities for the BIP-375 test vector generator.

Provides the BIP-352 crypto wrappers (spdk_psbt), PSBT key type constants,
deterministic key generation, and transaction signing. Bitcoin primitive
assembly (transactions, scripts, sighash, signing) is delegated to the
vendored Bitcoin Core test_framework; only the BIP-375 silent-payment
specifics remain custom here.

txid handling: All txids in our data structures are in internal byte order
(hash digest). When constructing PSBTs we convert to display byte order
(RPC format) as needed.
"""

from dataclasses import dataclass
import hashlib
from io import BytesIO
from typing import Dict, List, Optional, Tuple

import spdk_psbt

from test_framework import psbt as _tf_psbt
from test_framework.crypto.secp256k1 import GE, G
from test_framework.key import (
    ECKey,
    sign_schnorr,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    hash256,
    uint256_from_str,
)
from test_framework.script import (
    SIGHASH_ALL,
    LegacySignatureHash,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
)
from test_framework.script_util import keyhash_to_p2pkh_script


# ============================================================================
# PSBT Key Type Constants
# ============================================================================


class PSBTKeyType:
    """PSBT key type constants.

    Standard BIP-174/370 fields are sourced from the vendored Bitcoin Core
    test_framework; the BIP-375 silent-payment fields below have no Core
    equivalent and are defined from the BIP.
    """

    # Standard BIP-174/370 fields (Bitcoin Core test_framework)
    PSBT_GLOBAL_UNSIGNED_TX = _tf_psbt.PSBT_GLOBAL_UNSIGNED_TX
    PSBT_GLOBAL_TX_VERSION = _tf_psbt.PSBT_GLOBAL_TX_VERSION
    PSBT_GLOBAL_TX_MODIFIABLE = _tf_psbt.PSBT_GLOBAL_TX_MODIFIABLE
    PSBT_GLOBAL_VERSION = _tf_psbt.PSBT_GLOBAL_VERSION

    PSBT_IN_NON_WITNESS_UTXO = _tf_psbt.PSBT_IN_NON_WITNESS_UTXO
    PSBT_IN_WITNESS_UTXO = _tf_psbt.PSBT_IN_WITNESS_UTXO
    PSBT_IN_PARTIAL_SIG = _tf_psbt.PSBT_IN_PARTIAL_SIG
    PSBT_IN_SIGHASH_TYPE = _tf_psbt.PSBT_IN_SIGHASH_TYPE
    PSBT_IN_REDEEM_SCRIPT = _tf_psbt.PSBT_IN_REDEEM_SCRIPT
    PSBT_IN_WITNESS_SCRIPT = _tf_psbt.PSBT_IN_WITNESS_SCRIPT
    PSBT_IN_BIP32_DERIVATION = _tf_psbt.PSBT_IN_BIP32_DERIVATION
    PSBT_IN_PREVIOUS_TXID = _tf_psbt.PSBT_IN_PREVIOUS_TXID
    PSBT_IN_OUTPUT_INDEX = _tf_psbt.PSBT_IN_OUTPUT_INDEX
    PSBT_IN_SEQUENCE = _tf_psbt.PSBT_IN_SEQUENCE
    PSBT_IN_TAP_KEY_SIG = _tf_psbt.PSBT_IN_TAP_KEY_SIG
    PSBT_IN_TAP_INTERNAL_KEY = _tf_psbt.PSBT_IN_TAP_INTERNAL_KEY

    PSBT_OUT_BIP32_DERIVATION = _tf_psbt.PSBT_OUT_BIP32_DERIVATION
    PSBT_OUT_AMOUNT = _tf_psbt.PSBT_OUT_AMOUNT
    PSBT_OUT_SCRIPT = _tf_psbt.PSBT_OUT_SCRIPT

    # BIP-375 silent payment fields (no Bitcoin Core equivalent)
    PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
    PSBT_GLOBAL_SP_DLEQ = 0x08
    PSBT_IN_SP_ECDH_SHARE = 0x1D
    PSBT_IN_SP_DLEQ = 0x1E
    PSBT_OUT_SP_V0_INFO = 0x09
    PSBT_OUT_SP_V0_LABEL = 0x0A


# ============================================================================
# EC Key Types
# ============================================================================


class PrivateKey(int):
    """Private key (int subclass) with serialization helpers."""

    def __new__(cls, value: int):
        return super().__new__(cls, value)

    @property
    def bytes(self) -> bytes:
        return super().to_bytes(32, "big")

    @property
    def hex(self) -> str:
        return self.bytes.hex()

    def __add__(self, other):
        return PrivateKey((int(self) + int(other)) % GE.ORDER)

    def __mul__(self, other):
        result = super().__mul__(other)
        return PrivateKey(result) if isinstance(other, int) else result

    def __repr__(self):
        return f"PrivateKey({int(self)})"


class PublicKey(GE):
    """Public key (GE subclass) with serialization helpers."""

    def __new__(cls, point: GE):
        obj = object.__new__(cls)
        if hasattr(point, "infinity"):
            obj.infinity = point.infinity
        if hasattr(point, "x"):
            obj.x = point.x
        if hasattr(point, "y"):
            obj.y = point.y
        return obj

    def __init__(self, point: GE):
        pass

    @property
    def bytes(self) -> bytes:
        return self.to_bytes_compressed()

    @property
    def bytes_xonly(self) -> bytes:
        return self.to_bytes_xonly()

    @property
    def hex(self) -> str:
        return self.bytes.hex()

    def __add__(self, other):
        if isinstance(other, (PublicKey, GE)):
            return PublicKey(super().__add__(other))
        elif isinstance(other, bytes):
            return self.bytes + other
        else:
            return PublicKey(super().__add__(other))

    def __sub__(self, other):
        result = super().__sub__(other)
        return PublicKey(result)

    def __mul__(self, other):
        if isinstance(other, int):
            return PublicKey(super().__mul__(other))
        return NotImplemented

    def __rmul__(self, other):
        if isinstance(other, int):
            return PublicKey(super().__rmul__(other))
        return NotImplemented

    def __neg__(self):
        return PublicKey(super().__neg__())

    def __eq__(self, other):
        if isinstance(other, GE):
            if getattr(self, "infinity", False) and getattr(other, "infinity", False):
                return True
            return self.to_bytes_compressed() == other.to_bytes_compressed()
        return NotImplemented

    def __hash__(self):
        return hash(self.to_bytes_compressed())

    def __len__(self):
        return len(self.bytes)

    def __repr__(self):
        if self.infinity:
            return "PublicKey(infinity)"
        return f"PublicKey({self.hex})"


# ============================================================================
# Wallet (deterministic key generation)
# ============================================================================


class Wallet:
    """Deterministic wallet for generating silent payment keys (seed-based)."""

    def __init__(self, seed: str = "bip375_complete_seed"):
        self.seed = seed
        self.scan_priv, self.scan_pub = self.create_key_pair("scan", 0)
        self.spend_priv, self.spend_pub = self.create_key_pair("spend", 0)
        self.input_keys: list = []

    def deterministic_private_key(self, purpose: str, index: int = 0) -> int:
        data = f"{self.seed}_{purpose}_{index}".encode()
        hash_result = hashlib.sha256(data).digest()
        return int.from_bytes(hash_result, "big") % GE.ORDER

    def create_key_pair(
        self, purpose: str, index: int = 0
    ) -> Tuple[PrivateKey, PublicKey]:
        private_int = self.deterministic_private_key(purpose, index)
        public_point = private_int * G
        return PrivateKey(private_int), PublicKey(public_point)

    def input_key_pair(self, index: int = 0) -> Tuple[PrivateKey, PublicKey]:
        while len(self.input_keys) <= index:
            key_index = len(self.input_keys)
            self.input_keys.append(self.create_key_pair("input", key_index))
        return self.input_keys[index]

    @staticmethod
    def random_bytes(salt: int = 0) -> bytes:
        hash_result = hashlib.sha256(f"{salt}".encode()).digest()
        return (int.from_bytes(hash_result, "big") % GE.ORDER).to_bytes(32)


# ============================================================================
# BIP-352 Cryptographic Functions (spdk_psbt wrappers)
# ============================================================================


def apply_label_to_spend_key(
    spend_key_point: GE, scan_privkey_bytes: bytes, label: int
) -> GE:
    result_bytes = spdk_psbt.bip352_apply_label_to_spend_key(
        spend_key_point.to_bytes_compressed(), scan_privkey_bytes, label
    )
    return GE.from_bytes(result_bytes)


def compute_bip352_output_script(
    outpoints: List[Tuple[bytes, int]],
    summed_pubkey_bytes: bytes,
    ecdh_share_bytes: bytes,
    spend_pubkey_bytes: bytes,
    k: int = 0,
) -> bytes:
    """Compute BIP-352 silent payment output script (P2TR)."""
    serialized_outpoints = [
        txid + idx.to_bytes(4, "little") for txid, idx in outpoints
    ]
    smallest_outpoint = min(serialized_outpoints)

    input_hash = spdk_psbt.bip352_compute_input_hash(smallest_outpoint, summed_pubkey_bytes)
    shared_secret = spdk_psbt.bip352_compute_ecdh_share(input_hash, ecdh_share_bytes)
    output_pubkey = spdk_psbt.bip352_derive_silent_payment_output_pubkey(
        spend_pubkey_bytes, shared_secret, k
    )
    return spdk_psbt.bip352_tweaked_key_to_p2tr_script(output_pubkey)


def verify_receiver_detects_outputs(
    input_data: List[Dict],
    output_data: List[Dict],
    scan_privs: Dict[bytes, "PrivateKey"],
) -> None:
    """Independently verify silent payment output scripts by scanning like a receiver.

    For each scan key, derive the BIP-352 shared secret the way a receiver would
    (b_scan * sum(eligible input pubkeys), tweaked by the input hash), then scan
    exactly like a BIP-352 receiver: try k = 0, 1, 2, ... and at each k match the
    remaining outputs against the receiver's base spend key and the labels it uses.

    Crucially this does NOT assume the sender's ordering (it never reuses the
    BIP-375 canonical sort). It only enforces the invariants a real receiver
    actually depends on:
      * every generated output is detected,
      * k is contiguous from 0 (a gap makes later outputs unrecoverable), and
      * no two outputs collide on the same k.

    Because the spend keys are recomputed here from the base spend key and the
    owning scan key's private key, an output whose script was built with the wrong
    scan key (wrong B_m) is also detected (it simply never matches).

    Raises AssertionError if any output is not recoverable as expected.
    """
    eligible = [inp for inp in input_data if inp.get("is_eligible", False)]
    if not eligible:
        return

    summed_pubkey = None
    for inp in eligible:
        pk = inp["public_key"]
        summed_pubkey = pk if summed_pubkey is None else summed_pubkey + pk
    summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

    # Smallest outpoint over ALL inputs (BIP-352 input_hash).
    serialized_outpoints = [
        inp["previous_txid"] + inp["prevout_index"].to_bytes(4, "little")
        for inp in input_data
    ]
    smallest_outpoint = min(serialized_outpoints)
    input_hash = spdk_psbt.bip352_compute_input_hash(
        smallest_outpoint, summed_pubkey_bytes
    )

    # Group silent payment outputs (those with a computed script) by scan key.
    # Silent payment outputs are identified by the presence of "scan_pubkey".
    groups: Dict[bytes, List[Dict]] = {}
    for out in output_data:
        if "scan_pubkey" not in out or not out.get("script"):
            continue
        if out.get("force_wrong_script"):
            continue
        groups.setdefault(out["scan_pubkey"].to_bytes_compressed(), []).append(out)

    for scan_pub_bytes, outs in groups.items():
        b_scan = scan_privs[scan_pub_bytes]
        # Receiver-side shared secret: input_hash * (b_scan * A_sum).
        ecdh_point = int(b_scan) * summed_pubkey
        shared_secret = spdk_psbt.bip352_compute_ecdh_share(
            input_hash, ecdh_point.to_bytes_compressed()
        )

        # A receiver knows one base spend key per scan key (its own wallet) plus
        # the set of labels it uses. Outputs sharing a scan key but with different
        # base spend keys would be different wallets, which this model does not
        # cover (and which silent payments do not produce in practice).
        base_spend_set = {out["base_spend_pubkey"].to_bytes_compressed() for out in outs}
        assert len(base_spend_set) == 1, (
            f"scan {scan_pub_bytes.hex()[:12]}: outputs share a scan key but have "
            f"different base spend keys; receiver model assumes one wallet per scan key"
        )
        base_spend = outs[0]["base_spend_pubkey"]
        known_labels = sorted(
            {out.get("label") for out in outs}, key=lambda m: (m is not None, m)
        )

        def script_for(label: Optional[int], k: int) -> bytes:
            if label is None:
                spend_bytes = base_spend.to_bytes_compressed()
            else:
                spend_bytes = apply_label_to_spend_key(
                    base_spend, b_scan.bytes, label
                ).to_bytes_compressed()
            output_key = spdk_psbt.bip352_derive_silent_payment_output_pubkey(
                spend_bytes, shared_secret, k
            )
            return spdk_psbt.bip352_tweaked_key_to_p2tr_script(output_key)

        # Scan like a BIP-352 receiver: increment k and, at each k, match the
        # remaining outputs against the base key and every known label. We never
        # assume which output the sender placed at which k.
        remaining = list(outs)
        k = 0
        while remaining:
            matched = [
                out
                for out in remaining
                if any(out["script"] == script_for(label, k) for label in known_labels)
            ]
            if not matched:
                break
            assert len(matched) == 1, (
                f"scan {scan_pub_bytes.hex()[:12]}: outputs "
                f"{[m['output_index'] for m in matched]} collide on k={k}"
            )
            remaining.remove(matched[0])
            k += 1

        assert not remaining, (
            f"scan {scan_pub_bytes.hex()[:12]}: receiver scan could not detect "
            f"output(s) {[o['output_index'] for o in remaining]} with contiguous k "
            f"from 0 (wrong script, wrong scan key, or non-contiguous k assignment)"
        )


def verify_no_empty_output_script_headers(serialized_psbt: bytes, description: str) -> None:
    """Assert no output carries a PSBT_OUT_SCRIPT header with an empty value.

    An empty output script must be represented by the *absence* of the
    PSBT_OUT_SCRIPT (0x04) key, not by a present-but-zero-length header
    (which serializes as a malformed PSBT). Parses the serialized PSBT the
    way a consumer would and inspects each output's key map.

    Raises AssertionError if any output violates this.
    """
    psbt = _tf_psbt.PSBT().deserialize(BytesIO(serialized_psbt))
    violations = [
        idx
        for idx, output_map in enumerate(psbt.o)
        if output_map.map.get(_tf_psbt.PSBT_OUT_SCRIPT) == b""
    ]
    assert not violations, (
        f"{description}: output(s) {violations} serialize a PSBT_OUT_SCRIPT "
        f"header with an empty value; empty scripts must omit the field"
    )


def _field_sort_key(item: Tuple) -> Tuple[int, bytes]:
    """Sort key for a PSBT map entry: (type_value, key_data).

    test_framework stores keyless fields as an int (the type byte) and keyed
    fields as the full key bytes (type byte + key data).
    """
    key = item[0]
    if isinstance(key, int):
        return (key, b"")
    return (key[0], key[1:])


def normalize_psbt_field_order(serialized_psbt: bytes) -> bytes:
    """Re-serialize a PSBT with every key-value map in canonical key order.

    spdk_psbt emits map fields in an order that depends on the installed library
    build, so regenerating against a rebuilt wheel reshuffles the vectors even
    though the contents are identical. BIP-174 maps are unordered, so we
    canonicalize each map to ascending (type_value, key_data) -- the same total
    order rust-psbt sorts by -- making the published vectors deterministic
    regardless of the serializer.
    """
    psbt = _tf_psbt.PSBT().deserialize(BytesIO(serialized_psbt))
    for field_map in [psbt.g, *psbt.i, *psbt.o]:
        field_map.map = dict(sorted(field_map.map.items(), key=_field_sort_key))
    return psbt.serialize()


# ============================================================================
# Transaction Signing (for error-injection test cases)
# ============================================================================


@dataclass
class UTXO:
    """Simplified UTXO for signing purposes."""

    txid: str
    vout: int
    amount: int
    script_pubkey: str  # hex
    private_key: Optional[PrivateKey] = None
    sequence: int = 0xFFFFFFFE

    @property
    def script_pubkey_bytes(self) -> bytes:
        return bytes.fromhex(self.script_pubkey)


def _build_tx(inputs: List[UTXO], outputs: List[dict]) -> CTransaction:
    """Build a CTransaction (version 2) from UTXO inputs and output dicts.

    inp.txid is internal byte order (hash digest); COutPoint stores it as the
    little-endian integer it serializes back to, so prevout serialization
    commits to the same internal-order txid.
    """
    tx = CTransaction()
    tx.version = 2
    tx.nLockTime = 0
    for inp in inputs:
        prevout = COutPoint(uint256_from_str(bytes.fromhex(inp.txid)), inp.vout)
        tx.vin.append(CTxIn(prevout, b"", inp.sequence))
    for out in outputs:
        spk = bytes.fromhex(out.get("script_pubkey", "") or "")
        tx.vout.append(CTxOut(out["amount"], spk))
    return tx


def _eckey(private_key: int) -> ECKey:
    k = ECKey()
    k.set(int(private_key).to_bytes(32, "big"), True)
    return k


def sign_p2wpkh_input(
    private_key: int,
    inputs: List[UTXO],
    outputs: List[dict],
    input_index: int,
    pubkey_hash: bytes,
    amount: int,
    sighash_type: int = SIGHASH_ALL,
) -> bytes:
    """Sign a P2WPKH input (BIP-143). Returns DER signature + sighash byte."""
    tx = _build_tx(inputs, outputs)
    script_code = keyhash_to_p2pkh_script(pubkey_hash)
    sighash = SegwitV0SignatureHash(script_code, tx, input_index, sighash_type, amount)
    sig = _eckey(private_key).sign_ecdsa(sighash, low_s=True, rfc6979=True)
    return sig + bytes([sighash_type])


def sign_p2pkh_input(
    private_key: int,
    inputs: List[UTXO],
    outputs: List[dict],
    input_index: int,
    pubkey_hash: bytes,
    sighash_type: int = SIGHASH_ALL,
) -> bytes:
    """Sign a P2PKH input (legacy). Returns DER signature + sighash byte."""
    tx = _build_tx(inputs, outputs)
    script = keyhash_to_p2pkh_script(pubkey_hash)
    sighash, err = LegacySignatureHash(script, tx, input_index, sighash_type)
    assert err is None
    sig = _eckey(private_key).sign_ecdsa(sighash, low_s=True, rfc6979=True)
    return sig + bytes([sighash_type])


def sign_p2tr_input(
    private_key: int,
    inputs: List[UTXO],
    outputs: List[dict],
    input_index: int,
    sighash_type: int = SIGHASH_ALL,
) -> bytes:
    """Sign a P2TR key-path input (BIP-341).

    Applies the key-path tweak with an empty script tree and produces a
    64-byte Schnorr signature with an explicit sighash trailing byte.
    The input already carries the tweaked output keypair (see _create_p2tr_input),
    so we sign with the private key directly.
    """
    tx = _build_tx(inputs, outputs)
    spent_utxos = [
        CTxOut(inp.amount, bytes.fromhex(inp.script_pubkey)) for inp in inputs
    ]
    sighash = TaprootSignatureHash(
        tx, spent_utxos, sighash_type, input_index=input_index
    )

    sig = sign_schnorr(int(private_key).to_bytes(32, "big"), sighash)
    return sig + bytes([sighash_type])


# ============================================================================
# PSBT Unique ID Computation
# ============================================================================


def compute_transaction_id(
    input_data: List[Dict],
    output_data: List[Dict],
) -> str:
    """Compute BIP-375 PSBT unique identifier from data structures.

    Uses SP_V0_INFO bytes for silent payment outputs (BIP-375 extension)
    and the output script for regular outputs. Returns hex txid in display order.
    """
    tx = CTransaction()
    tx.version = 2
    tx.nLockTime = 0

    for inp in input_data:
        prevout = COutPoint(
            uint256_from_str(inp["previous_txid"]), inp["prevout_index"]
        )
        # sequence = 0 per BIP-370
        tx.vin.append(CTxIn(prevout, b"", 0))

    for out in output_data:
        # For BIP-375 silent payment outputs, use the SP_V0_INFO bytes as the
        # script, prepending the zero version byte per BIP-375.
        if "sp_v0_info" in out:
            script = b"\x00" + out["sp_v0_info"]
        elif "script" in out:
            script = out["script"]
        else:
            script = b""
        tx.vout.append(CTxOut(out["amount"], script))

    txid = hash256(tx.serialize_without_witness())
    return txid[::-1].hex()
