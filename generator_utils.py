#!/usr/bin/env python3
"""
Self-contained utilities for the BIP-375 test vector generator.

Provides BIP-352 crypto wrapper, PSBT key type constants, witness UTXO
construction, ECDSA signing, and unique ID computation — everything the
generator needs not provided by spdk_psbt.
"""

from dataclasses import dataclass
import hashlib
import hmac
import struct
from typing import Dict, List, Optional, Tuple

import spdk_psbt

# secp256k1 reference implementation
from secp256k1 import GE, G


# ============================================================================
# PSBT Key Type Constants (from BIP 174/370/375)
# ============================================================================


class PSBTKeyType:
    """PSBT Key Type Constants for BIP 174/370/375"""

    # Global fields
    PSBT_GLOBAL_UNSIGNED_TX = 0x00
    PSBT_GLOBAL_XPUB = 0x01
    PSBT_GLOBAL_TX_VERSION = 0x02
    PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
    PSBT_GLOBAL_INPUT_COUNT = 0x04
    PSBT_GLOBAL_OUTPUT_COUNT = 0x05
    PSBT_GLOBAL_TX_MODIFIABLE = 0x06
    PSBT_GLOBAL_VERSION = 0xFB
    PSBT_GLOBAL_PROPRIETARY = 0xFC
    # BIP 375 Silent Payment global fields
    PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
    PSBT_GLOBAL_SP_DLEQ = 0x08

    # Input fields
    PSBT_IN_NON_WITNESS_UTXO = 0x00
    PSBT_IN_WITNESS_UTXO = 0x01
    PSBT_IN_PARTIAL_SIG = 0x02
    PSBT_IN_SIGHASH_TYPE = 0x03
    PSBT_IN_REDEEM_SCRIPT = 0x04
    PSBT_IN_WITNESS_SCRIPT = 0x05
    PSBT_IN_BIP32_DERIVATION = 0x06
    PSBT_IN_FINAL_SCRIPTSIG = 0x07
    PSBT_IN_TAP_INTERNAL_KEY = 0x17
    PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
    PSBT_IN_PREVIOUS_TXID = 0x0E
    PSBT_IN_OUTPUT_INDEX = 0x0F
    PSBT_IN_SEQUENCE = 0x10
    PSBT_IN_PROPRIETARY = 0xFC
    # BIP 375 Silent Payment input fields
    PSBT_IN_SP_ECDH_SHARE = 0x1D
    PSBT_IN_SP_DLEQ = 0x1E

    # Output fields
    PSBT_OUT_REDEEM_SCRIPT = 0x00
    PSBT_OUT_WITNESS_SCRIPT = 0x01
    PSBT_OUT_BIP32_DERIVATION = 0x02
    PSBT_OUT_AMOUNT = 0x03
    PSBT_OUT_SCRIPT = 0x04
    PSBT_OUT_PROPRIETARY = 0xFC
    # BIP 375 Silent Payment output fields
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
# Serialization helpers
# ============================================================================


def compact_size_uint(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<L", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def create_witness_utxo(amount: int, script_pubkey: bytes) -> bytes:
    """Create witness UTXO field value: amount (8 LE) + compact_size + script."""
    return struct.pack("<Q", amount) + compact_size_uint(len(script_pubkey)) + script_pubkey


# ============================================================================
# BIP-352 Cryptographic Functions
# ============================================================================


def TaggedHash(tag: str, data: bytes) -> bytes:
    ss = hashlib.sha256(tag.encode()).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()


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
    serialized_outpoints = [txid + struct.pack("<I", idx) for txid, idx in outpoints]
    smallest_outpoint = min(serialized_outpoints)

    input_hash = spdk_psbt.bip352_compute_input_hash(smallest_outpoint, summed_pubkey_bytes)
    shared_secret = spdk_psbt.bip352_compute_ecdh_share(input_hash, ecdh_share_bytes)
    output_pubkey = spdk_psbt.bip352_derive_silent_payment_output_pubkey(
        spend_pubkey_bytes, shared_secret, k
    )
    return spdk_psbt.bip352_tweaked_key_to_p2tr_script(output_pubkey)


# ============================================================================
# ECDSA Signing (for error-injection test cases)
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
    def txid_bytes(self) -> bytes:
        return bytes.fromhex(self.txid)

    @property
    def script_pubkey_bytes(self) -> bytes:
        return bytes.fromhex(self.script_pubkey)


def _deterministic_nonce(private_key: int, message_hash: bytes) -> int:
    """RFC 6979 deterministic nonce for ECDSA."""
    private_key_bytes = private_key.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(
        k, v + b"\x00" + private_key_bytes + message_hash, hashlib.sha256
    ).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(
        k, v + b"\x01" + private_key_bytes + message_hash, hashlib.sha256
    ).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate_k = int.from_bytes(v, "big")
        if 1 <= candidate_k < GE.ORDER:
            return candidate_k
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _ecdsa_sign(private_key: int, message_hash: bytes) -> Tuple[int, int]:
    """ECDSA sign producing (r, s) with low-S."""
    z = int.from_bytes(message_hash, "big")
    while True:
        k = _deterministic_nonce(private_key, message_hash)
        R = k * G
        if R.infinity:
            continue
        r = int(R.x) % GE.ORDER
        if r == 0:
            continue
        k_inv = pow(k, -1, GE.ORDER)
        s = (k_inv * (z + r * private_key)) % GE.ORDER
        if s == 0:
            continue
        if s > GE.ORDER // 2:
            s = GE.ORDER - s
        return (r, s)


def _der_encode_signature(r: int, s: int) -> bytes:
    """DER-encode ECDSA signature."""

    def encode_integer(value: int) -> bytes:
        byte_length = (value.bit_length() + 7) // 8 or 1
        value_bytes = value.to_bytes(byte_length, "big")
        if value_bytes[0] & 0x80:
            value_bytes = b"\x00" + value_bytes
        return b"\x02" + bytes([len(value_bytes)]) + value_bytes

    r_enc = encode_integer(r)
    s_enc = encode_integer(s)
    content = r_enc + s_enc
    return b"\x30" + bytes([len(content)]) + content


def _sighash_all(
    inputs: List[UTXO],
    outputs: List[dict],
    input_index: int,
    script_code: bytes,
    amount: int,
) -> bytes:
    """BIP 143 SIGHASH_ALL for P2WPKH input signing."""
    version = struct.pack("<I", 2)

    prevouts_data = b""
    for inp in inputs:
        prevouts_data += bytes.fromhex(inp.txid)[::-1]
        prevouts_data += struct.pack("<I", inp.vout)
    prevouts_hash = hashlib.sha256(hashlib.sha256(prevouts_data).digest()).digest()

    sequences_data = b""
    for inp in inputs:
        sequences_data += struct.pack("<I", inp.sequence)
    sequences_hash = hashlib.sha256(hashlib.sha256(sequences_data).digest()).digest()

    current_input = inputs[input_index]
    outpoint = bytes.fromhex(current_input.txid)[::-1] + struct.pack(
        "<I", current_input.vout
    )
    script_code_with_length = bytes([len(script_code)]) + script_code
    amount_bytes = struct.pack("<Q", amount)
    sequence = struct.pack("<I", current_input.sequence)

    outputs_data = b""
    for out in outputs:
        outputs_data += struct.pack("<Q", out["amount"])
        script = bytes.fromhex(out.get("script_pubkey", ""))
        outputs_data += bytes([len(script)]) + script
    outputs_hash = hashlib.sha256(hashlib.sha256(outputs_data).digest()).digest()

    locktime = struct.pack("<I", 0)
    sighash_type = struct.pack("<I", 1)

    preimage = (
        version
        + prevouts_hash
        + sequences_hash
        + outpoint
        + script_code_with_length
        + amount_bytes
        + sequence
        + outputs_hash
        + locktime
        + sighash_type
    )
    return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()


def sign_p2wpkh_input(
    private_key: int,
    inputs: List[UTXO],
    outputs: List[dict],
    input_index: int,
    pubkey_hash: bytes,
    amount: int,
) -> bytes:
    """Sign a P2WPKH input. Returns DER signature + SIGHASH_ALL byte."""
    script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
    sighash = _sighash_all(inputs, outputs, input_index, script_code, amount)
    r, s = _ecdsa_sign(private_key, sighash)
    return _der_encode_signature(r, s) + b"\x01"


# ============================================================================
# PSBT Unique ID Computation
# ============================================================================


def compute_unique_id(
    input_data: List[Dict],
    output_data: List[Dict],
) -> str:
    """Compute BIP-375 PSBT unique identifier from data structures.

    Uses SP_V0_INFO bytes for silent payment outputs (BIP-375 extension)
    and output script for regular outputs.  Returns hex txid in display order.
    """
    tx_bytes = struct.pack("<I", 2)  # version
    tx_bytes += bytes([len(input_data)])

    for inp in input_data:
        tx_bytes += inp["prevout_txid"]  # 32 bytes
        tx_bytes += struct.pack("<I", inp["prevout_index"])
        tx_bytes += b"\x00"  # empty scriptSig
        tx_bytes += struct.pack("<I", 0)  # sequence = 0 per BIP-370

    tx_bytes += bytes([len(output_data)])

    for out in output_data:
        tx_bytes += struct.pack("<Q", out["amount"])
        if "_sp_info_bytes" in out:
            # Silent payment: use SP_V0_INFO as script placeholder
            sp_info = out["_sp_info_bytes"]
            tx_bytes += bytes([len(sp_info)]) + sp_info
        elif "script" in out:
            script = out["script"]
            tx_bytes += bytes([len(script)]) + script
        else:
            tx_bytes += b"\x00"

    tx_bytes += struct.pack("<I", 0)  # locktime

    txid = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
    return txid[::-1].hex()
