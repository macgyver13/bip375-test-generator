"""Pure-Python stand-in for the spdk_psbt Rust extension.

Implements the slice of the spdk_psbt API this repository drives, on top of the
vendored Bitcoin Core test framework. Behaviour is matched against the Rust
crates (spdk-uniffi, rust-psbt, spdk's psbt signer and silentpayments, rust-dleq)
rather than re-derived, and checked byte for byte by `just test-parity`.

Do not import generator_utils here: it imports psbt_backend, which imports this
module, so the import at module scope would be circular.
"""

import os
import struct
from io import BytesIO

from test_framework.crypto.secp256k1 import G, GE
from test_framework.key import ECKey, TaggedHash, tweak_add_pubkey
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    ser_compact_size,
    uint256_from_str,
)
from test_framework.psbt import (
    PSBT,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_VERSION,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_SEQUENCE,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_MERKLE_ROOT,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_WITNESS_UTXO,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
    PSBTMap,
)
from test_framework.script import (
    CScript,
    OP_0,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    SIGHASH_ALL,
    LegacySignatureHash,
    SegwitV0SignatureHash,
    hash160,
)
from test_framework.script_util import keyhash_to_p2pkh_script

# BIP-375 silent payment fields. The vendored framework predates them.
PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
PSBT_GLOBAL_SP_DLEQ = 0x08
PSBT_IN_SP_ECDH_SHARE = 0x1D
PSBT_IN_SP_DLEQ = 0x1E
PSBT_OUT_SP_V0_INFO = 0x09
PSBT_OUT_SP_V0_LABEL = 0x0A

_ORDER = GE.ORDER

# BIP-352 NUMS point H: a taproot internal key of H means no key path, so the
# input is excluded from the shared secret.
_NUMS_H = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

_TX_MODIFIABLE_INPUTS = 0x01
_TX_MODIFIABLE_OUTPUTS = 0x02
_TX_MODIFIABLE_SINGLE = 0x04

_SIGHASH_ANYONECANPAY = 0x80


class Bip375Error(Exception):
    """Raised for the conditions the Rust binding reports as Bip375Error."""


def _scalar(data):
    """Interpret 32 big-endian bytes as a secp256k1 scalar, or None."""
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "big")
    if value <= 0 or value >= _ORDER:
        return None
    return value


def _pubkey(data):
    """Decode a compressed public key, or None."""
    if len(data) != 33 or data[0] not in (2, 3):
        return None
    return GE.from_bytes(data)


def _point(scalar):
    """The compressed encoding of scalar*G."""
    return (scalar * G).to_bytes_compressed()


def _add_points(points):
    total = None
    for point in points:
        total = point if total is None else total + point
    return total


def _tagged_scalar(tag, data):
    """BIP-340 tagged hash reduced into a scalar. Raises if it is not one."""
    value = int.from_bytes(TaggedHash(tag, data), "big") % _ORDER
    if value == 0:
        raise Bip375Error("hash is not a valid scalar")
    return value


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _key(key):
    """A PSBT map key: an int for a keyless field, bytes for a keyed one."""
    if isinstance(key, int):
        return bytes([key])
    return key


def _type_of(key):
    return key if isinstance(key, int) else key[0]


def _find(psbt_map, type_value, key_data):
    """The value stored under (type, key data), matching int or bytes keys."""
    want = bytes([type_value]) + key_data
    for key, value in psbt_map.map.items():
        if _key(key) == want:
            return value
    return None


def _put(psbt_map, type_value, key_data, value):
    """Insert a field, replacing any field with the same full key."""
    full = bytes([type_value]) + key_data
    for key in list(psbt_map.map):
        if _key(key) == full:
            del psbt_map.map[key]
            break
    psbt_map.map[full if key_data else type_value] = value


def _drop_type(psbt_map, type_value):
    for key in [key for key in psbt_map.map if _type_of(key) == type_value]:
        del psbt_map.map[key]


def _keyed(psbt_map, type_value, key_len, value_len=None):
    """Fields of one type as (key data, value), in insertion order."""
    found = []
    for key, value in psbt_map.map.items():
        if isinstance(key, int) or key[0] != type_value or len(key) != 1 + key_len:
            continue
        if value_len is not None and len(value) != value_len:
            continue
        found.append((key[1:], value))
    return found


def _is_p2pkh(script):
    return (
        len(script) == 25
        and script[0] == OP_DUP
        and script[1] == OP_HASH160
        and script[2] == 20
        and script[23] == OP_EQUALVERIFY
        and script[24] == OP_CHECKSIG
    )


def _is_p2wpkh(script):
    return len(script) == 22 and script[0] == OP_0 and script[1] == 20


def _is_p2sh(script):
    return len(script) == 23 and script[0] == OP_HASH160 and script[1] == 20 and script[22] == OP_EQUAL


def _is_p2tr(script):
    return len(script) == 34 and script[0] == 0x51 and script[1] == 32


def _p2pkh_script(pubkey):
    return bytes(keyhash_to_p2pkh_script(hash160(pubkey)))


def _p2wpkh_script(pubkey):
    return bytes(CScript([OP_0, hash160(pubkey)]))


def _p2sh_script(redeem):
    return bytes(CScript([OP_HASH160, hash160(redeem), OP_EQUAL]))


def _script_matches(pubkey, script, redeem=None):
    """Whether `pubkey` is the key the funding script commits to."""
    if _is_p2wpkh(script):
        return _p2wpkh_script(pubkey) == script
    if _is_p2pkh(script):
        return _p2pkh_script(pubkey) == script
    if _is_p2sh(script) and redeem is not None and _is_p2wpkh(redeem):
        return _p2sh_script(redeem) == script and _p2wpkh_script(pubkey) == redeem
    return False


def _derivation_keys(psbt_map):
    """Compressed public keys named by PSBT_IN_BIP32_DERIVATION."""
    return [key for key, _ in _keyed(psbt_map, PSBT_IN_BIP32_DERIVATION, 33)]


def _input_pubkey(psbt_map):
    """The public key an input contributes to the BIP-352 shared secret.

    None when the input does not contribute: a script that is not one of the
    four eligible templates, a P2SH input that is not P2SH-P2WPKH, a taproot
    input whose internal key is NUMS (no key path), or an input whose pubkey
    cannot be confirmed against the funding script.
    """
    utxo = _find(psbt_map, PSBT_IN_WITNESS_UTXO, b"")
    if utxo is None:
        utxo = _prevout_script(_find(psbt_map, PSBT_IN_NON_WITNESS_UTXO, b""), psbt_map)
    if utxo is None:
        return None
    script = _txout_script(utxo)
    if _is_p2tr(script):
        internal = _find(psbt_map, PSBT_IN_TAP_INTERNAL_KEY, b"")
        if internal == _NUMS_H:
            return None
        # BIP-352 uses the taproot output key, lifted to even parity.
        return b"\x02" + bytes(script[2:])
    if not (_is_p2wpkh(script) or _is_p2pkh(script) or _is_p2sh(script)):
        return None
    redeem = _find(psbt_map, PSBT_IN_REDEEM_SCRIPT, b"")
    for pubkey in _derivation_keys(psbt_map):
        if _script_matches(pubkey, bytes(script), redeem):
            return pubkey
    return None


def _prevout_script(raw_tx, psbt_map):
    """The spent output of a non-witness UTXO, serialized, or None."""
    if raw_tx is None:
        return None
    index = _find(psbt_map, PSBT_IN_OUTPUT_INDEX, b"")
    if index is None or len(index) != 4:
        return None
    tx = CTransaction()
    tx.deserialize(BytesIO(raw_tx))
    vout = struct.unpack("<I", index)[0]
    if vout >= len(tx.vout):
        return None
    return tx.vout[vout].serialize()


def _funding_script_and_value(psbt_map):
    """(script, value) of the spent output, preferring the witness UTXO."""
    raw = _find(psbt_map, PSBT_IN_WITNESS_UTXO, b"")
    if raw is None:
        raw = _prevout_script(_find(psbt_map, PSBT_IN_NON_WITNESS_UTXO, b""), psbt_map)
    if raw is None:
        raise Bip375Error("input has no funding UTXO")
    return _parse_txout(raw)


def _parse_txout(raw):
    """(scriptPubKey, value) from a consensus-encoded TxOut."""
    txout = CTxOut()
    txout.deserialize(BytesIO(raw))
    return bytes(txout.scriptPubKey), txout.nValue


def _txout_script(raw):
    return _parse_txout(raw)[0]


def _outpoint(psbt_map):
    """The 36-byte outpoint: txid in internal byte order, then the vout."""
    txid = _find(psbt_map, PSBT_IN_PREVIOUS_TXID, b"")
    index = _find(psbt_map, PSBT_IN_OUTPUT_INDEX, b"")
    if txid is None or index is None:
        raise Bip375Error("input is missing its outpoint")
    return txid + index


def _sequence(psbt_map):
    raw = _find(psbt_map, PSBT_IN_SEQUENCE, b"")
    if raw is None:
        return 0xFFFFFFFF
    return struct.unpack("<I", raw)[0]


def _sighash_type(psbt_map):
    raw = _find(psbt_map, PSBT_IN_SIGHASH_TYPE, b"")
    if raw is None:
        return SIGHASH_ALL
    return struct.unpack("<I", raw)[0]


def _scan_keys(psbt):
    """The distinct scan keys across the silent payment outputs, sorted."""
    seen = set()
    for output in psbt.o:
        info = _find(output, PSBT_OUT_SP_V0_INFO, b"")
        if info is not None and len(info) == 66 and _pubkey(info[:33]) is not None:
            seen.add(info[:33])
    return sorted(seen)


def _dleq_proof(scalar, scan_key, aux):
    """A BIP-374 proof that scalar*G and scalar*scan_key share a discrete log."""
    point_a = scalar * G
    point_c = scalar * GE.from_bytes(scan_key)
    blinded = _xor(scalar.to_bytes(32, "big"), TaggedHash("BIP0374/aux", aux))
    nonce = _tagged_scalar(
        "BIP0374/nonce",
        blinded + point_a.to_bytes_compressed() + point_c.to_bytes_compressed(),
    )
    nonce_g = nonce * G
    nonce_scan = nonce * GE.from_bytes(scan_key)
    challenge = _tagged_scalar(
        "BIP0374/challenge",
        b"".join(
            p.to_bytes_compressed()
            for p in (point_a, GE.from_bytes(scan_key), point_c, G, nonce_g, nonce_scan)
        ),
    )
    proof = challenge.to_bytes(32, "big") + ((nonce + challenge * scalar) % _ORDER).to_bytes(32, "big")
    if not _dleq_valid(point_a.to_bytes_compressed(), scan_key, point_c.to_bytes_compressed(), proof):
        raise Bip375Error("DLEQ proof failed self verification")
    return proof


def _dleq_valid(point_a, point_b, point_c, proof):
    a, b, c = _pubkey(point_a), _pubkey(point_b), _pubkey(point_c)
    if a is None or b is None or c is None or len(proof) != 64:
        return False
    e = int.from_bytes(proof[:32], "big")
    s = int.from_bytes(proof[32:], "big")
    if e >= _ORDER or s >= _ORDER:
        return False
    r1 = s * G + (_ORDER - e) * a
    r2 = s * b + (_ORDER - e) * c
    if r1.infinity or r2.infinity:
        return False
    challenge = int.from_bytes(
        TaggedHash(
            "BIP0374/challenge",
            b"".join(p.to_bytes_compressed() for p in (a, b, c, G, r1, r2)),
        ),
        "big",
    ) % _ORDER
    return challenge == e


def _owned_scalar(psbt_map, secret):
    """The scalar this secret contributes for an input it owns, or None.

    Ownership mirrors rust-psbt's SecretKey GetKey: the secret matches an input
    whose public key it reproduces, never by BIP-32 origin. A taproot input is
    matched on its output key and normalized to even parity.
    """
    pubkey = _input_pubkey(psbt_map)
    if pubkey is None:
        return None
    own = _point(secret)
    if _is_p2tr(_funding_script_and_value(psbt_map)[0]):
        if own[1:] != pubkey[1:]:
            return None
        if own[0] == 3:
            return _ORDER - secret
        return secret
    if own == pubkey:
        return secret
    return None


def _input_hash(psbt):
    """The BIP-352 input hash over the smallest outpoint and the summed keys."""
    pubkeys = [pk for pk in (_input_pubkey(m) for m in psbt.i) if pk is not None]
    if not pubkeys:
        raise Bip375Error("no eligible inputs")
    smallest = min(_outpoint(m) for m in psbt.i)
    summed = _add_points(GE.from_bytes(pk) for pk in pubkeys).to_bytes_compressed()
    return _tagged_scalar("BIP0352/Inputs", smallest + summed)


def _shared_secret(psbt, scan):
    """The BIP-352 shared secret for one scan key, from the shares on the PSBT.

    A global share takes precedence. It is verified against the sum of the
    eligible input keys; if that proof fails, complete per-input coverage is
    tried instead. A missing global proof is not rescued that way.
    """
    share = _find(psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE, scan)
    if share is not None:
        proof = _find(psbt.g, PSBT_GLOBAL_SP_DLEQ, scan)
        if proof is None:
            raise Bip375Error("global share has no DLEQ proof")
        pubkeys = [pk for pk in (_input_pubkey(m) for m in psbt.i) if pk is not None]
        summed = _add_points(GE.from_bytes(pk) for pk in pubkeys).to_bytes_compressed()
        if _dleq_valid(summed, scan, share, proof):
            secret = share
        else:
            secret = _aggregate_partials(psbt, scan)
    else:
        secret = _aggregate_partials(psbt, scan)
    tweaked = _input_hash(psbt) * GE.from_bytes(secret)
    return tweaked.to_bytes_compressed()


def _aggregate_partials(psbt, scan):
    """The sum of every eligible input's partial share, each proof checked."""
    shares = []
    for psbt_map in psbt.i:
        if _input_pubkey(psbt_map) is None:
            continue
        share = _find(psbt_map, PSBT_IN_SP_ECDH_SHARE, scan)
        proof = _find(psbt_map, PSBT_IN_SP_DLEQ, scan)
        if share is None or proof is None:
            raise Bip375Error("incomplete per-input shares")
        if not _dleq_valid(_input_pubkey(psbt_map), scan, share, proof):
            raise Bip375Error("per-input DLEQ proof failed")
        shares.append(GE.from_bytes(share))
    if not shares:
        raise Bip375Error("no per-input shares")
    return _add_points(shares).to_bytes_compressed()


def _output_script(spend, shared, k):
    tweak = _tagged_scalar("BIP0352/SharedSecret", shared + k.to_bytes(4, "big"))
    xonly = (GE.from_bytes(spend) + tweak * G).to_bytes_xonly()
    return bytes([0x51, 0x20]) + xonly


def _sp_outputs(psbt):
    """Silent payment outputs as (index, scan, spend), sorted for the k counter.

    Sorted by the 66-byte sp_v0_info, ties broken by output index, which is the
    order the BIP-352 counter increments within a scan key.
    """
    outputs = []
    for index, output in enumerate(psbt.o):
        info = _find(output, PSBT_OUT_SP_V0_INFO, b"")
        if info is not None and len(info) == 66:
            outputs.append((index, info[:33], info[33:]))
    outputs.sort(key=lambda item: (item[1] + item[2], item[0]))
    return outputs


def _unsigned_tx(psbt):
    """The transaction the sighash commits to: version 2, locktime 0."""
    tx = CTransaction()
    tx.version = struct.unpack("<I", psbt.g.map[PSBT_GLOBAL_TX_VERSION])[0]
    tx.nLockTime = 0
    for psbt_map in psbt.i:
        txid = _find(psbt_map, PSBT_IN_PREVIOUS_TXID, b"")
        vout = struct.unpack("<I", _find(psbt_map, PSBT_IN_OUTPUT_INDEX, b""))[0]
        tx.vin.append(CTxIn(COutPoint(uint256_from_str(txid), vout), b"", _sequence(psbt_map)))
    for output in psbt.o:
        amount = struct.unpack("<Q", _find(output, PSBT_OUT_AMOUNT, b""))[0]
        script = _find(output, PSBT_OUT_SCRIPT, b"") or b""
        tx.vout.append(CTxOut(amount, script))
    return tx


def _ecdsa_sighash(psbt, index, script_code, sighash_type):
    script, value = _funding_script_and_value(psbt.i[index])
    tx = _unsigned_tx(psbt)
    if _is_p2wpkh(script) or (_is_p2sh(script) and _is_p2wpkh(script_code)):
        return SegwitV0SignatureHash(CScript(script_code), tx, index, sighash_type, value)
    digest, err = LegacySignatureHash(CScript(script_code), tx, index, sighash_type)
    if err is not None:
        raise Bip375Error("legacy sighash failed")
    return digest


def _ecdsa_signature(secret, sighash, sighash_type):
    key = ECKey()
    key.set(secret.to_bytes(32, "big"), True)
    return key.sign_ecdsa(sighash, low_s=True, rfc6979=True) + bytes([sighash_type & 0xFF])


def _sign_input(psbt, index, secret):
    """Sign one input the way rust-psbt's signer does, writing the PSBT fields.

    TODO: taproot key-path signing is not covered. No PSBT this repo builds reaches
    sign_input with a P2TR input (the workflows are P2WPKH only), and the binding's
    signer only signs taproot off tap_key_origins, which neither update_inputs nor the
    raw setter populates. Its Schnorr signature also draws random aux, so it is not
    reproducible. A P2TR input therefore gets no signature here, matching the binding.
    """
    psbt_map = psbt.i[index]
    script, _ = _funding_script_and_value(psbt_map)
    sighash_type = _sighash_type(psbt_map)
    redeem = _find(psbt_map, PSBT_IN_REDEEM_SCRIPT, b"")
    signed = False
    for pubkey in _derivation_keys(psbt_map):
        if not _script_matches(pubkey, script, redeem):
            continue
        if _point(secret) != pubkey:
            continue
        script_code = _p2pkh_script(pubkey)
        sighash = _ecdsa_sighash(psbt, index, script_code, sighash_type)
        _put(psbt_map, PSBT_IN_PARTIAL_SIG, pubkey, _ecdsa_signature(secret, sighash, sighash_type))
        signed = True
    if signed:
        _apply_sighash_flags(psbt, sighash_type)


def _apply_sighash_flags(psbt, sighash_type):
    """BIP-370: clear the modifiable flags a signature of this type commits to."""
    base = sighash_type & 0x1F
    flags = psbt.g.map.get(PSBT_GLOBAL_TX_MODIFIABLE, b"\x00")[0]
    if not sighash_type & _SIGHASH_ANYONECANPAY:
        flags &= ~_TX_MODIFIABLE_INPUTS
    if base not in (2,):
        flags &= ~_TX_MODIFIABLE_OUTPUTS
    if base == 3:
        flags |= _TX_MODIFIABLE_SINGLE
    psbt.g.map[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([flags])


def _finalize_input(psbt_map):
    """Build the final scriptSig and witness, then drop the pre-final fields.

    The silent payment fields and anything unrecognized survive, matching
    rust-psbt's Input::finalize.
    """
    script, _ = _funding_script_and_value(psbt_map)
    redeem = _find(psbt_map, PSBT_IN_REDEEM_SCRIPT, b"")
    script_sig, witness = _satisfy(psbt_map, script, redeem)
    keep = {}
    for key, value in psbt_map.map.items():
        if _type_of(key) in (
            PSBT_IN_PREVIOUS_TXID,
            PSBT_IN_OUTPUT_INDEX,
            PSBT_IN_SEQUENCE,
            PSBT_IN_WITNESS_UTXO,
            PSBT_IN_NON_WITNESS_UTXO,
            PSBT_IN_SP_ECDH_SHARE,
            PSBT_IN_SP_DLEQ,
        ) or _type_of(key) >= 0xFC or _type_of(key) not in _KNOWN_INPUT_TYPES:
            keep[key] = value
    if script_sig:
        keep[PSBT_IN_FINAL_SCRIPTSIG] = script_sig
    if witness is not None:
        keep[PSBT_IN_FINAL_SCRIPTWITNESS] = witness
    psbt_map.map = keep


_KNOWN_INPUT_TYPES = {
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_SEQUENCE,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_MERKLE_ROOT,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
}


def _partial_sigs(psbt_map):
    return _keyed(psbt_map, PSBT_IN_PARTIAL_SIG, 33)


def _satisfy(psbt_map, script, redeem):
    """(scriptSig, witness serialization or None) for one input."""
    if _is_p2wpkh(script):
        return b"", _witness([_matching_sig(psbt_map, script, None), _matching_pubkey(psbt_map, script, None)])
    if _is_p2pkh(script):
        pubkey = _matching_pubkey(psbt_map, script, None)
        return bytes(CScript([_sig_for(psbt_map, pubkey), pubkey])), None
    if _is_p2sh(script) and redeem is not None and _is_p2wpkh(redeem):
        pubkey = _matching_pubkey(psbt_map, script, redeem)
        return bytes(CScript([redeem])), _witness([_sig_for(psbt_map, pubkey), pubkey])
    if _is_p2sh(script) and redeem is not None:
        return bytes(CScript(_multisig_stack(psbt_map, redeem) + [redeem])), None
    if _is_p2tr(script):
        key_sig = _find(psbt_map, PSBT_IN_TAP_KEY_SIG, b"")
        if key_sig is not None:
            return b"", _witness([key_sig])
        return b"", _witness(_tapleaf_stack(psbt_map, script))
    raise Bip375Error("cannot finalize input")


def _matching_pubkey(psbt_map, script, redeem):
    for pubkey, _ in _partial_sigs(psbt_map):
        if _script_matches(pubkey, script, redeem):
            return pubkey
    raise Bip375Error("no signature matches the funding script")


def _sig_for(psbt_map, pubkey):
    for key, sig in _partial_sigs(psbt_map):
        if key == pubkey:
            return sig
    raise Bip375Error("missing signature")


def _matching_sig(psbt_map, script, redeem):
    return _sig_for(psbt_map, _matching_pubkey(psbt_map, script, redeem))


def _multisig_stack(psbt_map, redeem):
    """OP_0 plus one signature per key the redeem script names, in its order."""
    keys = [item for item in CScript(redeem) if isinstance(item, bytes) and len(item) == 33]
    sigs = {key: sig for key, sig in _partial_sigs(psbt_map)}
    stack = [OP_0]
    for key in keys:
        if key in sigs:
            stack.append(sigs[key])
    return stack


def _leaf_commits_to(script, version, control, leaf_hash):
    """BIP-341 script-path check: the control block and leaf reproduce the prevout's output key."""
    if len(control) < 33 or (len(control) - 33) % 32 or control[0] & 0xFE != version:
        return False
    node = leaf_hash
    for i in range(33, len(control), 32):
        sibling = control[i:i + 32]
        node = TaggedHash("TapBranch", node + sibling if node < sibling else sibling + node)
    internal = control[1:33]
    tweaked = tweak_add_pubkey(internal, TaggedHash("TapTweak", internal + node))
    return tweaked is not None and tweaked[0] == script[2:34] and tweaked[1] == bool(control[0] & 1)


def _tapleaf_stack(psbt_map, script_pubkey):
    """The script-path witness: signature, leaf script, control block."""
    leaves = [
        (key[1:], value)
        for key, value in psbt_map.map.items()
        if not isinstance(key, int) and key[0] == PSBT_IN_TAP_LEAF_SCRIPT
    ]
    if not leaves:
        raise Bip375Error("taproot input has neither a key-path nor a script-path signature")
    control, leaf = leaves[0]
    script, version = leaf[:-1], leaf[-1]
    leaf_hash = TaggedHash("TapLeaf", bytes([version]) + ser_compact_size(len(script)) + script)
    # rust-psbt's Finalizer runs the interpreter over the result and refuses a leaf the prevout does not commit to
    if not _leaf_commits_to(script_pubkey, version, control, leaf_hash):
        raise Bip375Error("taproot control block does not commit to the prevout")
    sigs = _keyed(psbt_map, PSBT_IN_TAP_SCRIPT_SIG, 64)
    sig = next((sig for key, sig in sigs if key[32:] == leaf_hash), None)
    if sig is None:
        raise Bip375Error("no signature for the taproot leaf")
    return [sig, script, control]


def _witness(stack):
    wit = CTxInWitness()
    wit.scriptWitness.stack = stack
    return wit.serialize()


def _parse(data):
    return PSBT().deserialize(BytesIO(data))


def _check_scalar(data, label):
    if _scalar(data) is None:
        raise Bip375Error(f"invalid {label}")
    return int.from_bytes(data, "big")


def _check_pubkey(data, label):
    if _pubkey(data) is None:
        raise Bip375Error(f"invalid {label}")
    return data


# ---------------------------------------------------------------------------
# BIP-352 and BIP-374 primitives
# ---------------------------------------------------------------------------


def bip352_compute_ecdh_share(privkey, pubkey):
    """scalar*point, compressed. Despite the name, the first argument is the scalar."""
    point = GE.from_bytes(_check_pubkey(pubkey, "public key"))
    return (_check_scalar(privkey, "private key") * point).to_bytes_compressed()


def bip352_derive_silent_payment_output_pubkey(spend_key, ecdh_secret, k):
    if len(ecdh_secret) != 33 or _pubkey(ecdh_secret) is None:
        raise Bip375Error("invalid shared secret")
    tweak = _tagged_scalar("BIP0352/SharedSecret", ecdh_secret + int(k).to_bytes(4, "big"))
    return (GE.from_bytes(_check_pubkey(spend_key, "spend key")) + tweak * G).to_bytes_compressed()


def bip352_tweaked_key_to_p2tr_script(pubkey):
    point = _pubkey(_check_pubkey(pubkey, "public key"))
    return bytes([0x51, 0x20]) + point.to_bytes_xonly()


def bip352_apply_label_to_spend_key(spend_key, scan_privkey, label):
    tweak = _tagged_scalar("BIP0352/Label", scan_privkey + int(label).to_bytes(4, "big"))
    return (GE.from_bytes(_check_pubkey(spend_key, "spend key")) + tweak * G).to_bytes_compressed()


def bip352_compute_input_hash(smallest_outpoint, summed_pubkey):
    if len(smallest_outpoint) != 36:
        raise Bip375Error("outpoint must be 36 bytes")
    _check_pubkey(summed_pubkey, "summed public key")
    return _tagged_scalar("BIP0352/Inputs", smallest_outpoint + summed_pubkey).to_bytes(32, "big")


def dleq_generate_proof(privkey, pubkey, aux_rand):
    if len(aux_rand) != 32:
        raise Bip375Error("aux randomness must be 32 bytes")
    return _dleq_proof(
        _check_scalar(privkey, "private key"),
        _check_pubkey(pubkey, "public key"),
        aux_rand,
    )


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class SilentPaymentAddress:
    def __init__(self, scan_key, spend_key, network=None):
        self.scan_key = scan_key
        self.spend_key = spend_key
        self.network = network


class EcdhShare:
    def __init__(self, scan_key, share_point, dleq_proof):
        self.scan_key = scan_key
        self.share_point = share_point
        self.dleq_proof = dleq_proof


class Utxo:
    def __init__(self, txid, vout, amount, script_pubkey, sequence=None, public_key=None,
                 master_fingerprint=None, derivation_path=None):
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.script_pubkey = script_pubkey
        self.sequence = sequence
        self.public_key = public_key
        self.master_fingerprint = master_fingerprint
        self.derivation_path = derivation_path


class PsbtOutput:
    def __init__(self):
        raise RuntimeError("PsbtOutput cannot be instantiated directly")

    class REGULAR:
        def __init__(self, amount, script_pubkey):
            self.amount = amount
            self.script_pubkey = script_pubkey

    class SILENT_PAYMENT:
        def __init__(self, amount, address, label=None):
            self.amount = amount
            self.address = address
            self.label = label


PsbtOutput.REGULAR = type("PsbtOutput.REGULAR", (PsbtOutput.REGULAR, PsbtOutput), {})
PsbtOutput.SILENT_PAYMENT = type("PsbtOutput.SILENT_PAYMENT", (PsbtOutput.SILENT_PAYMENT, PsbtOutput), {})


def _blank_input():
    """The null outpoint rust-psbt's Input::new writes for an unspecified input."""
    return PSBTMap({
        PSBT_IN_PREVIOUS_TXID: b"\x00" * 32,
        PSBT_IN_OUTPUT_INDEX: b"\xff\xff\xff\xff",
    })


def _blank_output():
    return PSBTMap({PSBT_OUT_AMOUNT: b"\x00" * 8, PSBT_OUT_SCRIPT: b""})


class SilentPaymentPsbt:
    def __init__(self, psbt):
        self._psbt = psbt

    @staticmethod
    def create(num_inputs, num_outputs):
        """An empty PSBT v2 with the standard global fields and blank maps."""
        psbt = PSBT()
        psbt.version = 2
        psbt.g.map = {
            PSBT_GLOBAL_VERSION: struct.pack("<I", 2),
            PSBT_GLOBAL_TX_VERSION: struct.pack("<I", 2),
            PSBT_GLOBAL_INPUT_COUNT: ser_compact_size(num_inputs),
            PSBT_GLOBAL_OUTPUT_COUNT: ser_compact_size(num_outputs),
            PSBT_GLOBAL_TX_MODIFIABLE: b"\x00",
        }
        psbt.i = [_blank_input() for _ in range(num_inputs)]
        psbt.o = [_blank_output() for _ in range(num_outputs)]
        return SilentPaymentPsbt(psbt)

    @staticmethod
    def deserialize(data):
        return SilentPaymentPsbt(_parse(data))

    def serialize(self):
        return self._psbt.serialize()

    def num_inputs(self):
        return len(self._psbt.i)

    def num_outputs(self):
        return len(self._psbt.o)

    def set_tx_modifiable(self, flags):
        self._psbt.g.map[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([flags])

    def add_inputs(self, utxos):
        """Replace the inputs with the outpoints (and sequences) given."""
        if self._psbt.i and len(self._psbt.i) != len(utxos):
            raise Bip375Error("input count does not match the PSBT")
        inputs = []
        for utxo in utxos:
            psbt_map = PSBTMap({
                PSBT_IN_PREVIOUS_TXID: bytes.fromhex(utxo.txid)[::-1],
                PSBT_IN_OUTPUT_INDEX: struct.pack("<I", utxo.vout),
            })
            if utxo.sequence is not None:
                psbt_map.map[PSBT_IN_SEQUENCE] = struct.pack("<I", utxo.sequence)
            inputs.append(psbt_map)
        self._psbt.i = inputs
        self._psbt.g.map[PSBT_GLOBAL_INPUT_COUNT] = ser_compact_size(len(inputs))

    def add_outputs(self, outputs):
        """Replace the outputs. A silent payment output starts with no script."""
        if self._psbt.o and len(self._psbt.o) != len(outputs):
            raise Bip375Error("output count does not match the PSBT")
        built = []
        for output in outputs:
            if isinstance(output, PsbtOutput.SILENT_PAYMENT):
                psbt_map = PSBTMap({PSBT_OUT_AMOUNT: struct.pack("<Q", output.amount)})
                _put(psbt_map, PSBT_OUT_SP_V0_INFO, b"", output.address.scan_key + output.address.spend_key)
                if output.label is not None:
                    psbt_map.map[PSBT_OUT_SP_V0_LABEL] = struct.pack("<I", output.label)
            else:
                psbt_map = PSBTMap({
                    PSBT_OUT_AMOUNT: struct.pack("<Q", output.amount),
                    PSBT_OUT_SCRIPT: output.script_pubkey,
                })
            built.append(psbt_map)
        self._psbt.o = built
        self._psbt.g.map[PSBT_GLOBAL_OUTPUT_COUNT] = ser_compact_size(len(built))

    def update_inputs(self, utxos):
        """Add the witness UTXO and BIP-32 derivation the Updater contributes."""
        for index, utxo in enumerate(utxos):
            if index >= len(self._psbt.i):
                break
            psbt_map = self._psbt.i[index]
            txout = CTxOut(utxo.amount, utxo.script_pubkey)
            psbt_map.map[PSBT_IN_WITNESS_UTXO] = txout.serialize()
            if utxo.public_key:
                fingerprint = utxo.master_fingerprint or b"\x00\x00\x00\x00"
                path = b"".join(struct.pack("<I", child) for child in (utxo.derivation_path or []))
                _put(psbt_map, PSBT_IN_BIP32_DERIVATION, utxo.public_key, fingerprint[:4] + path)

    def _add_shares(self, secrets, per_input):
        scan_keys = _scan_keys(self._psbt)
        if not scan_keys:
            return
        if any(_partial_sigs(m) or _find(m, PSBT_IN_TAP_KEY_SIG, b"") for m in self._psbt.i):
            raise Bip375Error("shares must be added before signing")
        owned = []
        for index, psbt_map in enumerate(self._psbt.i):
            for secret in secrets:
                scalar = _owned_scalar(psbt_map, secret)
                if scalar is not None:
                    owned.append((index, psbt_map, scalar))
                    break
        if per_input:
            if _find(self._psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE, scan_keys[0]) is not None:
                raise Bip375Error("global and per-input shares must not coexist")
            if not owned:
                raise Bip375Error("no inputs owned by the provided keys")
            for _, psbt_map, _ in owned:
                if any(_find(psbt_map, PSBT_IN_SP_ECDH_SHARE, scan) for scan in scan_keys):
                    raise Bip375Error("shares already present")
            for _, psbt_map, scalar in owned:
                for scan in scan_keys:
                    _put(psbt_map, PSBT_IN_SP_ECDH_SHARE, scan, (scalar * GE.from_bytes(scan)).to_bytes_compressed())
                    _put(psbt_map, PSBT_IN_SP_DLEQ, scan, _dleq_proof(scalar, scan, os.urandom(32)))
        else:
            if any(_find(self._psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE, scan) for scan in scan_keys):
                raise Bip375Error("shares already present")
            if any(_find(m, PSBT_IN_SP_ECDH_SHARE, scan_keys[0]) for m in self._psbt.i):
                raise Bip375Error("global and per-input shares must not coexist")
            if len(owned) != sum(_input_pubkey(m) is not None for m in self._psbt.i):
                raise Bip375Error("a single signer must own every eligible input")
            total = sum(scalar for _, _, scalar in owned) % _ORDER
            for scan in scan_keys:
                _put(self._psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE, scan, (total * GE.from_bytes(scan)).to_bytes_compressed())
                _put(self._psbt.g, PSBT_GLOBAL_SP_DLEQ, scan, _dleq_proof(total, scan, os.urandom(32)))

    def generate_single_signer_ecdh_shares(self, spend_key):
        self._add_shares([_check_scalar(spend_key, "spend key")], per_input=False)

    def generate_single_signer_ecdh_shares_with_keys(self, spend_keys):
        self._add_shares([_check_scalar(k, "spend key") for k in spend_keys], per_input=False)

    def generate_multi_signer_ecdh_shares(self, spend_key):
        self._add_shares([_check_scalar(spend_key, "spend key")], per_input=True)

    def compute_sp_output_scripts(self):
        """Derive and set every silent payment output script, then fix the tx."""
        outputs = _sp_outputs(self._psbt)
        if not outputs:
            return
        secrets = {}
        counters = {}
        for index, scan, spend in outputs:
            if scan not in secrets:
                secrets[scan] = _shared_secret(self._psbt, scan)
            k = counters.get(scan, 0)
            counters[scan] = k + 1
            _put(self._psbt.o[index], PSBT_OUT_SCRIPT, b"", _output_script(spend, secrets[scan], k))
        flags = self._psbt.g.map.get(PSBT_GLOBAL_TX_MODIFIABLE, b"\x00")[0]
        flags &= ~(_TX_MODIFIABLE_INPUTS | _TX_MODIFIABLE_OUTPUTS)
        self._psbt.g.map[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([flags])

    def sign_input(self, input_index, privkey):
        if input_index >= len(self._psbt.i):
            raise Bip375Error("input index out of range")
        _sign_input(self._psbt, input_index, _check_scalar(privkey, "private key"))

    def finalize(self):
        for psbt_map in self._psbt.i:
            if _find(psbt_map, PSBT_IN_FINAL_SCRIPTSIG, b"") or _find(psbt_map, PSBT_IN_FINAL_SCRIPTWITNESS, b""):
                continue
            _funding_script_and_value(psbt_map)
            _finalize_input(psbt_map)

    def extract_transaction(self):
        """The finalized transaction. Does not modify the PSBT."""
        tx = _unsigned_tx(self._psbt)
        for index, psbt_map in enumerate(self._psbt.i):
            script_sig = _find(psbt_map, PSBT_IN_FINAL_SCRIPTSIG, b"")
            if script_sig:
                tx.vin[index].scriptSig = script_sig
            witness = _find(psbt_map, PSBT_IN_FINAL_SCRIPTWITNESS, b"")
            if witness:
                wit = CTxInWitness()
                wit.deserialize(BytesIO(witness))
                tx.wit.vtxinwit.append(wit)
            else:
                tx.wit.vtxinwit.append(CTxInWitness())
        return tx.serialize_with_witness()

    def get_global_ecdh_shares(self):
        return [
            EcdhShare(scan, share, _find(self._psbt.g, PSBT_GLOBAL_SP_DLEQ, scan))
            for scan, share in _keyed(self._psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE, 33, 33)
        ]

    def get_input_ecdh_shares(self, input_index):
        if input_index >= len(self._psbt.i):
            raise Bip375Error("input index out of range")
        psbt_map = self._psbt.i[input_index]
        return [
            EcdhShare(scan, share, _find(psbt_map, PSBT_IN_SP_DLEQ, scan))
            for scan, share in _keyed(psbt_map, PSBT_IN_SP_ECDH_SHARE, 33, 33)
        ]

    def get_output_sp_address(self, output_index):
        if output_index >= len(self._psbt.o):
            raise Bip375Error("output index out of range")
        info = _find(self._psbt.o[output_index], PSBT_OUT_SP_V0_INFO, b"")
        if info is None or len(info) != 66:
            return None
        return SilentPaymentAddress(info[:33], info[33:])

    def get_output_script(self, output_index):
        if output_index >= len(self._psbt.o):
            raise Bip375Error("output index out of range")
        return _find(self._psbt.o[output_index], PSBT_OUT_SCRIPT, b"") or b""


# ---------------------------------------------------------------------------
# Raw field access
# ---------------------------------------------------------------------------


def _map_for(psbt, kind, index):
    if kind == "global":
        return psbt._psbt.g
    maps = psbt._psbt.i if kind == "input" else psbt._psbt.o
    if index >= len(maps):
        raise Bip375Error("index out of range")
    return maps[index]


def add_raw_global_field(psbt, type_value, key_data, value):
    _put(_map_for(psbt, "global", 0), type_value, key_data, value)


def add_raw_input_field(psbt, input_index, type_value, key_data, value):
    _put(_map_for(psbt, "input", input_index), type_value, key_data, value)


def add_raw_output_field(psbt, output_index, type_value, key_data, value):
    _put(_map_for(psbt, "output", output_index), type_value, key_data, value)


def remove_raw_input_fields_by_type(psbt, input_index, type_value):
    _drop_type(_map_for(psbt, "input", input_index), type_value)
