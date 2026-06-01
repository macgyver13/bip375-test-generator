"""Spec checks for every PSBT in the committed BIP-375 vectors.

Parsing uses Bitcoin Core's vendored test framework, not py_spdk, so the
parser is not the code that built the PSBT. Invalid vectors name the
properties they break in the config's violates list. That list is not part
of the JSON.
"""

import base64
import json
import struct
import unittest
from io import BytesIO
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT))

from dleq import dleq_verify_proof
from test_generator import ConfigBasedTestGenerator, ScanKeySpec
from test_framework.crypto.secp256k1 import G, GE
from test_framework.key import ECPubKey, TaggedHash, tweak_add_pubkey, verify_schnorr
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    hash256,
    ser_string,
    uint256_from_str,
)
from test_framework.psbt import PSBT
from test_framework.script import (
    CScript,
    OP_0,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_DEFAULT,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    LegacySignatureHash,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
    hash160,
)
from test_framework.script_util import keyhash_to_p2pkh_script

# The committed standard set, and the extended set `just gen-extended` writes to out/.
VECTOR_FILES = (ROOT / "bip375_test_vectors.json", ROOT / "out" / "bip375_test_vectors_extended.json")
INVALID_CONFIGS = ROOT / "test_configs" / "invalid"

NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

PSBT_GLOBAL_TX_VERSION = 0x02
PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
PSBT_GLOBAL_TX_MODIFIABLE = 0x06
PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
PSBT_GLOBAL_SP_DLEQ = 0x08
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
PSBT_IN_PREVIOUS_TXID = 0x0E
PSBT_IN_OUTPUT_INDEX = 0x0F
PSBT_IN_SEQUENCE = 0x10
PSBT_IN_TAP_KEY_SIG = 0x13
PSBT_IN_TAP_SCRIPT_SIG = 0x14
PSBT_IN_TAP_LEAF_SCRIPT = 0x15
PSBT_IN_TAP_INTERNAL_KEY = 0x17
PSBT_IN_TAP_MERKLE_ROOT = 0x18
PSBT_IN_SP_ECDH_SHARE = 0x1D
PSBT_IN_SP_DLEQ = 0x1E
PSBT_OUT_AMOUNT = 0x03
PSBT_OUT_SCRIPT = 0x04
PSBT_OUT_SP_V0_INFO = 0x09
PSBT_OUT_SP_V0_LABEL = 0x0A

INPUTS_MODIFIABLE = 0x01
OUTPUTS_MODIFIABLE = 0x02
HAS_SIGHASH_SINGLE = 0x04

PROPERTIES = (
    "bip174_framing",
    "bip371_taproot",
    "signatures",
    "bip352_outputs",
    "bip374_dleq",
    "bip375_ecdh",
    "bip370_modifiable",
    "bip375_sighash_all",
    "bip370_outputs",
    "bip375_eligibility",
)


def _entries(psbt_map):
    for key, value in psbt_map.map.items():
        if isinstance(key, int):
            yield key, b"", value
        else:
            yield key[0], key[1:], value


def _all(psbt_map, type_byte):
    return [(keydata, value) for typ, keydata, value in _entries(psbt_map) if typ == type_byte]


def _one(psbt_map, type_byte, keydata=b""):
    for kd, value in _all(psbt_map, type_byte):
        if kd == keydata:
            return value
    return None


def _witness_program(script):
    if not script:
        return None
    first = script[0]
    if first == 0:
        version = 0
    elif 0x51 <= first <= 0x60:
        version = first - 0x50
    else:
        return None
    if len(script) < 2:
        return None
    push = script[1]
    if push != len(script) - 2 or not 2 <= push <= 40:
        return None
    return version, script[2:]


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
    program = _witness_program(script)
    return program is not None and program[0] == 0 and len(program[1]) == 20


def _is_p2wsh(script):
    program = _witness_program(script)
    return program is not None and program[0] == 0 and len(program[1]) == 32


def _is_p2sh(script):
    return len(script) == 23 and script[0] == OP_HASH160 and script[1] == 20 and script[22] == OP_EQUAL


def _is_p2tr(script):
    program = _witness_program(script)
    return program is not None and program[0] == 1 and len(program[1]) == 32


def _p2sh_script(redeem):
    return bytes(CScript([OP_HASH160, hash160(redeem), OP_EQUAL]))


def _spent_output(inp):
    raw = _one(inp, PSBT_IN_WITNESS_UTXO)
    if raw is not None:
        txout = CTxOut()
        txout.deserialize(BytesIO(raw))
        return txout
    raw_tx = _one(inp, PSBT_IN_NON_WITNESS_UTXO)
    index = _one(inp, PSBT_IN_OUTPUT_INDEX)
    if raw_tx is None or index is None or len(index) != 4:
        return None
    tx = CTransaction()
    tx.deserialize(BytesIO(raw_tx))
    vout = struct.unpack("<I", index)[0]
    if vout >= len(tx.vout):
        return None
    return tx.vout[vout]


def _scriptsig_pushes(inp):
    raw = _one(inp, PSBT_IN_FINAL_SCRIPTSIG)
    if not raw:
        return []
    return [item for item in CScript(raw) if isinstance(item, (bytes, bytearray))]


def _witness_stack(inp):
    raw = _one(inp, PSBT_IN_FINAL_SCRIPTWITNESS)
    if not raw:
        return []
    wit = CTxInWitness()
    wit.deserialize(BytesIO(raw))
    return list(wit.scriptWitness.stack)


def _redeem_script(inp):
    raw = _one(inp, PSBT_IN_REDEEM_SCRIPT)
    if raw is not None:
        return raw
    script = _spent_script(inp)
    if script and _is_p2sh(script):
        pushes = _scriptsig_pushes(inp)
        if pushes:
            return pushes[-1]
    return None


def _witness_script(inp):
    raw = _one(inp, PSBT_IN_WITNESS_SCRIPT)
    if raw is not None:
        return raw
    if _is_p2wsh(_spent_script(inp) or b""):
        stack = _witness_stack(inp)
        if stack:
            return stack[-1]
    return None


def _spent_script(inp):
    spent = _spent_output(inp)
    if spent is None:
        return None
    return bytes(spent.scriptPubKey)


def _derivation_pubkeys(inp):
    return [keydata for keydata, _value in _all(inp, PSBT_IN_BIP32_DERIVATION) if len(keydata) in (33, 65)]


def _script_commits(pubkey, script, redeem):
    if _is_p2wpkh(script):
        return bytes(CScript([OP_0, hash160(pubkey)])) == bytes(script)
    if _is_p2pkh(script):
        return bytes(keyhash_to_p2pkh_script(hash160(pubkey))) == bytes(script)
    if _is_p2sh(script) and redeem is not None and _is_p2wpkh(redeem):
        return _p2sh_script(redeem) == bytes(script) and _script_commits(pubkey, redeem, None)
    return False


def _leaf_commits(output_xonly, control, script, version):
    if len(control) < 33 or (len(control) - 33) % 32:
        return False
    if control[0] & 0xFE != version:
        return False
    internal = control[1:33]
    digest = TaggedHash("TapLeaf", bytes([version]) + ser_string(script))
    path = control[33:]
    for offset in range(0, len(path), 32):
        sibling = path[offset:offset + 32]
        pair = digest + sibling if digest < sibling else sibling + digest
        digest = TaggedHash("TapBranch", pair)
    tweaked, negated = tweak_add_pubkey(internal, TaggedHash("TapTweak", internal + digest))
    if tweaked is None:
        return False
    return tweaked == output_xonly and bool(negated) == bool(control[0] & 1)


def _tweaked_output(internal, merkle):
    tweaked, _negated = tweak_add_pubkey(internal, TaggedHash("TapTweak", internal + merkle))
    return tweaked


def _nums_claims(inp, script):
    """(committed, uncommitted) NUMS internal keys claimed for this input."""
    committed = False
    uncommitted = False
    if not script or not _is_p2tr(script):
        return committed, uncommitted
    output = script[2:]
    internal = _one(inp, PSBT_IN_TAP_INTERNAL_KEY)
    if internal == NUMS_H:
        merkle = _one(inp, PSBT_IN_TAP_MERKLE_ROOT)
        if _tweaked_output(internal, b"" if merkle is None else merkle) == output:
            committed = True
        else:
            uncommitted = True
    for control, value in _all(inp, PSBT_IN_TAP_LEAF_SCRIPT):
        if len(control) < 33 or len(value) < 1 or control[1:33] != NUMS_H:
            continue
        leaf, version = value[:-1], value[-1]
        if _leaf_commits(output, control, leaf, version):
            committed = True
        else:
            uncommitted = True
    stack = _witness_stack(inp)
    if len(stack) >= 2:
        control = stack[-1]
        leaf = stack[-2]
        if len(control) >= 33 and control[1:33] == NUMS_H:
            version = control[0] & 0xFE
            if _leaf_commits(output, control, leaf, version):
                committed = True
            else:
                uncommitted = True
    return committed, uncommitted


def _pubkey(inp):
    """Compressed pubkey an eligible input contributes, or None."""
    script = _spent_script(inp)
    if script is None:
        return None
    if _is_p2tr(script):
        committed, _uncommitted = _nums_claims(inp, script)
        if committed:
            return None
        return b"\x02" + script[2:]
    redeem = _redeem_script(inp)
    candidates = list(_derivation_pubkeys(inp))
    stack = _witness_stack(inp)
    if stack and len(stack[-1]) in (33, 65):
        candidates.append(stack[-1])
    pushes = _scriptsig_pushes(inp)
    if pushes and len(pushes[-1]) in (33, 65):
        candidates.append(pushes[-1])
    for pubkey in candidates:
        if _script_commits(pubkey, script, redeem):
            return pubkey
    return None


def _eligible_template(inp):
    script = _spent_script(inp)
    if script is None:
        return False
    if _is_p2tr(script):
        committed, _uncommitted = _nums_claims(inp, script)
        return not committed
    if _is_p2pkh(script) or _is_p2wpkh(script):
        return True
    redeem = _redeem_script(inp)
    return bool(redeem is not None and _is_p2sh(script) and _is_p2wpkh(redeem) and _p2sh_script(redeem) == script)


def _outpoint(inp):
    txid = _one(inp, PSBT_IN_PREVIOUS_TXID)
    index = _one(inp, PSBT_IN_OUTPUT_INDEX)
    if txid is None or index is None:
        return None
    return txid, struct.unpack("<I", index)[0]


def _scan_privs():
    """Scan private keys of every scan key the configs declare, by compressed pubkey."""
    if getattr(_scan_privs, "cache", None) is None:
        generator = ConfigBasedTestGenerator()
        found = {}
        for path in sorted((ROOT / "test_configs").glob("*/*.yaml")):
            for case in yaml.safe_load(path.read_text()).get("test_cases", []):
                specs = [
                    ScanKeySpec(key["key_id"], key.get("derivation_suffix", ""))
                    for key in case.get("scan_keys", [{"key_id": "default"}])
                ]
                generator.builder._generate_scan_keys(specs)
                for pub, priv in generator.builder.scan_privs.items():
                    found[pub] = int(priv)
        _scan_privs.cache = found
    return _scan_privs.cache


def _add_points(pubkeys):
    total = None
    for pubkey in pubkeys:
        point = GE.from_bytes(pubkey)
        total = point if total is None else total + point
    return total


def _sp_script(outpoints, summed, ecdh_share, spend, k):
    smallest = min(txid + index.to_bytes(4, "little") for txid, index in outpoints)
    input_hash = int.from_bytes(TaggedHash("BIP0352/Inputs", smallest + summed.to_bytes_compressed()), "big") % GE.ORDER
    shared = (input_hash * GE.from_bytes(ecdh_share)).to_bytes_compressed()
    tweak = int.from_bytes(TaggedHash("BIP0352/SharedSecret", shared + k.to_bytes(4, "big")), "big") % GE.ORDER
    output = GE.from_bytes(spend) + tweak * G
    return bytes([0x51, 0x20]) + output.to_bytes_xonly()


def _length_errors(psbt):
    errors = []
    fixed = {
        "g": {
            0x02: (0, 4),
            0x03: (0, 4),
            0x06: (0, 1),
            0xFB: (0, 4),
        },
        "i": {
            PSBT_IN_SIGHASH_TYPE: (0, 4),
            PSBT_IN_PREVIOUS_TXID: (0, 32),
            PSBT_IN_OUTPUT_INDEX: (0, 4),
            PSBT_IN_SEQUENCE: (0, 4),
            PSBT_IN_TAP_KEY_SIG: (0, None),
            PSBT_IN_TAP_INTERNAL_KEY: (0, 32),
            PSBT_IN_TAP_MERKLE_ROOT: (0, 32),
        },
        "o": {
            PSBT_OUT_AMOUNT: (0, 8),
            PSBT_OUT_SP_V0_INFO: (0, 66),
            PSBT_OUT_SP_V0_LABEL: (0, 4),
        },
    }
    sections = (("g", [psbt.g]), ("i", psbt.i), ("o", psbt.o))
    for name, maps in sections:
        for psbt_map in maps:
            for typ, keydata, value in _entries(psbt_map):
                if name == "g" and typ in (PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_GLOBAL_SP_DLEQ):
                    if len(keydata) != 33 or len(value) != (33 if typ == PSBT_GLOBAL_SP_ECDH_SHARE else 64):
                        errors.append(f"global type {typ:#x} has key {len(keydata)} value {len(value)}")
                    continue
                if name == "i" and typ in (PSBT_IN_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ):
                    if len(keydata) != 33 or len(value) != (33 if typ == PSBT_IN_SP_ECDH_SHARE else 64):
                        errors.append(f"input type {typ:#x} has key {len(keydata)} value {len(value)}")
                    continue
                if name == "i" and typ == PSBT_IN_PARTIAL_SIG and len(keydata) not in (33, 65):
                    errors.append(f"partial sig key is {len(keydata)} bytes")
                if name == "i" and typ == PSBT_IN_TAP_SCRIPT_SIG and (len(keydata) != 64 or len(value) not in (64, 65)):
                    errors.append("tap script sig has the wrong size")
                if name == "i" and typ == PSBT_IN_TAP_KEY_SIG and len(value) not in (64, 65):
                    errors.append(f"tap key sig is {len(value)} bytes")
                if name == "i" and typ == PSBT_IN_BIP32_DERIVATION:
                    if len(keydata) not in (33, 65) or len(value) < 4 or (len(value) - 4) % 4:
                        errors.append("bip32 derivation has the wrong size")
                if name == "i" and typ == PSBT_IN_TAP_LEAF_SCRIPT:
                    if len(keydata) < 33 or (len(keydata) - 33) % 32 or len(value) < 1:
                        errors.append("tap leaf script has the wrong size")
                expected = fixed[name].get(typ)
                if expected is None:
                    continue
                key_len, value_len = expected
                if len(keydata) != key_len or (value_len is not None and len(value) != value_len):
                    errors.append(f"{name} type {typ:#x} has key {len(keydata)} value {len(value)}")
    return errors


def _framing(b64):
    raw = base64.b64decode(b64, validate=True)
    if not raw.startswith(b"psbt\xff"):
        return None, ["missing psbt magic"]
    try:
        psbt = PSBT.from_base64(b64)
        encoded = psbt.serialize()
    except Exception as exc:
        return None, [f"parse failed: {exc}"]
    errors = []
    if encoded != raw:
        errors.append("re-serialization does not reproduce the original bytes")
    errors.extend(_length_errors(psbt))
    return psbt, errors


def _tx(psbt):
    version = _one(psbt.g, PSBT_GLOBAL_TX_VERSION)
    if version is None or len(version) != 4:
        raise ValueError("missing tx version")
    tx = CTransaction()
    tx.version = struct.unpack("<i", version)[0]
    locktime = _one(psbt.g, PSBT_GLOBAL_FALLBACK_LOCKTIME)
    tx.nLockTime = struct.unpack("<I", locktime)[0] if locktime else 0
    for inp in psbt.i:
        outpoint = _outpoint(inp)
        if outpoint is None:
            raise ValueError("input is missing its outpoint")
        txid, vout = outpoint
        sequence = _one(inp, PSBT_IN_SEQUENCE)
        seq = struct.unpack("<I", sequence)[0] if sequence else 0xFFFFFFFF
        tx.vin.append(CTxIn(COutPoint(uint256_from_str(txid), vout), b"", seq))
    for out in psbt.o:
        amount = _one(out, PSBT_OUT_AMOUNT)
        if amount is None:
            raise ValueError("output is missing its amount")
        script = _one(out, PSBT_OUT_SCRIPT) or b""
        tx.vout.append(CTxOut(int.from_bytes(amount, "little"), script))
    return tx


def _unique_id(psbt):
    """BIP-370 unique id, with PSBT_OUT_SP_V0_INFO as the script of sp outputs (BIP-375).

    The generator writes no PSBT_IN_REQUIRED_*_LOCKTIME fields, so the computed
    locktime is the fallback locktime.
    """
    tx = _tx(psbt)
    for txin in tx.vin:
        txin.nSequence = 0
    for txout, out in zip(tx.vout, psbt.o):
        info = _one(out, PSBT_OUT_SP_V0_INFO)
        if info is not None:
            txout.scriptPubKey = b"\x00" + info
    return hash256(tx.serialize_without_witness())[::-1].hex()


def _sighash_of(sig_bytes, kind):
    if kind == "schnorr":
        if len(sig_bytes) == 64:
            return SIGHASH_DEFAULT, sig_bytes
        if len(sig_bytes) == 65:
            # BIP-341: SIGHASH_DEFAULT is encoded only by omitting the byte.
            if sig_bytes[-1] == SIGHASH_DEFAULT:
                raise ValueError("65-byte schnorr signature carries an explicit SIGHASH_DEFAULT byte")
            return sig_bytes[-1], sig_bytes[:-1]
        raise ValueError(f"schnorr signature is {len(sig_bytes)} bytes")
    if not sig_bytes:
        raise ValueError("empty ecdsa signature")
    return sig_bytes[-1], sig_bytes[:-1]


def _collect_sigs(psbt):
    found = []
    for index, inp in enumerate(psbt.i):
        for keydata, value in _all(inp, PSBT_IN_PARTIAL_SIG):
            sighash, der = _sighash_of(value, "ecdsa")
            found.append({"index": index, "kind": "ecdsa", "sighash": sighash, "body": der, "pubkey": keydata, "leaf": None})
        for _keydata, value in _all(inp, PSBT_IN_TAP_KEY_SIG):
            sighash, body = _sighash_of(value, "schnorr")
            script = _spent_script(inp)
            pubkey = script[2:] if script and _is_p2tr(script) else b""
            found.append({"index": index, "kind": "schnorr", "sighash": sighash, "body": body, "pubkey": pubkey, "leaf": None})
        for keydata, value in _all(inp, PSBT_IN_TAP_SCRIPT_SIG):
            sighash, body = _sighash_of(value, "schnorr")
            found.append({
                "index": index,
                "kind": "schnorr",
                "sighash": sighash,
                "body": body,
                "pubkey": keydata[:32],
                "leaf": keydata[32:],
            })
        script = _spent_script(inp)
        stack = _witness_stack(inp)
        pushes = _scriptsig_pushes(inp)
        if script and _is_p2tr(script) and stack:
            if len(stack) == 1:
                sighash, body = _sighash_of(stack[0], "schnorr")
                found.append({"index": index, "kind": "schnorr", "sighash": sighash, "body": body, "pubkey": script[2:], "leaf": None})
            elif len(stack) >= 3:
                sighash, body = _sighash_of(stack[0], "schnorr")
                leaf = stack[-2]
                version = stack[-1][0] & 0xFE
                leaf_hash = TaggedHash("TapLeaf", bytes([version]) + ser_string(leaf))
                found.append({
                    "index": index,
                    "kind": "schnorr",
                    "sighash": sighash,
                    "body": body,
                    "pubkey": b"",
                    "leaf": leaf_hash,
                    "leaf_script": leaf,
                    "leaf_version": version,
                })
        elif script and (_is_p2wpkh(script) or _is_p2wsh(script)) and stack:
            sighash, der = _sighash_of(stack[0], "ecdsa")
            pubkey = stack[1] if len(stack) > 1 and not _is_p2wsh(script) else b""
            found.append({"index": index, "kind": "ecdsa", "sighash": sighash, "body": der, "pubkey": pubkey, "leaf": None})
        elif script and _is_p2sh(script) and _redeem_script(inp) and _is_p2wpkh(_redeem_script(inp)) and stack:
            sighash, der = _sighash_of(stack[0], "ecdsa")
            pubkey = stack[1] if len(stack) > 1 else b""
            found.append({"index": index, "kind": "ecdsa", "sighash": sighash, "body": der, "pubkey": pubkey, "leaf": None})
        elif script and (_is_p2pkh(script) or _is_p2sh(script)) and pushes:
            sig_pushes = pushes[:-1] if _is_p2sh(script) else pushes[:1]
            for push in sig_pushes:
                if not push or push[0] != 0x30:
                    continue
                sighash, der = _sighash_of(push, "ecdsa")
                found.append({"index": index, "kind": "ecdsa", "sighash": sighash, "body": der, "pubkey": b"", "leaf": None})
    return found


def _verify_sig(psbt, tx, spent, item):
    index = item["index"]
    inp = psbt.i[index]
    script = bytes(spent[index].scriptPubKey)
    sighash_type = item["sighash"]
    if item["kind"] == "schnorr":
        if item["leaf"] is None:
            digest = TaprootSignatureHash(tx, spent, sighash_type, input_index=index)
            pubkey = item["pubkey"]
        else:
            leaf_script = item.get("leaf_script")
            if leaf_script is None:
                for _control, value in _all(inp, PSBT_IN_TAP_LEAF_SCRIPT):
                    leaf, version = value[:-1], value[-1]
                    if TaggedHash("TapLeaf", bytes([version]) + ser_string(leaf)) == item["leaf"]:
                        leaf_script = leaf
                        break
            if leaf_script is None:
                return "tap script signature has no leaf script"
            digest = TaprootSignatureHash(
                tx,
                spent,
                sighash_type,
                input_index=index,
                scriptpath=True,
                leaf_script=CScript(leaf_script),
                codeseparator_pos=0xFFFFFFFF,
            )
            pubkey = item["pubkey"]
            if not pubkey:
                # A finalized script-path witness does not repeat the x-only key.
                # The leaf is a CHECKSIG of one 32-byte key.
                pushes = [push for push in CScript(leaf_script) if isinstance(push, (bytes, bytearray)) and len(push) == 32]
                if len(pushes) != 1:
                    return "tap leaf does not commit to one key"
                pubkey = pushes[0]
        if len(pubkey) != 32 or not verify_schnorr(pubkey, item["body"], digest):
            return f"input {index} schnorr signature does not verify"
        return None
    candidates = [item["pubkey"]] if item["pubkey"] else []
    for candidate in _derivation_pubkeys(inp):
        if candidate not in candidates:
            candidates.append(candidate)
    for body in (_redeem_script(inp), _witness_script(inp)):
        if not body:
            continue
        for script_item in CScript(body):
            if isinstance(script_item, (bytes, bytearray)) and len(script_item) in (33, 65):
                raw = bytes(script_item)
                if raw not in candidates:
                    candidates.append(raw)
    stack = _witness_stack(inp)
    if len(stack) >= 2 and len(stack[-1]) in (33, 65) and stack[-1] not in candidates:
        candidates.append(stack[-1])
    pushes = _scriptsig_pushes(inp)
    if pushes and len(pushes[-1]) in (33, 65) and pushes[-1] not in candidates:
        candidates.append(pushes[-1])
    if _is_p2wpkh(script):
        digest = SegwitV0SignatureHash(keyhash_to_p2pkh_script(script[2:]), tx, index, sighash_type, spent[index].nValue)
    elif _is_p2pkh(script):
        digest, _err = LegacySignatureHash(CScript(script), tx, index, sighash_type)
    elif _is_p2sh(script):
        redeem = _redeem_script(inp)
        if redeem is None:
            return f"input {index} p2sh signature has no redeem script"
        if _is_p2wpkh(redeem):
            digest = SegwitV0SignatureHash(keyhash_to_p2pkh_script(redeem[2:]), tx, index, sighash_type, spent[index].nValue)
        else:
            digest, _err = LegacySignatureHash(CScript(redeem), tx, index, sighash_type)
    elif _is_p2wsh(script):
        witness = _witness_script(inp)
        if witness is None:
            return f"input {index} p2wsh signature has no witness script"
        digest = SegwitV0SignatureHash(CScript(witness), tx, index, sighash_type, spent[index].nValue)
    else:
        return f"input {index} signature spends an unsupported script"
    for candidate in candidates:
        key = ECPubKey()
        key.set(candidate)
        if key.verify_ecdsa(item["body"], digest, low_s=True):
            return None
    return f"input {index} ecdsa signature does not verify"


def _check_signatures(psbt):
    errors = []
    try:
        sigs = _collect_sigs(psbt)
    except Exception as exc:
        return [f"could not read signatures: {exc}"]
    if not sigs:
        return []
    try:
        tx = _tx(psbt)
        spent = []
        for inp in psbt.i:
            txout = _spent_output(inp)
            if txout is None:
                return ["signature is present but an input has no prevout"]
            spent.append(txout)
    except Exception as exc:
        return [f"could not build the signed transaction: {exc}"]
    for item in sigs:
        declared = _one(psbt.i[item["index"]], PSBT_IN_SIGHASH_TYPE)
        if declared is not None:
            declared_type = struct.unpack("<I", declared)[0]
            if declared_type != item["sighash"]:
                errors.append(
                    f"input {item['index']} sighash {item['sighash']:#x} does not match PSBT_IN_SIGHASH_TYPE {declared_type:#x}"
                )
        try:
            error = _verify_sig(psbt, tx, spent, item)
        except Exception as exc:
            error = f"input {item['index']} signature check failed: {exc}"
        if error:
            errors.append(error)
    return errors


def _sp_outputs(psbt):
    outputs = []
    for index, out in enumerate(psbt.o):
        info = _one(out, PSBT_OUT_SP_V0_INFO)
        if info is None:
            continue
        outputs.append((index, info, _one(out, PSBT_OUT_SCRIPT), _one(out, PSBT_OUT_SP_V0_LABEL)))
    return outputs


def _k_map(outputs):
    groups = {}
    for index, info, _script, _label in outputs:
        if len(info) != 66:
            continue
        groups.setdefault(info[:33], []).append((info[33:], index))
    assigned = {}
    for entries in groups.values():
        for k, (_spend, index) in enumerate(sorted(entries)):
            assigned[index] = k
    return assigned


def _share_for(psbt, scan, covered_pubkeys):
    """The share a scan key should have, from the scan private key."""
    priv = _scan_privs().get(scan)
    if priv is None:
        return None, "scan key is not from the vector wallets"
    if not covered_pubkeys:
        return None, "share covers no input key"
    point = priv * _add_points(covered_pubkeys)
    return point.to_bytes_compressed(), None


def _check_ecdh(psbt):
    errors = []
    eligible = []
    for index, inp in enumerate(psbt.i):
        if not _eligible_template(inp):
            continue
        pubkey = _pubkey(inp)
        eligible.append((index, pubkey))
    global_shares = _all(psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE)
    if global_shares:
        missing = [index for index, pubkey in eligible if pubkey is None]
        if missing:
            errors.append(f"global share omits eligible inputs {missing}")
        else:
            pubkeys = [pubkey for _index, pubkey in eligible]
            for scan, share in global_shares:
                expected, error = _share_for(psbt, scan, pubkeys)
                if error:
                    errors.append(error)
                elif share != expected:
                    errors.append(f"global share for {scan.hex()[:12]} is not scan times every eligible key")
    for index, inp in enumerate(psbt.i):
        if not _eligible_template(inp):
            continue
        for scan, share in _all(inp, PSBT_IN_SP_ECDH_SHARE):
            pubkey = _pubkey(inp)
            if pubkey is None:
                errors.append(f"input {index} share has no eligible pubkey")
                continue
            expected, error = _share_for(psbt, scan, [pubkey])
            if error:
                errors.append(error)
            elif share != expected:
                errors.append(f"input {index} share for {scan.hex()[:12]} is not scan times that input key")
    return errors


def _check_dleq(psbt):
    errors = []
    eligible_pubkeys = [pubkey for inp in psbt.i if (pubkey := _pubkey(inp)) is not None and _eligible_template(inp)]
    proofs = {keydata: value for keydata, value in _all(psbt.g, PSBT_GLOBAL_SP_DLEQ)}
    shares = {keydata: value for keydata, value in _all(psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE)}
    for scan in set(proofs) | set(shares):
        proof = proofs.get(scan)
        share = shares.get(scan)
        if proof is None or share is None:
            errors.append("global ECDH share and DLEQ proof must both be set")
            continue
        if any(pubkey is None for inp in psbt.i if _eligible_template(inp) for pubkey in [_pubkey(inp)]):
            errors.append("global DLEQ proof does not cover every eligible input")
            continue
        if not eligible_pubkeys:
            errors.append("global DLEQ proof has no eligible inputs")
            continue
        try:
            ok = dleq_verify_proof(_add_points(eligible_pubkeys), GE.from_bytes(scan), GE.from_bytes(share), proof)
        except Exception as exc:
            ok = False
            errors.append(f"global DLEQ proof failed: {exc}")
            continue
        if not ok:
            errors.append(f"global DLEQ proof for {scan.hex()[:12]} does not verify")
    for index, inp in enumerate(psbt.i):
        proofs = {keydata: value for keydata, value in _all(inp, PSBT_IN_SP_DLEQ)}
        shares = {keydata: value for keydata, value in _all(inp, PSBT_IN_SP_ECDH_SHARE)}
        if not _eligible_template(inp):
            continue
        pubkey = _pubkey(inp)
        for scan in set(proofs) | set(shares):
            proof = proofs.get(scan)
            share = shares.get(scan)
            if proof is None or share is None or pubkey is None:
                if proof is not None or share is not None:
                    errors.append(f"input {index} DLEQ proof does not verify")
                continue
            try:
                ok = dleq_verify_proof(GE.from_bytes(pubkey), GE.from_bytes(scan), GE.from_bytes(share), proof)
            except Exception:
                ok = False
            if not ok:
                errors.append(f"input {index} DLEQ proof for {scan.hex()[:12]} does not verify")
    return errors


def _check_outputs(psbt):
    outputs = _sp_outputs(psbt)
    if not any(script is not None for _index, _info, script, _label in outputs):
        return []
    outpoints = []
    for inp in psbt.i:
        outpoint = _outpoint(inp)
        if outpoint is None:
            return ["output script is set but an input has no outpoint"]
        outpoints.append(outpoint)
    eligible = [(_outpoint(inp), _pubkey(inp)) for inp in psbt.i if _eligible_template(inp)]
    if any(pubkey is None for _op, pubkey in eligible):
        return ["output script is set but an eligible input has no pubkey"]
    summed = _add_points([pubkey for _op, pubkey in eligible])
    if summed is None:
        return ["output script is set but there is no eligible input"]
    shares = {scan: share for scan, share in _all(psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE)}
    per_scan = {}
    for inp in psbt.i:
        if not _eligible_template(inp):
            continue
        outpoint = _outpoint(inp)
        for scan, share in _all(inp, PSBT_IN_SP_ECDH_SHARE):
            per_scan.setdefault(scan, []).append((outpoint, share))
    for scan, items in per_scan.items():
        if scan in shares:
            continue
        if len(items) != len(eligible):
            return [f"output script is set but scan {scan.hex()[:12]} does not cover every eligible input"]
        total = None
        for _op, share in sorted(items, key=lambda item: item[0]):
            point = GE.from_bytes(share)
            total = point if total is None else total + point
        shares[scan] = total.to_bytes_compressed()
    assigned = _k_map(outputs)
    errors = []
    for index, info, script, _label in outputs:
        if script is None:
            continue
        if len(info) != 66 or info[:33] not in shares:
            errors.append(f"output {index} script does not match a complete ECDH share")
            continue
        try:
            expected = _sp_script(outpoints, summed, shares[info[:33]], info[33:], assigned[index])
        except Exception as exc:
            errors.append(f"output {index} script could not be derived: {exc}")
            continue
        if script != expected:
            errors.append(f"output {index} script is not the BIP-352 output for k={assigned[index]}")
    return errors


def _check_taproot(psbt):
    errors = []
    for index, inp in enumerate(psbt.i):
        script = _spent_script(inp)
        if not script or not _is_p2tr(script):
            continue
        output = script[2:]
        internal = _one(inp, PSBT_IN_TAP_INTERNAL_KEY)
        if internal is not None:
            merkle = _one(inp, PSBT_IN_TAP_MERKLE_ROOT)
            tweaked = _tweaked_output(internal, b"" if merkle is None else merkle)
            if tweaked != output:
                errors.append(f"input {index} internal key does not tweak to the prevout")
        for control, value in _all(inp, PSBT_IN_TAP_LEAF_SCRIPT):
            if len(value) < 1 or not _leaf_commits(output, control, value[:-1], value[-1]):
                errors.append(f"input {index} tap leaf does not commit to the prevout")
    return errors


def _check_modifiable(psbt, sigs):
    if not sigs:
        return []
    raw = _one(psbt.g, PSBT_GLOBAL_TX_MODIFIABLE)
    flags = raw[0] if raw else 0
    types = [item["sighash"] for item in sigs]
    errors = []
    if not all(item & SIGHASH_ANYONECANPAY for item in types) and flags & INPUTS_MODIFIABLE:
        errors.append("Inputs Modifiable is set but a signature is not ANYONECANPAY")
    if not all((item & 0x1F) == SIGHASH_NONE for item in types) and flags & OUTPUTS_MODIFIABLE:
        errors.append("Outputs Modifiable is set but a signature is not SIGHASH_NONE")
    if any((item & 0x1F) == SIGHASH_SINGLE for item in types) and not flags & HAS_SIGHASH_SINGLE:
        errors.append("a SIGHASH_SINGLE signature is present but Has SIGHASH_SINGLE is clear")
    return errors


def _sighash_allowed(sighash, taproot):
    return sighash == SIGHASH_ALL or (taproot and sighash == SIGHASH_DEFAULT)


def _check_sighash_all(psbt, sigs):
    if not _sp_outputs(psbt):
        return []
    errors = []
    for index, inp in enumerate(psbt.i):
        raw = _one(inp, PSBT_IN_SIGHASH_TYPE)
        if raw is None:
            continue
        sighash = struct.unpack("<I", raw)[0]
        script = _spent_script(inp)
        if not _sighash_allowed(sighash, bool(script and _is_p2tr(script))):
            errors.append(f"input {index} PSBT_IN_SIGHASH_TYPE {sighash:#x} is not SIGHASH_ALL")
    for item in sigs:
        script = _spent_script(psbt.i[item["index"]])
        taproot = item["kind"] == "schnorr" or bool(script and _is_p2tr(script))
        if not _sighash_allowed(item["sighash"], taproot):
            errors.append(f"input {item['index']} sighash {item['sighash']:#x} is not SIGHASH_ALL")
    return errors


def _check_outputs_present(psbt):
    errors = []
    for index, out in enumerate(psbt.o):
        if _one(out, PSBT_OUT_SCRIPT) is None and _one(out, PSBT_OUT_SP_V0_INFO) is None:
            errors.append(f"output {index} has neither a script nor a silent payment code")
    return errors


def _check_eligibility(psbt, sigs):
    errors = []
    outputs = _sp_outputs(psbt)
    if outputs and sigs:
        for index, _info, script, _label in outputs:
            if script is None:
                errors.append(f"output {index} has no script but a signature is already present")
    # A label with no silent payment code is still a BIP-375 field error.
    for index, out in enumerate(psbt.o):
        if _one(out, PSBT_OUT_SP_V0_LABEL) is not None and _one(out, PSBT_OUT_SP_V0_INFO) is None:
            errors.append(f"output {index} label is set without PSBT_OUT_SP_V0_INFO")
    if outputs:
        raw = _one(psbt.g, PSBT_GLOBAL_TX_MODIFIABLE)
        flags = raw[0] if raw else 0
        if flags & (INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE):
            for index, _info, script, _label in outputs:
                if script is not None and len(script) > 0:
                    errors.append(f"output {index} has script set but TX_MODIFIABLE flags are not cleared")
        for index, inp in enumerate(psbt.i):
            script = _spent_script(inp)
            program = _witness_program(script) if script else None
            if program is not None and program[0] > 1:
                errors.append(f"input {index} spends witness version {program[0]}")
            if script and _is_p2sh(script):
                redeem = _redeem_script(inp)
                if redeem is not None and _p2sh_script(redeem) != script:
                    errors.append(f"input {index} redeem script does not match the prevout")
            if script and _is_p2tr(script):
                _committed, uncommitted = _nums_claims(inp, script)
                if uncommitted:
                    errors.append(f"input {index} NUMS claim is not committed to the prevout")
    return errors


def evaluate(b64):
    psbt, framing = _framing(b64)
    if psbt is None:
        return {"bip174_framing": framing}
    results = {"bip174_framing": framing}
    try:
        sigs = _collect_sigs(psbt)
    except Exception as exc:
        sigs = []
        results["signatures"] = [f"could not read signatures: {exc}"]
    def safe(fn, *args):
        try:
            return fn(*args)
        except Exception as exc:
            return [f"check failed: {exc}"]

    results.setdefault("signatures", safe(_check_signatures, psbt))
    results["bip371_taproot"] = safe(_check_taproot, psbt)
    results["bip352_outputs"] = safe(_check_outputs, psbt)
    results["bip374_dleq"] = safe(_check_dleq, psbt)
    results["bip375_ecdh"] = safe(_check_ecdh, psbt)
    results["bip370_modifiable"] = safe(_check_modifiable, psbt, sigs)
    results["bip375_sighash_all"] = safe(_check_sighash_all, psbt, sigs)
    results["bip370_outputs"] = safe(_check_outputs_present, psbt)
    results["bip375_eligibility"] = safe(_check_eligibility, psbt, sigs)
    return results


def _failed(results):
    return {name for name, errors in results.items() if errors}


def _load_violates():
    found = {}
    for path in sorted(INVALID_CONFIGS.glob("*.yaml")):
        config = yaml.safe_load(path.read_text())
        for case in config.get("test_cases", []):
            found[case["description"]] = case.get("violates")
    return found


def _psbts(vector):
    blobs = [("psbt", vector["psbt"])]
    expected = vector.get("expected") or {}
    if expected.get("psbt"):
        blobs.append(("expected.psbt", expected["psbt"]))
    return blobs


class ComplianceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {path.name: json.loads(path.read_text()) for path in VECTOR_FILES}
        cls.violates = _load_violates()

    def test_valid_and_workflows(self):
        failures = []
        for name, vectors in self.files.items():
            for section in ("valid", "workflows"):
                for vector in vectors.get(section, []):
                    for label, blob in _psbts(vector):
                        if not blob:
                            continue
                        failed = _failed(evaluate(blob))
                        if failed:
                            failures.append(f"{name} {section} {vector['description']} {label}: {sorted(failed)}")
        if failures:
            self.fail("\n".join(failures[:40]))

    def test_psbt_unique_id(self):
        failures = []
        for name, vectors in self.files.items():
            for section in ("valid", "workflows"):
                for vector in vectors.get(section, []):
                    expected = vector.get("expected") or {}
                    claims = [
                        ("supplementary", (vector.get("supplementary") or {}).get("psbt_unique_id"), vector["psbt"]),
                        ("expected", expected.get("psbt_unique_id"), expected.get("psbt") or vector["psbt"]),
                    ]
                    for label, claimed, blob in claims:
                        if claimed is None:
                            continue
                        actual = _unique_id(PSBT.from_base64(blob))
                        if claimed != actual:
                            failures.append(f"{name} {section} {vector['description']} {label}: {claimed} != {actual}")
        if failures:
            self.fail("\n".join(failures[:40]))

    def test_invalid_only_declared_properties(self):
        failures = []
        for name, vectors in self.files.items():
            for vector in vectors["invalid"]:
                declared = self.violates.get(vector["description"])
                failed = _failed(evaluate(vector["psbt"]))
                if declared is None:
                    failures.append(f"{name} {vector['description']}: missing violates, failed {sorted(failed)}")
                    continue
                if set(declared) != failed:
                    failures.append(
                        f"{name} {vector['description']}: violates {declared} but failed {sorted(failed)}"
                    )
        if failures:
            self.fail("\n".join(failures[:50]))

    def test_invalid_configs_declare_known_violates(self):
        known = set(PROPERTIES)
        failures = []
        for path in sorted(INVALID_CONFIGS.glob("*.yaml")):
            config = yaml.safe_load(path.read_text())
            for case in config.get("test_cases", []):
                declared = case.get("violates")
                if not declared:
                    failures.append(f"{path.name} {case['description']}: missing violates")
                    continue
                unknown = set(declared) - known
                if unknown:
                    failures.append(f"{path.name} {case['description']}: unknown checks {sorted(unknown)}")
        if failures:
            self.fail("\n".join(failures))


if __name__ == "__main__":
    unittest.main()
