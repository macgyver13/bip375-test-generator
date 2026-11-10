#!/usr/bin/env python3
"""BIP-374 DLEQ proof generation and verification.

The same proof as bip-0374's reference, on the vendored test framework's
secp256k1 instead of secp256k1lab.
"""

from test_framework.crypto.secp256k1 import G, GE
from test_framework.key import TaggedHash


DLEQ_TAG_AUX = "BIP0374/aux"
DLEQ_TAG_NONCE = "BIP0374/nonce"
DLEQ_TAG_CHALLENGE = "BIP0374/challenge"


def _xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(b0, b1))


def dleq_challenge(A: GE, B: GE, C: GE, R1: GE, R2: GE, m: bytes | None, G: GE) -> int:
    if m is not None:
        assert len(m) == 32
    m = bytes([]) if m is None else m
    return int.from_bytes(
        TaggedHash(
            DLEQ_TAG_CHALLENGE,
            A.to_bytes_compressed()
            + B.to_bytes_compressed()
            + C.to_bytes_compressed()
            + G.to_bytes_compressed()
            + R1.to_bytes_compressed()
            + R2.to_bytes_compressed()
            + m,
        ),
        "big",
    ) % GE.ORDER


def dleq_verify_proof(A: GE, B: GE, C: GE, proof: bytes, G: GE = G, m: bytes | None = None) -> bool:
    if A.infinity or B.infinity or C.infinity or G.infinity:
        return False
    if len(proof) != 64:
        return False
    e = int.from_bytes(proof[:32], "big")
    if e >= GE.ORDER:
        return False
    s = int.from_bytes(proof[32:], "big")
    if s >= GE.ORDER:
        return False
    # GE has no subtraction. (n - e) * P is -e * P.
    R1 = s * G + ((GE.ORDER - e) % GE.ORDER) * A
    if R1.infinity:
        return False
    R2 = s * B + ((GE.ORDER - e) % GE.ORDER) * C
    if R2.infinity:
        return False
    if e != dleq_challenge(A, B, C, R1, R2, m, G):
        return False
    return True
