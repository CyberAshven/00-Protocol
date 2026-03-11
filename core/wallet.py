# core/wallet.py
"""BIP32/BIP44 secp256k1 key derivation for chat.cash.

Path: m/44'/145'/0'/0/0  (coin_type 145 = Bitcoin Cash)

Usage:
    from mnemonic import Mnemonic
    seed = Mnemonic.to_seed("word1 word2 ...")  # 64 bytes
    key  = seed_to_bch_key(seed)
    print(key.address)   # bitcoincash:q...
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcash import Key

# secp256k1 group order
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# BIP44 path for BCH: m/44'/145'/0'/0/0
_BIP44_BCH_PATH = (
    0x80000000 | 44,   # purpose  44'
    0x80000000 | 145,  # coin     145' (BCH)
    0x80000000 | 0,    # account  0'
    0,                  # change   0  (external)
    0,                  # address  0
)


def _compressed_pubkey(priv: bytes) -> bytes:
    """Derive compressed secp256k1 public key (33 bytes) from private key."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    sk = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256K1())
    return sk.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )


def _derive_child(priv: bytes, chain: bytes, index: int) -> tuple[bytes, bytes]:
    """BIP32 child private-key derivation."""
    if index >= 0x80000000:
        # hardened: use privkey
        data = b"\x00" + priv + struct.pack(">I", index)
    else:
        # normal: use compressed pubkey
        data = _compressed_pubkey(priv) + struct.pack(">I", index)

    I = hmac.new(chain, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    IL_int = int.from_bytes(IL, "big")
    if IL_int >= _SECP256K1_N:
        raise ValueError("BIP32: IL >= n (invalid key, try next index)")

    child_int = (IL_int + int.from_bytes(priv, "big")) % _SECP256K1_N
    if child_int == 0:
        raise ValueError("BIP32: child key is zero (invalid, try next index)")

    return child_int.to_bytes(32, "big"), IR


def seed_to_bch_key(seed: bytes) -> "Key":
    """
    Derive a bitcash.Key from a BIP39 seed via BIP44 path m/44'/145'/0'/0/0.

    Args:
        seed: 64-byte BIP39 seed (output of Mnemonic.to_seed()).

    Returns:
        bitcash.Key ready for signing and broadcasting BCH transactions.
    """
    try:
        from bitcash import Key
    except ImportError:
        raise ImportError("bitcash not installed — pip install bitcash")

    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    priv, chain = I[:32], I[32:]

    for idx in _BIP44_BCH_PATH:
        priv, chain = _derive_child(priv, chain, idx)

    return Key.from_hex(priv.hex())


def bch_key_from_priv_hex(priv_hex: str) -> "Key":
    """Load a bitcash.Key directly from a 32-byte secp256k1 private key (hex)."""
    try:
        from bitcash import Key
    except ImportError:
        raise ImportError("bitcash not installed — pip install bitcash")
    return Key.from_hex(priv_hex)


def gen_bch_priv_hex() -> str:
    """Generate a random valid secp256k1 private key (hex string, 64 chars)."""
    while True:
        raw = os.urandom(32)
        if 0 < int.from_bytes(raw, "big") < _SECP256K1_N:
            return raw.hex()
