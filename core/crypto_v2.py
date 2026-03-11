# core/crypto_v2.py
"""
CCSH v2 — Split-Knowledge Cryptography

XOR One-Time Pad split + AES-256-GCM dual encryption.

Flow:
  1. encrypt_for_pubkey() → ciphertext bundle (same as v1)
  2. xor_split(bundle) → (shard_a, pad_b)  — OTP split
  3. aes_wrap(shard_a, key_chain) → blob_chain  — for OP_RETURN
  4. aes_wrap(pad_b, key_relay)  → blob_relay  — for Nostr relay

Keys are derived differently for each channel:
  key_chain = SHA-256(shared_secret || "ccsh-chain")
  key_relay = SHA-256(shared_secret || "ccsh-relay")

This ensures that even if one AES key is compromised,
the other channel's ciphertext remains independently encrypted.
"""
from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ──────────────────────────────────────────
# XOR One-Time Pad
# ──────────────────────────────────────────

def xor_split(data: bytes) -> Tuple[bytes, bytes]:
    """
    Split data into two pieces using XOR with a random pad.

    Returns (shard_a, pad_b) where:
      shard_a = data XOR pad_b
      pad_b   = random bytes (same length)

    Individually, each piece is indistinguishable from random noise.
    This is information-theoretically secure (One-Time Pad).
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)
    pad_b = os.urandom(len(data))
    shard_a = bytes(a ^ b for a, b in zip(data, pad_b))
    return shard_a, pad_b


def xor_merge(shard_a: bytes, pad_b: bytes) -> bytes:
    """
    Reconstruct original data from XOR split pieces.

    data = shard_a XOR pad_b
    """
    if len(shard_a) != len(pad_b):
        raise ValueError(f"length mismatch: shard={len(shard_a)}, pad={len(pad_b)}")
    return bytes(a ^ b for a, b in zip(shard_a, pad_b))


# ──────────────────────────────────────────
# Dual-channel KDF
# ──────────────────────────────────────────

def derive_key_chain(shared_secret: bytes) -> bytes:
    """Derive AES key for on-chain channel."""
    return hashlib.sha256(bytes(shared_secret) + b"ccsh-chain").digest()


def derive_key_relay(shared_secret: bytes) -> bytes:
    """Derive AES key for relay channel."""
    return hashlib.sha256(bytes(shared_secret) + b"ccsh-relay").digest()


# ──────────────────────────────────────────
# AES-256-GCM wrap/unwrap
# ──────────────────────────────────────────

def aes_wrap(data: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM encrypt.
    Output: nonce(12) || ciphertext+tag
    """
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, bytes(data), None)
    return nonce + ct


def aes_unwrap(blob: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM decrypt.
    Input: nonce(12) || ciphertext+tag
    """
    if len(blob) < 12:
        raise ValueError("blob too short")
    aes = AESGCM(key)
    return aes.decrypt(blob[:12], blob[12:], None)


# ──────────────────────────────────────────
# High-level: split-encrypt for pubkey
# ──────────────────────────────────────────

@dataclass(frozen=True)
class SplitBundle:
    """Result of split encryption — two independent blobs."""
    chain_blob: bytes   # encrypted shard A → goes to OP_RETURN
    relay_blob: bytes   # encrypted pad B   → goes to Nostr relay
    eph_pub: bytes      # ephemeral X25519 pubkey (32 bytes) — needed for decryption


def split_encrypt(plaintext: bytes, recipient_pub: bytes) -> SplitBundle:
    """
    Full v2 encryption pipeline:

    1. ECDH with ephemeral key → shared_secret
    2. Encrypt plaintext with AES-GCM (classic, same as v1)
    3. XOR split the ciphertext → (shard_a, pad_b)
    4. Wrap shard_a with chain-derived key
    5. Wrap pad_b with relay-derived key

    Returns a SplitBundle with two independent encrypted blobs.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    if not isinstance(recipient_pub, (bytes, bytearray, memoryview)):
        raise TypeError("recipient_pub must be bytes-like")
    recipient_pub = bytes(recipient_pub)
    if len(recipient_pub) != 32:
        raise ValueError("recipient_pub must be 32 bytes (X25519)")

    # 1. Ephemeral ECDH
    recipient_pubkey = x25519.X25519PublicKey.from_public_bytes(recipient_pub)
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()
    shared = eph_priv.exchange(recipient_pubkey)

    # 2. Encrypt plaintext (inner layer — same as v1)
    inner_key = hashlib.sha256(shared).digest()
    aes_inner = AESGCM(inner_key)
    inner_nonce = os.urandom(12)
    inner_ct = inner_nonce + aes_inner.encrypt(inner_nonce, bytes(plaintext), None)

    # 3. XOR split
    shard_a, pad_b = xor_split(inner_ct)

    # 4. Wrap each piece with channel-specific keys
    key_chain = derive_key_chain(shared)
    key_relay = derive_key_relay(shared)

    chain_blob = aes_wrap(shard_a, key_chain)
    relay_blob = aes_wrap(pad_b, key_relay)

    return SplitBundle(
        chain_blob=chain_blob,
        relay_blob=relay_blob,
        eph_pub=eph_pub,
    )


def split_decrypt(
    chain_blob: bytes,
    relay_blob: bytes,
    eph_pub: bytes,
    recipient_priv: x25519.X25519PrivateKey,
) -> bytes:
    """
    Full v2 decryption pipeline:

    1. ECDH with eph_pub → shared_secret
    2. Derive channel keys
    3. Unwrap both blobs
    4. XOR merge → inner ciphertext
    5. Decrypt inner layer → plaintext
    """
    # 1. ECDH
    eph_pubkey = x25519.X25519PublicKey.from_public_bytes(bytes(eph_pub))
    shared = recipient_priv.exchange(eph_pubkey)

    # 2. Channel keys
    key_chain = derive_key_chain(shared)
    key_relay = derive_key_relay(shared)

    # 3. Unwrap
    shard_a = aes_unwrap(chain_blob, key_chain)
    pad_b = aes_unwrap(relay_blob, key_relay)

    # 4. XOR merge
    inner_ct = xor_merge(shard_a, pad_b)

    # 5. Decrypt inner
    inner_key = hashlib.sha256(shared).digest()
    aes_inner = AESGCM(inner_key)
    return aes_inner.decrypt(inner_ct[:12], inner_ct[12:], None)
