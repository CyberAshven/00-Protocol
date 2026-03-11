# core/crypto.py
from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------
# Key material helpers
# ---------------------------

@dataclass
class KeyPair:
    priv: x25519.X25519PrivateKey
    pub: bytes  # raw 32 bytes (X25519)


def gen_keypair() -> KeyPair:
    """
    Génère une paire de clés cryptographiques X25519.

    IMPORTANT :
    - Ces clés ne servent PAS à signer des transactions BCH.
    - Elles servent UNIQUEMENT à chiffrer/déchiffrer les messages (messagerie).
    - On est ici dans la crypto "hors blockchain" (layer applicatif).

    X25519 est utilisé pour :
    - l’échange de clé sécurisé (ECDH)
    - établir un secret partagé entre deux personnes
    - chiffrer ensuite les messages avec AES-GCM
    """

    # -----------------------------
    # 1) Génération de la clé privée
    # -----------------------------
    # X25519PrivateKey.generate() :
    # - génère une clé privée aléatoire
    # - sécurisée
    # - basée sur Curve25519
    priv = x25519.X25519PrivateKey.generate()

    # -----------------------------
    # 2) Dérivation de la clé publique
    # -----------------------------
    # La clé publique est calculée à partir de la clé privée.
    # C’est une opération à sens unique (impossible de retrouver la clé privée).
    pub = priv.public_key().public_bytes_raw()

    # pub est exactement 32 octets :
    # - format "raw"
    # - pas compressé
    # - pas ASN.1
    # → parfait pour transport, QR code, OP_RETURN, etc.

    # -----------------------------
    # 3) Retour de la paire de clés
    # -----------------------------
    return KeyPair(
        priv=priv,  # objet clé privée (reste SECRET)
        pub=pub     # bytes de la clé publique (peut être partagé)
    )


# ---------------------------
# KDF
# ---------------------------

def derive_key(shared_secret: bytes) -> bytes:
    """
    Transforme un secret partagé brut (issu de X25519 / ECDH)
    en une clé symétrique utilisable pour le chiffrement (AES-GCM).

    Pourquoi cette fonction est nécessaire ?
    - X25519 produit un "shared_secret" brut.
    - Ce secret n’est PAS directement une clé AES valide.
    - AES-GCM a besoin d’une clé de taille précise (ici 32 octets pour AES-256).
    - On utilise donc une KDF (Key Derivation Function).

    Cette version est volontairement simple :
    - SHA-256(shared_secret) → 32 octets
    - Suffisant pour un proto v1 / POC
    """

    # -----------------------------
    # 1) Vérification du type
    # -----------------------------
    # On s’assure que le secret partagé est bien une donnée binaire.
    # Cela évite des bugs ou des dérivations incohérentes.
    if not isinstance(shared_secret, (bytes, bytearray, memoryview)):
        raise TypeError("shared_secret must be bytes-like")

    # -----------------------------
    # 2) Normalisation en bytes
    # -----------------------------
    # bytes(...) garantit un type bytes "propre"
    secret = bytes(shared_secret)

    # -----------------------------
    # 3) Dérivation de clé
    # -----------------------------
    # SHA-256 :
    # - transforme une donnée arbitraire en 32 octets fixes
    # - diffusion uniforme (bonne entropie)
    # - déterministe : même entrée → même sortie
    #
    # Le résultat est une clé AES-256 parfaite (32 bytes).
    return hashlib.sha256(secret).digest()


# ---------------------------
# Low-level API (legacy)
# shared_secret -> encrypt/decrypt
# ---------------------------

def encrypt_message(shared_secret: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with a precomputed shared secret.
    Output format: nonce(12) || ciphertext+tag
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")

    key = derive_key(shared_secret)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, bytes(plaintext), None)
    return nonce + ciphertext


def decrypt_message(shared_secret: bytes, data: bytes) -> bytes:
    """
    Decrypt data produced by encrypt_message().
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)

    if len(data) < 12:
        raise ValueError("ciphertext too short")

    key = derive_key(shared_secret)
    aes = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aes.decrypt(nonce, ciphertext, None)


# ---------------------------
# High-level API
# pubkey -> encrypt/decrypt
# (includes ephemeral pubkey)
# ---------------------------

def encrypt_for_pubkey(plaintext: bytes, recipient_pub: bytes) -> bytes:
    """
    Encrypt plaintext for recipient X25519 pubkey.
    Output format:
      eph_pub(32) || nonce(12) || ciphertext+tag
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    if not isinstance(recipient_pub, (bytes, bytearray, memoryview)):
        raise TypeError("recipient_pub must be bytes-like")

    recipient_pub = bytes(recipient_pub)
    if len(recipient_pub) != 32:
        raise ValueError("recipient_pub must be 32 bytes (X25519 raw)")

    recipient_pubkey = x25519.X25519PublicKey.from_public_bytes(recipient_pub)

    # ephemeral sender key for forward secrecy
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()

    shared = eph_priv.exchange(recipient_pubkey)
    key = derive_key(shared)

    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, bytes(plaintext), None)

    return eph_pub + nonce + ciphertext


def decrypt_with_privkey(data: bytes, recipient_priv: x25519.X25519PrivateKey) -> bytes:
    """
    Decrypt data produced by encrypt_for_pubkey().
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)

    if len(data) < 32 + 12:
        raise ValueError("ciphertext too short")

    eph_pub = data[:32]
    nonce = data[32:44]
    ciphertext = data[44:]

    eph_pubkey = x25519.X25519PublicKey.from_public_bytes(eph_pub)
    shared = recipient_priv.exchange(eph_pubkey)
    key = derive_key(shared)

    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)