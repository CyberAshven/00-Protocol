# core/identity.py
"""
Gestion d'identité BIP39 pour chat.cash.

Flux :
  1. generate_mnemonic()    → 12 mots aléatoires (128 bits d'entropie)
  2. mnemonic_to_privkey()  → seed BIP39 (PBKDF2-SHA512) → 32 premiers bytes = clé privée X25519
  3. La clé publique X25519 est dérivée normalement via core.crypto.gen_keypair() ou X25519PrivateKey

Compatible côté browser : PBKDF2(mnemonic, "mnemonic"+passphrase, 2048 iter, SHA-512) → seed[:32]
"""
from __future__ import annotations

from mnemonic import Mnemonic

_m = Mnemonic("english")


def generate_mnemonic() -> str:
    """
    Génère un mnémonique BIP39 de 12 mots (128 bits d'entropie).

    >>> phrase = generate_mnemonic()
    >>> len(phrase.split()) == 12
    True
    """
    return _m.generate(strength=128)


def validate_mnemonic(words: str) -> bool:
    """
    Vérifie qu'un mnémonique BIP39 est valide (checksum + mots dans la wordlist).
    """
    return _m.check(words.strip())


def mnemonic_to_privkey(words: str, passphrase: str = "") -> bytes:
    """
    Dérive une clé privée X25519 (32 bytes) depuis un mnémonique BIP39.

    Algorithme (standard BIP39) :
        seed = PBKDF2-HMAC-SHA512(
            password = NFKD(mnemonic),
            salt     = NFKD("mnemonic" + passphrase),
            rounds   = 2048,
            dklen    = 64,
        )
        privkey = seed[:32]

    Le même calcul est effectué côté browser avec Web Crypto API
    (crypto.subtle.deriveBits, PBKDF2, SHA-512, 2048 iterations).
    """
    seed = Mnemonic.to_seed(words.strip(), passphrase=passphrase)  # 64 bytes
    return seed[:32]


def mnemonic_to_privkey_hex(words: str, passphrase: str = "") -> str:
    """Retourne la clé privée en hex (64 caractères)."""
    return mnemonic_to_privkey(words, passphrase).hex()


def is_mnemonic(text: str) -> bool:
    """
    Heuristique rapide : 12 mots séparés par des espaces.
    Utiliser validate_mnemonic() pour une vérification complète (checksum).
    """
    return len(text.strip().split()) >= 12
