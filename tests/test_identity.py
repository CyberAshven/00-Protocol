import pytest
from core.identity import (
    generate_mnemonic, validate_mnemonic,
    mnemonic_to_privkey, mnemonic_to_privkey_hex, is_mnemonic,
)


# ── generate_mnemonic ──

def test_generate_mnemonic_12_words():
    phrase = generate_mnemonic()
    assert len(phrase.split()) == 12


def test_generate_mnemonic_unique():
    assert generate_mnemonic() != generate_mnemonic()


def test_generate_mnemonic_valid_bip39():
    phrase = generate_mnemonic()
    assert validate_mnemonic(phrase)


# ── validate_mnemonic ──

def test_validate_known_good():
    # Standard BIP39 test vector
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assert validate_mnemonic(phrase)


def test_validate_wrong_checksum():
    # Last word wrong (invalid checksum)
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
    assert not validate_mnemonic(phrase)


def test_validate_invalid_word():
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon NOTAWORD"
    assert not validate_mnemonic(phrase)


def test_validate_too_short():
    assert not validate_mnemonic("abandon ability able")


def test_validate_strips_whitespace():
    phrase = "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  "
    assert validate_mnemonic(phrase)


# ── mnemonic_to_privkey ──

def test_privkey_length():
    phrase = generate_mnemonic()
    key = mnemonic_to_privkey(phrase)
    assert len(key) == 32


def test_privkey_type():
    key = mnemonic_to_privkey(generate_mnemonic())
    assert isinstance(key, bytes)


def test_privkey_deterministic():
    phrase = generate_mnemonic()
    assert mnemonic_to_privkey(phrase) == mnemonic_to_privkey(phrase)


def test_privkey_different_mnemonics():
    assert mnemonic_to_privkey(generate_mnemonic()) != mnemonic_to_privkey(generate_mnemonic())


def test_privkey_passphrase_changes_key():
    phrase = generate_mnemonic()
    k1 = mnemonic_to_privkey(phrase, passphrase="")
    k2 = mnemonic_to_privkey(phrase, passphrase="secret")
    assert k1 != k2


def test_privkey_known_vector():
    # BIP39 test vector — seed[:32] from "abandon" ×11 + "about" with no passphrase
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    key = mnemonic_to_privkey(phrase)
    # Known BIP39 seed for this phrase (no passphrase):
    # seed = 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc...
    assert key.hex().startswith("5eb00bbd")


# ── mnemonic_to_privkey_hex ──

def test_privkey_hex_length():
    hex_key = mnemonic_to_privkey_hex(generate_mnemonic())
    assert len(hex_key) == 64


def test_privkey_hex_is_hex():
    hex_key = mnemonic_to_privkey_hex(generate_mnemonic())
    assert all(c in "0123456789abcdef" for c in hex_key)


def test_privkey_hex_consistent():
    phrase = generate_mnemonic()
    assert mnemonic_to_privkey_hex(phrase) == mnemonic_to_privkey(phrase).hex()


# ── is_mnemonic ──

def test_is_mnemonic_true():
    phrase = "word " * 12
    assert is_mnemonic(phrase)


def test_is_mnemonic_false_hex():
    assert not is_mnemonic("4a2f" * 16)


def test_is_mnemonic_false_short():
    assert not is_mnemonic("only three words")


# ── integration: mnemonic → X25519 private key usable ──

def test_derived_key_usable_with_x25519():
    from cryptography.hazmat.primitives.asymmetric import x25519
    phrase = generate_mnemonic()
    priv_bytes = mnemonic_to_privkey(phrase)
    # Should not raise
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = priv.public_key().public_bytes_raw()
    assert len(pub) == 32
