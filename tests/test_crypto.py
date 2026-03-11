import pytest
from core.crypto import (
    gen_keypair, derive_key,
    encrypt_message, decrypt_message,
    encrypt_for_pubkey, decrypt_with_privkey,
)


def test_gen_keypair_pub_length():
    kp = gen_keypair()
    assert len(kp.pub) == 32


def test_gen_keypair_unique():
    assert gen_keypair().pub != gen_keypair().pub


def test_gen_keypair_priv_not_none():
    kp = gen_keypair()
    assert kp.priv is not None


def test_derive_key_length():
    assert len(derive_key(b"any secret")) == 32


def test_derive_key_deterministic():
    secret = b"shared_secret_bytes"
    assert derive_key(secret) == derive_key(secret)


def test_derive_key_different_inputs():
    assert derive_key(b"input_a") != derive_key(b"input_b")


def test_derive_key_type_error():
    with pytest.raises(TypeError):
        derive_key("not bytes")


def test_encrypt_decrypt_roundtrip():
    secret = b"32_byte_shared_secret_padded____"
    msg = b"hello world"
    enc = encrypt_message(secret, msg)
    assert decrypt_message(secret, enc) == msg


def test_encrypt_different_ciphertexts():
    secret = b"a" * 32
    msg = b"hello"
    assert encrypt_message(secret, msg) != encrypt_message(secret, msg)


def test_encrypt_wrong_key_fails():
    enc = encrypt_message(b"key_a" * 6, b"msg")
    with pytest.raises(Exception):
        decrypt_message(b"key_b" * 6, enc)


def test_encrypt_for_pubkey_roundtrip():
    alice = gen_keypair()
    bob = gen_keypair()
    msg = b"secret for bob only"
    enc = encrypt_for_pubkey(msg, bob.pub)
    assert decrypt_with_privkey(enc, bob.priv) == msg


def test_encrypt_for_pubkey_nondeterministic():
    bob = gen_keypair()
    msg = b"hello"
    assert encrypt_for_pubkey(msg, bob.pub) != encrypt_for_pubkey(msg, bob.pub)


def test_encrypt_for_pubkey_wrong_key():
    alice = gen_keypair()
    bob = gen_keypair()
    eve = gen_keypair()
    enc = encrypt_for_pubkey(b"secret", bob.pub)
    with pytest.raises(Exception):
        decrypt_with_privkey(enc, eve.priv)


def test_encrypt_for_pubkey_long_message():
    bob = gen_keypair()
    msg = b"x" * 10_000
    enc = encrypt_for_pubkey(msg, bob.pub)
    assert decrypt_with_privkey(enc, bob.priv) == msg


def test_encrypt_for_pubkey_bad_pub_type():
    with pytest.raises(TypeError):
        encrypt_for_pubkey(b"msg", "not bytes")


def test_encrypt_for_pubkey_bad_pub_length():
    with pytest.raises(ValueError):
        encrypt_for_pubkey(b"msg", b"\x00" * 16)


def test_encrypt_message_bad_plaintext():
    with pytest.raises(TypeError):
        encrypt_message(b"secret", "not bytes")


def test_decrypt_too_short():
    with pytest.raises(ValueError):
        decrypt_message(b"secret" * 5, b"\x00" * 5)
