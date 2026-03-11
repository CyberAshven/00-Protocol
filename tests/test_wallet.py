# tests/test_wallet.py
"""Tests for BIP32/BIP44 secp256k1 key derivation (core/wallet.py)."""
import pytest

try:
    from bitcash import Key as _BitcashKey
    _HAS_BITCASH = True
except ImportError:
    _HAS_BITCASH = False

try:
    from mnemonic import Mnemonic as _Mnemonic
    _HAS_MNEMONIC = True
except ImportError:
    _HAS_MNEMONIC = False

_skip_bitcash  = pytest.mark.skipif(not _HAS_BITCASH,  reason="bitcash not installed")
_skip_mnemonic = pytest.mark.skipif(not _HAS_MNEMONIC, reason="mnemonic not installed")


# ── _derive_child internals ────────────────────────────────────────────────────

def test_derive_child_returns_32_bytes():
    from core.wallet import _derive_child
    priv  = bytes(range(1, 33))   # 32 non-zero bytes
    chain = bytes(range(33, 65))
    child_priv, child_chain = _derive_child(priv, chain, 0x80000000)  # hardened
    assert len(child_priv)  == 32
    assert len(child_chain) == 32


def test_derive_child_hardened_differs_from_normal():
    from core.wallet import _derive_child
    priv  = bytes(range(1, 33))
    chain = bytes(range(33, 65))
    h_priv, h_chain = _derive_child(priv, chain, 0x80000000)
    n_priv, n_chain = _derive_child(priv, chain, 0)
    assert h_priv  != n_priv
    assert h_chain != n_chain


def test_derive_child_deterministic():
    from core.wallet import _derive_child
    priv  = bytes(range(1, 33))
    chain = bytes(range(33, 65))
    a = _derive_child(priv, chain, 0x80000001)
    b = _derive_child(priv, chain, 0x80000001)
    assert a == b


def test_derive_child_different_indices_differ():
    from core.wallet import _derive_child
    priv  = bytes(range(1, 33))
    chain = bytes(range(33, 65))
    a, _ = _derive_child(priv, chain, 0x80000000)
    b, _ = _derive_child(priv, chain, 0x80000001)
    assert a != b


# ── gen_bch_priv_hex ──────────────────────────────────────────────────────────

def test_gen_bch_priv_hex_length():
    from core.wallet import gen_bch_priv_hex
    h = gen_bch_priv_hex()
    assert len(h) == 64


def test_gen_bch_priv_hex_is_valid_int():
    from core.wallet import gen_bch_priv_hex, _SECP256K1_N
    h = gen_bch_priv_hex()
    v = int(h, 16)
    assert 0 < v < _SECP256K1_N


def test_gen_bch_priv_hex_random():
    from core.wallet import gen_bch_priv_hex
    assert gen_bch_priv_hex() != gen_bch_priv_hex()


# ── bch_key_from_priv_hex ─────────────────────────────────────────────────────

@_skip_bitcash
def test_bch_key_from_priv_hex_returns_key():
    from core.wallet import bch_key_from_priv_hex, gen_bch_priv_hex
    key = bch_key_from_priv_hex(gen_bch_priv_hex())
    assert isinstance(key, _BitcashKey)


@_skip_bitcash
def test_bch_key_from_priv_hex_has_address():
    from core.wallet import bch_key_from_priv_hex, gen_bch_priv_hex
    key = bch_key_from_priv_hex(gen_bch_priv_hex())
    assert key.address


@_skip_bitcash
def test_bch_key_from_priv_hex_deterministic():
    from core.wallet import bch_key_from_priv_hex, gen_bch_priv_hex
    h = gen_bch_priv_hex()
    assert bch_key_from_priv_hex(h).address == bch_key_from_priv_hex(h).address


# ── seed_to_bch_key ───────────────────────────────────────────────────────────

@_skip_bitcash
@_skip_mnemonic
def test_seed_to_bch_key_returns_key():
    from core.wallet import seed_to_bch_key
    seed = _Mnemonic.to_seed("abandon " * 11 + "about")
    key  = seed_to_bch_key(seed)
    assert isinstance(key, _BitcashKey)


@_skip_bitcash
@_skip_mnemonic
def test_seed_to_bch_key_has_cashaddr():
    from core.wallet import seed_to_bch_key
    seed = _Mnemonic.to_seed("abandon " * 11 + "about")
    key  = seed_to_bch_key(seed)
    assert key.address.startswith("bitcoincash:") or key.address.startswith("q")


@_skip_bitcash
@_skip_mnemonic
def test_seed_to_bch_key_deterministic():
    from core.wallet import seed_to_bch_key
    seed  = _Mnemonic.to_seed("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
    key1  = seed_to_bch_key(seed)
    key2  = seed_to_bch_key(seed)
    assert key1.address == key2.address


@_skip_bitcash
@_skip_mnemonic
def test_seed_to_bch_key_different_seeds_differ():
    from core.wallet import seed_to_bch_key
    seed1 = _Mnemonic.to_seed("abandon " * 11 + "about")
    seed2 = _Mnemonic.to_seed("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
    assert seed_to_bch_key(seed1).address != seed_to_bch_key(seed2).address


@_skip_bitcash
@_skip_mnemonic
def test_seed_to_bch_key_64_byte_seed_required():
    """Shorter seed should still work (padding handled by HMAC)."""
    from core.wallet import seed_to_bch_key
    # 32-byte seed (non-standard but should not crash)
    seed = b"\x01" * 32
    key  = seed_to_bch_key(seed)
    assert key.address


# ── NodeClient Protocol ───────────────────────────────────────────────────────

def test_node_client_protocol_importable():
    from transport.node_client import NodeClient
    assert NodeClient is not None


def test_ec_client_satisfies_protocol():
    from transport.node_client import NodeClient
    from transport.ec_client import EcClient
    ec = EcClient(ec_path="/nonexistent")
    assert isinstance(ec, NodeClient)


def test_bitcash_client_satisfies_protocol():
    from transport.node_client import NodeClient
    from transport.bitcash_client import BitcashClient
    bc = BitcashClient()
    assert isinstance(bc, NodeClient)
