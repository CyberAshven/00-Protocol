# tests/test_history.py
"""Tests for core/history.py — encrypted message history."""
import time
import pytest
from pathlib import Path

from core.crypto import gen_keypair
from core.history import HistoryStore, HistoryEntry, _derive_key, _contact_filename


def _priv_hex() -> str:
    kp = gen_keypair()
    from cryptography.hazmat.primitives import serialization
    return kp.priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()


# ── _derive_key ────────────────────────────────────────────────────────────────

def test_derive_key_length():
    key = _derive_key(_priv_hex())
    assert len(key) == 32


def test_derive_key_deterministic():
    ph = _priv_hex()
    assert _derive_key(ph) == _derive_key(ph)


def test_derive_key_different_privkeys_differ():
    assert _derive_key(_priv_hex()) != _derive_key(_priv_hex())


# ── _contact_filename ──────────────────────────────────────────────────────────

def test_contact_filename_format():
    key = _derive_key(_priv_hex())
    fn = _contact_filename(key, "Alice")
    assert fn.endswith(".enc")
    assert len(fn) == 36  # 32 hex chars + ".enc"


def test_contact_filename_deterministic():
    key = _derive_key(_priv_hex())
    assert _contact_filename(key, "Alice") == _contact_filename(key, "Alice")


def test_contact_filename_different_contacts_differ():
    key = _derive_key(_priv_hex())
    assert _contact_filename(key, "Alice") != _contact_filename(key, "Bob")


def test_contact_filename_different_keys_differ():
    k1, k2 = _derive_key(_priv_hex()), _derive_key(_priv_hex())
    assert _contact_filename(k1, "Alice") != _contact_filename(k2, "Alice")


# ── HistoryStore.append + load ─────────────────────────────────────────────────

def test_append_and_load_basic(tmp_path: Path):
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    store.append("Alice", "out", "hello")
    entries = store.load("Alice")
    assert len(entries) == 1
    assert entries[0].text == "hello"
    assert entries[0].direction == "out"
    assert entries[0].contact == "Alice"


def test_append_multiple(tmp_path: Path):
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    store.append("Alice", "out", "msg1")
    store.append("Alice", "in", "msg2")
    store.append("Alice", "out", "msg3")
    entries = store.load("Alice")
    assert len(entries) == 3
    assert [e.text for e in entries] == ["msg1", "msg2", "msg3"]


def test_entries_sorted_by_timestamp(tmp_path: Path):
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    store.append("Bob", "out", "first")
    time.sleep(0.01)
    store.append("Bob", "in", "second")
    entries = store.load("Bob")
    assert entries[0].text == "first"
    assert entries[1].text == "second"


def test_load_empty_returns_empty(tmp_path: Path):
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    assert store.load("nobody") == []


def test_persist_across_store_instances(tmp_path: Path):
    ph = _priv_hex()
    s1 = HistoryStore(tmp_path, ph)
    s1.append("Alice", "out", "persistent")
    s2 = HistoryStore(tmp_path, ph)
    entries = s2.load("Alice")
    assert entries[0].text == "persistent"


def test_wrong_key_cannot_decrypt(tmp_path: Path):
    ph1 = _priv_hex()
    ph2 = _priv_hex()
    s1 = HistoryStore(tmp_path, ph1)
    s1.append("Alice", "out", "secret")

    s2 = HistoryStore(tmp_path, ph2)
    # Different key → different filename, so it returns empty (can't find the file)
    entries = s2.load("Alice")
    assert entries == []


def test_contacts_are_isolated(tmp_path: Path):
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    store.append("Alice", "out", "to alice")
    store.append("Bob", "in", "from bob")
    assert store.load("Alice")[0].text == "to alice"
    assert store.load("Bob")[0].text == "from bob"


def test_filenames_are_opaque(tmp_path: Path):
    """Contact names must not appear in filenames."""
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    store.append("Charlie", "out", "x")
    files = list(tmp_path.iterdir())
    assert len(files) == 1
    assert "Charlie" not in files[0].name
    assert "charlie" not in files[0].name.lower()


def test_file_content_not_plaintext(tmp_path: Path):
    """Raw file bytes must not contain the plaintext message."""
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    store.append("Alice", "out", "super secret message")
    raw = next(tmp_path.iterdir()).read_bytes()
    assert b"super secret message" not in raw


def test_unicode_messages(tmp_path: Path):
    ph = _priv_hex()
    store = HistoryStore(tmp_path, ph)
    msg = "こんにちは 🔐 مرحبا"
    store.append("Alice", "in", msg)
    assert store.load("Alice")[0].text == msg


def test_display_line_out():
    e = HistoryEntry(ts=0.0, direction="out", contact="Bob", text="yo")
    assert e.display_line() == "me: yo"


def test_display_line_in():
    e = HistoryEntry(ts=0.0, direction="in", contact="Bob", text="hey")
    assert e.display_line() == "Bob: hey"


# ── contact_card ──────────────────────────────────────────────────────────────

def test_encode_decode_roundtrip():
    from core.contact_card import encode_contact_card, decode_contact_card
    url = encode_contact_card("bitcoincash:qpabc123", "ab" * 32, "Alice")
    result = decode_contact_card(url)
    assert result["bch_address"] == "bitcoincash:qpabc123"
    assert result["pub_hex"] == "ab" * 32
    assert result["name"] == "Alice"


def test_decode_wrong_scheme():
    from core.contact_card import decode_contact_card
    with pytest.raises(ValueError, match="Not a chatcash"):
        decode_contact_card("https://example.com")


def test_decode_short_pub_hex():
    from core.contact_card import decode_contact_card
    with pytest.raises(ValueError, match="Invalid pub_hex"):
        decode_contact_card("chatcash:bitcoincash:q123?pub=tooshort&name=x")


def test_decode_name_fallback():
    from core.contact_card import encode_contact_card, decode_contact_card
    url = encode_contact_card("bitcoincash:qpabc", "cd" * 32, "")
    result = decode_contact_card(url)
    assert result["name"]  # fallback to first 16 chars of address


def test_encode_url_scheme():
    from core.contact_card import encode_contact_card
    url = encode_contact_card("bitcoincash:qp1234", "ef" * 32, "Bob")
    assert url.startswith("chatcash:")


def test_decode_name_with_spaces():
    from core.contact_card import encode_contact_card, decode_contact_card
    url = encode_contact_card("bitcoincash:qpabc", "01" * 32, "Jean Pierre")
    result = decode_contact_card(url)
    assert result["name"] == "Jean Pierre"
