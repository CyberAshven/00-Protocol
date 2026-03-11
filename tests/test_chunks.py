import pytest
from core.chunks import chunk_bytes, rebuild_bytes, chunk_text_utf8, rebuild_text_utf8


def test_chunk_normal():
    data = b"0123456789"
    chunks = chunk_bytes(data, 4)
    assert chunks == [b"0123", b"4567", b"89"]


def test_chunk_exact_multiple():
    data = b"0123456789"
    chunks = chunk_bytes(data, 5)
    assert chunks == [b"01234", b"56789"]


def test_chunk_single():
    assert chunk_bytes(b"hello", 100) == [b"hello"]


def test_chunk_empty():
    assert chunk_bytes(b"", 4) == []


def test_rebuild_roundtrip():
    data = b"hello world this is a long test message"
    chunks = chunk_bytes(data, 7)
    assert rebuild_bytes(chunks) == data


def test_chunk_one_byte():
    assert chunk_bytes(b"ABC", 1) == [b"A", b"B", b"C"]


def test_rebuild_single():
    assert rebuild_bytes([b"hello"]) == b"hello"


def test_rebuild_empty_list():
    assert rebuild_bytes([]) == b""


def test_chunk_text_utf8_roundtrip():
    text = "héllo wörld 🔒"
    chunks = chunk_text_utf8(text, 5)
    assert rebuild_text_utf8(chunks) == text


def test_chunk_invalid_type():
    with pytest.raises(TypeError):
        chunk_bytes("not bytes", 4)


def test_chunk_invalid_size_zero():
    with pytest.raises(ValueError):
        chunk_bytes(b"data", 0)


def test_chunk_invalid_size_negative():
    with pytest.raises(ValueError):
        chunk_bytes(b"data", -1)


def test_rebuild_none():
    with pytest.raises(ValueError):
        rebuild_bytes(None)


def test_rebuild_contains_none():
    with pytest.raises(ValueError):
        rebuild_bytes([b"ok", None, b"end"])


def test_rebuild_invalid_chunk_type():
    with pytest.raises(TypeError):
        rebuild_bytes([b"ok", "not_bytes"])


def test_chunk_text_invalid_type():
    with pytest.raises(TypeError):
        chunk_text_utf8(42, 4)
