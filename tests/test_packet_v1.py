import pytest
from core.packet_v1 import (
    pack_packet, unpack_packet, new_msg_id, PacketV1,
    MSG_TYPE_ENCRYPTED_CHUNK, MSG_TYPE_ADDR_CHANGE,
    FIXED_HEADER_LEN, MAGIC, VERSION,
)


def _pkt(**kw):
    defaults = dict(
        msg_id=new_msg_id(),
        sender_pub=bytes(32),
        chunk_index=0,
        chunk_total=1,
        ciphertext_chunk=b"payload",
    )
    defaults.update(kw)
    return PacketV1(**defaults)


# ── Constants ──

def test_magic():
    assert MAGIC == b"CCSH"


def test_version():
    assert VERSION == 0x01


def test_fixed_header_len():
    assert FIXED_HEADER_LEN == 61


def test_msg_type_encrypted_chunk():
    assert MSG_TYPE_ENCRYPTED_CHUNK == 0x01


def test_msg_type_addr_change():
    assert MSG_TYPE_ADDR_CHANGE == 0x02


# ── new_msg_id ──

def test_new_msg_id_length():
    assert len(new_msg_id()) == 16


def test_new_msg_id_unique():
    assert new_msg_id() != new_msg_id()


def test_new_msg_id_type():
    assert isinstance(new_msg_id(), bytes)


# ── pack / unpack roundtrip ──

def test_roundtrip_basic():
    pkt = _pkt()
    got = unpack_packet(pack_packet(pkt))
    assert got.msg_id == pkt.msg_id
    assert got.sender_pub == pkt.sender_pub
    assert got.ciphertext_chunk == pkt.ciphertext_chunk
    assert got.chunk_index == 0
    assert got.chunk_total == 1
    assert got.msg_type == MSG_TYPE_ENCRYPTED_CHUNK


def test_roundtrip_addr_change():
    pkt = _pkt(msg_type=MSG_TYPE_ADDR_CHANGE)
    got = unpack_packet(pack_packet(pkt))
    assert got.msg_type == MSG_TYPE_ADDR_CHANGE


def test_roundtrip_large_payload():
    big = bytes(range(256)) * 2
    pkt = _pkt(ciphertext_chunk=big)
    got = unpack_packet(pack_packet(pkt))
    assert got.ciphertext_chunk == big


def test_roundtrip_multi_chunk():
    mid = new_msg_id()
    pub = bytes(range(32))
    pkts = [
        _pkt(msg_id=mid, sender_pub=pub, chunk_index=i, chunk_total=3,
             ciphertext_chunk=bytes([i]) * 10)
        for i in range(3)
    ]
    for p in pkts:
        got = unpack_packet(pack_packet(p))
        assert got.chunk_index == p.chunk_index
        assert got.chunk_total == 3


def test_pack_size():
    pkt = _pkt(ciphertext_chunk=b"hello")
    raw = pack_packet(pkt)
    assert len(raw) == FIXED_HEADER_LEN + 5


# ── Error cases ──

def test_too_short():
    with pytest.raises(ValueError):
        unpack_packet(b"\x00" * 10)


def test_bad_magic():
    raw = bytearray(b"\x00" * FIXED_HEADER_LEN + b"payload")
    with pytest.raises(ValueError, match="bad magic"):
        unpack_packet(bytes(raw))


def test_bad_version():
    raw = bytearray(pack_packet(_pkt()))
    raw[4] = 0x99
    with pytest.raises(ValueError, match="unsupported version"):
        unpack_packet(bytes(raw))


def test_length_mismatch_extra():
    raw = pack_packet(_pkt()) + b"\x00"
    with pytest.raises(ValueError, match="length mismatch"):
        unpack_packet(raw)


def test_length_mismatch_short():
    raw = pack_packet(_pkt())[:-1]
    with pytest.raises(ValueError):
        unpack_packet(raw)


def test_bad_msg_id_length():
    with pytest.raises(ValueError, match="msg_id"):
        _pkt(msg_id=b"\x00" * 8).validate()


def test_bad_sender_pub_length():
    with pytest.raises(ValueError, match="sender_pub"):
        _pkt(sender_pub=b"\x00" * 16).validate()


def test_chunk_index_gte_total():
    with pytest.raises(ValueError):
        _pkt(chunk_index=1, chunk_total=1).validate()


def test_chunk_total_zero():
    with pytest.raises(ValueError):
        _pkt(chunk_total=0).validate()


def test_unpack_not_bytes():
    with pytest.raises(ValueError):
        unpack_packet("not bytes")
