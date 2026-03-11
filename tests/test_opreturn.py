import pytest
from core.opreturn import build_op_return, parse_op_return, OP_RETURN_MAX_PAYLOAD


def test_max_payload_constant():
    assert OP_RETURN_MAX_PAYLOAD == 223


# ── build_op_return ──

def test_small_payload_format():
    data = b"hello"
    script = build_op_return(data)
    assert script[0] == 0x6a         # OP_RETURN
    assert script[1] == len(data)    # direct length (≤ 75)
    assert script[2:] == data


def test_small_payload_boundary_75():
    data = b"x" * 75
    script = build_op_return(data)
    assert script[0] == 0x6a
    assert script[1] == 75
    assert script[2:] == data


def test_medium_payload_pushdata1():
    data = b"X" * 100
    script = build_op_return(data)
    assert script[0] == 0x6a
    assert script[1] == 0x4c         # OP_PUSHDATA1
    assert script[2] == 100
    assert script[3:] == data


def test_max_payload_accepted():
    data = bytes(range(223))
    script = build_op_return(data)
    assert parse_op_return(script) == data


def test_too_large_raises():
    with pytest.raises(ValueError, match=">223"):
        build_op_return(b"x" * 224)


def test_empty_payload():
    script = build_op_return(b"")
    assert script[0] == 0x6a
    assert parse_op_return(script) == b""


def test_invalid_type():
    with pytest.raises(TypeError):
        build_op_return("not bytes")


# ── parse_op_return ──

def test_roundtrip_small():
    data = b"test payload"
    assert parse_op_return(build_op_return(data)) == data


def test_roundtrip_large():
    data = bytes(range(200))
    assert parse_op_return(build_op_return(data)) == data


def test_parse_not_opreturn():
    with pytest.raises(ValueError, match="Not OP_RETURN"):
        parse_op_return(b"\x00\x05hello")


def test_parse_truncated():
    with pytest.raises(ValueError):
        parse_op_return(b"\x6a")  # OP_RETURN with no length byte


def test_parse_truncated_pushdata1():
    # OP_RETURN OP_PUSHDATA1 <len> but data shorter than len
    with pytest.raises(ValueError):
        parse_op_return(b"\x6a\x4c\x10" + b"\x00" * 5)  # says 16 bytes but only 5


def test_parse_invalid_type():
    with pytest.raises(TypeError):
        parse_op_return("not bytes")
