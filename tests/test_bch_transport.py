import pytest
from transport.bch_transport import (
    BchTransport, OpReturnOutput,
    opreturn_script, opreturn_script_hex,
)


# ── opreturn_script helpers ──

def test_opreturn_script_starts_with_6a():
    s = opreturn_script(b"hello")
    assert s[0] == 0x6A


def test_opreturn_script_hex_type():
    h = opreturn_script_hex(b"test")
    assert isinstance(h, str)
    assert h.startswith("6a")


def test_opreturn_script_roundtrip():
    data = b"some payload 123"
    script = opreturn_script(data)
    # OP_RETURN + pushdata
    assert data in script


# ── BchTransport.assert_packets_fit ──

def test_assert_packets_fit_ok():
    packets = [b"x" * 50, b"y" * 100]
    BchTransport.assert_packets_fit(packets)  # no exception


def test_assert_packets_fit_too_large():
    too_big = b"z" * (BchTransport.MAX_OPRETURN_DATA + 1)
    with pytest.raises(ValueError, match="exceed OP_RETURN data limit"):
        BchTransport.assert_packets_fit([too_big])


def test_assert_packets_fit_exact_limit():
    edge = b"e" * BchTransport.MAX_OPRETURN_DATA
    BchTransport.assert_packets_fit([edge])  # no exception


# ── BchTransport.packets_to_opreturn_outputs ──

def test_packets_to_opreturn_outputs_basic():
    packets = [b"a" * 30, b"b" * 60]
    outs = BchTransport.packets_to_opreturn_outputs(packets)
    assert len(outs) == 2
    assert all(isinstance(o, OpReturnOutput) for o in outs)
    assert all(o.size <= BchTransport.MAX_OPRETURN_DATA for o in outs)


def test_packets_to_opreturn_outputs_script_hex():
    packets = [b"test"]
    outs = BchTransport.packets_to_opreturn_outputs(packets)
    assert outs[0].script_hex.startswith("6a")
    assert outs[0].data_hex == "74657374"  # "test" in hex
    assert outs[0].size == 4


def test_packets_to_opreturn_outputs_too_large_raises():
    too_big = [b"x" * 300]
    with pytest.raises(ValueError):
        BchTransport.packets_to_opreturn_outputs(too_big)


# ── BchTransport.build_payto_lines_for_message ──

def test_build_payto_lines_content():
    lines = BchTransport.build_payto_lines_for_message(
        packets=[b"x"],
        recipient_bch_address="bitcoincash:qptest000",
        dust_sats=546,
    )
    assert len(lines) == 1
    assert "bitcoincash:qptest000" in lines[0]
    assert "0.00000546" in lines[0]


def test_build_payto_lines_empty_address():
    with pytest.raises(ValueError, match="empty"):
        BchTransport.build_payto_lines_for_message(packets=[b"x"], recipient_bch_address="")


def test_build_payto_lines_custom_dust():
    lines = BchTransport.build_payto_lines_for_message(
        packets=[b"x"],
        recipient_bch_address="bitcoincash:qptest",
        dust_sats=1000,
    )
    assert "0.00001000" in lines[0]


# ── BchTransport.build_opreturn_script_hex_for_message ──

def test_build_opreturn_hex_single_chunk():
    packets = [b"p" * 50]
    h = BchTransport.build_opreturn_script_hex_for_message(packets)
    assert isinstance(h, str)
    assert len(h) > 0


def test_build_opreturn_hex_multi_chunk_raises():
    packets = [b"a" * 50, b"b" * 50]
    with pytest.raises(ValueError, match="2 OP_RETURN"):
        BchTransport.build_opreturn_script_hex_for_message(packets)


# ── BchTransport._sats_to_bch_str ──

def test_sats_dust():
    assert BchTransport._sats_to_bch_str(546) == "0.00000546"


def test_sats_one_bch():
    assert BchTransport._sats_to_bch_str(100_000_000) == "1.00000000"


def test_sats_zero():
    assert BchTransport._sats_to_bch_str(0) == "0.00000000"
