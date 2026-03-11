"""Tests encode/decode MSG_TYPE_ADDR_CHANGE (rotation d'adresse BCH)."""
import pytest
from core.crypto import gen_keypair
from core.protocol import encode_addr_change, decode_addr_change_packets, AddrChangeMessage
from core.packet_v1 import unpack_packet, MSG_TYPE_ADDR_CHANGE, MSG_TYPE_ENCRYPTED_CHUNK

NEW_ADDR  = "bitcoincash:qpnewaddress000000000000000000000000"
NEW_ADDR2 = "bitcoincash:qpnewaddress111111111111111111111111"


def _kp():
    kp = gen_keypair()
    return kp.priv.private_bytes_raw().hex(), kp.pub.hex()


# ── encode_addr_change ────────────────────────────────────────────────────────

def test_encode_returns_packets():
    _, alice_pub = _kp()
    bob_priv, bob_pub = _kp()
    pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub)
    assert len(pkts) >= 1
    assert all(isinstance(p, bytes) for p in pkts)


def test_encode_msg_type_field():
    _, alice_pub = _kp()
    _, bob_pub = _kp()
    pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub)
    p = unpack_packet(pkts[0])
    assert p.msg_type == MSG_TYPE_ADDR_CHANGE


def test_encode_sender_pub_in_header():
    _, alice_pub = _kp()
    _, bob_pub = _kp()
    pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub)
    p = unpack_packet(pkts[0])
    assert p.sender_pub.hex() == alice_pub


# ── decode_addr_change_packets ────────────────────────────────────────────────

def test_roundtrip_basic():
    _, alice_pub = _kp()
    bob_priv, bob_pub = _kp()

    pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub)
    results = decode_addr_change_packets(pkts, bob_priv)

    assert len(results) == 1
    r = results[0]
    assert isinstance(r, AddrChangeMessage)
    assert r.new_bch_address == NEW_ADDR
    assert r.sender_pub_hex == alice_pub
    assert r.new_pub_hex is None


def test_roundtrip_with_new_pub_hex():
    _, alice_pub = _kp()
    bob_priv, bob_pub = _kp()
    _, new_alice_pub = _kp()

    pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub, new_pub_hex=new_alice_pub)
    [r] = decode_addr_change_packets(pkts, bob_priv)

    assert r.new_bch_address == NEW_ADDR
    assert r.new_pub_hex == new_alice_pub


def test_wrong_recipient_key_fails():
    _, alice_pub = _kp()
    _, bob_pub = _kp()
    wrong_priv, _ = _kp()

    pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub)
    with pytest.raises(Exception):
        decode_addr_change_packets(pkts, wrong_priv)


def test_skips_non_addr_change_packets():
    _, alice_pub = _kp()
    bob_priv, bob_pub = _kp()

    from core.packet_v1 import pack_packet, PacketV1, new_msg_id
    noise = pack_packet(PacketV1(
        msg_id=new_msg_id(),
        sender_pub=bytes.fromhex(alice_pub),
        chunk_index=0, chunk_total=1,
        ciphertext_chunk=b"noise",
        msg_type=MSG_TYPE_ENCRYPTED_CHUNK,
    ))
    addr_pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub)

    results = decode_addr_change_packets([noise] + addr_pkts, bob_priv)
    assert len(results) == 1
    assert results[0].new_bch_address == NEW_ADDR


def test_multi_chunk_roundtrip():
    _, alice_pub = _kp()
    bob_priv, bob_pub = _kp()
    long_addr = "bitcoincash:qp" + "a" * 38

    pkts = encode_addr_change(long_addr, alice_pub, bob_pub, max_chunk_size=20)
    assert len(pkts) > 1
    [r] = decode_addr_change_packets(pkts, bob_priv)
    assert r.new_bch_address == long_addr


def test_multiple_addr_changes_same_batch():
    """Deux expéditeurs différents envoient chacun un ADDR_CHANGE."""
    _, alice_pub = _kp()
    _, bob_pub = _kp()
    carol_priv, carol_pub = _kp()

    pkts_from_alice = encode_addr_change(NEW_ADDR, alice_pub, carol_pub)
    pkts_from_bob   = encode_addr_change(NEW_ADDR2, bob_pub, carol_pub)

    results = decode_addr_change_packets(pkts_from_alice + pkts_from_bob, carol_priv)
    assert len(results) == 2
    addrs = {r.new_bch_address for r in results}
    assert addrs == {NEW_ADDR, NEW_ADDR2}


# ── Intégration : encode_message + encode_addr_change côte à côte ─────────────

def test_addr_change_independent_from_dm():
    """Un ADDR_CHANGE n'interfère pas avec un DM ordinaire."""
    from core.protocol import encode_message, decode_packets

    _, alice_pub = _kp()
    bob_priv, bob_pub = _kp()

    dm_pkts   = encode_message("hello", alice_pub, alice_pub, bob_pub)
    addr_pkts = encode_addr_change(NEW_ADDR, alice_pub, bob_pub)

    # decode_packets ignore les ADDR_CHANGE
    decoded_dms = decode_packets(dm_pkts + addr_pkts, bob_priv)
    assert len(decoded_dms) == 1
    assert decoded_dms[0].plaintext == "hello"

    # decode_addr_change_packets ignore les DM
    decoded_changes = decode_addr_change_packets(dm_pkts + addr_pkts, bob_priv)
    assert len(decoded_changes) == 1
    assert decoded_changes[0].new_bch_address == NEW_ADDR
