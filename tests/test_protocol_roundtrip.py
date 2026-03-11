from core.crypto import gen_keypair
from core.protocol import encode_message, decode_packets


def test_protocol_roundtrip_single_packet():
    alice = gen_keypair()
    bob = gen_keypair()

    alice_priv = alice.priv.private_bytes_raw().hex()
    alice_pub = alice.pub.hex()
    bob_priv = bob.priv.private_bytes_raw().hex()
    bob_pub = bob.pub.hex()

    packets = encode_message(
        plaintext="hello",
        sender_priv_hex=alice_priv,
        sender_pub_hex=alice_pub,
        recipient_pub_hex=bob_pub,
        max_chunk_size=162,
    )

    decoded = decode_packets(packets, recipient_priv_hex=bob_priv)
    assert len(decoded) == 1
    assert decoded[0].plaintext == "hello"
    assert decoded[0].sender_pub_hex == alice_pub


def test_protocol_roundtrip_multi_chunk():
    alice = gen_keypair()
    bob = gen_keypair()

    alice_priv = alice.priv.private_bytes_raw().hex()
    alice_pub = alice.pub.hex()
    bob_priv = bob.priv.private_bytes_raw().hex()
    bob_pub = bob.pub.hex()

    # Force multiple chunks
    msg = "A" * 5000

    packets = encode_message(
        plaintext=msg,
        sender_priv_hex=alice_priv,
        sender_pub_hex=alice_pub,
        recipient_pub_hex=bob_pub,
        max_chunk_size=80,  # small to force chunking
    )

    decoded = decode_packets(packets, recipient_priv_hex=bob_priv)
    assert len(decoded) == 1
    assert decoded[0].plaintext == msg
    assert decoded[0].sender_pub_hex == alice_pub