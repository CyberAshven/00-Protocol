from core.crypto import gen_keypair
from core.protocol import encode_message
from transport.bch_transport import BchTransport


def test_packets_fit_in_opreturn_default_chunk():
    alice = gen_keypair()
    bob = gen_keypair()

    packets = encode_message(
        plaintext="hello",
        sender_priv_hex=alice.priv.private_bytes_raw().hex(),
        sender_pub_hex=alice.pub.hex(),
        recipient_pub_hex=bob.pub.hex(),
        max_chunk_size=158,  # IMPORTANT for BCH OP_RETURN
    )

    # Should not raise
    outs = BchTransport.packets_to_opreturn_outputs(packets)
    assert len(outs) >= 1
    assert all(o.size <= BchTransport.MAX_OPRETURN_DATA for o in outs)