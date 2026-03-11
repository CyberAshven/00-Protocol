# cli/export_opreturns.py
from __future__ import annotations

import os
import pathlib
import random

from core.packet_v1 import PacketV1, new_msg_id, pack_packet, FIXED_HEADER_LEN
from core.chunks import chunk_bytes
from core.crypto import gen_keypair, encrypt_for_pubkey
from core.opreturn import build_op_return, OP_RETURN_MAX_PAYLOAD


def main() -> None:
    alice = gen_keypair()
    bob = gen_keypair()

    plaintext = (b"hello from chat.cash " * 250) + os.urandom(128)
    msg_id = new_msg_id()

    ciphertext = encrypt_for_pubkey(plaintext, bob.pub)

    max_chunk_size = OP_RETURN_MAX_PAYLOAD - FIXED_HEADER_LEN
    chunks = chunk_bytes(ciphertext, max_chunk_size=max_chunk_size)
    total = len(chunks)

    scripts: list[bytes] = []
    for idx, c in enumerate(chunks):
        pkt = PacketV1(
            msg_id=msg_id,
            sender_pub=alice.pub,
            chunk_index=idx,
            chunk_total=total,
            ciphertext_chunk=c,
        )
        payload = pack_packet(pkt)
        scripts.append(build_op_return(payload))

    # (optionnel) shuffle pour simuler chain, mais pour export on garde l’ordre
    # random.shuffle(scripts)

    outdir = pathlib.Path("out")
    outdir.mkdir(exist_ok=True)

    path = outdir / f"opreturns_{msg_id.hex()}.txt"
    path.write_text("\n".join(s.hex() for s in scripts) + "\n", encoding="utf-8")

    print(f"msg_id: {msg_id.hex()}")
    print(f"chunks: {len(scripts)}")
    print(f"export: {path}")


if __name__ == "__main__":
    main()