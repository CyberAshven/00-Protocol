# core/packet_v2.py
"""
CCSH v2 — Split-Knowledge Packet Format

Quantum-resistant messaging via XOR One-Time Pad split:
  - Piece A (on-chain OP_RETURN) = encrypted XOR shard → permanent but useless alone
  - Piece B (Nostr ephemeral relay) = encrypted XOR pad → disappears after TTL

Even if AES-256 is broken by quantum computers:
  - Decrypting piece A yields random noise (XOR shard)
  - Piece B no longer exists on the relay
  - Reconstruction is mathematically impossible without both pieces

This is information-theoretically secure (One-Time Pad),
not just computationally hard like PQC algorithms.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

MAGIC = b"CCSH"
VERSION_V2 = 0x02

# --- Message types (same as v1 + new) ---
MSG_TYPE_ENCRYPTED_CHUNK     = 0x01  # standard DM (v1 compat)
MSG_TYPE_ADDR_CHANGE         = 0x02  # address rotation
MSG_TYPE_GROUP_MSG           = 0x03  # group message
MSG_TYPE_GROUP_INVITE        = 0x04  # group invitation
MSG_TYPE_GROUP_ADDR_CHANGE   = 0x05  # group key rotation
MSG_TYPE_SPLIT_CHAIN         = 0x10  # v2: XOR shard A (on-chain)
MSG_TYPE_SPLIT_RELAY         = 0x11  # v2: XOR pad B (Nostr relay)

# --- Flags ---
FLAG_SPLIT_MODE = 0x01  # bit 0: message uses XOR split

# --- Header sizes ---
SENDER_PUB_LEN = 32     # X25519 raw pubkey
MSG_ID_LEN = 16          # UUID4 bytes

# MAGIC(4) | VER(1) | TYPE(1) | FLAGS(1) | MSG_ID(16) | SENDER_PUB(32) |
# CHUNK_INDEX(2) | CHUNK_TOTAL(2) | CIPH_LEN(2)
FIXED_HEADER_LEN = 4 + 1 + 1 + 1 + MSG_ID_LEN + SENDER_PUB_LEN + 2 + 2 + 2  # 61 bytes


@dataclass(frozen=True)
class PacketV2:
    msg_id: bytes                 # 16 bytes — links chain + relay pieces
    sender_pub: bytes             # 32 bytes (X25519 raw pubkey)
    chunk_index: int              # uint16
    chunk_total: int              # uint16
    ciphertext_chunk: bytes       # variable
    msg_type: int = MSG_TYPE_SPLIT_CHAIN
    flags: int = FLAG_SPLIT_MODE

    def validate(self) -> None:
        if not isinstance(self.msg_id, (bytes, bytearray)) or len(self.msg_id) != MSG_ID_LEN:
            raise ValueError("msg_id must be 16 bytes")
        if not isinstance(self.sender_pub, (bytes, bytearray)) or len(self.sender_pub) != SENDER_PUB_LEN:
            raise ValueError(f"sender_pub must be {SENDER_PUB_LEN} bytes")
        if not (0 <= self.chunk_index <= 0xFFFF):
            raise ValueError("chunk_index out of uint16 range")
        if not (1 <= self.chunk_total <= 0xFFFF):
            raise ValueError("chunk_total out of uint16 range")
        if self.chunk_index >= self.chunk_total:
            raise ValueError("chunk_index must be < chunk_total")
        if not isinstance(self.ciphertext_chunk, (bytes, bytearray)):
            raise ValueError("ciphertext_chunk must be bytes")
        if len(self.ciphertext_chunk) > 0xFFFF:
            raise ValueError("ciphertext_chunk too large")
        if not (0 <= self.flags <= 0xFF):
            raise ValueError("flags out of byte range")
        if not (0 <= self.msg_type <= 0xFF):
            raise ValueError("msg_type out of byte range")


def new_msg_id() -> bytes:
    return uuid.uuid4().bytes


def pack_v2(pkt: PacketV2) -> bytes:
    """
    Binary format (identical layout to v1, different VERSION byte):
      MAGIC(4) | VER(1)=0x02 | TYPE(1) | FLAGS(1) |
      MSG_ID(16) | SENDER_PUB(32) |
      CHUNK_INDEX(2) | CHUNK_TOTAL(2) | CIPH_LEN(2) |
      CIPHERTEXT(var)
    """
    pkt.validate()
    out = bytearray()
    out += MAGIC
    out += bytes([VERSION_V2])
    out += bytes([pkt.msg_type])
    out += bytes([pkt.flags])
    out += pkt.msg_id
    out += pkt.sender_pub
    out += int(pkt.chunk_index).to_bytes(2, "big")
    out += int(pkt.chunk_total).to_bytes(2, "big")
    out += int(len(pkt.ciphertext_chunk)).to_bytes(2, "big")
    out += pkt.ciphertext_chunk
    return bytes(out)


def unpack_v2(raw: bytes) -> PacketV2:
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("raw must be bytes")
    if len(raw) < FIXED_HEADER_LEN:
        raise ValueError(f"raw too short: {len(raw)} < {FIXED_HEADER_LEN}")
    if raw[0:4] != MAGIC:
        raise ValueError("bad magic")

    ver = raw[4]
    if ver != VERSION_V2:
        raise ValueError(f"expected v2 (0x02), got {ver:#x}")

    msg_type = raw[5]
    flags = raw[6]
    pos = 7

    msg_id = raw[pos:pos + MSG_ID_LEN]; pos += MSG_ID_LEN
    sender_pub = raw[pos:pos + SENDER_PUB_LEN]; pos += SENDER_PUB_LEN
    chunk_index = int.from_bytes(raw[pos:pos + 2], "big"); pos += 2
    chunk_total = int.from_bytes(raw[pos:pos + 2], "big"); pos += 2
    clen = int.from_bytes(raw[pos:pos + 2], "big"); pos += 2

    if len(raw) != pos + clen:
        raise ValueError(f"length mismatch: declared {clen}, got {len(raw) - pos}")

    ciphertext_chunk = raw[pos:pos + clen]

    pkt = PacketV2(
        msg_id=bytes(msg_id),
        sender_pub=bytes(sender_pub),
        chunk_index=chunk_index,
        chunk_total=chunk_total,
        ciphertext_chunk=bytes(ciphertext_chunk),
        msg_type=msg_type,
        flags=flags,
    )
    pkt.validate()
    return pkt
