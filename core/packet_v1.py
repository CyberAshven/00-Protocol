# core/packet_v1.py
from __future__ import annotations

import uuid
from dataclasses import dataclass

MAGIC = b"CCSH"         # 4 bytes
VERSION = 0x01          # 1 byte

MSG_TYPE_ENCRYPTED_CHUNK  = 0x01   # DM chiffré X25519
MSG_TYPE_ADDR_CHANGE      = 0x02   # rotation d'adresse BCH personnelle (DM X25519)
MSG_TYPE_GROUP_MSG        = 0x03   # message groupe chiffré AES-256-GCM (group_key)
MSG_TYPE_GROUP_INVITE     = 0x04   # invitation groupe → DM X25519 (JSON payload)
MSG_TYPE_GROUP_ADDR_CHANGE = 0x05  # kick/rotation groupe → DM X25519 (JSON payload)

# Header sizes
SENDER_PUB_LEN = 32     # X25519 raw pubkey
MSG_ID_LEN = 16         # UUID4 bytes

# MAGIC(4) | VER(1) | TYPE(1) | FLAGS(1) | MSG_ID(16) | SENDER_PUB(32) |
# CHUNK_INDEX(2) | CHUNK_TOTAL(2) | CIPH_LEN(2)
FIXED_HEADER_LEN = 4 + 1 + 1 + 1 + MSG_ID_LEN + SENDER_PUB_LEN + 2 + 2 + 2  # 61 bytes


@dataclass(frozen=True)
class PacketV1:
    msg_id: bytes                 # 16
    sender_pub: bytes             # 32 (X25519 raw pubkey)
    chunk_index: int              # uint16
    chunk_total: int              # uint16
    ciphertext_chunk: bytes       # variable
    msg_type: int = MSG_TYPE_ENCRYPTED_CHUNK
    flags: int = 0

    def validate(self) -> None:
        if not isinstance(self.msg_id, (bytes, bytearray)) or len(self.msg_id) != MSG_ID_LEN:
            raise ValueError("msg_id must be 16 bytes")
        if not isinstance(self.sender_pub, (bytes, bytearray)) or len(self.sender_pub) != SENDER_PUB_LEN:
            raise ValueError(f"sender_pub must be {SENDER_PUB_LEN} bytes (X25519 raw pubkey)")
        if not (0 <= self.chunk_index <= 0xFFFF):
            raise ValueError("chunk_index out of uint16 range")
        if not (1 <= self.chunk_total <= 0xFFFF):
            raise ValueError("chunk_total out of uint16 range")
        if self.chunk_index >= self.chunk_total:
            raise ValueError("chunk_index must be < chunk_total")
        if not isinstance(self.ciphertext_chunk, (bytes, bytearray)):
            raise ValueError("ciphertext_chunk must be bytes")
        if len(self.ciphertext_chunk) > 0xFFFF:
            raise ValueError("ciphertext_chunk too large (uint16 length)")
        if not (0 <= self.flags <= 0xFF):
            raise ValueError("flags out of byte range")
        if not (0 <= self.msg_type <= 0xFF):
            raise ValueError("msg_type out of byte range")


def new_msg_id() -> bytes:
    """Convenience: random unique message id."""
    return uuid.uuid4().bytes


def pack_packet(pkt: PacketV1) -> bytes:
    """
    Binary format:
      MAGIC(4) | VER(1) | TYPE(1) | FLAGS(1) |
      MSG_ID(16) | SENDER_PUB(32) |
      CHUNK_INDEX(2) | CHUNK_TOTAL(2) | CIPH_LEN(2) |
      CIPH(bytes)
    """
    pkt.validate()

    out = bytearray()
    out += MAGIC
    out += bytes([VERSION])
    out += bytes([pkt.msg_type])
    out += bytes([pkt.flags])
    out += pkt.msg_id
    out += pkt.sender_pub
    out += int(pkt.chunk_index).to_bytes(2, "big")
    out += int(pkt.chunk_total).to_bytes(2, "big")
    out += int(len(pkt.ciphertext_chunk)).to_bytes(2, "big")
    out += pkt.ciphertext_chunk
    return bytes(out)


def unpack_packet(raw: bytes) -> PacketV1:
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("raw must be bytes")
    if len(raw) < FIXED_HEADER_LEN:
        raise ValueError(f"raw too short: {len(raw)} < {FIXED_HEADER_LEN}")

    if raw[0:4] != MAGIC:
        raise ValueError("bad magic")
    ver = raw[4]
    if ver != VERSION:
        raise ValueError(f"unsupported version: {ver}")

    msg_type = raw[5]
    flags = raw[6]

    pos = 7
    msg_id = raw[pos:pos + MSG_ID_LEN]
    pos += MSG_ID_LEN

    sender_pub = raw[pos:pos + SENDER_PUB_LEN]
    pos += SENDER_PUB_LEN

    chunk_index = int.from_bytes(raw[pos:pos + 2], "big")
    pos += 2
    chunk_total = int.from_bytes(raw[pos:pos + 2], "big")
    pos += 2

    clen = int.from_bytes(raw[pos:pos + 2], "big")
    pos += 2

    if len(raw) != pos + clen:
        raise ValueError(f"length mismatch: declared {clen} but raw has {len(raw) - pos}")

    ciphertext_chunk = raw[pos:pos + clen]

    pkt = PacketV1(
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