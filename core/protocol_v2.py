# core/protocol_v2.py
"""
CCSH v2 — Split-Knowledge Protocol

High-level API for encoding/decoding split messages:

SEND:
  plaintext
    → split_encrypt() → (chain_blob, relay_blob, eph_pub)
    → chunk chain_blob → CCSH v2 packets (MSG_TYPE_SPLIT_CHAIN) → OP_RETURN TXs
    → chunk relay_blob → CCSH v2 packets (MSG_TYPE_SPLIT_RELAY) → Nostr ephemeral event

RECEIVE:
  OP_RETURN TXs → unpack SPLIT_CHAIN packets → reassemble chain_blob
  Nostr event    → unpack SPLIT_RELAY packets → reassemble relay_blob
    → split_decrypt(chain_blob, relay_blob, eph_pub) → plaintext

The eph_pub (32 bytes) is embedded in the first chain chunk's header
via the sender_pub field (overloaded in v2 split mode), or as a
separate field prepended to chain_blob.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import x25519

from . import chunks
from .crypto_v2 import split_encrypt, split_decrypt, SplitBundle
from .packet_v2 import (
    PacketV2, pack_v2, unpack_v2, new_msg_id,
    MSG_TYPE_SPLIT_CHAIN, MSG_TYPE_SPLIT_RELAY,
    FLAG_SPLIT_MODE,
)


@dataclass(frozen=True)
class DecodedMessageV2:
    msg_id: str
    sender_pub_hex: str
    plaintext: str


@dataclass(frozen=True)
class SplitEncoded:
    """Ready-to-send packets for both channels."""
    chain_packets: List[bytes]   # → embed in OP_RETURN
    relay_packets: List[bytes]   # → send to Nostr relay
    msg_id_hex: str              # shared msg_id linking both halves


def encode_message_v2(
    plaintext: str,
    sender_pub_hex: str,
    recipient_pub_hex: str,
    *,
    max_chunk_size: int = 162,
    relay_ttl: int = 3600,       # seconds before relay should delete (default 1h)
) -> SplitEncoded:
    """
    High-level v2 encode:
      plaintext → split_encrypt → chunk both blobs → CCSH v2 packets

    Returns SplitEncoded with packets for both channels.
    The msg_id is shared so the recipient can match chain + relay pieces.
    """
    recipient_pub = bytes.fromhex(recipient_pub_hex)
    sender_pub = bytes.fromhex(sender_pub_hex)
    if len(sender_pub) != 32:
        raise ValueError("sender_pub must be 32 bytes (X25519)")

    # 1. Split encrypt
    bundle: SplitBundle = split_encrypt(
        plaintext.encode("utf-8"),
        recipient_pub,
    )

    # 2. Prepend eph_pub to chain_blob so recipient can extract it
    #    Format: eph_pub(32) || chain_blob
    chain_data = bundle.eph_pub + bundle.chain_blob
    relay_data = bundle.relay_blob

    # 3. Chunk both
    chain_chunks = chunks.chunk_bytes(chain_data, max_chunk_size=max_chunk_size)
    relay_chunks = chunks.chunk_bytes(relay_data, max_chunk_size=max_chunk_size)

    # 4. Pack into CCSH v2 packets (same msg_id for both)
    msg_id = new_msg_id()

    chain_packets = [
        pack_v2(PacketV2(
            msg_id=msg_id,
            sender_pub=sender_pub,
            chunk_index=idx,
            chunk_total=len(chain_chunks),
            ciphertext_chunk=part,
            msg_type=MSG_TYPE_SPLIT_CHAIN,
            flags=FLAG_SPLIT_MODE,
        ))
        for idx, part in enumerate(chain_chunks)
    ]

    relay_packets = [
        pack_v2(PacketV2(
            msg_id=msg_id,
            sender_pub=sender_pub,
            chunk_index=idx,
            chunk_total=len(relay_chunks),
            ciphertext_chunk=part,
            msg_type=MSG_TYPE_SPLIT_RELAY,
            flags=FLAG_SPLIT_MODE,
        ))
        for idx, part in enumerate(relay_chunks)
    ]

    return SplitEncoded(
        chain_packets=chain_packets,
        relay_packets=relay_packets,
        msg_id_hex=msg_id.hex(),
    )


def decode_message_v2(
    chain_packets: List[bytes],
    relay_packets: List[bytes],
    recipient_priv_hex: str,
) -> List[DecodedMessageV2]:
    """
    High-level v2 decode:
      chain_packets (from OP_RETURN) + relay_packets (from Nostr)
      → group by msg_id → reassemble both blobs → split_decrypt → plaintext

    Both packet lists can contain multiple messages; they are matched by msg_id.
    """
    recipient_priv = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(recipient_priv_hex)
    )

    # Group chain packets by msg_id
    chain_grouped: Dict[bytes, List[Tuple[int, int, bytes, bytes]]] = {}
    for raw in chain_packets:
        p = unpack_v2(raw)
        if p.msg_type != MSG_TYPE_SPLIT_CHAIN:
            continue
        chain_grouped.setdefault(p.msg_id, []).append(
            (p.chunk_index, p.chunk_total, p.sender_pub, p.ciphertext_chunk)
        )

    # Group relay packets by msg_id
    relay_grouped: Dict[bytes, List[Tuple[int, int, bytes]]] = {}
    for raw in relay_packets:
        p = unpack_v2(raw)
        if p.msg_type != MSG_TYPE_SPLIT_RELAY:
            continue
        relay_grouped.setdefault(p.msg_id, []).append(
            (p.chunk_index, p.chunk_total, p.ciphertext_chunk)
        )

    # Decode each message that has both halves
    decoded: List[DecodedMessageV2] = []
    for msg_id, chain_parts in chain_grouped.items():
        relay_parts = relay_grouped.get(msg_id)
        if relay_parts is None:
            continue  # missing relay half — cannot decrypt (by design)

        # Reassemble chain blob
        chain_sorted = sorted(chain_parts, key=lambda x: x[0])
        total_c = chain_sorted[0][1]
        if len(chain_sorted) != total_c:
            continue  # incomplete
        sender_pub = chain_sorted[0][2]
        chain_data = chunks.rebuild_bytes([c for (_, _, _, c) in chain_sorted])

        # Reassemble relay blob
        relay_sorted = sorted(relay_parts, key=lambda x: x[0])
        total_r = relay_sorted[0][1]
        if len(relay_sorted) != total_r:
            continue  # incomplete
        relay_data = chunks.rebuild_bytes([c for (_, _, c) in relay_sorted])

        # Extract eph_pub from chain_data (first 32 bytes)
        if len(chain_data) < 32:
            continue
        eph_pub = chain_data[:32]
        chain_blob = chain_data[32:]

        # Split decrypt
        try:
            plaintext_bytes = split_decrypt(
                chain_blob=chain_blob,
                relay_blob=relay_data,
                eph_pub=eph_pub,
                recipient_priv=recipient_priv,
            )
        except Exception:
            continue  # decryption failed — skip

        decoded.append(DecodedMessageV2(
            msg_id=msg_id.hex(),
            sender_pub_hex=sender_pub.hex(),
            plaintext=plaintext_bytes.decode("utf-8", errors="replace"),
        ))

    return decoded


# ──────────────────────────────────────────
# Nostr event helpers
# ──────────────────────────────────────────

def build_nostr_ephemeral_event(
    relay_packets: List[bytes],
    msg_id_hex: str,
    recipient_pub_hex: str,
    ttl: int = 3600,
) -> dict:
    """
    Build a Nostr event (NIP-40 expiration) to carry the relay packets.

    Kind 21059 = ephemeral encrypted DM (custom kind in 20000-29999 range).
    Ephemeral events (NIP-16) are not stored permanently by relays.

    The event content is the hex-encoded relay packets concatenated,
    with packet boundaries indicated by a length prefix per packet.

    Tags:
      ["p", recipient_pub_hex]     — for relay routing
      ["ccsh", msg_id_hex]         — for matching with chain half
      ["expiration", timestamp]    — NIP-40 TTL
    """
    import time

    # Encode relay packets: 2-byte length prefix (BE) + packet data
    payload = bytearray()
    for pkt in relay_packets:
        payload += len(pkt).to_bytes(2, "big")
        payload += pkt

    expiration = str(int(time.time()) + ttl)

    return {
        "kind": 21059,
        "content": payload.hex(),
        "tags": [
            ["p", recipient_pub_hex],
            ["ccsh", msg_id_hex],
            ["expiration", expiration],
        ],
    }


def parse_nostr_ephemeral_event(event: dict) -> List[bytes]:
    """
    Parse relay packets from a Nostr ephemeral event.
    Returns list of raw CCSH v2 packet bytes.
    """
    payload = bytes.fromhex(event["content"])
    packets = []
    pos = 0
    while pos < len(payload):
        if pos + 2 > len(payload):
            break
        pkt_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        if pos + pkt_len > len(payload):
            break
        packets.append(payload[pos:pos + pkt_len])
        pos += pkt_len
    return packets
