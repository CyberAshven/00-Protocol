# core/protocol.py
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import x25519

from . import chunks
from . import crypto
from .packet_v1 import (
    PacketV1, pack_packet, unpack_packet, new_msg_id,
    MSG_TYPE_ENCRYPTED_CHUNK, MSG_TYPE_ADDR_CHANGE,
)


@dataclass(frozen=True)
class DecodedMessage:
    msg_id: str
    sender_pub_hex: str
    plaintext: str


@dataclass(frozen=True)
class AddrChangeMessage:
    msg_id: str
    sender_pub_hex: str       # X25519 pubkey de l'expéditeur (permet d'identifier le contact)
    new_bch_address: str      # nouvelle adresse BCH à utiliser pour envoyer à cet expéditeur
    new_pub_hex: Optional[str] = None  # nouvelle clé X25519 si rotation complète d'identité


def encode_message(
    plaintext: str,
    sender_priv_hex: str,
    sender_pub_hex: str,
    recipient_pub_hex: str,
    *,
    max_chunk_size: int = 162,
) -> List[bytes]:
    """
    High-level API:
      plaintext -> encrypt(recipient_pub) -> chunk -> CCSH v1 packets (bytes)

    Returns a list of raw packet bytes ready to be embedded in OP_RETURN or any transport.
    """
    recipient_pub = bytes.fromhex(recipient_pub_hex)

    # Encrypt for recipient (X25519 + AES-GCM with ephemeral key)
    ct_bundle = crypto.encrypt_for_pubkey(plaintext.encode("utf-8"), recipient_pub)

    # Chunk the ciphertext bundle (bytes)
    blob_chunks = chunks.chunk_bytes(ct_bundle, max_chunk_size=max_chunk_size)

    # Pack chunks into CCSH v1 packets
    packets: List[bytes] = []
    msg_id = new_msg_id()
    sender_pub = bytes.fromhex(sender_pub_hex)
    if len(sender_pub) != 32:
        raise ValueError("sender_pub must be 32 bytes (X25519 raw)")

    total = len(blob_chunks)
    for idx, part in enumerate(blob_chunks):
        pkt = PacketV1(
            msg_id=msg_id,
            sender_pub=sender_pub,
            chunk_index=idx,
            chunk_total=total,
            ciphertext_chunk=part,
        )
        packets.append(pack_packet(pkt))
    return packets


def decode_packets(
    packets: List[bytes],
    recipient_priv_hex: str,
) -> List[DecodedMessage]:
    """
    High-level API:
      CCSH v1 packets -> group by msg_id -> reassemble -> decrypt(recipient_priv) -> plaintext

    Returns a list because you may pass packets from multiple messages.
    """
    recipient_priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(recipient_priv_hex))

    grouped: Dict[bytes, List[Tuple[int, int, bytes, bytes]]] = {}
    # msg_id -> list of (idx, total, sender_pub, chunk)

    for raw in packets:
        p = unpack_packet(raw)
        if p.msg_type != MSG_TYPE_ENCRYPTED_CHUNK:
            continue  # ignore ADDR_CHANGE, GROUP_MSG, etc.
        msg_id = p.msg_id
        grouped.setdefault(msg_id, []).append(
            (p.chunk_index, p.chunk_total, p.sender_pub, p.ciphertext_chunk)
        )

    decoded: List[DecodedMessage] = []
    for msg_id, parts in grouped.items():
        # Validate totals are consistent
        totals = {t for (_, t, _, _) in parts}
        if len(totals) != 1:
            raise ValueError(f"Inconsistent chunk_total for msg_id={msg_id.hex()}")

        total = next(iter(totals))
        # Reassemble
        parts_sorted = sorted(parts, key=lambda x: x[0])
        if len(parts_sorted) != total:
            raise ValueError(
                f"Missing chunks for msg_id={msg_id.hex()} ({len(parts_sorted)}/{total})"
            )

        sender_pub = parts_sorted[0][2]
        blob = chunks.rebuild_bytes([c for (_, _, _, c) in parts_sorted])

        # Decrypt
        plaintext_bytes = crypto.decrypt_with_privkey(blob, recipient_priv)
        decoded.append(
            DecodedMessage(
                msg_id=msg_id.hex(),
                sender_pub_hex=sender_pub.hex(),
                plaintext=plaintext_bytes.decode("utf-8", errors="replace"),
            )
        )

    return decoded


def encode_addr_change(
    new_bch_address: str,
    sender_pub_hex: str,
    recipient_pub_hex: str,
    new_pub_hex: Optional[str] = None,
    *,
    max_chunk_size: int = 162,
) -> List[bytes]:
    """
    Encode un MSG_TYPE_ADDR_CHANGE chiffré X25519 pour un contact.

    L'expéditeur a changé d'adresse BCH (et optionnellement de clé X25519).
    Ce paquet est envoyé à l'adresse BCH personnelle du destinataire.

    Payload JSON : { new_bch_address, new_pub_hex? }
    """
    payload: dict = {"new_bch_address": new_bch_address}
    if new_pub_hex:
        payload["new_pub_hex"] = new_pub_hex

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ct_bundle = crypto.encrypt_for_pubkey(payload_bytes, bytes.fromhex(recipient_pub_hex))
    blob_chunks = chunks.chunk_bytes(ct_bundle, max_chunk_size=max_chunk_size)

    msg_id = new_msg_id()
    sender_pub = bytes.fromhex(sender_pub_hex)
    total = len(blob_chunks)

    return [
        pack_packet(PacketV1(
            msg_id=msg_id,
            sender_pub=sender_pub,
            chunk_index=idx,
            chunk_total=total,
            ciphertext_chunk=part,
            msg_type=MSG_TYPE_ADDR_CHANGE,
        ))
        for idx, part in enumerate(blob_chunks)
    ]


def decode_addr_change_packets(
    packets: List[bytes],
    recipient_priv_hex: str,
) -> List[AddrChangeMessage]:
    """
    Décode les paquets MSG_TYPE_ADDR_CHANGE reçus.
    Les paquets d'autres types sont ignorés.
    """
    recipient_priv = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(recipient_priv_hex)
    )

    grouped: Dict[bytes, List[Tuple[int, int, bytes, bytes]]] = {}
    for raw in packets:
        p = unpack_packet(raw)
        if p.msg_type != MSG_TYPE_ADDR_CHANGE:
            continue
        grouped.setdefault(p.msg_id, []).append(
            (p.chunk_index, p.chunk_total, p.sender_pub, p.ciphertext_chunk)
        )

    results: List[AddrChangeMessage] = []
    for msg_id, parts in grouped.items():
        totals = {t for (_, t, _, _) in parts}
        if len(totals) != 1:
            raise ValueError(f"chunk_total incohérent pour msg_id={msg_id.hex()}")
        total = next(iter(totals))
        parts_sorted = sorted(parts, key=lambda x: x[0])
        if len(parts_sorted) != total:
            raise ValueError(f"chunks manquants pour msg_id={msg_id.hex()}")

        sender_pub = parts_sorted[0][2]
        blob = chunks.rebuild_bytes([c for (_, _, _, c) in parts_sorted])
        plaintext_bytes = crypto.decrypt_with_privkey(blob, recipient_priv)
        data = json.loads(plaintext_bytes.decode("utf-8"))

        results.append(AddrChangeMessage(
            msg_id=msg_id.hex(),
            sender_pub_hex=sender_pub.hex(),
            new_bch_address=data["new_bch_address"],
            new_pub_hex=data.get("new_pub_hex"),
        ))

    return results