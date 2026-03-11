# core/group.py
"""
Groupes CCSH — état, protocole, encode/decode.

Architecture :
  GROUP_MSG        — message groupe : AES-256-GCM(group_key) → channel_address BCH
  GROUP_INVITE     — invitation     : X25519 DM → adresse personnelle du destinataire
  GROUP_ADDR_CHANGE— kick/rotation  : X25519 DM → adresse personnelle de chaque membre restant

Flux kick :
  1. Admin génère new_channel_address + new_group_key via rotate_group()
  2. Pour chaque membre restant : encode_addr_change() → 1 tx BCH (DM X25519)
  3. Membre exclu ne reçoit rien → reste aveugle sur l'ancien channel mort
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import List

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .chunks import chunk_bytes, rebuild_bytes
from .crypto import encrypt_for_pubkey, decrypt_with_privkey
from .packet_v1 import (
    PacketV1, pack_packet, unpack_packet, new_msg_id,
    MSG_TYPE_GROUP_MSG, MSG_TYPE_GROUP_INVITE, MSG_TYPE_GROUP_ADDR_CHANGE,
)

_CONTROL_TYPES = {MSG_TYPE_GROUP_INVITE, MSG_TYPE_GROUP_ADDR_CHANGE}


# ── State ──────────────────────────────────────────────────────────────────────

@dataclass
class Member:
    pub_hex: str
    alias: str = ""

    def to_dict(self) -> dict:
        return {"pub_hex": self.pub_hex, "alias": self.alias}

    @classmethod
    def from_dict(cls, d: dict) -> Member:
        return cls(pub_hex=d["pub_hex"], alias=d.get("alias", ""))


@dataclass
class GroupState:
    group_id: str          # 16 bytes hex (32 chars)
    name: str
    channel_address: str   # adresse BCH "boîte aux lettres" du groupe
    group_key: bytes       # 32 bytes AES-256-GCM
    epoch: int             # incrémenté à chaque rotation/kick
    members: List[Member]
    is_admin: bool = False

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "channel_address": self.channel_address,
            "group_key": self.group_key.hex(),
            "epoch": self.epoch,
            "members": [m.to_dict() for m in self.members],
            "is_admin": self.is_admin,
        }

    @classmethod
    def from_dict(cls, d: dict) -> GroupState:
        return cls(
            group_id=d["group_id"],
            name=d["name"],
            channel_address=d["channel_address"],
            group_key=bytes.fromhex(d["group_key"]),
            epoch=d["epoch"],
            members=[Member.from_dict(m) for m in d.get("members", [])],
            is_admin=d.get("is_admin", False),
        )


# ── Decoded types ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DecodedGroupMessage:
    msg_id: str
    sender_pub_hex: str
    plaintext: str


@dataclass(frozen=True)
class GroupControlMessage:
    """Résultat du décodage d'un INVITE ou ADDR_CHANGE."""
    msg_type: int          # MSG_TYPE_GROUP_INVITE | MSG_TYPE_GROUP_ADDR_CHANGE
    payload: dict          # JSON désérialisé


# ── CRUD état ──────────────────────────────────────────────────────────────────

def create_group(name: str, admin_pub_hex: str, channel_address: str) -> GroupState:
    """
    Crée un nouveau groupe.
    channel_address : adresse BCH fraîche générée par le wallet de l'admin.
    """
    return GroupState(
        group_id=os.urandom(16).hex(),
        name=name,
        channel_address=channel_address,
        group_key=os.urandom(32),
        epoch=0,
        members=[Member(pub_hex=admin_pub_hex)],
        is_admin=True,
    )


def add_member(state: GroupState, pub_hex: str, alias: str = "") -> GroupState:
    """Retourne un nouvel état avec le membre ajouté (no-op si déjà présent)."""
    if any(m.pub_hex == pub_hex for m in state.members):
        return state
    return GroupState(
        group_id=state.group_id,
        name=state.name,
        channel_address=state.channel_address,
        group_key=state.group_key,
        epoch=state.epoch,
        members=list(state.members) + [Member(pub_hex=pub_hex, alias=alias)],
        is_admin=state.is_admin,
    )


def rotate_group(
    state: GroupState,
    new_channel_address: str,
    kicked_pub_hex: str | None = None,
) -> GroupState:
    """
    Génère un nouveau group_key + channel_address.
    Si kicked_pub_hex fourni, retire ce membre.

    Le caller doit ensuite envoyer encode_addr_change() à chaque membre restant.
    """
    new_members = [m for m in state.members if m.pub_hex != kicked_pub_hex]
    return GroupState(
        group_id=state.group_id,
        name=state.name,
        channel_address=new_channel_address,
        group_key=os.urandom(32),
        epoch=state.epoch + 1,
        members=new_members,
        is_admin=state.is_admin,
    )


def apply_invite(state_from_control: GroupControlMessage) -> GroupState:
    """Construit un GroupState à partir d'un message INVITE reçu."""
    p = state_from_control.payload
    return GroupState.from_dict({
        "group_id": p["group_id"],
        "name": p["name"],
        "channel_address": p["channel_address"],
        "group_key": p["group_key"],
        "epoch": p["epoch"],
        "members": p.get("members", []),
        "is_admin": False,
    })


def apply_addr_change(
    current_state: GroupState,
    ctrl: GroupControlMessage,
) -> GroupState:
    """Met à jour un GroupState suite à la réception d'un ADDR_CHANGE."""
    p = ctrl.payload
    if p.get("group_id") != current_state.group_id:
        raise ValueError("group_id mismatch in ADDR_CHANGE payload")
    kicked = p.get("kicked_pubkey")
    new_members = [m for m in current_state.members if m.pub_hex != kicked]
    return GroupState(
        group_id=current_state.group_id,
        name=current_state.name,
        channel_address=p["new_channel_address"],
        group_key=bytes.fromhex(p["new_group_key"]),
        epoch=p["epoch"],
        members=new_members,
        is_admin=current_state.is_admin,
    )


# ── Encode / Decode messages groupe ────────────────────────────────────────────

def encode_group_msg(
    plaintext: str,
    state: GroupState,
    sender_pub_hex: str,
    *,
    max_chunk_size: int = 162,
) -> List[bytes]:
    """
    Chiffre un message groupe avec AES-256-GCM(group_key).
    Format bundle : nonce(12) || ciphertext+tag
    Envoi : channel_address BCH du groupe.
    """
    aes = AESGCM(state.group_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    bundle = nonce + ct

    blob_chunks = chunk_bytes(bundle, max_chunk_size=max_chunk_size)
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
            msg_type=MSG_TYPE_GROUP_MSG,
        ))
        for idx, part in enumerate(blob_chunks)
    ]


def decode_group_msg(
    packets: List[bytes],
    state: GroupState,
) -> List[DecodedGroupMessage]:
    """
    Déchiffre les GROUP_MSG avec group_key.
    Les paquets non-GROUP_MSG sont ignorés.
    """
    grouped: dict = {}
    for raw in packets:
        p = unpack_packet(raw)
        if p.msg_type != MSG_TYPE_GROUP_MSG:
            continue
        grouped.setdefault(p.msg_id, []).append(
            (p.chunk_index, p.chunk_total, p.sender_pub, p.ciphertext_chunk)
        )

    aes = AESGCM(state.group_key)
    results: List[DecodedGroupMessage] = []

    for msg_id, parts in grouped.items():
        totals = {t for (_, t, _, _) in parts}
        if len(totals) != 1:
            raise ValueError(f"chunk_total incohérent pour msg_id={msg_id.hex()}")
        parts_sorted = sorted(parts, key=lambda x: x[0])
        total = next(iter(totals))
        if len(parts_sorted) != total:
            raise ValueError(f"chunks manquants pour msg_id={msg_id.hex()}")

        bundle = rebuild_bytes([c for (_, _, _, c) in parts_sorted])
        nonce, ct = bundle[:12], bundle[12:]
        plaintext = aes.decrypt(nonce, ct, None).decode("utf-8", errors="replace")
        sender_pub = parts_sorted[0][2]

        results.append(DecodedGroupMessage(
            msg_id=msg_id.hex(),
            sender_pub_hex=sender_pub.hex(),
            plaintext=plaintext,
        ))

    return results


# ── Encode / Decode messages de contrôle (INVITE, ADDR_CHANGE) ────────────────

def _encode_control(
    payload: dict,
    sender_pub_hex: str,
    recipient_pub_hex: str,
    msg_type: int,
    *,
    max_chunk_size: int = 162,
) -> List[bytes]:
    """Encode un message de contrôle : X25519 DM → adresse personnelle du destinataire."""
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ct_bundle = encrypt_for_pubkey(payload_bytes, bytes.fromhex(recipient_pub_hex))
    blob_chunks = chunk_bytes(ct_bundle, max_chunk_size=max_chunk_size)
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
            msg_type=msg_type,
        ))
        for idx, part in enumerate(blob_chunks)
    ]


def encode_invite(
    state: GroupState,
    sender_pub_hex: str,
    recipient_pub_hex: str,
) -> List[bytes]:
    """
    Encode une invitation groupe (X25519 DM).
    Envoi : adresse BCH personnelle du destinataire.
    """
    payload = {
        "type": "invite",
        "group_id": state.group_id,
        "name": state.name,
        "channel_address": state.channel_address,
        "group_key": state.group_key.hex(),
        "epoch": state.epoch,
        "members": [m.to_dict() for m in state.members],
    }
    return _encode_control(payload, sender_pub_hex, recipient_pub_hex, MSG_TYPE_GROUP_INVITE)


def encode_addr_change(
    old_state: GroupState,
    new_state: GroupState,
    sender_pub_hex: str,
    recipient_pub_hex: str,
    kicked_pub_hex: str | None = None,
) -> List[bytes]:
    """
    Encode une notification de changement d'adresse groupe (X25519 DM).
    À envoyer à chaque membre restant individuellement.
    L'admin paie N-1 transactions (une par membre restant).
    """
    payload = {
        "type": "addr_change",
        "group_id": old_state.group_id,
        "new_channel_address": new_state.channel_address,
        "new_group_key": new_state.group_key.hex(),
        "epoch": new_state.epoch,
        "kicked_pubkey": kicked_pub_hex,
    }
    return _encode_control(payload, sender_pub_hex, recipient_pub_hex, MSG_TYPE_GROUP_ADDR_CHANGE)


def decode_group_control(
    packets: List[bytes],
    recipient_priv_hex: str,
) -> List[GroupControlMessage]:
    """
    Décode les paquets INVITE ou ADDR_CHANGE reçus sur l'adresse personnelle.
    Les paquets d'autres types sont ignorés.
    """
    recipient_priv = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(recipient_priv_hex)
    )

    grouped: dict = {}
    for raw in packets:
        p = unpack_packet(raw)
        if p.msg_type not in _CONTROL_TYPES:
            continue
        key = (p.msg_id, p.msg_type)
        grouped.setdefault(key, []).append(
            (p.chunk_index, p.chunk_total, p.ciphertext_chunk)
        )

    results: List[GroupControlMessage] = []
    for (msg_id, msg_type), parts in grouped.items():
        parts_sorted = sorted(parts, key=lambda x: x[0])
        bundle = rebuild_bytes([c for (_, _, c) in parts_sorted])
        plaintext_bytes = decrypt_with_privkey(bundle, recipient_priv)
        payload = json.loads(plaintext_bytes.decode("utf-8"))
        results.append(GroupControlMessage(msg_type=msg_type, payload=payload))

    return results
