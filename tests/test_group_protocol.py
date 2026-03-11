"""Tests encode/decode groupe — GROUP_MSG, GROUP_INVITE, GROUP_ADDR_CHANGE."""
import pytest
from core.crypto import gen_keypair
from core.group import (
    create_group, add_member, rotate_group,
    encode_group_msg, decode_group_msg,
    encode_invite, encode_addr_change, decode_group_control,
    apply_invite, apply_addr_change,
    DecodedGroupMessage, GroupControlMessage,
)
from core.packet_v1 import (
    unpack_packet,
    MSG_TYPE_GROUP_MSG, MSG_TYPE_GROUP_INVITE, MSG_TYPE_GROUP_ADDR_CHANGE,
)

FAKE_ADDR  = "bitcoincash:qptest000000000000000000000000000000"
FAKE_ADDR2 = "bitcoincash:qptest111111111111111111111111111111"


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_keypair():
    kp = gen_keypair()
    priv_hex = kp.priv.private_bytes_raw().hex()
    pub_hex = kp.pub.hex()
    return priv_hex, pub_hex


# ── GROUP_MSG encode/decode ────────────────────────────────────────────────────

def test_group_msg_roundtrip():
    admin_priv, admin_pub = make_keypair()
    state = create_group("TestGroup", admin_pub, FAKE_ADDR)

    packets = encode_group_msg("hello group", state, admin_pub)
    assert len(packets) >= 1

    results = decode_group_msg(packets, state)
    assert len(results) == 1
    assert results[0].plaintext == "hello group"
    assert results[0].sender_pub_hex == admin_pub


def test_group_msg_type_field():
    _, admin_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    packets = encode_group_msg("test", state, admin_pub)
    p = unpack_packet(packets[0])
    assert p.msg_type == MSG_TYPE_GROUP_MSG


def test_group_msg_wrong_key():
    _, admin_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    state2 = create_group("G2", admin_pub, FAKE_ADDR2)  # different group_key

    packets = encode_group_msg("secret", state, admin_pub)
    with pytest.raises(Exception):
        decode_group_msg(packets, state2)


def test_group_msg_unicode():
    _, admin_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    text = "Héllo wörld 🔒 日本語"
    packets = encode_group_msg(text, state, admin_pub)
    results = decode_group_msg(packets, state)
    assert results[0].plaintext == text


def test_group_msg_empty_string():
    _, admin_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    packets = encode_group_msg("", state, admin_pub)
    results = decode_group_msg(packets, state)
    assert results[0].plaintext == ""


def test_group_msg_long_message():
    _, admin_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    long_text = "x" * 500
    packets = encode_group_msg(long_text, state, admin_pub, max_chunk_size=80)
    assert len(packets) > 1
    results = decode_group_msg(packets, state)
    assert results[0].plaintext == long_text


def test_group_msg_skips_non_group_packets():
    _, admin_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    packets = encode_group_msg("msg", state, admin_pub)

    # Ajouter un paquet de type inconnu (inject bytes différents)
    from core.packet_v1 import pack_packet, PacketV1, new_msg_id, MSG_TYPE_ENCRYPTED_CHUNK
    noise = pack_packet(PacketV1(
        msg_id=new_msg_id(),
        sender_pub=bytes.fromhex(admin_pub),
        chunk_index=0, chunk_total=1,
        ciphertext_chunk=b"noise",
        msg_type=MSG_TYPE_ENCRYPTED_CHUNK,
    ))
    results = decode_group_msg(packets + [noise], state)
    assert len(results) == 1


def test_group_msg_multiple_messages():
    _, admin_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    p1 = encode_group_msg("msg1", state, admin_pub)
    p2 = encode_group_msg("msg2", state, admin_pub)
    results = decode_group_msg(p1 + p2, state)
    texts = {r.plaintext for r in results}
    assert texts == {"msg1", "msg2"}


# ── GROUP_INVITE encode/decode ────────────────────────────────────────────────

def test_invite_roundtrip():
    admin_priv, admin_pub = make_keypair()
    member_priv, member_pub = make_keypair()

    state = create_group("MyGroup", admin_pub, FAKE_ADDR)
    packets = encode_invite(state, admin_pub, member_pub)
    assert len(packets) >= 1

    results = decode_group_control(packets, member_priv)
    assert len(results) == 1
    ctrl = results[0]
    assert ctrl.msg_type == MSG_TYPE_GROUP_INVITE
    assert ctrl.payload["group_id"] == state.group_id
    assert ctrl.payload["name"] == "MyGroup"
    assert ctrl.payload["channel_address"] == FAKE_ADDR
    assert ctrl.payload["group_key"] == state.group_key.hex()
    assert ctrl.payload["epoch"] == 0


def test_invite_apply():
    _, admin_pub = make_keypair()
    member_priv, member_pub = make_keypair()

    state = create_group("MyGroup", admin_pub, FAKE_ADDR)
    state = add_member(state, member_pub, alias="bob")
    packets = encode_invite(state, admin_pub, member_pub)
    [ctrl] = decode_group_control(packets, member_priv)

    joined = apply_invite(ctrl)
    assert joined.group_id == state.group_id
    assert joined.group_key == state.group_key
    assert joined.channel_address == FAKE_ADDR
    assert joined.is_admin is False


def test_invite_msg_type_field():
    _, admin_pub = make_keypair()
    _, member_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    packets = encode_invite(state, admin_pub, member_pub)
    p = unpack_packet(packets[0])
    assert p.msg_type == MSG_TYPE_GROUP_INVITE


def test_invite_wrong_privkey():
    _, admin_pub = make_keypair()
    _, member_pub = make_keypair()
    wrong_priv, _ = make_keypair()

    state = create_group("G", admin_pub, FAKE_ADDR)
    packets = encode_invite(state, admin_pub, member_pub)
    with pytest.raises(Exception):
        decode_group_control(packets, wrong_priv)


# ── GROUP_ADDR_CHANGE encode/decode ───────────────────────────────────────────

def test_addr_change_roundtrip():
    admin_priv, admin_pub = make_keypair()
    member_priv, member_pub = make_keypair()

    state = create_group("G", admin_pub, FAKE_ADDR)
    state = add_member(state, member_pub)
    new_state = rotate_group(state, FAKE_ADDR2, kicked_pub_hex=None)

    packets = encode_addr_change(state, new_state, admin_pub, member_pub)
    [ctrl] = decode_group_control(packets, member_priv)

    assert ctrl.msg_type == MSG_TYPE_GROUP_ADDR_CHANGE
    assert ctrl.payload["group_id"] == state.group_id
    assert ctrl.payload["new_channel_address"] == FAKE_ADDR2
    assert ctrl.payload["new_group_key"] == new_state.group_key.hex()
    assert ctrl.payload["epoch"] == 1


def test_addr_change_apply():
    admin_priv, admin_pub = make_keypair()
    member_priv, member_pub = make_keypair()
    kicked_priv, kicked_pub = make_keypair()

    state = create_group("G", admin_pub, FAKE_ADDR)
    state = add_member(state, member_pub)
    state = add_member(state, kicked_pub)
    new_state = rotate_group(state, FAKE_ADDR2, kicked_pub_hex=kicked_pub)

    packets = encode_addr_change(state, new_state, admin_pub, member_pub, kicked_pub_hex=kicked_pub)
    [ctrl] = decode_group_control(packets, member_priv)

    updated = apply_addr_change(state, ctrl)
    assert updated.channel_address == FAKE_ADDR2
    assert updated.group_key == new_state.group_key
    assert updated.epoch == 1
    assert all(m.pub_hex != kicked_pub for m in updated.members)


def test_addr_change_msg_type_field():
    _, admin_pub = make_keypair()
    _, member_pub = make_keypair()
    state = create_group("G", admin_pub, FAKE_ADDR)
    new_state = rotate_group(state, FAKE_ADDR2)
    packets = encode_addr_change(state, new_state, admin_pub, member_pub)
    p = unpack_packet(packets[0])
    assert p.msg_type == MSG_TYPE_GROUP_ADDR_CHANGE


def test_decode_control_skips_group_msg():
    _, admin_pub = make_keypair()
    member_priv, member_pub = make_keypair()

    state = create_group("G", admin_pub, FAKE_ADDR)
    group_msg_packets = encode_group_msg("hello", state, admin_pub)
    # Aucun paquet de contrôle → résultat vide
    results = decode_group_control(group_msg_packets, member_priv)
    assert results == []


# ── Full flow : create → invite → chat → kick → addr_change ──────────────────

def test_full_group_flow():
    admin_priv, admin_pub = make_keypair()
    bob_priv, bob_pub = make_keypair()
    carol_priv, carol_pub = make_keypair()

    # 1. Admin crée le groupe
    state_admin = create_group("Team", admin_pub, FAKE_ADDR)

    # 2. Invite bob
    state_admin = add_member(state_admin, bob_pub, alias="bob")
    inv_packets = encode_invite(state_admin, admin_pub, bob_pub)
    [ctrl] = decode_group_control(inv_packets, bob_priv)
    state_bob = apply_invite(ctrl)
    assert state_bob.group_key == state_admin.group_key

    # 3. Bob envoie un message
    msg_packets = encode_group_msg("hello team", state_bob, bob_pub)
    results = decode_group_msg(msg_packets, state_admin)
    assert results[0].plaintext == "hello team"

    # 4. Admin invite carol
    state_admin = add_member(state_admin, carol_pub, alias="carol")
    inv2 = encode_invite(state_admin, admin_pub, carol_pub)
    [ctrl2] = decode_group_control(inv2, carol_priv)
    state_carol = apply_invite(ctrl2)

    # 5. Admin kick bob (rotation)
    state_new = rotate_group(state_admin, FAKE_ADDR2, kicked_pub_hex=bob_pub)

    # 6. Notifier carol (bob ne reçoit rien)
    change_packets = encode_addr_change(state_admin, state_new, admin_pub, carol_pub, kicked_pub_hex=bob_pub)
    [ctrl3] = decode_group_control(change_packets, carol_priv)
    state_carol_updated = apply_addr_change(state_carol, ctrl3)

    assert state_carol_updated.channel_address == FAKE_ADDR2
    assert state_carol_updated.group_key == state_new.group_key
    assert all(m.pub_hex != bob_pub for m in state_carol_updated.members)

    # 7. Message post-kick → bob ne peut pas déchiffrer (mauvaise clé)
    msg2 = encode_group_msg("bob can't read this", state_new, admin_pub)
    with pytest.raises(Exception):
        decode_group_msg(msg2, state_bob)  # state_bob a l'ancienne clé
