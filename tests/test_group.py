"""Tests pour core/group.py — état GroupState, CRUD, sérialisation."""
import pytest
from core.group import (
    Member, GroupState,
    create_group, add_member, rotate_group, apply_invite, apply_addr_change,
    GroupControlMessage,
)
from core.packet_v1 import MSG_TYPE_GROUP_INVITE, MSG_TYPE_GROUP_ADDR_CHANGE

FAKE_ADDR   = "bitcoincash:qptest000000000000000000000000000000"
FAKE_ADDR2  = "bitcoincash:qptest111111111111111111111111111111"
ADMIN_PUB   = "a" * 64   # 32 bytes hex
MEMBER1_PUB = "b" * 64
MEMBER2_PUB = "c" * 64


# ── Member ────────────────────────────────────────────────────────────────────

def test_member_to_from_dict():
    m = Member(pub_hex=ADMIN_PUB, alias="alice")
    d = m.to_dict()
    assert d == {"pub_hex": ADMIN_PUB, "alias": "alice"}
    m2 = Member.from_dict(d)
    assert m2.pub_hex == ADMIN_PUB
    assert m2.alias == "alice"


def test_member_alias_optional():
    m = Member.from_dict({"pub_hex": ADMIN_PUB})
    assert m.alias == ""


# ── GroupState sérialisation ──────────────────────────────────────────────────

def test_groupstate_roundtrip():
    g = create_group("TestGroup", ADMIN_PUB, FAKE_ADDR)
    d = g.to_dict()
    g2 = GroupState.from_dict(d)
    assert g2.group_id == g.group_id
    assert g2.name == "TestGroup"
    assert g2.channel_address == FAKE_ADDR
    assert g2.group_key == g.group_key
    assert g2.epoch == 0
    assert len(g2.members) == 1
    assert g2.is_admin is True


def test_groupstate_group_key_32_bytes():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    assert len(g.group_key) == 32


# ── create_group ──────────────────────────────────────────────────────────────

def test_create_group_defaults():
    g = create_group("MyGroup", ADMIN_PUB, FAKE_ADDR)
    assert g.name == "MyGroup"
    assert g.channel_address == FAKE_ADDR
    assert g.epoch == 0
    assert g.is_admin is True
    assert len(g.members) == 1
    assert g.members[0].pub_hex == ADMIN_PUB


def test_create_group_unique_ids():
    g1 = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g2 = create_group("G", ADMIN_PUB, FAKE_ADDR)
    assert g1.group_id != g2.group_id


def test_create_group_unique_keys():
    g1 = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g2 = create_group("G", ADMIN_PUB, FAKE_ADDR)
    assert g1.group_key != g2.group_key


# ── add_member ────────────────────────────────────────────────────────────────

def test_add_member():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g2 = add_member(g, MEMBER1_PUB, alias="bob")
    assert len(g2.members) == 2
    assert g2.members[1].pub_hex == MEMBER1_PUB
    assert g2.members[1].alias == "bob"


def test_add_member_no_duplicate():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g2 = add_member(g, ADMIN_PUB)
    assert len(g2.members) == 1


def test_add_member_immutable():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g2 = add_member(g, MEMBER1_PUB)
    assert len(g.members) == 1  # original inchangé


# ── rotate_group (kick) ───────────────────────────────────────────────────────

def test_rotate_group_changes_key_and_address():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g = add_member(g, MEMBER1_PUB)
    g2 = rotate_group(g, FAKE_ADDR2, kicked_pub_hex=MEMBER1_PUB)
    assert g2.channel_address == FAKE_ADDR2
    assert g2.group_key != g.group_key
    assert g2.epoch == g.epoch + 1


def test_rotate_group_removes_kicked():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g = add_member(g, MEMBER1_PUB)
    g = add_member(g, MEMBER2_PUB)
    g2 = rotate_group(g, FAKE_ADDR2, kicked_pub_hex=MEMBER1_PUB)
    pubs = [m.pub_hex for m in g2.members]
    assert MEMBER1_PUB not in pubs
    assert ADMIN_PUB in pubs
    assert MEMBER2_PUB in pubs


def test_rotate_group_no_kick():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g2 = rotate_group(g, FAKE_ADDR2)
    assert len(g2.members) == len(g.members)
    assert g2.epoch == 1


def test_rotate_group_preserves_group_id():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g2 = rotate_group(g, FAKE_ADDR2)
    assert g2.group_id == g.group_id


# ── apply_invite ──────────────────────────────────────────────────────────────

def test_apply_invite():
    g = create_group("MyGroup", ADMIN_PUB, FAKE_ADDR)
    g = add_member(g, MEMBER1_PUB)
    ctrl = GroupControlMessage(
        msg_type=MSG_TYPE_GROUP_INVITE,
        payload={
            "type": "invite",
            "group_id": g.group_id,
            "name": g.name,
            "channel_address": g.channel_address,
            "group_key": g.group_key.hex(),
            "epoch": g.epoch,
            "members": [m.to_dict() for m in g.members],
        },
    )
    joined = apply_invite(ctrl)
    assert joined.group_id == g.group_id
    assert joined.name == "MyGroup"
    assert joined.group_key == g.group_key
    assert joined.is_admin is False


# ── apply_addr_change ─────────────────────────────────────────────────────────

def test_apply_addr_change():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    g = add_member(g, MEMBER1_PUB)
    g2 = rotate_group(g, FAKE_ADDR2, kicked_pub_hex=MEMBER1_PUB)

    ctrl = GroupControlMessage(
        msg_type=MSG_TYPE_GROUP_ADDR_CHANGE,
        payload={
            "type": "addr_change",
            "group_id": g.group_id,
            "new_channel_address": g2.channel_address,
            "new_group_key": g2.group_key.hex(),
            "epoch": g2.epoch,
            "kicked_pubkey": MEMBER1_PUB,
        },
    )
    updated = apply_addr_change(g, ctrl)
    assert updated.channel_address == FAKE_ADDR2
    assert updated.group_key == g2.group_key
    assert updated.epoch == 1
    assert all(m.pub_hex != MEMBER1_PUB for m in updated.members)


def test_apply_addr_change_wrong_group_id():
    g = create_group("G", ADMIN_PUB, FAKE_ADDR)
    ctrl = GroupControlMessage(
        msg_type=MSG_TYPE_GROUP_ADDR_CHANGE,
        payload={
            "type": "addr_change",
            "group_id": "wrongid",
            "new_channel_address": FAKE_ADDR2,
            "new_group_key": "aa" * 32,
            "epoch": 1,
            "kicked_pubkey": None,
        },
    )
    with pytest.raises(ValueError, match="group_id mismatch"):
        apply_addr_change(g, ctrl)
