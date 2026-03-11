# cli/build_raw_tx.py
from __future__ import annotations

import struct
import pathlib
from typing import List

from core.opreturn import parse_op_return
from core.packet_v1 import unpack_packet

def varint(n: int) -> bytes:
    """
    Encode un entier `n` au format Bitcoin / Bitcoin Cash appelé "varint"
    (variable integer = entier à taille variable).

    À quoi ça sert ?
    - Dans une transaction BCH, certains champs n'ont PAS une taille fixe :
      * nombre d'inputs
      * nombre d'outputs
      * taille d'un script
    - Le format varint permet de stocker ces nombres de manière compacte :
      * petit nombre → peu d'octets
      * grand nombre → plus d'octets

    Règles du format varint :
    - Si n < 253 (0xFD) :
        → stocké sur 1 octet
    - Si 253 ≤ n ≤ 65 535 (0xFFFF) :
        → 0xFD + n sur 2 octets (little-endian)
    - Si 65 536 ≤ n ≤ 4 294 967 295 (0xFFFFFFFF) :
        → 0xFE + n sur 4 octets (little-endian)
    - Si n est plus grand :
        → 0xFF + n sur 8 octets (little-endian)

    Important :
    - "little-endian" signifie que l'octet de poids faible est écrit en premier.
    - Les préfixes 0xFD, 0xFE et 0xFF indiquent combien d'octets sont utilisés ensuite.
    """

    # Cas 1 : nombre très petit → 1 seul octet suffit
    if n < 0xfd:
        return bytes([n])

    # Cas 2 : nombre moyen → préfixe 0xFD + entier sur 2 octets
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)

    # Cas 3 : nombre plus grand → préfixe 0xFE + entier sur 4 octets
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)

    # Cas 4 : très grand nombre → préfixe 0xFF + entier sur 8 octets
    else:
        return b"\xff" + struct.pack("<Q", n)


def le_hex(h: str) -> bytes:
    """
    Convertit une chaîne hexadécimale représentant un hash (txid, block hash, etc.)
    en bytes, puis INVERSE l’ordre des octets (little-endian).

    Pourquoi cette fonction existe ?
    - Les hash (txid, block hash) sont affichés "à l’endroit" par les humains
      (big-endian, lecture normale).
    - MAIS dans une transaction Bitcoin / BCH, ces mêmes hash sont stockés
      à l’envers (little-endian).
    - Il faut donc inverser les octets AVANT de les mettre dans le raw tx.

    Exemple simple :
    h = "a1b2c3d4"
    bytes.fromhex(h)  -> b'\\xa1\\xb2\\xc3\\xd4'
    [::-1]            -> b'\\xd4\\xc3\\xb2\\xa1'

    Sans cette inversion :
    - la transaction serait invalide
    - le txid référencé ne correspondrait à rien
    """

    # 1) Convertit la chaîne hexadécimale en bytes
    raw = bytes.fromhex(h)

    # 2) Inverse l’ordre des octets (big-endian → little-endian)
    return raw[::-1]


def build_raw_tx(
    utxo_txid: str,                 # txid du UTXO qu’on dépense (hex "humain")
    utxo_vout: int,                 # index de l’output dans cette txid (0,1,2...)
    utxo_script_pubkey_hex: str,    # (ici non utilisé car tx unsigned)
    op_return_scripts: List[bytes], # scripts OP_RETURN (déjà construits)
    change_script_pubkey_hex: str,  # scriptPubKey de l’adresse de change (hex)
    change_amount: int,             # montant du change en satoshis
) -> bytes:
    """
    Construit une transaction BCH brute (raw tx) NON SIGNÉE.

    Important :
    - Une tx NON SIGNÉE a un scriptSig vide dans chaque input.
    - Elle n’est pas diffusable telle quelle (il manque les signatures),
      mais elle est utile pour tester la sérialisation + outputs OP_RETURN.
    """
    tx = bytearray()

    # -----------------------------
    # 1) Version (4 bytes little-endian)
    # -----------------------------
    # "<I" = unsigned int 32-bit, little-endian
    # Version = 2 est courant (mais 1 fonctionne aussi)
    tx += struct.pack("<I", 2)

    # -----------------------------
    # 2) Inputs
    # -----------------------------

    # Nombre d’inputs (varint)
    # Ici on ne gère qu’UN seul input pour simplifier.
    tx += varint(1)

    # Input #0 : référence de l'UTXO qu’on dépense
    # - txid doit être en little-endian dans le raw tx => le_hex()
    tx += le_hex(utxo_txid)

    # - vout = index de l'output (4 bytes little-endian)
    tx += struct.pack("<I", utxo_vout)

    # scriptSig (unlock script) :
    # - Dans une tx signée, ici il y aura signature + pubkey (P2PKH)
    # - Là on construit une tx NON SIGNÉE => scriptSig vide
    tx += varint(0)  # longueur du scriptSig = 0
    # tx += b""      # pas besoin, longueur=0 signifie "rien"

    # sequence (4 bytes)
    # 0xffffffff = valeur standard ("final"), laisse le locktime classique
    tx += struct.pack("<I", 0xffffffff)

    # -----------------------------
    # 3) Outputs
    # -----------------------------

    # Nombre d’outputs = (nombre d'OP_RETURN) + 1 output de change
    tx += varint(len(op_return_scripts) + 1)

    # 3.a) Outputs OP_RETURN
    for script in op_return_scripts:
        # Montant de l’output (8 bytes little-endian)
        # OP_RETURN est généralement à 0 sat
        tx += struct.pack("<Q", 0)

        # Longueur du scriptPubKey
        tx += varint(len(script))

        # scriptPubKey (le script OP_RETURN complet : 6a + pushdata + payload)
        tx += script

    # 3.b) Output de change
    # Montant du change (8 bytes little-endian)
    tx += struct.pack("<Q", change_amount)

    # scriptPubKey du change
    change_spk = bytes.fromhex(change_script_pubkey_hex)

    # longueur + script
    tx += varint(len(change_spk))
    tx += change_spk

    # -----------------------------
    # 4) Locktime (4 bytes little-endian)
    # -----------------------------
    # 0 = pas de locktime (valide immédiatement)
    tx += struct.pack("<I", 0)

    return bytes(tx)


def main() -> None:
    # Read OP_RETURN scripts from file
    path_str = input("Path to opreturns_*.txt: ").strip()
    path = pathlib.Path(path_str)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    scripts_hex = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    scripts = [bytes.fromhex(h) for h in scripts_hex]

    # Sanity: must be OP_RETURN scripts and same msg_id
    msg_ids = set()
    for i, s in enumerate(scripts):
        if len(s) < 1 or s[0] != 0x6A:
            raise SystemExit(f"[line {i+1}] Not an OP_RETURN script (missing 0x6a)")
        payload = parse_op_return(s)
        pkt = unpack_packet(payload)
        msg_ids.add(pkt.msg_id)

    if len(msg_ids) != 1:
        raise SystemExit(f"Mixed msg_id in file! Found {len(msg_ids)} distinct msg_id values.")

    msg_id = next(iter(msg_ids)).hex()
    print(f"OK: {len(scripts)} OP_RETURN scripts for msg_id={msg_id}")

    # Fake UTXO (offline build)
    utxo_txid = "00" * 32
    utxo_vout = 0
    utxo_amount = 200_000  # sat

    # Change scriptPubKey (fake P2PKH)
    change_script_pubkey = "76a914" + "22" * 20 + "88ac"

    # Fee model: fixed (offline)
    fee = 1500
    change_amount = utxo_amount - fee
    if change_amount <= 0:
        raise SystemExit("UTXO amount too small for fee")

    raw_tx = build_raw_tx(
        utxo_txid=utxo_txid,
        utxo_vout=utxo_vout,
        utxo_script_pubkey_hex="",  # unused in unsigned tx (scriptSig empty)
        op_return_scripts=scripts,
        change_script_pubkey_hex=change_script_pubkey,
        change_amount=change_amount,
    )

    print("\nRaw TX (hex):")
    print(raw_tx.hex())


if __name__ == "__main__":
    main()