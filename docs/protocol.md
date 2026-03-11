# CCSH v1 — chat.cash Secure Header

## Objectif
CCSH v1 définit un format binaire compact pour transporter des messages chiffrés,
découpés en chunks, via n’importe quel transport (fichiers, OP_RETURN BCH, etc.).

Le pipeline est :
plaintext (UTF-8) → encrypt (X25519 + AES-GCM) → chunk → packets CCSH v1 → transport

## Format de paquet
Chaque paquet est un blob binaire sérialisé par `core/packet_v1.py`.

Champs (ordre exact) :

- MAGIC (4 bytes): ASCII `CCSH`
- VERSION (1 byte): `0x01`
- MSG_TYPE (1 byte): `0x01` (MSG)
- FLAGS (1 byte): `0x00` (réservé)
- RESERVED (1 byte): `0x00` (réservé)
- MSG_ID (16 bytes): identifiant unique (UUID bytes)
- SENDER_PUB (32 bytes): clé publique X25519 raw du sender
- CHUNK_INDEX (2 bytes, big-endian): index du chunk (0..N-1)
- CHUNK_TOTAL (2 bytes, big-endian): nombre total de chunks (N)
- CIPHER_LEN (2 bytes, big-endian): longueur du chunk ciphertext qui suit
- CIPHERTEXT_CHUNK (CIPHER_LEN bytes): fragment du ciphertext “bundle”

## Règles de chunking
- Le message chiffré est un **bundle binaire** (voir section Crypto).
- Ce bundle est découpé en chunks de taille `max_chunk_size` (par défaut 162).
- Chaque chunk est encapsulé dans un paquet CCSH v1 avec les mêmes :
  - MSG_ID
  - SENDER_PUB
  - CHUNK_TOTAL
- Chaque chunk a un CHUNK_INDEX unique.

## Reassembly (côté réception)
- Les paquets sont regroupés par MSG_ID.
- Pour un MSG_ID, on attend exactement CHUNK_TOTAL chunks.
- On reconstitue le bundle en triant par CHUNK_INDEX croissant.
- Si un chunk manque → message incomplet (on attend encore).

## Crypto
Algorithmes :
- Key exchange: X25519
- Symmetric: AES-GCM

Bundle chiffré (format attendu par `core/crypto.py`) :
- EPHEMERAL_PUB (32 bytes): pubkey X25519 éphémère du sender
- NONCE (12 bytes): nonce AES-GCM
- CIPHERTEXT (variable): AES-GCM(ciphertext + tag)

Dérivation de la clé :
- shared = recipient_priv.exchange(eph_pub)
- sym_key = KDF(shared) (implémentation conforme à `core/crypto.py`)

Déchiffrement :
- Parse bundle → eph_pub, nonce, ciphertext
- Recompute shared → sym_key
- AES-GCM decrypt → plaintext UTF-8

## Transport
CCSH v1 ne dépend d’aucun transport.

Un transport doit :
- envoyer une liste de packets (bytes)
- fournir au receiver une liste de packets (bytes) + meta optionnelle

Exemples :
- FileTransport: écrit un JSON avec `packets_hex`
- BchTransport (futur): embed chaque paquet dans OP_RETURN (1 packet/output)

## Limites & recommandations
- `max_chunk_size` doit être choisi pour respecter les limites du transport.
  Exemple OP_RETURN BCH : contraintes de taille/policy → chunk size typiquement ~160-180.
- FLAGS / MSG_TYPE sont réservés pour extensions (attachments, ack, etc.).