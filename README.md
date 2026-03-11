# 0penw0rld

Self-custody BCH wallet with features that never existed before on Bitcoin Cash.

**Live:** [0penw0rld.com](https://0penw0rld.com) — single-file HTML, no backend, no accounts, runs in your browser.

---

## What's in it

### Wallet
Full HD wallet (BIP44 m/44'/145'/0') with seed backup, multiple profiles, Ledger hardware support, UTXO coin control, and address gap-limit scanning.

### 00 Chat
Encrypted peer-to-peer messaging embedded in BCH transactions via OP_RETURN. No servers, no accounts — messages live on-chain forever.

### 00 Fusion
CashFusion-style CoinJoin coordinated over Nostr. No central server. Wallets find each other, negotiate, and co-sign a joint transaction that breaks the tx graph.

### 00 Stealth
ECDH stealth payments — a problem discussed for years on BCH, never implemented until now.

---

## 00 Stealth — How it works

The problem: if someone knows your address, every payment to you is visible on-chain.

The solution: each payment goes to a **one-time address** that only the recipient can detect and spend. On-chain, it looks like a normal P2PKH transaction.

```
Sender (Alice) has: a (input privkey), A = a*G
Bob publishes: S (scan pubkey), B (spend pubkey)

1. ECDH shared secret:  e = a * S  (only Alice and Bob can compute this)
2. Tweak scalar:        c = SHA256( SHA256(e.x) || outpoint )
3. Stealth pubkey:      P = B + c*G
4. Stealth address:     addr = hash160(P) → normal P2PKH CashAddr
5. Alice sends BCH to addr — looks like any other transaction

Bob detects it:
1. Gets notification via Nostr (NIP-04 encrypted DM)
2. Computes same shared secret: e = s * A  (scan privkey × sender pubkey)
3. Derives same tweak: c = SHA256( SHA256(e.x) || outpoint )
4. Verifies: P = B + c*G matches the output
5. Spending key: p = b + c  — only Bob knows this
```

No beacon, no OP_RETURN marker, no on-chain fingerprint. The transaction is indistinguishable from a regular payment.

BIP352 (Silent Payments) requires Taproot (P2TR). BCH doesn't have Taproot — but it doesn't need it. The ECDH math is output-type agnostic. P2PKH works the same way, and BCH actually has a scanning advantage: sender pubkeys are always visible in scriptSig.

Nostr is used as a fast notification channel (ephemeral sender keys for unlinkability). If Nostr is down, chain scanning still works as fallback.

---

## 00 Fusion — How it works

The problem: every BCH transaction links sender to recipient on a public ledger.

The solution: multiple wallets combine their inputs and outputs into a single transaction. An observer can't tell which input paid which output.

```
Before fusion:
  Wallet A: 0.05 BCH → addr_A
  Wallet B: 0.05 BCH → addr_B
  Wallet C: 0.05 BCH → addr_C

After fusion (single tx):
  inputs:  addr_A, addr_B, addr_C
  outputs: addr_A2, addr_B2, addr_C2  (all 0.05 BCH minus fees)

Who paid who? Nobody can tell.
```

Coordination happens over Nostr relays:
1. A wallet creates a fusion pool (Nostr event)
2. Other wallets discover and join
3. Each wallet contributes inputs + provides a fresh output address
4. The transaction is built collaboratively and signed by all parties
5. Broadcast to BCH network — done

No server, no coordinator trust, no registration.

---

## 00 Chat — How it works

Encrypted messages embedded in BCH transactions using OP_RETURN outputs.

```
Alice wants to message Bob:
1. Encrypt message with Bob's public key (ECIES)
2. Sign with Alice's private key
3. Embed ciphertext in OP_RETURN (up to 220 bytes per tx)
4. If message is larger → split into chunks across multiple txs
5. Broadcast as normal BCH transaction

Bob scans the chain:
1. Detects OP_RETURN outputs addressed to his pubkey
2. Decrypts locally
3. Verifies sender signature
```

Messages are permanent, censorship-resistant, and transport-agnostic (works over LoRa, Bluetooth mesh, or any medium that can relay a BCH transaction).

---

## Tech stack

- Pure HTML/JS — no build step, no framework, no dependencies beyond ESM imports
- `@noble/curves` for secp256k1 ECDH, Schnorr, key derivation
- `@noble/hashes` for SHA256, RIPEMD160, HMAC, PBKDF2
- Fulcrum ElectrumX for blockchain queries
- Nostr relays for Fusion coordination and Stealth notifications
- Service Worker for offline PWA support

---

## Run it

Open `wallet.html` in a browser. That's it.

Or visit [0penw0rld.com](https://0penw0rld.com).

---

## License

Open source. MIT.
