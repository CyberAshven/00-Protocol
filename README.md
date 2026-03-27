# 00 Protocol

Decentralized privacy infrastructure built on Bitcoin Cash. Zero central server, zero custody, zero borders.

**Live:** [0penw0rld.com](https://0penw0rld.com) — static HTML/JS, no backend, no accounts, runs in your browser.

---

## Overview

00 Protocol is a suite of cryptographic primitives and applications running entirely in the browser as a Progressive Web App. Every key is generated locally, every operation happens client-side. No analytics, no tracking, no KYC.

| App | Description |
|---|---|
| **00 Wallet** | Multi-chain HD wallet (BCH/BTC/ETH/XMR) |
| **00 Chat** | Split-knowledge encrypted messaging |
| **00 Stealth** | Beaconless ECDH stealth payments |
| **00 Fusion** | CoinJoin privacy mixing |
| **00 Swap** | Atomic cross-chain swaps |
| **00 Onion** | Multi-hop HTLC onion payments |
| **00 Vault** | MuSig2 stealth multisig |
| **00 DEX** | On-chain CashToken swaps |
| **00 Loan** | BCH-collateralized stablecoins |
| **00 Pay** | Payment terminal + QR invoices |
| **00 ID** | Nostr-based sovereign identity |
| **00 Mesh** | Nostr social + relay networking |
| **WizardConnect** | BCH dapp/wallet connection protocol |
| **P2PKH Indexer** | Privacy-preserving pubkey indexer |

---

## 00 Stealth — Full Protocol Specification

The 00 Protocol implements **beaconless stealth addresses** on Bitcoin Cash using ECDH on secp256k1. No OP_RETURN notification required. Every payment creates a unique, unlinkable P2PKH address — indistinguishable from a normal transaction on-chain.

BIP352 (Silent Payments) requires Taproot (P2TR). BCH doesn't have Taproot — it doesn't need it. P2PKH works identically for the ECDH math, and BCH has a scanning advantage: sender pubkeys are always visible in scriptSig inputs.

### Paycode Format

```
stealth:<scan_pubkey_33bytes_hex><spend_pubkey_33bytes_hex>
```

`stealth:` prefix + 66 hex chars (scan) + 66 hex chars (spend) = **140 characters total**

### Key Derivation

**BIP32 path (recommended):**
```
m/352'/145'/0'/scan'/0     ← scan key  (hardened branch)
m/352'/145'/0'/spend'/0    ← spend key (hardened branch)
```
BIP352-style derivation under a fully isolated hardened tree. Compromise of the scan branch does not expose spend capability.

**Raw key method:**
SHA256 with domain separation (ERC-5564-inspired), deriving stealth keys from raw private keys without BIP32. Deterministic but wallet-import-specific — same entropy produces different stealth keys depending on import method.

### ECDH Mechanism

```
Sender (Alice) has: a (UTXO input privkey), A = a*G
Bob publishes paycode: S (scan pubkey), B (spend pubkey)

1. Shared secret:   e = a * S  (= s * A — symmetric ECDH)
2. Tweak scalar:    c = SHA256(SHA256(e.x) || outpoint)
3. Stealth pubkey:  P = B + c*G
4. Stealth address: hash160(P) → standard P2PKH CashAddr

Bob detects it:
1. Gets scan key s, computes: e = s * A
2. Derives same tweak: c = SHA256(SHA256(e.x) || outpoint)
3. Verifies P = B + c*G appears in transaction outputs
4. Spending key: p = b + c  (only Bob knows b)
```

No beacon. No OP_RETURN marker. No on-chain fingerprint.

### Send Flow
1. Parse and validate recipient paycode
2. Select UTXOs (excluding stealth-received funds — separate pool)
3. Derive one-time address using first UTXO private key
4. Build and broadcast standard P2PKH transaction
5. Send encrypted Nostr DM (kind 4) with txid using an ephemeral random key

### Receive Flow
1. Listen for encrypted Nostr DMs (kind 4)
2. Extract sender's P2PKH input pubkeys from transaction
3. Compute ECDH with scan private key for each input pubkey
4. Test whether derived stealth address appears in transaction outputs
5. On match: compute tweaked spend key `p = b + c` → register UTXO for normal spending

### Scanning Methods

| Method | Trigger | Coverage | Speed |
|---|---|---|---|
| Nostr DM | Real-time | Specific transaction | Instant |
| Periodic Auto-Scan | Every 60 seconds | New TXs on known addresses | Fast |
| Manual Chain Scan | User-initiated | Own address history | Medium |
| Advanced Deep Scan | User selects date range | All TXs in block range | Slow |

> Periodic and chain scans are limited to known addresses. Advanced Deep Scan via the [P2PKH Indexer](#p2pkh-pubkey-indexer) is required to detect unsolicited payments.

### Balance Separation
Regular BCH balance excludes stealth-received UTXOs. Stealth UTXOs are tracked separately with their tweaked private keys and spend as normal P2PKH outputs.

### Security Properties

- **On-chain privacy:** Stealth outputs are indistinguishable from standard P2PKH
- **Sender unlinkability:** Nostr notifications use ephemeral random keys
- **Plausible deniability:** Without the scan key, stealth funds are undetectable
- **Key isolation:** Hardened derivation prevents scan key compromise from exposing spend key
- **Nostr fallback:** If Nostr is unavailable, chain scanning still works

### Test Status
All 8 test cases passed (v482, March 2026): cross-wallet sends (12-word ↔ raw key), stealth UTXO spending, balance separation, Advanced Scan verification, and chain scanning fallback.

---

## P2PKH Pubkey Indexer

**[Live →](https://0penw0rld.com/indexer.html)**

Privacy-preserving indexer infrastructure for stealth address scanning on BCH. Enables client-side ECDH scanning without revealing which addresses you control to any server.

### Privacy Model

The server returns **all compressed public keys from P2PKH transaction inputs for a requested block range** — not specific addresses. Equivalent privacy to downloading full blocks, but ~90% less data. Confirmed block responses are immutably cached.

### Why This Matters

Without this indexer, a wallet scanning for stealth payments must either:
- Download full blocks (high bandwidth)
- Query specific addresses (reveals your scanning activity to the server)

With the indexer, the client fetches all pubkeys for a block range and performs ECDH locally. The server never learns what you're looking for.

### API

| Endpoint | Description |
|---|---|
| `GET /api/pubkeys?from=<height>&to=<height>` | P2PKH input pubkeys — max 100 blocks/request |
| `GET /api/health` | Server status |
| `GET /api/stats` | Cache stats and indexed block range |

**JSON response fields:** `height`, `txid`, `vin_index`, `pubkey` (33 bytes compressed hex), `outpoint`

**Binary format:** 106 bytes/entry (~60% smaller than JSON) for bulk scanning

**Typical volume:** 200–400 pubkeys/block · ~50–100 KB/block · ~7–15 MB/day

### Supported Protocols
- Stealth Addresses (00 Protocol) — live
- RPA (Reusable Payment Addresses) — compatible
- Confidential Transactions — compatible

### Self-Hosting

Single Node.js file, one dependency (`ws`).

**Source modes:**
- `Fulcrum` — connects to public WebSocket servers, no local node required
- `BCHN` — local node for full sovereignty

**Output targets:** HTTP/JSON API (port 3847), CLI streaming, direct library import

**Deployment:** standalone process, systemd service, nginx reverse proxy, Docker

---

## WizardConnect

**[Live →](https://0penw0rld.com/wizard.html)**

BCH HD wallet connection protocol — secure bridge between decentralized applications and wallets. Dapps derive addresses and request signatures without ever touching private keys.

### Transport

All messages travel as Nostr **NIP-04 encrypted events (kind 21059)** — AES-256-CBC via ECDH shared secrets. Default relay: `wss://relay.cauldron.quest:443`.

### Connection Flow

1. Dapp generates a `wiz://` URI (bech32 pubkey + session secret + relay + protocol)
2. User scans QR code or pastes URI in wallet
3. Wallet responds with extended public keys (xpubs) for requested paths
4. Dapp derives child addresses locally — no further private key interaction needed for address generation

Session secret in URI prevents man-in-the-middle attacks.

### HD Path Structure

| Purpose | Path | Notes |
|---|---|---|
| Receive | `m/44'/145'/0'/0` | Standard BIP44 |
| Change | `m/44'/145'/0'/1` | Standard BIP44 |
| DeFi | `m/44'/145'/0'/7` | Isolated index |
| Stealth scan | `m/352'/145'/0'/scan'` | Fully isolated hardened tree |
| Stealth spend | `m/352'/145'/0'/spend'` | Fully isolated hardened tree |
| RPA/Paycodes | BIP47 structure | Reusable payment addresses |

**Even if the BIP44 account xpub leaks, stealth keys are unreachable** — complete tree isolation.

### Capabilities

**Address derivation:** Dapps receive xpubs at handshake and derive unlimited child pubkeys locally.

**Transaction signing:** Dapp specifies input paths + indices. Wallet shows confirmation UI. 5-minute timeout on pending requests.

**Stealth sending:** Dapp handles ECDH derivation and one-time address computation, then requests a standard P2PKH signature. Works through any connected wallet.

### Implementation

`wizardconnect.js` — 783 lines, three classes:
- `WizRelay` — transport layer (Nostr WebSocket)
- `WizWalletManager` — server side (wallet)
- `WizDappManager` — client side (dapp)

---

## 00 Fusion — How It Works

CashFusion-style CoinJoin coordinated over Nostr. No central coordinator, no registration.

```
Before fusion:
  Wallet A: 0.05 BCH → addr_A
  Wallet B: 0.05 BCH → addr_B
  Wallet C: 0.05 BCH → addr_C

After fusion (single tx):
  inputs:  addr_A, addr_B, addr_C
  outputs: addr_A2, addr_B2, addr_C2  (equal amounts minus fees)

Who paid who? Unresolvable.
```

Coordination over Nostr:
1. Wallet creates a fusion pool (Nostr event)
2. Other wallets discover and join
3. Each contributes inputs + fresh output address
4. Transaction built collaboratively, signed by all parties
5. Broadcast to BCH network

---

## 00 Chat — CCSH Protocol (v2)

Split-knowledge encrypted messaging — information-theoretically secure when both channels are required.

```
Alice messages Bob:
1. X25519 ECDH → shared secret
2. AES-256-GCM encrypt plaintext
3. XOR-split ciphertext into two shares:
   - Share A → BCH OP_RETURN (on-chain, permanent)
   - Share B → Nostr ephemeral event (off-chain, fast)
4. Neither the blockchain nor the relay can read the message alone

Bob receives:
1. Detect OP_RETURN addressed to his pubkey
2. Fetch matching Nostr event
3. XOR-recombine → decrypt
```

Neither channel alone is sufficient. Permanent on-chain anchoring + fast relay delivery.

---

## 00 Onion

Decentralized Fusion/Silent Joiner relay for encrypted routing and coordination through Nostr 


                        Nostr Relays
                       (public infra)
                      /       |       \
        User A  ----+        |        +----  User B
        User C  ----+        |        +----  User D
                      \       |       /
                       Onion Relay
                      /             \
            Fulcrum WSS          BCHN RPC
           (blockchain)         (blockchain)

---

## 00 Vault — Stealth Multisig

MuSig2 key aggregation — multi-party signing that appears as a standard single-key address on-chain.

- Multiple participants aggregate keys into one on-chain pubkey
- Vault state and coordination synced over Nostr
- Signature requires threshold of participants
- No on-chain multisig fingerprint

---

## 00 Swap — Atomic Cross-Chain

Trustless atomic swaps using HTLC contracts on-chain.

- BCH ↔ BTC: cross-chain HTLC with hashlock/timelock
- BCH ↔ XMR: adaptor signatures for Monero's non-scripted outputs
- P2P OTC orderbook published on Nostr
- No custodian, no escrow, no intermediary

## 00 Multi-Chain Mixer - HTLC Payment

Coming Soon

---

## Security Architecture

| Layer | Mechanism |
|---|---|
| Key generation | `crypto.getRandomValues()` (OS entropy) |
| Key storage | AES-256-GCM, PBKDF2-SHA256 (200k iterations), unique salt+IV per encryption |
| BIP39 | 2,048 PBKDF2-SHA512 iterations → BIP32 master key |
| Session tokens | 30-minute TTL |
| Stealth keys | Hardened BIP32 tree, fully isolated from wallet xpub |
| WizardConnect | NIP-04 AES-256-CBC + session secret anti-MITM |
| Chat | XOR split — information-theoretically secure with two-channel requirement |

No analytics. No third-party tracking. Auditable via browser DevTools.

---

## Tech Stack

- **Pure HTML/CSS/JS** — no framework, no build step, no bundler
- **PWA** — installable, offline-first via Service Worker
- **`@noble/curves`** — secp256k1, X25519, ed25519, Schnorr
- **`@noble/hashes`** — SHA-256, RIPEMD-160, HMAC, PBKDF2, keccak
- **Fulcrum ElectrumX** — blockchain queries over WebSocket
- **Nostr relays** — coordination, notifications, messaging, sync
- **Monero-ts** — XMR wallet scanning + atomic swap support
- **WalletConnect v2** — optional ETH wallet connection
- **WizardConnect** — BCH dapp/wallet bridge over Nostr NIP-04
- **P2PKH Indexer** — privacy-preserving pubkey indexer (Node.js, `ws`)
- **Ledger** — hardware wallet support via WebHID + APDU

All crypto dependencies loaded at runtime via [esm.sh](https://esm.sh) — zero server-side code.

---

## Run

Open [0penw0rld.com](https://0penw0rld.com) in a browser.

Or serve locally:
```bash
npx serve landing
```

---

---

## SDK

The `sdk/` directory contains the **00 Protocol JavaScript SDK** — migrated from the standalone `@00-protocol/sdk` package.

A self-contained, zero-dependency (except `@noble/curves` + `@noble/hashes`) privacy toolkit for Bitcoin Cash.

### Modules

| Module | Import path | Description |
|--------|------------|-------------|
| **Stealth** | `sdk/src/stealth/index.js` | BIP352-style stealth addresses — one-time ECDH address derivation |
| **Joiner** | `sdk/src/joiner/index.js` | Silent CoinJoin coordination (CashFusion-compatible) |
| **Onion** | `sdk/src/onion/index.js` | Multi-hop HTLC onion routing over Nostr |
| **Chat** | `sdk/src/chat/index.js` | NIP-44 encrypted messaging (X25519 + AES-GCM) |
| **WizConnect** | `sdk/src/wizconnect/index.js` | BCH dapp/wallet connection protocol |
| **Common** | `sdk/src/common/index.js` | Shared crypto primitives (secp256k1, hashing, encoding) |

### Usage

```javascript
import { StealthKeys } from './sdk/src/stealth/index.js';
import { joinRound }   from './sdk/src/joiner/index.js';
import { OnionRouter } from './sdk/src/onion/index.js';
import { Chat }        from './sdk/src/chat/index.js';
```

See [`sdk/README.md`](sdk/README.md) for full API documentation.

**Tag:** `00-Protocol-SDK` · **Version:** `1.0.0-beta.1`


## License

MIT
