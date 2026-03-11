# cli/ui.py
"""Temporary UI (v0) to exercise the core protocol.

Goal:
  - Run TWO instances (Alice/Bob) on the same machine.
  - Manage contacts (name + BCH address + chat pubkey).
  - Send encrypted messages as CCSH v1 packets.
  - Receive packets from a transport, decrypt, display.

This UI does NOT talk to the BCH network yet.
Instead it uses a file-based transport (transport.file_transport.FileTransport).

Later, the exact same "pack->OP_RETURN" outputs will be embedded into a real
unsigned/signed BCH transaction (BchTransport).
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from transport.file_transport import FileTransport
from transport.bch_transport import BchTransport
from transport.bitcash_client import BitcashClient
from transport.bch_inbox_scanner import BchInboxScanner

from core.crypto import gen_keypair
from core.packet_v1 import unpack_packet
from core.protocol import encode_message, decode_packets
from core.history import HistoryStore
from core.contact_card import encode_contact_card, decode_contact_card, make_qr_image

from typing import Set

# ------------------------------
# Storage / profile
# ------------------------------


def _priv_to_hex(priv: x25519.X25519PrivateKey) -> str:
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw.hex()


def _priv_from_hex(h: str) -> x25519.X25519PrivateKey:
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise ValueError("X25519 private key must be 32 bytes")
    return x25519.X25519PrivateKey.from_private_bytes(b)


def _pub_to_hex(pub: bytes) -> str:
    if len(pub) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    return bytes(pub).hex()


@dataclass
class Contact:
    name: str
    bch_address: str
    chat_pub_hex: str  # X25519 pubkey (hex)
    inbox_id: str      # used only for the file-transport simulation

    def chat_pub_bytes(self) -> bytes:
        b = bytes.fromhex(self.chat_pub_hex)
        if len(b) != 32:
            raise ValueError("chat_pub must be 32 bytes (X25519)")
        return b


@dataclass
class Profile:
    username: str
    priv_hex: str
    pub_hex: str
    bch_address: str
    contacts: Dict[str, Contact]
    bch_priv_hex: Optional[str] = None  # secp256k1, BIP44 or random

    @property
    def priv(self) -> x25519.X25519PrivateKey:
        return _priv_from_hex(self.priv_hex)

    @property
    def pub(self) -> bytes:
        return bytes.fromhex(self.pub_hex)


def load_or_create_profile(path: Path, username: str) -> Profile:
    """Load a profile JSON, or create it if missing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        contacts: Dict[str, Contact] = {}
        for c in data.get("contacts", []):
            contacts[c["name"]] = Contact(
                name=c["name"],
                bch_address=c.get("bch_address", ""),
                chat_pub_hex=c.get("chat_pub_hex", ""),
                inbox_id=c.get("inbox_id", c["name"].lower()),
            )
        return Profile(
            username=data.get("username", username),
            priv_hex=data["priv_hex"],
            pub_hex=data["pub_hex"],
            bch_address=data.get("bch_address", ""),
            contacts=contacts,
            bch_priv_hex=data.get("bch_priv_hex"),
        )

    # Create new identity
    from core.wallet import gen_bch_priv_hex
    kp = gen_keypair()
    prof = Profile(
        username=username,
        priv_hex=_priv_to_hex(kp.priv),
        pub_hex=_pub_to_hex(kp.pub),
        bch_address="",
        contacts={},
        bch_priv_hex=gen_bch_priv_hex(),
    )
    save_profile(path, prof)
    return prof


def save_profile(path: Path, prof: Profile) -> None:
    data = {
        "username": prof.username,
        "priv_hex": prof.priv_hex,
        "pub_hex": prof.pub_hex,
        "bch_address": prof.bch_address,
        "bch_priv_hex": prof.bch_priv_hex,
        "contacts": [
            {
                "name": c.name,
                "bch_address": c.bch_address,
                "chat_pub_hex": c.chat_pub_hex,
                "inbox_id": c.inbox_id,
            }
            for c in prof.contacts.values()
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# ------------------------------
# UI
# ------------------------------
def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def load_seen(path: Path) -> Set[str]:
    """
    Persisted de-dup store.
    Each entry is a string key like: "<txid>:<msg_id>"
    """
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data.get("seen", [])
        return set(str(x) for x in items)
    except Exception:
        return set()


def save_seen(path: Path, seen: Set[str]) -> None:
    _safe_mkdir(path.parent)
    payload = {"seen": sorted(seen)}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

class ChatUI(tk.Tk):
    def __init__(
        self,
        *,
        profile_path: Path,
        username: str,
        net_dir: Path,
        poll_ms: int = 750,
    ):
        super().__init__()
        self.title(f"chat.cash v0 — {username}")
        self.geometry("980x600")

        self.profile_path = profile_path
        self.profile = load_or_create_profile(profile_path, username)

        # Transport
        self.net_dir = net_dir
        self.transport = FileTransport(net_dir=self.net_dir, inbox_id=self.profile.username)

        self.poll_ms = poll_ms

        # Conversation memory (display lines, populated lazily from history)
        self._conv: Dict[str, List[str]] = {}
        self._history_loaded: Set[str] = set()

        # Encrypted history store
        self.history = HistoryStore(
            history_dir=self.net_dir / "history",
            priv_hex=self.profile.priv_hex,
        )

        # UI shutdown guard
        self._closed = False

        # De-dup for on-chain messages (persisted)
        self.seen_path = self.net_dir / "state" / f"{self.profile.username}_seen_messages.json"
        self._seen: Set[str] = load_seen(self.seen_path)

        self._build_widgets()
        self._refresh_contacts_list()
        self._render_identity()

        # --- BCH inbox scanner (Blockchair REST, no Electron Cash needed) ---
        if not self.profile.bch_address:
            self.status_var.set("No BCH address in profile; scan disabled.")
        else:
            state_path = self.net_dir / "state" / f"{self.profile.username}_scan.json"
            self.bch_scanner = BchInboxScanner(
                ec=BitcashClient(),
                address=self.profile.bch_address,
                recipient_priv_hex=self.profile.priv_hex,
                state_path=state_path,
                poll_s=30.0,   # Blockchair rate limit: ~30 req/min
                on_message=self._on_decoded_message_thread,
            )
            self.bch_scanner.start()

        # Clean shutdown
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- lifecycle ----------

    def _on_close(self) -> None:
        # prevent any future UI updates from background threads
        self._closed = True
        try:
            if getattr(self, "bch_scanner", None) is not None:
                try:
                    self.bch_scanner.stop()
                except Exception:
                    pass

            if getattr(self, "transport", None) is not None:
                try:
                    self.transport.stop()
                except Exception:
                    pass
        finally:
            try:
                self.destroy()
            except Exception:
                pass

    # ---------- transport callbacks ----------

    def _on_packets_thread(self, packets: List[bytes], meta: dict) -> None:
        # Transport thread -> Tk main thread
        self.after(0, lambda: self._handle_packets(packets, meta))

    def _handle_packets(self, packets: List[bytes], meta: dict) -> None:
        try:
            decoded = decode_packets(packets, recipient_priv_hex=self.profile.priv_hex)
            for msg in decoded:
                sender_name = self._resolve_sender(bytes.fromhex(msg.sender_pub_hex))
                line = f"{sender_name}: {msg.plaintext}"
                self._append_to_conversation(sender_name, line)

            frm = meta.get("from", "unknown")
            self.status_var.set(f"received {len(packets)} packets from {frm}")
        except Exception as e:
            self.status_var.set(f"inbox decode error: {e}")

    def _on_decoded_message_thread(self, msg, meta: dict) -> None:
        # scanner thread -> Tk main thread
        if self._closed:
            return
        self.after(0, lambda: self._handle_decoded_message(msg, meta))

    def _handle_decoded_message(self, msg, meta: dict) -> None:
        if self._closed:
            return

        txid = (meta.get("txid") or "").strip()
        msg_id = (getattr(msg, "msg_id", "") or "").strip()

        # Build a stable de-dup key
        key = f"{txid}:{msg_id}" if txid else f"no-txid:{msg_id}"

        if key in self._seen:
            # already shown
            return

        # mark seen + persist
        self._seen.add(key)
        save_seen(self.seen_path, self._seen)

        # resolve sender
        try:
            sender_pub_hex = msg.sender_pub_hex
            sender_name = self._resolve_sender(bytes.fromhex(sender_pub_hex))
        except Exception:
            sender_name = "unknown[bad-sender]"

        line = f"{sender_name}: {msg.plaintext}"
        self._append_to_conversation(sender_name, line)
        try:
            self.history.append(sender_name, "in", msg.plaintext)
        except Exception:
            pass

        short_tx = (txid[:10] + "…") if txid else "no-txid"
        self.status_var.set(f"on-chain recv tx={short_tx} msg_id={msg_id[:8]}…")

    # ---------- layout ----------

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Left: contacts
        left = ttk.Frame(self, padding=10)
        left.grid(row=0, column=0, sticky="ns")

        ttk.Label(left, text="Contacts", font=("Helvetica", 14, "bold")).grid(row=0, column=0, sticky="w")

        self.contacts_list = tk.Listbox(left, height=20, width=28)
        self.contacts_list.grid(row=1, column=0, sticky="ns")
        self.contacts_list.bind("<<ListboxSelect>>", lambda _e: self._on_select_contact())

        btns = ttk.Frame(left)
        btns.grid(row=2, column=0, pady=(8, 0), sticky="ew")
        ttk.Button(btns, text="Add", command=self._ui_add_contact).grid(row=0, column=0, sticky="ew")
        ttk.Button(btns, text="Delete", command=self._ui_delete_contact).grid(row=0, column=1, padx=(6, 0), sticky="ew")
        ttk.Button(btns, text="Copy my pubkey", command=self._copy_my_pub).grid(row=0, column=2, padx=(6, 0), sticky="ew")

        # Identity / settings
        ident = ttk.Labelframe(left, text="My identity (chat)")
        ident.grid(row=3, column=0, pady=(12, 0), sticky="ew")
        self.my_pub_var = tk.StringVar(value="")
        ttk.Entry(ident, textvariable=self.my_pub_var, width=38).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(ident, text="Rotate identity", command=self._rotate_identity).grid(row=1, column=0, padx=6, pady=(0, 6), sticky="ew")

        ttk.Button(ident, text="Share my contact", command=self._show_contact_card).grid(row=2, column=0, padx=6, pady=(0, 6), sticky="ew")

        ident2 = ttk.Labelframe(left, text="My BCH address")
        ident2.grid(row=4, column=0, pady=(12, 0), sticky="ew")
        self.my_bch_var = tk.StringVar(value=self.profile.bch_address)
        ttk.Entry(ident2, textvariable=self.my_bch_var, width=38).grid(row=0, column=0, padx=6, pady=6)

        # Right: chat
        right = ttk.Frame(self, padding=10)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self.chat_title = ttk.Label(right, text="Select a contact", font=("Helvetica", 14, "bold"))
        self.chat_title.grid(row=0, column=0, sticky="w")

        self.chat_box = tk.Text(right, wrap="word", state="disabled")
        self.chat_box.grid(row=1, column=0, sticky="nsew", pady=(8, 8))

        composer = ttk.Frame(right)
        composer.grid(row=2, column=0, sticky="ew")
        composer.columnconfigure(0, weight=1)

        self.msg_entry = ttk.Entry(composer)
        self.msg_entry.grid(row=0, column=0, sticky="ew")
        self.msg_entry.bind("<Return>", lambda _e: self._send_message())
        ttk.Button(composer, text="Send", command=self._send_message).grid(row=0, column=1, padx=(8, 0))

        # small status line
        self.status_var = tk.StringVar(value="ready")
        ttk.Label(right, textvariable=self.status_var).grid(row=3, column=0, sticky="w", pady=(6, 0))

    # ---------- contacts ----------

    def _refresh_contacts_list(self) -> None:
        self.contacts_list.delete(0, tk.END)
        for name in sorted(self.profile.contacts.keys()):
            self.contacts_list.insert(tk.END, name)

    def _selected_contact_name(self) -> Optional[str]:
        sel = self.contacts_list.curselection()
        if not sel:
            return None
        return self.contacts_list.get(sel[0])

    def _on_select_contact(self) -> None:
        name = self._selected_contact_name()
        if not name:
            return
        self.chat_title.config(text=f"Chat with {name}")
        self._ensure_history_loaded(name)
        self._render_conversation(name)

    def _ensure_history_loaded(self, contact: str) -> None:
        if contact in self._history_loaded:
            return
        self._history_loaded.add(contact)
        entries = self.history.load(contact)
        if entries:
            self._conv[contact] = [e.display_line() for e in entries]

    def _ui_add_contact(self) -> None:
        win = tk.Toplevel(self)
        win.title("Add contact")
        win.geometry("540x330")

        # --- Contact card paste ---
        ttk.Label(win, text="Contact card URL (chatcash:…)").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        card_e = ttk.Entry(win, width=60)
        card_e.grid(row=0, column=1, sticky="ew", padx=10, pady=(10, 0))

        def row(lbl: str, r: int) -> ttk.Entry:
            ttk.Label(win, text=lbl).grid(row=r, column=0, sticky="w", padx=10, pady=(6, 0))
            e = ttk.Entry(win, width=60)
            e.grid(row=r, column=1, sticky="ew", padx=10, pady=(6, 0))
            return e

        name_e = row("Name", 1)
        bch_e  = row("BCH address", 2)
        pub_e  = row("Chat pubkey hex (X25519, 32 bytes)", 3)
        inbox_e = row("Inbox id (local test only)", 4)

        def on_parse_card() -> None:
            url = card_e.get().strip()
            if not url:
                return
            try:
                parsed = decode_contact_card(url)
            except ValueError as exc:
                messagebox.showerror("Invalid contact card", str(exc), parent=win)
                return
            name_e.delete(0, tk.END); name_e.insert(0, parsed["name"])
            bch_e.delete(0, tk.END);  bch_e.insert(0, parsed["bch_address"])
            pub_e.delete(0, tk.END);  pub_e.insert(0, parsed["pub_hex"])

        card_e.bind("<Return>", lambda _e: on_parse_card())
        card_e.bind("<FocusOut>", lambda _e: on_parse_card())
        ttk.Button(win, text="Parse", command=on_parse_card).grid(row=0, column=2, padx=(0, 10), pady=(10, 0))

        def on_ok() -> None:
            name = name_e.get().strip()
            bch = bch_e.get().strip()
            if not bch:
                messagebox.showerror("Error", "BCH address is required")
                return
            pub = pub_e.get().strip().lower()
            inbox_id = inbox_e.get().strip() or name.lower()
            if not name:
                messagebox.showerror("Error", "Name is required")
                return
            try:
                pb = bytes.fromhex(pub)
                if len(pb) != 32:
                    raise ValueError
            except Exception:
                messagebox.showerror("Error", "Chat pubkey must be 32 bytes hex")
                return

            self.profile.contacts[name] = Contact(
                name=name,
                bch_address=bch,
                chat_pub_hex=pub,
                inbox_id=inbox_id,
            )
            save_profile(self.profile_path, self.profile)
            self._refresh_contacts_list()
            win.destroy()

        ttk.Button(win, text="Save", command=on_ok).grid(row=6, column=1, sticky="e", padx=10, pady=16)

    def _ui_delete_contact(self) -> None:
        name = self._selected_contact_name()
        if not name:
            return
        if not messagebox.askyesno("Delete", f"Delete contact '{name}'?"):
            return
        self.profile.contacts.pop(name, None)
        save_profile(self.profile_path, self.profile)
        self._refresh_contacts_list()
        self.chat_title.config(text="Select a contact")
        self._set_chat_text("")

    # ---------- identity ----------

    def _render_identity(self) -> None:
        self.my_pub_var.set(self.profile.pub_hex)

    def _copy_my_pub(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.profile.pub_hex)
        self.status_var.set("copied my chat pubkey to clipboard")

    def _show_contact_card(self) -> None:
        """Show a dialog with the user's contact card URL and optional QR code."""
        if not self.profile.bch_address:
            messagebox.showwarning("No BCH address", "Set a BCH address in your profile first.")
            return

        url = encode_contact_card(
            bch_address=self.profile.bch_address,
            pub_hex=self.profile.pub_hex,
            name=self.profile.username,
        )

        win = tk.Toplevel(self)
        win.title("My contact card")
        win.geometry("560x380")

        ttk.Label(win, text="Share this URL or QR code with your contacts:", wraplength=520).pack(padx=12, pady=(12, 4))

        url_box = tk.Text(win, height=4, wrap="word")
        url_box.insert("1.0", url)
        url_box.configure(state="disabled")
        url_box.pack(fill="x", padx=12, pady=(0, 8))

        def copy_url() -> None:
            self.clipboard_clear()
            self.clipboard_append(url)
            self.status_var.set("contact card URL copied")

        ttk.Button(win, text="Copy URL", command=copy_url).pack(pady=(0, 8))

        # QR code (requires qrcode + PIL)
        qr_img = make_qr_image(url)
        if qr_img is not None:
            try:
                from PIL import ImageTk
                qr_img = qr_img.resize((220, 220))
                photo = ImageTk.PhotoImage(qr_img)
                lbl = tk.Label(win, image=photo)
                lbl.image = photo  # keep reference
                lbl.pack(pady=4)
            except ImportError:
                ttk.Label(win, text="(install Pillow to display QR image)").pack()
        else:
            ttk.Label(win, text="(install qrcode to display QR code)").pack()

    def _rotate_identity(self) -> None:
        if not messagebox.askyesno(
            "Rotate identity",
            "This will generate a NEW chat keypair for this profile.\n"
            "Old contacts will still exist but they won't be able to message you\n"
            "unless you share your new pubkey. Continue?",
        ):
            return
        kp = gen_keypair()
        self.profile.priv_hex = _priv_to_hex(kp.priv)
        self.profile.pub_hex = _pub_to_hex(kp.pub)
        save_profile(self.profile_path, self.profile)
        self._render_identity()
        self.my_bch_var.set(self.profile.bch_address)
        self.status_var.set("rotated chat identity")

    # ---------- sending ----------

    def _send_message(self) -> None:
        name = self._selected_contact_name()
        if not name:
            messagebox.showwarning("No contact", "Select a contact first")
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return

        c = self.profile.contacts[name]
        try:
            packed_packets = encode_message(
                plaintext=msg,
                sender_priv_hex=self.profile.priv_hex,
                sender_pub_hex=self.profile.pub_hex,
                recipient_pub_hex=c.chat_pub_hex,
                max_chunk_size=158,
            )
        except Exception as e:
            messagebox.showerror("Send failed", str(e))
            return

        first = unpack_packet(packed_packets[0])
        msg_id_hex = first.msg_id.hex()

        if not c.bch_address:
            messagebox.showerror("Send failed", f"Contact '{c.name}' has no BCH address")
            return

        # --- Mode A: on-chain send via bitcash (if BCH key is available) ---
        if self.profile.bch_priv_hex:
            try:
                from bitcash import Key
                bch_key = Key.from_hex(self.profile.bch_priv_hex)
                txids = []
                for pkt_bytes in packed_packets:
                    txid = bch_key.send(
                        [(c.bch_address, 546, "satoshi")],
                        message=pkt_bytes,
                    )
                    txids.append(txid)
                self._append_to_conversation(name, f"me: {msg}")
                self.history.append(name, "out", msg)
                self.msg_entry.delete(0, tk.END)
                short = txids[0][:12] + "…"
                n_tx = len(txids)
                self.status_var.set(f"Sent {n_tx} tx(s) on-chain — {short}")
            except Exception as e:
                messagebox.showerror("Send failed", str(e))
            return

        # --- Mode B fallback: draft files for Electron Cash copy-paste ---
        try:
            payto_lines = BchTransport.build_payto_lines_for_message(
                packed_packets,
                recipient_bch_address=c.bch_address,
                dust_sats=546,
            )
            opreturn_script_hex = BchTransport.build_opreturn_script_hex_for_message(packed_packets)
        except Exception as e:
            messagebox.showerror("Send failed", str(e))
            return

        out_dir = self.net_dir / "tx_outbox" / c.inbox_id
        out_dir.mkdir(parents=True, exist_ok=True)

        payto_path = out_dir / f"payto_{msg_id_hex}.txt"
        payto_path.write_text("\n".join(payto_lines) + "\n", encoding="utf-8")

        opreturn_path = out_dir / f"opreturn_{msg_id_hex}.txt"
        opreturn_path.write_text(opreturn_script_hex + "\n", encoding="utf-8")

        self._append_to_conversation(name, f"me: {msg}")
        self.history.append(name, "out", msg)
        self.msg_entry.delete(0, tk.END)
        self.status_var.set(
            f"Drafts written: payto={payto_path} | opreturn={opreturn_path}"
        )

    # ---------- helpers ----------

    def _resolve_sender(self, sender_pub: bytes) -> str:
        pub_hex = sender_pub.hex()
        for c in self.profile.contacts.values():
            if c.chat_pub_hex.lower() == pub_hex:
                return c.name
        return f"unknown[{pub_hex[:10]}]"

    # ---------- conversation rendering ----------

    def _append_to_conversation(self, contact_name: str, line: str) -> None:
        self._conv.setdefault(contact_name, []).append(line)
        sel = self._selected_contact_name()
        if sel == contact_name:
            self._render_conversation(contact_name)

    def _render_conversation(self, contact_name: str) -> None:
        lines = self._conv.get(contact_name, [])
        self._set_chat_text("\n".join(lines))

    def _set_chat_text(self, text: str) -> None:
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", tk.END)
        self.chat_box.insert(tk.END, text)
        self.chat_box.configure(state="disabled")


def main() -> None:
    ap = argparse.ArgumentParser(description="chat.cash temporary UI (file transport)")
    ap.add_argument("--user", required=True, help="profile name (e.g. alice / bob)")
    ap.add_argument("--net", default="simnet", help="base dir for the local simulation")
    ap.add_argument("--poll-ms", type=int, default=750)
    args = ap.parse_args()

    net_dir = Path(args.net)
    profile_path = net_dir / "profiles" / f"{args.user}.json"

    app = ChatUI(profile_path=profile_path, username=args.user, net_dir=net_dir, poll_ms=args.poll_ms)
    app.mainloop()


if __name__ == "__main__":
    main()