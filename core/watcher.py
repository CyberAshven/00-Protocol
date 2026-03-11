# core/watcher.py
from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Any, Dict


@dataclass(frozen=True)
class WatchEvent:
    """
    Evènement émis quand un nouveau fichier msg_*.json est détecté.
    - path: le chemin du fichier détecté
    - payload: le contenu JSON déjà parsé (dict)
    """
    path: Path
    payload: Dict[str, Any]


class InboxWatcher:
    """
    Surveille un dossier pour détecter de nouveaux fichiers msg_*.json.

    - Pas de dépendance externe (pas de watchdog)
    - Thread + polling (scan toutes les N secondes)
    - Déduplication par nom de fichier (évite de traiter 2 fois)

    Usage:
        watcher = InboxWatcher(inbox_dir, on_event=callback)
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(
        self,
        inbox_dir: str | Path,
        on_event: Callable[[WatchEvent], None],
        pattern: str = "msg_*.json",
        poll_interval_s: float = 0.4,
        ignore_errors: bool = True,
    ) -> None:
        self.inbox_dir = Path(inbox_dir).expanduser().resolve()
        self.on_event = on_event
        self.pattern = pattern
        self.poll_interval_s = poll_interval_s
        self.ignore_errors = ignore_errors

        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen: set[str] = set()  # noms de fichiers déjà traités

    def start(self) -> None:
        """Démarre le thread de surveillance."""
        self.inbox_dir.mkdir(parents=True, exist_ok=True)

        if self._thread and self._thread.is_alive():
            return

        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="InboxWatcher",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stoppe proprement le watcher."""
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        """Boucle principale du thread."""
        while not self._stop_evt.is_set():
            try:
                self._scan_once()
            except Exception:
                if not self.ignore_errors:
                    raise
                # sinon: on ignore l'erreur et on continue
            time.sleep(self.poll_interval_s)

    def _scan_once(self) -> None:
        """
        Scanne le dossier une fois.
        On trie par mtime pour un traitement "humain" (ordre d’arrivée).
        """
        files = sorted(self.inbox_dir.glob(self.pattern), key=lambda p: p.stat().st_mtime)

        for path in files:
            fname = path.name
            if fname in self._seen:
                continue

            payload = self._safe_load_json(path)
            if payload is None:
                # fichier illisible ou en cours d’écriture -> on retentera au prochain tour
                continue

            self._seen.add(fname)
            self.on_event(WatchEvent(path=path, payload=payload))

    def _safe_load_json(self, path: Path) -> Optional[Dict[str, Any]]:
        """
        Essaie de lire + parser le JSON.
        Retourne None si le fichier est corrompu / incomplet / verrouillé / en cours d’écriture.
        """
        try:
            raw = path.read_text(encoding="utf-8")
            return json.loads(raw)
        except Exception:
            return None