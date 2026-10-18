"""Nonces van de verifier: uitgeven en eenmalig verbruiken, ook bij gelijktijdige verzoeken."""

from __future__ import annotations

import contextlib
import secrets
import sqlite3
import time
from collections.abc import Generator
from pathlib import Path

NONCE_GELDIG_S = 60


class Nonces:
    """SQLite-tabel met nonces; verbruik gebeurt in één `BEGIN IMMEDIATE`-transactie."""

    def __init__(self, pad: Path) -> None:
        self.pad = pad
        pad.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS nonces"
                " (waarde TEXT PRIMARY KEY, verloopt INTEGER NOT NULL)"
            )

    @contextlib.contextmanager
    def _db(self) -> Generator[sqlite3.Connection]:
        """Een verbinding die na het blok altijd sluit (sqlite3 zelf sluit niet bij `with`)."""
        db = sqlite3.connect(self.pad, isolation_level=None, timeout=10)
        try:
            yield db
        finally:
            db.close()

    def nieuw(self) -> str:
        """Geef een nieuwe nonce uit (60 seconden geldig)."""
        waarde = secrets.token_urlsafe(24)
        nu = int(time.time())
        with self._db() as db:
            db.execute("DELETE FROM nonces WHERE verloopt < ?", (nu,))
            db.execute("INSERT INTO nonces VALUES (?, ?)", (waarde, nu + NONCE_GELDIG_S))
        return waarde

    def verbruik(self, waarde: str) -> bool:
        """Verbruik een nonce; True als hij bestond en niet verlopen was. Nooit twee keer True."""
        nu = int(time.time())
        with self._db() as db:
            # Een fout vóór COMMIT (ook in COMMIT zelf) sluit de verbinding zonder commit:
            # SQLite draait de transactie dan terug en de nonce blijft onverbruikt.
            db.execute("BEGIN IMMEDIATE")
            rij = db.execute("SELECT verloopt FROM nonces WHERE waarde = ?", (waarde,)).fetchone()
            db.execute("DELETE FROM nonces WHERE waarde = ?", (waarde,))
            db.execute("COMMIT")
        return rij is not None and rij[0] >= nu
