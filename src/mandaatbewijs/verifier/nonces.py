"""Nonces van de verifier: uitgeven en eenmalig verbruiken, ook bij gelijktijdige verzoeken."""

from __future__ import annotations

import secrets
import sqlite3
import time
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

    def _db(self) -> sqlite3.Connection:
        return sqlite3.connect(self.pad, isolation_level=None, timeout=10)

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
            db.execute("BEGIN IMMEDIATE")
            try:
                rij = db.execute(
                    "SELECT verloopt FROM nonces WHERE waarde = ?", (waarde,)
                ).fetchone()
                db.execute("DELETE FROM nonces WHERE waarde = ?", (waarde,))
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
        return rij is not None and rij[0] >= nu
