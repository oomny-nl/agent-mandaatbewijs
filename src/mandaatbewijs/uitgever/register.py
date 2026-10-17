"""Mandaatregister van de uitgever (SQLite): verzoeken, mandaten, blokkadelijst en statuslijst.

Elke toestandsovergang gebeurt in één `BEGIN IMMEDIATE`-transactie, zodat gelijktijdige verzoeken
(twee keer ophalen, toestemming na noodstop) nooit allebei slagen.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mandaatbewijs.statuslijst import GELDIG, INGETROKKEN, Statuslijst

POSITIES = 1 << 16
VERZOEK_GELDIG_S = 600

SCHEMA = """
CREATE TABLE IF NOT EXISTS verzoeken (
    id TEXT PRIMARY KEY,
    medewerker TEXT NOT NULL,
    agent_jwk TEXT NOT NULL,
    jkt TEXT NOT NULL,
    doel TEXT NOT NULL,
    acties TEXT NOT NULL,
    dossiers TEXT NOT NULL,
    status TEXT NOT NULL,
    aangemaakt INTEGER NOT NULL,
    verloopt INTEGER NOT NULL,
    mandaat_id TEXT,
    credential TEXT
);
CREATE TABLE IF NOT EXISTS mandaten (
    id TEXT PRIMARY KEY,
    verzoek_id TEXT NOT NULL,
    medewerker TEXT NOT NULL,
    jkt TEXT NOT NULL,
    idx INTEGER NOT NULL UNIQUE,
    iat INTEGER NOT NULL,
    exp INTEGER NOT NULL,
    status TEXT NOT NULL,
    gewijzigd INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS blokkade (jkt TEXT PRIMARY KEY, tijd INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS statuslijst (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    inhoud BLOB NOT NULL,
    token TEXT,
    getekend INTEGER NOT NULL
);
"""


class RegisterFout(Exception):
    """Een toestandsovergang die niet mag; `status` is de HTTP-status voor de API."""

    def __init__(self, reden: str, status: int = 409) -> None:
        super().__init__(reden)
        self.reden = reden
        self.status = status


@dataclass(frozen=True)
class Verzoek:
    """Een mandaatverzoek zoals opgeslagen."""

    id: str
    medewerker: str
    agent_jwk: dict[str, Any]
    jkt: str
    doel: str
    acties: list[str]
    dossiers: list[str]
    status: str
    aangemaakt: int
    verloopt: int
    mandaat_id: str | None
    credential: str | None

    @classmethod
    def uit_rij(cls, rij: sqlite3.Row) -> Verzoek:
        """Bouw uit een databaserij."""
        return cls(
            rij["id"],
            rij["medewerker"],
            json.loads(rij["agent_jwk"]),
            rij["jkt"],
            rij["doel"],
            json.loads(rij["acties"]),
            json.loads(rij["dossiers"]),
            rij["status"],
            rij["aangemaakt"],
            rij["verloopt"],
            rij["mandaat_id"],
            rij["credential"],
        )

    def openbaar(self) -> dict[str, Any]:
        """Inhoud voor het toestemmingsscherm en de API (zonder credential)."""
        return {
            "id": self.id,
            "medewerker": self.medewerker,
            "agent_jkt": self.jkt,
            "doel": self.doel,
            "acties": self.acties,
            "dossiers": self.dossiers,
            "status": self.status,
            "verloopt": self.verloopt,
            "mandaat_id": self.mandaat_id,
        }


class Register:
    """Het register. Elke methode opent een eigen verbinding; schrijvers nemen `BEGIN IMMEDIATE`."""

    def __init__(self, pad: Path) -> None:
        self.pad = pad
        pad.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript(SCHEMA)
            if db.execute("SELECT 1 FROM statuslijst").fetchone() is None:
                db.execute(
                    "INSERT INTO statuslijst (id, inhoud, token, getekend) VALUES (1, ?, NULL, 0)",
                    (bytes(Statuslijst.leeg(POSITIES).inhoud),),
                )

    @contextmanager
    def _db(self) -> Generator[sqlite3.Connection]:
        db = sqlite3.connect(self.pad, isolation_level=None, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _transactie(self) -> Generator[sqlite3.Connection]:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")

    # Verzoeken ---------------------------------------------------------------------------------

    def nieuw_verzoek(self, velden: dict[str, Any], jkt: str) -> Verzoek:
        """Sla een verzoek op; weigert een geblokkeerde sleutel."""
        nu = int(time.time())
        verzoek_id = f"v-{secrets.token_urlsafe(16)}"
        with self._transactie() as db:
            if db.execute("SELECT 1 FROM blokkade WHERE jkt = ?", (jkt,)).fetchone():
                raise RegisterFout("sleutel_geblokkeerd", 403)
            db.execute(
                "INSERT INTO verzoeken VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                (
                    verzoek_id,
                    velden["medewerker"],
                    json.dumps(velden["agent_jwk"]),
                    jkt,
                    velden["doel"],
                    json.dumps(velden["acties"]),
                    json.dumps(velden["dossiers"]),
                    "ingediend",
                    nu,
                    nu + VERZOEK_GELDIG_S,
                ),
            )
        return self.verzoek(verzoek_id)

    def verzoek(self, verzoek_id: str) -> Verzoek:
        """Lees een verzoek."""
        with self._db() as db:
            rij = db.execute("SELECT * FROM verzoeken WHERE id = ?", (verzoek_id,)).fetchone()
        if rij is None:
            raise RegisterFout("verzoek_onbekend", 404)
        return Verzoek.uit_rij(rij)

    def weiger(self, verzoek_id: str, medewerker: str) -> Verzoek:
        """De medewerker zegt nee."""
        with self._transactie() as db:
            v = self._ingediend(db, verzoek_id, medewerker)
            db.execute("UPDATE verzoeken SET status = 'geweigerd' WHERE id = ?", (v.id,))
        return self.verzoek(verzoek_id)

    def keur_goed(self, verzoek_id: str, medewerker: str, maak_credential: Any) -> Verzoek:
        """Keur goed: kies een vrije index, teken de credential, leg het mandaat vast.

        Args:
            verzoek_id: Het verzoek.
            medewerker: Wie goedkeurt; moet de medewerker uit het verzoek zijn.
            maak_credential: `(verzoek, mandaat_id, idx) -> (credential, iat, exp)`.
        """
        with self._transactie() as db:
            v = self._ingediend(db, verzoek_id, medewerker)
            if db.execute("SELECT 1 FROM blokkade WHERE jkt = ?", (v.jkt,)).fetchone():
                db.execute("UPDATE verzoeken SET status = 'geweigerd' WHERE id = ?", (v.id,))
                raise RegisterFout("sleutel_geblokkeerd", 403)
            idx = self._vrije_idx(db)
            mandaat_id = f"m-{secrets.token_urlsafe(9)}"
            credential, iat, exp = maak_credential(v, mandaat_id, idx)
            db.execute(
                "INSERT INTO mandaten VALUES (?,?,?,?,?,?,?,'actief',?)",
                (mandaat_id, v.id, v.medewerker, v.jkt, idx, iat, exp, iat),
            )
            db.execute(
                "UPDATE verzoeken SET status = 'goedgekeurd', mandaat_id = ?, credential = ? "
                "WHERE id = ?",
                (mandaat_id, credential, v.id),
            )
        return self.verzoek(verzoek_id)

    def haal_op(self, verzoek_id: str, jkt: str) -> str:
        """Eenmalige ophaling van de credential door de sleutel uit het verzoek.

        Een goedgekeurd verzoek dat niet binnen de verzoektermijn is opgehaald, vervalt: de
        opgeslagen credential wordt gewist en de ophaling geweigerd (410).
        """
        with self._transactie() as db:
            rij = db.execute("SELECT * FROM verzoeken WHERE id = ?", (verzoek_id,)).fetchone()
            if rij is None:
                raise RegisterFout("verzoek_onbekend", 404)
            v = Verzoek.uit_rij(rij)
            if v.jkt != jkt:
                raise RegisterFout("sleutel_hoort_niet_bij_verzoek", 403)
            if v.status != "goedgekeurd" or v.credential is None:
                raise RegisterFout(f"verzoek_niet_ophaalbaar:{v.status}", 409)
            if db.execute("SELECT 1 FROM blokkade WHERE jkt = ?", (jkt,)).fetchone():
                raise RegisterFout("sleutel_geblokkeerd", 403)
            verlopen = v.verloopt < int(time.time())
            nieuwe_status = "verlopen" if verlopen else "opgehaald"
            db.execute(
                "UPDATE verzoeken SET status = ?, credential = NULL WHERE id = ?",
                (nieuwe_status, v.id),
            )
        if verlopen:
            raise RegisterFout("verzoek_verlopen", 410)
        return v.credential

    def _ingediend(self, db: sqlite3.Connection, verzoek_id: str, medewerker: str) -> Verzoek:
        rij = db.execute("SELECT * FROM verzoeken WHERE id = ?", (verzoek_id,)).fetchone()
        if rij is None:
            raise RegisterFout("verzoek_onbekend", 404)
        v = Verzoek.uit_rij(rij)
        if v.medewerker != medewerker:
            raise RegisterFout("verzoek_hoort_bij_andere_medewerker", 403)
        if v.status != "ingediend":
            raise RegisterFout(f"verzoek_al_afgehandeld:{v.status}", 409)
        if v.verloopt < int(time.time()):
            db.execute("UPDATE verzoeken SET status = 'verlopen' WHERE id = ?", (v.id,))
            raise RegisterFout("verzoek_verlopen", 410)
        return v

    @staticmethod
    def _vrije_idx(db: sqlite3.Connection) -> int:
        for _ in range(100):
            idx = secrets.randbelow(POSITIES)
            if db.execute("SELECT 1 FROM mandaten WHERE idx = ?", (idx,)).fetchone() is None:
                return idx
        raise RegisterFout("geen_vrije_index", 503)

    # Mandaten ----------------------------------------------------------------------------------

    def mandaten(self, medewerker: str | None = None) -> list[dict[str, Any]]:
        """Mandaten, eventueel van één medewerker."""
        with self._db() as db:
            if medewerker is None:
                rijen = db.execute("SELECT * FROM mandaten ORDER BY iat").fetchall()
            else:
                rijen = db.execute(
                    "SELECT * FROM mandaten WHERE medewerker = ? ORDER BY iat", (medewerker,)
                ).fetchall()
        return [dict(r) for r in rijen]

    def trek_in(self, mandaat_id: str, medewerker: str | None) -> dict[str, Any]:
        """Zet het mandaat op ingetrokken en de bit op INVALID; `medewerker` None is beheer."""
        with self._transactie() as db:
            rij = db.execute("SELECT * FROM mandaten WHERE id = ?", (mandaat_id,)).fetchone()
            if rij is None:
                raise RegisterFout("mandaat_onbekend", 404)
            if medewerker is not None and rij["medewerker"] != medewerker:
                raise RegisterFout("mandaat_hoort_bij_andere_medewerker", 403)
            if rij["status"] != "actief":
                raise RegisterFout("mandaat_al_ingetrokken", 409)
            self._zet_ingetrokken(db, [rij["idx"]], [mandaat_id])
            return dict(db.execute("SELECT * FROM mandaten WHERE id = ?", (mandaat_id,)).fetchone())

    def noodstop(self, jkt: str) -> list[str]:
        """Blokkeer een agentsleutel en trek alle actieve mandaten op die sleutel in."""
        nu = int(time.time())
        with self._transactie() as db:
            db.execute("INSERT OR REPLACE INTO blokkade (jkt, tijd) VALUES (?, ?)", (jkt, nu))
            rijen = db.execute(
                "SELECT id, idx FROM mandaten WHERE jkt = ? AND status = 'actief'", (jkt,)
            ).fetchall()
            db.execute(
                "UPDATE verzoeken SET status = 'geweigerd' WHERE jkt = ? "
                "AND status IN ('ingediend', 'goedgekeurd')",
                (jkt,),
            )
            self._zet_ingetrokken(db, [r["idx"] for r in rijen], [r["id"] for r in rijen])
            return [r["id"] for r in rijen]

    def _zet_ingetrokken(self, db: sqlite3.Connection, idxs: list[int], ids: list[str]) -> None:
        nu = int(time.time())
        lijst = Statuslijst(
            1, bytearray(db.execute("SELECT inhoud FROM statuslijst").fetchone()[0])
        )
        for idx in idxs:
            lijst.zet(idx, INGETROKKEN)
        db.execute(
            "UPDATE statuslijst SET inhoud = ?, token = NULL WHERE id = 1",
            (bytes(lijst.inhoud),),
        )
        for mandaat_id in ids:
            db.execute(
                "UPDATE mandaten SET status = 'ingetrokken', gewijzigd = ? WHERE id = ?",
                (nu, mandaat_id),
            )

    def geblokkeerd(self) -> list[str]:
        """Geblokkeerde thumbprints."""
        with self._db() as db:
            return [r["jkt"] for r in db.execute("SELECT jkt FROM blokkade")]

    # Statuslijst -------------------------------------------------------------------------------

    def statuslijst(self) -> Statuslijst:
        """De huidige lijst."""
        with self._db() as db:
            return Statuslijst(
                1, bytearray(db.execute("SELECT inhoud FROM statuslijst").fetchone()[0])
            )

    def status_van(self, idx: int) -> int:
        """Statuswaarde op een index (GELDIG of INGETROKKEN)."""
        return self.statuslijst().lees(idx)

    def statustoken(self, maak_token: Any, max_leeftijd_s: int) -> str:
        """Het getekende Status List Token; opnieuw getekend als het ouder is dan `max_leeftijd_s`.

        Elk nieuw token krijgt een `iat` die strikt groter is dan die van het vorige, ook als een
        intrekking in dezelfde seconde valt als de vorige ondertekening. Zo kan een verifier een
        ouder token altijd herkennen en zijn twee tokens met dezelfde `iat` altijd gelijk van
        inhoud.

        Args:
            maak_token: `(lijst, iat) -> token`.
            max_leeftijd_s: Leeftijd waarna een nieuw token wordt getekend (de `ttl`).
        """
        nu = int(time.time())
        with self._transactie() as db:
            rij = db.execute("SELECT inhoud, token, getekend FROM statuslijst").fetchone()
            if rij["token"] is not None and rij["getekend"] + max_leeftijd_s > nu:
                return rij["token"]
            iat = max(nu, rij["getekend"] + 1)
            token = maak_token(Statuslijst(1, bytearray(rij["inhoud"])), iat)
            db.execute("UPDATE statuslijst SET token = ?, getekend = ? WHERE id = 1", (token, iat))
            return token


__all__ = ["GELDIG", "INGETROKKEN", "Register", "RegisterFout", "Verzoek"]
