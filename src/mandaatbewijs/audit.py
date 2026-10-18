"""Auditlog als hashketen in JSONL, voor uitgever en verifier.

Elk record krijgt een volgnummer, een tijdstempel, de hash van het vorige record en zijn eigen
hash. Wijzigen, weglaten of invoegen van een record breekt de keten. Tamper-evident, niet
tamper-proof: wie het bestand kan herschrijven, kan de keten herberekenen. In productie hoort het
log in WORM-opslag.

Events uit een transactionele outbox (de uitgever) dragen hun outboxnummer in `uitgaand`. Het log
schrijft elk nummer hooguit één keer, ook als een eerdere poging na het schrijven maar vóór het
opruimen van de outbox afbrak.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def nu_iso() -> str:
    """Huidige tijd als ISO 8601 in UTC, op milliseconden."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def ketenhash(vorige: str, record: dict[str, Any]) -> str:
    """Hash van een record (zonder `hash`), gekoppeld aan de vorige hash."""
    inhoud = {k: v for k, v in record.items() if k != "hash"}
    canon = json.dumps(inhoud, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((vorige + canon).encode()).hexdigest()


class Auditlog:
    """Append-only JSONL-log met hashketen; thread-veilig binnen één proces, mits één object."""

    def __init__(self, pad: Path, organisatie: str) -> None:
        self.pad = pad
        self.organisatie = organisatie
        self._slot = threading.Lock()
        pad.parent.mkdir(parents=True, exist_ok=True)
        pad.touch()
        records = lees(pad)
        laatste = records[-1:] or [{"nr": 0, "hash": GENESIS}]
        self._nr = int(laatste[0]["nr"])
        self._kop = str(laatste[0]["hash"])
        self._uitgaand = max((int(r.get("uitgaand", 0)) for r in records), default=0)

    def schrijf(self, **velden: Any) -> dict[str, Any]:
        """Voeg een record toe en geef het volledige record terug."""
        with self._slot:
            return self._voeg_toe(velden)

    def schrijf_uitgaand(self, nr: int, velden: dict[str, Any]) -> dict[str, Any] | None:
        """Schrijf outboxevent `nr`, of niets (None) als het al in het log staat.

        Outboxnummers stijgen (SQLite `AUTOINCREMENT`) en worden in volgorde geschreven.
        """
        with self._slot:
            if nr <= self._uitgaand:
                return None
            record = self._voeg_toe({**velden, "uitgaand": nr})
            self._uitgaand = nr
            return record

    def _voeg_toe(self, velden: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = {
            "nr": self._nr + 1,
            "tijd": nu_iso(),
            "organisatie": self.organisatie,
            **velden,
            "vorige": self._kop,
        }
        record["hash"] = ketenhash(self._kop, record)
        with self.pad.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._nr, self._kop = record["nr"], record["hash"]
        return record


def lees(pad: Path) -> list[dict[str, Any]]:
    """Lees alle records uit een JSONL-log."""
    if not pad.exists():
        return []
    return [json.loads(regel) for regel in pad.read_text(encoding="utf-8").splitlines() if regel]


def controleer(records: list[dict[str, Any]]) -> tuple[bool, str]:
    """Controleer de keten: volgnummers, koppeling en hashes."""
    vorige = GENESIS
    for verwacht_nr, record in enumerate(records, start=1):
        if record.get("nr") != verwacht_nr:
            return False, f"record {verwacht_nr} ontbreekt of staat verkeerd"
        if record.get("vorige") != vorige:
            return False, f"record {verwacht_nr} wijst niet naar het vorige record"
        if record.get("hash") != ketenhash(vorige, record):
            return False, f"record {verwacht_nr} is gewijzigd"
        vorige = str(record["hash"])
    return True, "intact"
