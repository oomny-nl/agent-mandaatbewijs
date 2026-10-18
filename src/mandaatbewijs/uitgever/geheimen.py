"""Lokaal gegenereerde geheimen van de uitgever: uitgeverssleutel en wachtwoorden.

Alles wordt bij de eerste start in de datamap aangemaakt; niets staat in git. De demo leest de
wachtwoorden uit dezelfde map (alleen-lezen volume) om de medewerkers te spelen.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from mandaatbewijs.sleutels import Sleutelpaar, lees_afgeschermd, maak_afgeschermd
from mandaatbewijs.uitgever.gegevens import MEDEWERKERS


def uitgeverssleutel(datamap: Path) -> Sleutelpaar:
    """Laad de uitgeverssleutel of maak hem bij de eerste start.

    Na het aanmaken wordt altijd van schijf gelezen, zodat twee gelijktijdige starts dezelfde
    sleutel gebruiken.
    """
    pad = datamap / "uitgever.jwk"
    if not pad.exists():
        Sleutelpaar.nieuw(kid=f"lindevoort-{secrets.token_hex(4)}").bewaar(pad)
    return Sleutelpaar.laad(pad)


def wachtwoorden(datamap: Path) -> dict[str, str]:
    """Wachtwoorden van de medewerkers; bij de eerste start willekeurig gegenereerd."""
    pad = datamap / "wachtwoorden.json"
    if not pad.exists():
        nieuw = {naam: secrets.token_urlsafe(24) for naam in MEDEWERKERS}
        maak_afgeschermd(pad, json.dumps(nieuw))
    return json.loads(lees_afgeschermd(pad))
