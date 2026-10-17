"""Lokaal gegenereerde geheimen van de uitgever: uitgeverssleutel en wachtwoorden.

Alles wordt bij de eerste start in de datamap aangemaakt; niets staat in git. De demo leest de
wachtwoorden uit dezelfde map (alleen-lezen volume) om de medewerkers te spelen.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.uitgever.gegevens import MEDEWERKERS


def uitgeverssleutel(datamap: Path) -> Sleutelpaar:
    """Laad de uitgeverssleutel of maak hem bij de eerste start."""
    pad = datamap / "uitgever.jwk"
    if pad.exists():
        return Sleutelpaar.laad(pad)
    paar = Sleutelpaar.nieuw(kid=f"lindevoort-{secrets.token_hex(4)}")
    paar.bewaar(pad)
    return paar


def wachtwoorden(datamap: Path) -> dict[str, str]:
    """Wachtwoorden van de medewerkers; bij de eerste start willekeurig gegenereerd."""
    pad = datamap / "wachtwoorden.json"
    if pad.exists():
        return json.loads(pad.read_text())
    pad.parent.mkdir(parents=True, exist_ok=True)
    nieuw = {naam: secrets.token_urlsafe(24) for naam in MEDEWERKERS}
    pad.write_text(json.dumps(nieuw))
    pad.chmod(0o600)
    return nieuw
