"""Credentialuitgifte en statustoken van de uitgever: de claims van het mandaat."""

from __future__ import annotations

import time
from dataclasses import dataclass

from mandaatbewijs.sdjwt import geef_uit
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.statuslijst import Statuslijst, Tokenbeleid, maak_token
from mandaatbewijs.uitgever.gegevens import MEDEWERKERS, VCT
from mandaatbewijs.uitgever.register import Verzoek

VERBORGEN = frozenset({"doel", "medewerker", "afdeling"})
PER_ELEMENT = frozenset({"acties", "dossiers"})


@dataclass(frozen=True)
class Uitgifte:
    """Tekent credentials en Status List Tokens namens de uitgever.

    Attributes:
        sleutel: Uitgeverssleutel met `kid`.
        iss: Identifier van de uitgever (basis-URL).
        beleid: `ttl` en geldigheid van het Status List Token.
    """

    sleutel: Sleutelpaar
    iss: str
    beleid: Tokenbeleid

    @property
    def statuslijst_uri(self) -> str:
        """URI van de enige statuslijst."""
        return f"{self.iss}/statuslijsten/1"

    def credential(
        self, verzoek: Verzoek, mandaat_id: str, idx: int, geldigheid_s: int
    ) -> tuple[str, int, int]:
        """Teken de SD-JWT VC voor een goedgekeurd verzoek; geeft (uitgiftevorm, iat, exp)."""
        nu = int(time.time())
        m = MEDEWERKERS[verzoek.medewerker]
        claims = {
            "iss": self.iss,
            "vct": VCT,
            "jti": mandaat_id,
            "iat": nu,
            "nbf": nu,
            "exp": nu + geldigheid_s,
            "cnf": {"jwk": verzoek.agent_jwk},
            "status": {"status_list": {"idx": idx, "uri": self.statuslijst_uri}},
            "doel": verzoek.doel,
            "medewerker": {"id": m.id, "naam": m.naam, "rol": m.rol},
            "afdeling": m.afdeling,
            "acties": list(verzoek.acties),
            "dossiers": list(verzoek.dossiers),
        }
        uitgiftevorm, _ = geef_uit(self.sleutel, claims, set(VERBORGEN), set(PER_ELEMENT))
        return uitgiftevorm, nu, nu + geldigheid_s

    def statustoken(self, lijst: Statuslijst, iat: int) -> str:
        """Teken het Status List Token voor de huidige lijst met uitgiftetijd `iat`."""
        return maak_token(self.sleutel, self.statuslijst_uri, lijst, self.beleid, iat)
