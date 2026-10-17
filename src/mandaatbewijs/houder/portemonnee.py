"""De portemonnee van de agent: eigen sleutelpaar, ontvangen mandaat en presentaties per aanroep.

De agent vraagt een mandaat aan bij de uitgever, haalt het na toestemming op met een bewijs van
sleutelbezit, en maakt per toolaanroep een presentatie met alleen de claims die de verifier voor
die tool nodig heeft (ONTWERP §6).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx2
from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from mandaatbewijs.sdjwt import Credential, Disclosure, SdJwtFout, controleer_uitgifte, presenteer
from mandaatbewijs.sleutels import Sleutelpaar, publieke_sleutel

TYP_PROOF = "mandaatbewijs-proof+jwt"


class PortemonneeFout(Exception):
    """De uitgever weigerde een verzoek of de portemonnee heeft geen mandaat."""


@dataclass
class Portemonnee:
    """Sleutel en mandaat van één agent.

    Attributes:
        sleutel: Het sleutelpaar van de agent (`cnf.jwk` in het mandaat).
        uitgever: Basis-URL van de uitgever.
        credential: Het ontvangen mandaat, of None.
    """

    sleutel: Sleutelpaar
    uitgever: str
    credential: Credential | None = None
    http: httpx2.Client = field(default_factory=lambda: httpx2.Client(timeout=10))

    @property
    def jkt(self) -> str:
        """Thumbprint van de agentsleutel."""
        return self.sleutel.jkt

    def vraag_mandaat(
        self, medewerker: str, doel: str, acties: list[str], dossiers: list[str]
    ) -> str:
        """Dien een mandaatverzoek in; geeft het verzoek-id voor het toestemmingsscherm."""
        antwoord = self.http.post(
            f"{self.uitgever}/mandaatverzoeken",
            json={
                "agent_jwk": self.sleutel.publieke_jwk,
                "medewerker": medewerker,
                "doel": doel,
                "acties": acties,
                "dossiers": dossiers,
            },
        )
        if antwoord.status_code != 201:
            raise PortemonneeFout(
                f"mandaatverzoek geweigerd: {antwoord.status_code} {antwoord.text}"
            )
        return str(antwoord.json()["id"])

    def _proof(self, verzoek_id: str) -> str:
        claims = {"aud": self.uitgever, "nonce": verzoek_id, "iat": int(time.time())}
        return self.sleutel.teken({"typ": TYP_PROOF}, claims)

    def haal_op(self, verzoek_id: str) -> Credential:
        """Haal het goedgekeurde mandaat op met een bewijs van sleutelbezit."""
        antwoord = self.http.post(
            f"{self.uitgever}/mandaatverzoeken/{verzoek_id}/credential",
            json={"proof": self._proof(verzoek_id)},
        )
        if antwoord.status_code != 200:
            raise PortemonneeFout(f"ophalen geweigerd: {antwoord.status_code} {antwoord.text}")
        self.credential = self.controleer(str(antwoord.json()["credential"]))
        return self.credential

    def controleer(self, serialisatie: str) -> Credential:
        """Controleer een ontvangen credential: handtekening van de uitgever (via diens
        gepubliceerde JWKS), disclosures, `iss`, tijdvenster en binding aan de eigen sleutel.

        Raises:
            PortemonneeFout: Als de credential niet klopt of de sleutel van de uitgever ontbreekt.
        """
        try:
            credential = Credential.uit_serialisatie(serialisatie)
            kid = jws.extract_compact(credential.jwt.encode()).protected.get("kid")
        except (SdJwtFout, JoseError, ValueError) as fout:
            raise PortemonneeFout(f"credential onleesbaar: {fout}") from fout
        if not isinstance(kid, str):
            raise PortemonneeFout("credential zonder kid")
        try:
            controleer_uitgifte(credential, self._uitgeverssleutel(kid), self.uitgever, self.jkt)
        except SdJwtFout as fout:
            raise PortemonneeFout(f"credential afgewezen: {fout.reden}: {fout.detail}") from fout
        return credential

    def _uitgeverssleutel(self, kid: str) -> ECKey:
        meta = self._json(f"{self.uitgever}/.well-known/jwt-vc-issuer")
        if meta.get("issuer") != self.uitgever:
            raise PortemonneeFout("uitgeversmetadata: issuer klopt niet")
        jwks = meta.get("jwks")
        if not isinstance(jwks, dict):
            jwks = self._json(str(meta.get("jwks_uri", "")))
        for jwk in jwks.get("keys", []) if isinstance(jwks, dict) else []:
            if isinstance(jwk, dict) and jwk.get("kid") == kid:
                try:
                    return publieke_sleutel(jwk)
                except (ValueError, JoseError, TypeError, KeyError) as fout:
                    raise PortemonneeFout(f"uitgeverssleutel ongeldig: {fout}") from fout
        raise PortemonneeFout(f"uitgeverssleutel {kid!r} niet gevonden")

    def _json(self, url: str) -> dict[str, Any]:
        antwoord = self.http.get(url)
        if antwoord.status_code != 200:
            raise PortemonneeFout(f"{url}: HTTP {antwoord.status_code}")
        try:
            inhoud = antwoord.json()
        except ValueError as fout:
            raise PortemonneeFout(f"{url}: geen JSON") from fout
        if not isinstance(inhoud, dict):
            raise PortemonneeFout(f"{url}: geen object")
        return inhoud

    def disclosures_voor(self, actie: str, dossier: str, met_doel: bool) -> list[Disclosure]:
        """Alleen de disclosures die deze aanroep nodig heeft; wat ontbreekt, ontbreekt."""
        if self.credential is None:
            raise PortemonneeFout("geen mandaat in de portemonnee")
        kandidaten = [
            self.credential.disclosure_voor("doel") if met_doel else None,
            self.credential.disclosure_voor("acties", actie),
            self.credential.disclosure_voor("dossiers", dossier),
        ]
        return [d for d in kandidaten if d is not None]

    def presentatie(self, aud: str, nonce: str, gekozen: list[Disclosure]) -> str:
        """SD-JWT+KB voor deze verifier en nonce."""
        if self.credential is None:
            raise PortemonneeFout("geen mandaat in de portemonnee")
        return presenteer(self.credential, gekozen, self.sleutel, aud, nonce)

    @property
    def mandaat(self) -> dict[str, Any]:
        """Beschrijving van het mandaat voor de vertelling (jti, exp, verborgen claims)."""
        if self.credential is None:
            return {}
        p = self.credential.payload
        return {
            "jti": p.get("jti"),
            "iss": p.get("iss"),
            "exp": p.get("exp"),
            "status_idx": (p.get("status") or {}).get("status_list", {}).get("idx"),
            "verborgen": sorted(self.credential.verborgen_namen),
        }
