"""P-256-sleutelparen voor uitgever en agent: JWK, thumbprint (RFC 7638), tekenen en bewaren.

Alle sleutels worden lokaal gegenereerd en staan nergens in git. In productie horen ze in een HSM,
TPM of key vault.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from joserfc import jws
from joserfc.jwk import ECKey, KeyParameters

ALG = "ES256"


@dataclass(frozen=True)
class Sleutelpaar:
    """Een P-256-sleutelpaar.

    Attributes:
        sleutel: De joserfc-sleutel (privé).
    """

    sleutel: ECKey

    @classmethod
    def nieuw(cls, kid: str | None = None) -> Sleutelpaar:
        """Genereer een nieuw sleutelpaar; `kid` is het sleutel-id voor een JWKS."""
        parameters: KeyParameters = {"use": "sig", "alg": ALG}
        if kid is not None:
            parameters["kid"] = kid
        return cls(ECKey.generate_key("P-256", parameters))

    @classmethod
    def laad(cls, pad: Path) -> Sleutelpaar:
        """Lees een sleutelpaar uit een JWK-bestand (privé)."""
        return cls(ECKey.import_key(json.loads(pad.read_text())))

    def bewaar(self, pad: Path) -> None:
        """Schrijf het sleutelpaar als privé-JWK, alleen leesbaar voor de eigenaar."""
        pad.parent.mkdir(parents=True, exist_ok=True)
        pad.write_text(json.dumps(self.sleutel.as_dict(private=True)))
        pad.chmod(0o600)

    @property
    def kid(self) -> str | None:
        """Sleutel-id."""
        return self.sleutel.kid

    @property
    def publieke_jwk(self) -> dict[str, Any]:
        """Publieke sleutel als JWK, alleen de leden die een `cnf.jwk` nodig heeft."""
        jwk = self.sleutel.as_dict(private=False)
        return {k: jwk[k] for k in ("kty", "crv", "x", "y")}

    @property
    def jwks_lid(self) -> dict[str, Any]:
        """Publieke sleutel als lid van een JWKS (met kid, use en alg)."""
        return self.sleutel.as_dict(private=False)

    @property
    def jkt(self) -> str:
        """JWK-thumbprint (RFC 7638, SHA-256)."""
        return self.sleutel.thumbprint()

    def teken(self, kop: dict[str, Any], claims: dict[str, Any]) -> str:
        """Teken claims als compacte JWS (ES256) met de gegeven kopvelden (bijvoorbeeld `typ`)."""
        protected = {"alg": ALG, **kop}
        if self.kid and "kid" not in protected:
            protected["kid"] = self.kid
        payload = json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode()
        return jws.serialize_compact(protected, payload, self.sleutel)


def thumbprint(jwk: dict[str, Any]) -> str:
    """Thumbprint van een publieke EC-JWK."""
    return ECKey.import_key(jwk).thumbprint()


def publieke_sleutel(jwk: dict[str, Any]) -> ECKey:
    """Maak een publieke verificatiesleutel uit een JWK; weigert privé-leden en andere typen."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise ValueError("verwacht een publieke P-256 EC-sleutel")
    return ECKey.import_key({k: jwk[k] for k in ("kty", "crv", "x", "y")})
