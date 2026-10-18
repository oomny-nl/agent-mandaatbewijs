"""P-256-sleutelparen voor uitgever en agent: JWK, thumbprint (RFC 7638), tekenen en bewaren.

Alle sleutels worden lokaal gegenereerd en staan nergens in git. In productie horen ze in een HSM,
TPM of key vault.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
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
        """Lees een sleutelpaar uit een JWK-bestand (privé) dat alleen de eigenaar kan lezen."""
        return cls(ECKey.import_key(json.loads(lees_afgeschermd(pad))))

    def bewaar(self, pad: Path) -> bool:
        """Schrijf het sleutelpaar als privé-JWK, alleen leesbaar voor de eigenaar.

        Returns:
            False als er al een bestand stond; dat blijft dan ongewijzigd.
        """
        return maak_afgeschermd(pad, json.dumps(self.sleutel.as_dict(private=True)))

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
    """Maak een publieke ES256-verificatiesleutel uit een JWK.

    Weigert privé-leden en andere sleuteltypen, en een sleutel waarvan een aanwezige
    gebruiksbeperking ES256-verificatie uitsluit (RFC 7517 §4.2-4.4, RFC 8725 §3.1): `use`
    moet `sig` zijn, `alg` moet ES256 zijn en `key_ops` moet `verify` bevatten.

    Raises:
        ValueError: Als de JWK geen bruikbare publieke P-256-verificatiesleutel is.
    """
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("verwacht een publieke P-256 EC-sleutel")
    if "d" in jwk:
        raise ValueError("verwacht een publieke P-256 EC-sleutel, kreeg een privésleutel")
    if jwk.get("use", "sig") != "sig":
        raise ValueError(f"sleutel is bestemd voor use={jwk['use']!r}, niet voor handtekeningen")
    if jwk.get("alg", ALG) != ALG:
        raise ValueError(f"sleutel is bestemd voor alg={jwk['alg']!r}, niet voor {ALG}")
    bewerkingen = jwk.get("key_ops", ["verify"])
    if not isinstance(bewerkingen, list) or "verify" not in bewerkingen:
        raise ValueError(f"key_ops {bewerkingen!r} staat verificatie niet toe")
    return ECKey.import_key({k: jwk[k] for k in ("kty", "crv", "x", "y")})


def jose_kop(compact: str) -> dict[str, Any]:
    """De beschermde kop van een compacte JWS, zonder handtekeningcontrole.

    joserfc geeft de kop terug zoals die in de JSON staat. Een lijst of tekst zou anders pas
    bij `.get` misgaan, of via `dict(["ab"])` stil een ander object worden; RFC 7515 §4 eist
    een JSON-object.

    Raises:
        ValueError: Als de tekst geen compacte JWS is of de kop geen JSON-object.
    """
    try:
        kop = jws.extract_compact(compact.encode()).protected
    except (JoseError, ValueError) as fout:
        raise ValueError(f"geen geldige compacte JWS: {fout}") from fout
    if not isinstance(kop, dict):
        raise ValueError(f"JOSE-kop is geen JSON-object maar {type(kop).__name__}")
    return kop


def maak_afgeschermd(pad: Path, inhoud: str) -> bool:
    """Maak een geheim bestand atomair aan, vanaf de eerste byte alleen leesbaar voor de eigenaar.

    Een tijdelijk bestand naast het doel wordt exclusief met rechten 0600 gemaakt, gevuld en
    gesynchroniseerd, en daarna met een harde link op zijn plaats gezet. Die link mislukt als het
    doel al bestaat, dus twee gelijktijdige starts overschrijven elkaars geheim niet.

    Returns:
        True als het bestand is aangemaakt, False als het al bestond (dan blijft het staan).
    """
    pad.parent.mkdir(parents=True, exist_ok=True)
    tijdelijk = pad.with_name(f".{pad.name}.{secrets.token_hex(8)}")
    fd = os.open(tijdelijk, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as bestand:
            bestand.write(inhoud)
            bestand.flush()
            os.fsync(bestand.fileno())
        os.link(tijdelijk, pad)
    except FileExistsError:
        return False
    finally:
        tijdelijk.unlink(missing_ok=True)
    return True


def lees_afgeschermd(pad: Path) -> str:
    """Lees een geheim bestand; weigert als groep of anderen het kunnen lezen of schrijven.

    Raises:
        PermissionError: Als de rechten ruimer zijn dan 0600, met de herstelopdracht.
    """
    rechten = pad.stat().st_mode & 0o777
    if rechten & 0o077:
        raise PermissionError(
            f"{pad} heeft rechten {rechten:o}; alleen de eigenaar mag een geheim lezen. "
            f"Herstel met: chmod 600 {pad}"
        )
    return pad.read_text(encoding="utf-8")
