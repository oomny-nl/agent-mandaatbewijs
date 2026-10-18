"""Token Status List (draft-ietf-oauth-status-list-21), JWT-vorm.

De lijst is een bytearray met `bits` bits per positie, gepakt van het minst significante bit naar
het meest significante (§4.1), gecomprimeerd met zlib (DEFLATE) en base64url-gecodeerd in `lst`.
Het Status List Token is een JWT met `typ: statuslist+jwt`, `sub` gelijk aan de URI van de
lijst, `iat`, `exp` en `ttl` (§5.1).
"""

from __future__ import annotations

import json
import time
import zlib
from dataclasses import dataclass
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from mandaatbewijs.sdjwt import ALG, b64url, b64url_decode
from mandaatbewijs.sleutels import Sleutelpaar, jose_kop

TYP = "statuslist+jwt"
MEDIATYPE = "application/statuslist+jwt"
GELDIG = 0x00
INGETROKKEN = 0x01
MAX_BYTES = 1 << 20


class StatuslijstFout(Exception):
    """Ongeldig Status List Token of ongeldige index; `reden` is een korte code."""

    def __init__(self, reden: str, detail: str = "") -> None:
        super().__init__(f"{reden}: {detail}" if detail else reden)
        self.reden = reden


@dataclass
class Statuslijst:
    """Een statuslijst met 1, 2, 4 of 8 bits per positie."""

    bits: int
    inhoud: bytearray

    @classmethod
    def leeg(cls, posities: int, bits: int = 1) -> Statuslijst:
        """Nieuwe lijst waarin elke positie GELDIG is."""
        if bits not in (1, 2, 4, 8):
            raise ValueError("bits moet 1, 2, 4 of 8 zijn")
        return cls(bits, bytearray((posities * bits + 7) // 8))

    @classmethod
    def decodeer(cls, lst: str, bits: int) -> Statuslijst:
        """Lees `lst` (base64url van zlib-gecomprimeerde bytes)."""
        if bits not in (1, 2, 4, 8):
            raise StatuslijstFout("bits_ongeldig", str(bits))
        try:
            d = zlib.decompressobj()
            inhoud = d.decompress(b64url_decode(lst), MAX_BYTES + 1)
        except (zlib.error, ValueError) as fout:
            raise StatuslijstFout("lst_ongeldig", str(fout)) from fout
        if len(inhoud) > MAX_BYTES:
            raise StatuslijstFout("lst_te_groot", f"meer dan {MAX_BYTES} bytes")
        if not d.eof:
            raise StatuslijstFout("lst_ongeldig", "zlib-stroom is afgeknot of onvolledig")
        return cls(bits, bytearray(inhoud))

    @property
    def posities(self) -> int:
        """Aantal posities in de lijst."""
        return len(self.inhoud) * 8 // self.bits

    def lees(self, idx: int) -> int:
        """Statuswaarde op `idx`; buiten de lijst is een fout (§8.3 stap 6)."""
        if not isinstance(idx, int) or idx < 0 or idx >= self.posities:
            raise StatuslijstFout("idx_buiten_lijst", str(idx))
        byte, verschuiving = divmod(idx * self.bits, 8)
        return (self.inhoud[byte] >> verschuiving) & ((1 << self.bits) - 1)

    def zet(self, idx: int, waarde: int) -> None:
        """Zet de statuswaarde op `idx`."""
        if idx < 0 or idx >= self.posities:
            raise StatuslijstFout("idx_buiten_lijst", str(idx))
        if waarde < 0 or waarde >= 1 << self.bits:
            raise ValueError(f"waarde {waarde} past niet in {self.bits} bit(s)")
        byte, verschuiving = divmod(idx * self.bits, 8)
        masker = ((1 << self.bits) - 1) << verschuiving
        self.inhoud[byte] = (self.inhoud[byte] & ~masker) | (waarde << verschuiving)

    @property
    def lst(self) -> str:
        """Gecomprimeerde, base64url-gecodeerde inhoud."""
        return b64url(zlib.compress(bytes(self.inhoud), 9))


@dataclass(frozen=True)
class Tokenbeleid:
    """Hoe lang een Status List Token gecachet mag worden (`ttl`) en geldig is (`exp`)."""

    ttl_s: int
    geldig_s: int


def maak_token(
    sleutel: Sleutelpaar, uri: str, lijst: Statuslijst, beleid: Tokenbeleid, nu: int | None = None
) -> str:
    """Teken een Status List Token voor `uri`.

    Args:
        sleutel: Uitgeverssleutel.
        uri: URI waarop het token wordt gepubliceerd (`sub`).
        lijst: De lijst.
        beleid: `ttl` (aanbevolen cacheduur) en geldigheid tot `exp`; na `exp` mag een verifier
            het token niet meer gebruiken.
        nu: Huidige tijd, voor tests.
    """
    nu = int(time.time()) if nu is None else nu
    claims = {
        "iss": uri.rsplit("/statuslijsten/", 1)[0],
        "sub": uri,
        "iat": nu,
        "exp": nu + beleid.geldig_s,
        "ttl": beleid.ttl_s,
        "status_list": {"bits": lijst.bits, "lst": lijst.lst},
    }
    return sleutel.teken({"typ": TYP}, claims)


@dataclass(frozen=True)
class Statustoken:
    """Een gelezen en geverifieerd Status List Token."""

    claims: dict[str, Any]
    lijst: Statuslijst

    @property
    def ttl(self) -> int:
        """Cacheduur in seconden."""
        return int(self.claims["ttl"])

    @property
    def exp(self) -> int:
        """Verlooptijd."""
        return int(self.claims["exp"])

    @property
    def iat(self) -> int:
        """Uitgiftetijd, om een ouder token niet over een nieuwer heen te schrijven."""
        return int(self.claims["iat"])


def _claims_uit_token(token: str, sleutel: ECKey) -> dict[str, Any]:
    try:
        kop = jose_kop(token)
    except ValueError as fout:
        raise StatuslijstFout("token_ongeldig", str(fout)) from fout
    if kop.get("typ") != TYP:
        raise StatuslijstFout("typ_onjuist", str(kop.get("typ")))
    if kop.get("alg") != ALG:
        raise StatuslijstFout("alg_onjuist", str(kop.get("alg")))
    try:
        claims = json.loads(jws.deserialize_compact(token, sleutel, algorithms=[ALG]).payload)
    except (JoseError, ValueError) as fout:
        raise StatuslijstFout("handtekening_ongeldig", str(fout)) from fout
    if not isinstance(claims, dict):
        raise StatuslijstFout("token_ongeldig", "payload is geen object")
    return claims


def _is_geheel(waarde: Any) -> bool:
    return isinstance(waarde, int) and not isinstance(waarde, bool)


def _controleer_tijden(claims: dict[str, Any], nu: int) -> None:
    for naam in ("iat", "exp", "ttl"):
        if not _is_geheel(claims[naam]):
            raise StatuslijstFout("claim_ongeldig", f"{naam} is geen geheel getal")
    if claims["ttl"] <= 0:
        raise StatuslijstFout("claim_ongeldig", "ttl moet positief zijn")
    if claims["exp"] <= nu:
        raise StatuslijstFout("token_verlopen", str(claims["exp"]))


def _controleer_claims(claims: dict[str, Any], uri: str, nu: int) -> None:
    ontbrekend = [n for n in ("sub", "iat", "exp", "ttl", "status_list") if n not in claims]
    if ontbrekend:
        raise StatuslijstFout("claim_ontbreekt", ", ".join(ontbrekend))
    if claims["sub"] != uri:
        raise StatuslijstFout("sub_onjuist", f"{claims['sub']!r} is niet {uri!r}")
    _controleer_tijden(claims, nu)
    sl = claims["status_list"]
    goed = isinstance(sl, dict) and _is_geheel(sl.get("bits")) and isinstance(sl.get("lst"), str)
    if not goed:
        raise StatuslijstFout(
            "status_list_ongeldig", "bits of lst ontbreekt of heeft verkeerd type"
        )


def lees_token(token: str, sleutel: ECKey, uri: str, nu: int | None = None) -> Statustoken:
    """Verifieer een Status List Token (§8.3 stap 3 en 4) en decodeer de lijst.

    Raises:
        StatuslijstFout: Bij een verkeerde typ, handtekening, `sub`, verlopen `exp`, ontbrekende
            of verkeerd getypte claims.
    """
    nu = int(time.time()) if nu is None else nu
    claims = _claims_uit_token(token, sleutel)
    _controleer_claims(claims, uri, nu)
    sl = claims["status_list"]
    return Statustoken(claims, Statuslijst.decodeer(sl["lst"], sl["bits"]))
