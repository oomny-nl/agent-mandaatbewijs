"""SD-JWT (draft-ietf-oauth-selective-disclosure-jwt-22) en het SD-JWT VC-profiel (draft-19).

Drie rollen, drie functies:

- uitgever: `geef_uit` maakt een SD-JWT met `_sd`-digests voor objectclaims, `...`-digests voor
  array-elementen en decoy-digests;
- houder: `presenteer` kiest disclosures en tekent een key binding JWT (`kb+jwt`) met `aud`,
  `nonce` en `sd_hash`;
- verifier: `ontleed` en `verifieer` volgen §7.1 en §7.3 van de draft: elke disclosure hoort bij
  precies één digest, geen dubbele claimnamen, geen `_sd` of `...` als claimnaam, verlopen of
  nog niet geldige tokens worden geweigerd.

De digest is SHA-256 over de US-ASCII-bytes van de base64url-gecodeerde disclosure (§4.2.3).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from mandaatbewijs.sleutels import ALG, Sleutelpaar, publieke_sleutel

TYP_VC = "dc+sd-jwt"
TYP_KB = "kb+jwt"
SD_ALG = "sha-256"
KLOKMARGE_S = 30
KB_GELDIGHEID_S = 60
MAX_PRESENTATIE = 16 * 1024


class SdJwtFout(Exception):
    """Ongeldige SD-JWT of presentatie; `reden` is een korte code voor audit en challenge."""

    def __init__(self, reden: str, detail: str = "") -> None:
        super().__init__(f"{reden}: {detail}" if detail else reden)
        self.reden = reden
        self.detail = detail


def b64url(data: bytes) -> str:
    """Base64url zonder padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(tekst: str) -> bytes:
    """Base64url-decodering met aangevuld padding."""
    return base64.urlsafe_b64decode(tekst + "=" * (-len(tekst) % 4))


def digest(disclosure: str) -> str:
    """Digest van een gecodeerde disclosure (§4.2.3)."""
    return b64url(hashlib.sha256(disclosure.encode("ascii")).digest())


# SD-JWT VC §2.2.2.3 (iss, nbf, exp, cnf, vct, vct#integrity, status) plus dit mandaatprofiel
# (iat, jti) en het niet-ondersteunde aka_vcts; ook hun subclaims mogen niet selectief zijn.
NIET_DISCLOSABLE = frozenset(
    {"iss", "vct", "vct#integrity", "aka_vcts", "jti", "iat", "nbf", "exp", "cnf", "status"}
)


@dataclass(frozen=True)
class Disclosure:
    """Eén disclosure: zout, claimnaam (None voor een array-element) en waarde.

    `ruw` is de ontvangen base64url-tekst; die bepaalt digest en `sd_hash`, nooit een
    her-serialisatie (RFC 9901 §4.3.1).
    """

    zout: str
    naam: str | None
    waarde: Any
    ruw: str | None = None

    @classmethod
    def nieuw(cls, naam: str | None, waarde: Any) -> Disclosure:
        """Nieuwe disclosure met 128 bits zout (§9.3)."""
        return cls(b64url(secrets.token_bytes(16)), naam, waarde)

    @classmethod
    def decodeer(cls, gecodeerd: str) -> Disclosure:
        """Lees een gecodeerde disclosure; weigert alles wat geen lijst van 2 of 3 is."""
        try:
            inhoud = json.loads(b64url_decode(gecodeerd))
        except (ValueError, UnicodeDecodeError) as fout:
            raise SdJwtFout("disclosure_ongeldig", "geen JSON") from fout
        if not isinstance(inhoud, list) or len(inhoud) not in (2, 3):
            raise SdJwtFout("disclosure_ongeldig", "geen lijst van 2 of 3 elementen")
        if not isinstance(inhoud[0], str):
            raise SdJwtFout("disclosure_ongeldig", "zout is geen string")
        if len(inhoud) == 3:
            if not isinstance(inhoud[1], str):
                raise SdJwtFout("disclosure_ongeldig", "claimnaam is geen string")
            return cls(inhoud[0], inhoud[1], inhoud[2], gecodeerd)
        return cls(inhoud[0], None, inhoud[1], gecodeerd)

    @property
    def gecodeerd(self) -> str:
        """De ontvangen tekst, of anders base64url van de JSON-lijst."""
        if self.ruw is not None:
            return self.ruw
        if self.naam is None:
            lijst = [self.zout, self.waarde]
        else:
            lijst = [self.zout, self.naam, self.waarde]
        return b64url(json.dumps(lijst, separators=(",", ":"), ensure_ascii=False).encode())

    @property
    def digest(self) -> str:
        """Digest van deze disclosure."""
        return digest(self.gecodeerd)


# Uitgever ---------------------------------------------------------------------------------------


def geef_uit(
    sleutel: Sleutelpaar,
    claims: dict[str, Any],
    verborgen: set[str],
    per_element: set[str],
    decoys: int = 2,
) -> tuple[str, list[Disclosure]]:
    """Maak een SD-JWT.

    Args:
        sleutel: Uitgeverssleutel (met kid).
        claims: Alle claims, inclusief de altijd zichtbare.
        verborgen: Claimnamen die als geheel selectief bekend te maken zijn (`_sd`).
        per_element: Claimnamen van lijsten waarvan elk element apart bekend te maken is (`...`).
        decoys: Aantal decoy-digests in `_sd`.

    Returns:
        De uitgiftevorm `<jwt>~<d1>~…~<dn>~` en de disclosures.
    """
    payload: dict[str, Any] = {}
    disclosures: list[Disclosure] = []
    sd_digests: list[str] = []
    for naam, waarde in claims.items():
        if naam in verborgen:
            d = Disclosure.nieuw(naam, waarde)
            disclosures.append(d)
            sd_digests.append(d.digest)
        elif naam in per_element:
            elementen = []
            for element in waarde:
                d = Disclosure.nieuw(None, element)
                disclosures.append(d)
                elementen.append({"...": d.digest})
            payload[naam] = elementen
        else:
            payload[naam] = waarde
    sd_digests.extend(digest(b64url(secrets.token_bytes(16))) for _ in range(decoys))
    if sd_digests:
        payload["_sd"] = sorted(sd_digests)
    payload["_sd_alg"] = SD_ALG
    jwt = sleutel.teken({"typ": TYP_VC}, payload)
    return serialiseer(jwt, disclosures, None), disclosures


def serialiseer(jwt: str, disclosures: list[Disclosure], kb: str | None) -> str:
    """Compacte serialisatie: `<jwt>~<d1>~…~<dn>~[<kb-jwt>]`."""
    return "~".join([jwt, *[d.gecodeerd for d in disclosures], kb or ""])


# Houder -----------------------------------------------------------------------------------------


@dataclass
class Credential:
    """Een ontvangen SD-JWT aan houderskant: de issuer-signed JWT met alle disclosures."""

    jwt: str
    disclosures: list[Disclosure]
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def uit_serialisatie(cls, serialisatie: str) -> Credential:
        """Lees de uitgiftevorm; een SD-JWT+KB wordt geweigerd (§7.2)."""
        jwt, disclosures, kb = _splits(serialisatie)
        if kb:
            raise SdJwtFout("credential_ongeldig", "uitgiftevorm bevat een key binding JWT")
        payload = _payload_zonder_controle(jwt)
        return cls(jwt, disclosures, payload)

    def disclosure_voor(self, naam: str, element: Any = None) -> Disclosure | None:
        """De disclosure van een objectclaim, of van één element van een lijstclaim."""
        if element is None:
            return next((d for d in self.disclosures if d.naam == naam), None)
        lijst = self.payload.get(naam)
        if not isinstance(lijst, list):
            return None
        digests = {e["..."] for e in lijst if isinstance(e, dict) and "..." in e}
        for d in self.disclosures:
            if d.naam is None and d.waarde == element and d.digest in digests:
                return d
        return None

    @property
    def verborgen_namen(self) -> list[str]:
        """Namen van objectclaims die alleen via een disclosure bekend worden."""
        return sorted(d.naam for d in self.disclosures if d.naam is not None)


def sd_hash(jwt: str, disclosures: list[Disclosure]) -> str:
    """`sd_hash` over `<jwt>~<d1>~…~<dn>~` (§4.3.1)."""
    tekst = serialiseer(jwt, disclosures, None)
    return b64url(hashlib.sha256(tekst.encode("ascii")).digest())


def presenteer(
    credential: Credential,
    gekozen: list[Disclosure],
    sleutel: Sleutelpaar,
    aud: str,
    nonce: str,
) -> str:
    """Maak een SD-JWT+KB met alleen de gekozen disclosures, getekend door de houder.

    Args:
        credential: De ontvangen credential.
        gekozen: Disclosures die bekend worden gemaakt.
        sleutel: Sleutel van de houder (hoort bij `cnf.jwk`).
        aud: Identifier van de verifier.
        nonce: Nonce van de verifier.

    Returns:
        De presentatie `<jwt>~<d1>~…~<dn>~<kb-jwt>`.
    """
    kb_claims = {
        "iat": int(time.time()),
        "aud": aud,
        "nonce": nonce,
        "sd_hash": sd_hash(credential.jwt, gekozen),
    }
    kb = sleutel.teken({"typ": TYP_KB}, kb_claims)
    return serialiseer(credential.jwt, gekozen, kb)


# Verifier ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Ontleed:
    """Een presentatie, opgesplitst maar nog niet geverifieerd."""

    jwt: str
    disclosures: list[Disclosure]
    kb: str
    kop: dict[str, Any]
    claims_zonder_controle: dict[str, Any]

    @property
    def iss(self) -> str:
        """Uitgever volgens de (nog ongecontroleerde) payload."""
        return str(self.claims_zonder_controle.get("iss", ""))

    @property
    def vct(self) -> str:
        """Credentialtype volgens de (nog ongecontroleerde) payload."""
        return str(self.claims_zonder_controle.get("vct", ""))


@dataclass(frozen=True)
class Geverifieerd:
    """Uitkomst van een geslaagde verificatie."""

    claims: dict[str, Any]
    bekendgemaakt: list[str]
    nonce: str
    jkt: str


def _splits(serialisatie: str) -> tuple[str, list[Disclosure], str]:
    if len(serialisatie) > MAX_PRESENTATIE:
        raise SdJwtFout("presentatie_te_groot", f"meer dan {MAX_PRESENTATIE} bytes")
    delen = serialisatie.split("~")
    if len(delen) < 2:
        raise SdJwtFout("presentatie_ongeldig", "geen ~ gevonden")
    return delen[0], [Disclosure.decodeer(d) for d in delen[1:-1]], delen[-1]


def _payload_zonder_controle(jwt: str) -> dict[str, Any]:
    try:
        obj = jws.extract_compact(jwt.encode())
    except (JoseError, ValueError) as fout:
        raise SdJwtFout("jwt_ongeldig", str(fout)) from fout
    try:
        payload = json.loads(obj.payload)
    except ValueError as fout:
        raise SdJwtFout("jwt_ongeldig", "payload is geen JSON") from fout
    if not isinstance(payload, dict):
        raise SdJwtFout("jwt_ongeldig", "payload is geen object")
    return payload


def ontleed(presentatie: str) -> Ontleed:
    """Splits een presentatie en lees kop en payload zonder handtekeningcontrole.

    Daarmee kan de verifier eerst `iss` tegen de vertrouwenslijst toetsen voordat hij sleutels
    ophaalt. Niets uit `claims_zonder_controle` mag worden vertrouwd vóór `verifieer`.
    """
    jwt, disclosures, kb = _splits(presentatie)
    if not kb:
        raise SdJwtFout("kb_ontbreekt", "presentatie zonder key binding JWT")
    try:
        kop = jws.extract_compact(jwt.encode()).protected
    except (JoseError, ValueError) as fout:
        raise SdJwtFout("jwt_ongeldig", str(fout)) from fout
    return Ontleed(jwt, disclosures, kb, dict(kop), _payload_zonder_controle(jwt))


def _controleer_kop(kop: dict[str, Any], typ: str) -> None:
    if kop.get("typ") != typ:
        raise SdJwtFout("typ_onjuist", f"verwacht typ {typ}, kreeg {kop.get('typ')!r}")
    if kop.get("alg") != ALG:
        raise SdJwtFout("alg_onjuist", f"alleen {ALG} is toegestaan, kreeg {kop.get('alg')!r}")


def _verifieer_jws(jwt: str, sleutel: ECKey, typ: str) -> dict[str, Any]:
    try:
        kop = dict(jws.extract_compact(jwt.encode()).protected)
    except (JoseError, ValueError) as fout:
        raise SdJwtFout("jwt_ongeldig", f"{typ}: {fout}") from fout
    _controleer_kop(kop, typ)
    try:
        obj = jws.deserialize_compact(jwt, sleutel, algorithms=[ALG])
    except (JoseError, ValueError) as fout:
        raise SdJwtFout("handtekening_ongeldig", f"{typ}: {fout}") from fout
    try:
        payload = json.loads(obj.payload)
    except ValueError as fout:
        raise SdJwtFout("jwt_ongeldig", f"{typ}: payload is geen JSON") from fout
    if not isinstance(payload, dict):
        raise SdJwtFout("jwt_ongeldig", "payload is geen object")
    return payload


def _tijdvenster(claims: dict[str, Any], nu: int) -> None:
    for naam in ("nbf", "exp"):
        if naam in claims and (not isinstance(claims[naam], int) or isinstance(claims[naam], bool)):
            raise SdJwtFout("tijd_ongeldig", f"{naam} is geen geheel getal")
    if "exp" not in claims:
        raise SdJwtFout("exp_ontbreekt", "credential zonder exp")
    if claims["exp"] + KLOKMARGE_S < nu:
        raise SdJwtFout("credential_verlopen", f"exp {claims['exp']} < nu {nu}")
    if claims.get("nbf", 0) - KLOKMARGE_S > nu:
        raise SdJwtFout("credential_nog_niet_geldig", f"nbf {claims['nbf']} > nu {nu}")


class _Verwerker:
    """Vervangt digests door disclosures volgens §7.1 stap 3 en 4, en telt het gebruik."""

    def __init__(self, disclosures: list[Disclosure]) -> None:
        self.per_digest = {d.digest: d for d in disclosures}
        if len(self.per_digest) != len(disclosures):
            raise SdJwtFout("disclosure_dubbel", "twee gelijke disclosures")
        self.gezien: set[str] = set()
        self.gebruikt: set[str] = set()
        self.bekendgemaakt: list[str] = []

    def _neem(self, dig: str) -> Disclosure | None:
        if dig in self.gezien:
            raise SdJwtFout("digest_dubbel", "digest komt meer dan eens voor")
        self.gezien.add(dig)
        d = self.per_digest.get(dig)
        if d is not None:
            self.gebruikt.add(dig)
        return d

    def verwerk(self, waarde: Any, naam: str | None = None) -> Any:
        """Verwerk een JSON-waarde recursief; `naam` is de claim waar de waarde onder hangt."""
        if isinstance(waarde, dict):
            return self._object(waarde)
        if isinstance(waarde, list):
            return self._lijst(waarde, naam)
        return waarde

    def _object(self, obj: dict[str, Any]) -> dict[str, Any]:
        uit: dict[str, Any] = {}
        for naam, waarde in obj.items():
            if naam in ("_sd", "_sd_alg"):
                continue
            uit[naam] = self.verwerk(waarde, naam)
        sd = obj.get("_sd", [])
        if not isinstance(sd, list) or not all(isinstance(x, str) for x in sd):
            raise SdJwtFout("sd_ongeldig", "_sd is geen lijst van strings")
        for dig in sd:
            d = self._neem(dig)
            if d is not None:
                naam = self._claimnaam(d, uit)
                uit[naam] = self.verwerk(d.waarde, naam)
                self._noteer(naam)
        return uit

    @staticmethod
    def _claimnaam(d: Disclosure, uit: dict[str, Any]) -> str:
        if d.naam is None:
            raise SdJwtFout("disclosure_ongeldig", "objectdisclosure zonder claimnaam")
        if d.naam in ("_sd", "...") or d.naam in uit:
            raise SdJwtFout("claimnaam_ongeldig", f"claimnaam {d.naam!r} is niet toegestaan")
        if d.naam in NIET_DISCLOSABLE:
            raise SdJwtFout("claimnaam_ongeldig", f"{d.naam!r} mag niet selectief zijn")
        return d.naam

    def _noteer(self, naam: str | None) -> None:
        if naam is not None and naam not in self.bekendgemaakt:
            self.bekendgemaakt.append(naam)

    def _lijst(self, lijst: list[Any], naam: str | None) -> list[Any]:
        uit = []
        for element in lijst:
            if _is_array_digest(element):
                d = self._neem(element["..."])
                if d is None:
                    continue
                if d.naam is not None:
                    raise SdJwtFout("disclosure_ongeldig", "array-disclosure met claimnaam")
                uit.append(self.verwerk(d.waarde))
                self._noteer(naam)
            else:
                uit.append(self.verwerk(element))
        return uit


def _is_array_digest(element: Any) -> bool:
    return isinstance(element, dict) and set(element) == {"..."} and isinstance(element["..."], str)


def _bevat_sd(waarde: Any) -> bool:
    """Of een subtree ergens een `_sd`-lid of een `...`-element heeft."""
    if isinstance(waarde, dict):
        return "_sd" in waarde or "..." in waarde or any(_bevat_sd(v) for v in waarde.values())
    if isinstance(waarde, list):
        return any(_bevat_sd(v) for v in waarde)
    return False


def verwerk_payload(
    payload: dict[str, Any], disclosures: list[Disclosure]
) -> tuple[dict[str, Any], list[str]]:
    """Pas disclosures toe op een geverifieerde payload (§7.1 stap 3 tot en met 5).

    Geeft ook de namen van de bekendgemaakte claims terug; een bekendgemaakt lijstelement telt
    als de naam van zijn lijstclaim (`acties`, `dossiers`).
    """
    if payload.get("_sd_alg", SD_ALG) != SD_ALG:
        raise SdJwtFout("sd_alg_onjuist", f"alleen {SD_ALG} wordt ondersteund")
    beschermd = [n for n in NIET_DISCLOSABLE if _bevat_sd(payload.get(n))]
    if beschermd:
        raise SdJwtFout("claimnaam_ongeldig", f"selectieve subclaims in {', '.join(beschermd)}")
    verwerker = _Verwerker(disclosures)
    claims = verwerker.verwerk(payload)
    ongebruikt = set(verwerker.per_digest) - verwerker.gebruikt
    if ongebruikt:
        raise SdJwtFout("disclosure_onbekend", f"{len(ongebruikt)} disclosure(s) horen nergens bij")
    return claims, sorted(verwerker.bekendgemaakt)


def _verifieer_kb(ontleed_: Ontleed, cnf_jwk: dict[str, Any], aud: str, nu: int) -> dict[str, Any]:
    try:
        houder = publieke_sleutel(cnf_jwk)
    except (ValueError, JoseError, TypeError) as fout:
        raise SdJwtFout("cnf_ongeldig", str(fout)) from fout
    try:
        kb = _verifieer_jws(ontleed_.kb, houder, TYP_KB)
    except SdJwtFout as fout:
        raise SdJwtFout(f"kb_{fout.reden}", fout.detail) from fout
    if kb.get("aud") != aud:
        raise SdJwtFout("aud_onjuist", f"kb aud {kb.get('aud')!r} is niet {aud!r}")
    iat = kb.get("iat")
    if not isinstance(iat, int) or abs(nu - iat) > KB_GELDIGHEID_S:
        raise SdJwtFout("kb_verlopen", f"iat {iat!r} buiten {KB_GELDIGHEID_S} s")
    if kb.get("sd_hash") != sd_hash(ontleed_.jwt, ontleed_.disclosures):
        raise SdJwtFout("sd_hash_onjuist", "kb hoort niet bij deze set disclosures")
    if not isinstance(kb.get("nonce"), str) or not kb["nonce"]:
        raise SdJwtFout("nonce_ontbreekt", "kb zonder nonce")
    return kb


def controleer_uitgifte(
    credential: Credential, sleutel: ECKey, iss: str, jkt: str
) -> dict[str, Any]:
    """Controleer een ontvangen credential aan houderskant vóór die in de portemonnee komt.

    Args:
        credential: De uitgiftevorm (issuer-signed JWT met alle disclosures).
        sleutel: Publieke sleutel van de uitgever die bij `kid` in de kop hoort.
        iss: Verwachte uitgever.
        jkt: Thumbprint van de eigen sleutel; `cnf.jwk` moet daarmee overeenkomen.

    Returns:
        De volledige claims na toepassing van alle disclosures.

    Raises:
        SdJwtFout: Bij een ongeldige handtekening, disclosure, `iss`, tijdvenster of key binding.
    """
    payload = _verifieer_jws(credential.jwt, sleutel, TYP_VC)
    claims, _ = verwerk_payload(payload, credential.disclosures)
    if claims.get("iss") != iss:
        raise SdJwtFout("iss_onjuist", f"{claims.get('iss')!r} is niet {iss!r}")
    _tijdvenster(claims, int(time.time()))
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise SdJwtFout("cnf_ontbreekt", "credential zonder cnf.jwk")
    try:
        gebonden = publieke_sleutel(cnf["jwk"]).thumbprint()
    except (ValueError, JoseError, TypeError, KeyError) as fout:
        raise SdJwtFout("cnf_ongeldig", str(fout)) from fout
    if gebonden != jkt:
        raise SdJwtFout("cnf_onjuist", "credential is aan een andere sleutel gebonden")
    _controleer_status_claim(claims)
    return claims


def _controleer_status_claim(claims: dict[str, Any]) -> None:
    status = claims.get("status")
    if status is None:
        return
    sl = status.get("status_list") if isinstance(status, dict) else None
    if not isinstance(sl, dict):
        raise SdJwtFout("status_ongeldig", "status zonder status_list")
    idx, uri = sl.get("idx"), sl.get("uri")
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        raise SdJwtFout("status_ongeldig", "idx is geen niet-negatief geheel getal")
    if not isinstance(uri, str) or not uri:
        raise SdJwtFout("status_ongeldig", "uri is geen string")


def verifieer(ontleed_: Ontleed, sleutel: ECKey, aud: str, nu: int | None = None) -> Geverifieerd:
    """Verifieer een SD-JWT+KB (§7.3): uitgever, disclosures, tijdvenster en key binding.

    De aanroeper heeft `iss` al tegen zijn vertrouwenslijst getoetst en de sleutel bij `kid`
    opgehaald. De nonce wordt teruggegeven en moet door de aanroeper eenmalig worden verbruikt.

    Args:
        ontleed_: Uitkomst van `ontleed`.
        sleutel: Publieke sleutel van de uitgever die bij `kid` hoort.
        aud: Eigen identifier van de verifier.
        nu: Huidige tijd (seconden), voor tests.

    Returns:
        De verwerkte claims, de bekendgemaakte claimnamen, de nonce en de thumbprint van de houder.

    Raises:
        SdJwtFout: Bij elke afwijking; de eerste afwijking telt.
    """
    nu = int(time.time()) if nu is None else nu
    payload = _verifieer_jws(ontleed_.jwt, sleutel, TYP_VC)
    claims, bekendgemaakt = verwerk_payload(payload, ontleed_.disclosures)
    _tijdvenster(claims, nu)
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise SdJwtFout("cnf_ontbreekt", "credential zonder cnf.jwk")
    _controleer_status_claim(claims)
    kb = _verifieer_kb(ontleed_, cnf["jwk"], aud, nu)
    jkt = publieke_sleutel(cnf["jwk"]).thumbprint()
    return Geverifieerd(claims, bekendgemaakt, kb["nonce"], jkt)
