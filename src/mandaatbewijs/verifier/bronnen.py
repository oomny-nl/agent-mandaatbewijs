"""Publieke bronnen van een uitgever, veilig opgehaald en gecachet: metadata, JWKS, statuslijst.

Ophalen (ONTWERP §7): dezelfde oorsprong als `iss`, `https` tenzij `STA_HTTP_TOE=1`, adrescontrole
vóór de verbinding, geen redirects, hoogstens 64 KiB en 5 seconden voor naamresolutie en
download samen.

Statuscache (ONTWERP §7): bruikbaar zolang `opgehaald + ttl > nu` én `nu < exp`; bij een netwerkfout
overbrugging tot `exp`; een ontvangen maar ongeldig token maakt de cache onbruikbaar tot een
geldige verversing. Gelijktijdige verversingen van dezelfde lijst worden geserialiseerd. Het
token met de hoogste `iat` blijft bewaard, ook als de cache onbruikbaar is: een ouder token
vervangt het nooit en bevestigt het ook niet (het telt als mislukte verversing), en een ander
token met dezelfde `iat` maar een andere lijst maakt de cache onbruikbaar. Een achtergrondtaak
ververst elke bekende lijst elke `ttl` seconden.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx2
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from mandaatbewijs.sleutels import publieke_sleutel
from mandaatbewijs.statuslijst import MEDIATYPE, StatuslijstFout, Statustoken, lees_token
from mandaatbewijs.verifier.vertrouwenslijst import Uitgever

MAX_ANTWOORD = 64 * 1024
TIMEOUT_S = 5.0
JWKS_CACHE_S = 300
JWKS_HERHAAL_S = 10

# Alleen deze netwerken mogen in de demo (`STA_HTTP_TOE=1`) voor een host op de vertrouwenslijst:
# RFC 1918, ULA en loopback (lokaal draaien zonder Docker). Link-local (zoals 169.254.169.254),
# shared address space en andere niet-publieke adressen blijven altijd geweigerd.
DEMO_NETWERKEN = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


class BronFout(Exception):
    """Een bron kon niet worden gebruikt; `klasse` is `netwerk` of `ongeldig`."""

    def __init__(self, reden: str, klasse: str, detail: str = "") -> None:
        super().__init__(f"{reden}: {detail}" if detail else reden)
        self.reden = reden
        self.klasse = klasse


def _zelfde_oorsprong(a: str, b: str) -> bool:
    sa, sb = urlsplit(a), urlsplit(b)
    return (sa.scheme, sa.hostname, sa.port) == (sb.scheme, sb.hostname, sb.port)


def _adressen_toegestaan(
    adressen: set[str], host: str, http_toe: bool, vertrouwde_hosts: frozenset[str]
) -> bool:
    """Of elk opgelost adres publiek is, of (demo) een RFC1918/ULA-adres van een vertrouwde host."""
    if not adressen:
        return False
    for adres in adressen:
        ip = ipaddress.ip_address(adres.split("%", 1)[0])
        if ip.is_multicast:  # `is_global` sluit multicast niet uit
            return False
        if ip.is_global:
            continue
        demo = http_toe and host in vertrouwde_hosts and any(ip in n for n in DEMO_NETWERKEN)
        if not demo:
            return False
    return True


def _adres_toegestaan(host: str, http_toe: bool, vertrouwde_hosts: frozenset[str]) -> bool:
    """Synchrone variant (resolutie via `socket.getaddrinfo`), voor tests en hulpscripts."""
    try:
        adressen = {str(info[4][0]) for info in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False
    return _adressen_toegestaan(adressen, host, http_toe, vertrouwde_hosts)


@dataclass
class Ophaler:
    """Haalt URL's op binnen de grenzen van ONTWERP §7."""

    http_toe: bool
    vertrouwde_hosts: frozenset[str]
    client: httpx2.AsyncClient = field(
        default_factory=lambda: httpx2.AsyncClient(timeout=TIMEOUT_S, follow_redirects=False)
    )

    def controleer_url(self, url: str, iss: str) -> None:
        """Weiger een URL met een verkeerd schema of een andere oorsprong dan `iss`.

        De adrescontrole gebeurt in `haal`, na asynchrone naamresolutie.
        """
        delen = urlsplit(url)
        if delen.scheme != "https" and not (delen.scheme == "http" and self.http_toe):
            raise BronFout("url_schema_ongeldig", "ongeldig", url)
        if not _zelfde_oorsprong(url, iss):
            raise BronFout("url_andere_oorsprong", "ongeldig", f"{url} hoort niet bij {iss}")

    async def _controleer_adres(self, host: str) -> None:
        loop = asyncio.get_running_loop()
        try:
            info = await loop.getaddrinfo(host, None)
        except socket.gaierror as fout:
            raise BronFout("adres_onbekend", "netwerk", f"{host}: {fout}") from fout
        adressen = {str(i[4][0]) for i in info}
        if not _adressen_toegestaan(adressen, host, self.http_toe, self.vertrouwde_hosts):
            raise BronFout("adres_niet_toegestaan", "ongeldig", host)

    async def haal(self, url: str, iss: str, accept: str) -> httpx2.Response:
        """Haal een URL op; netwerkfouten, HTTP-fouten en de tijdslimiet zijn klasse `netwerk`."""
        self.controleer_url(url, iss)
        try:
            async with asyncio.timeout(TIMEOUT_S):
                await self._controleer_adres(urlsplit(url).hostname or "")
                return await self._download(url, accept)
        except TimeoutError as fout:
            raise BronFout("netwerkfout", "netwerk", f"{url}: tijdslimiet") from fout
        except httpx2.HTTPError as fout:
            raise BronFout("netwerkfout", "netwerk", f"{url}: {fout}") from fout

    async def _download(self, url: str, accept: str) -> httpx2.Response:
        async with self.client.stream("GET", url, headers={"Accept": accept}) as antwoord:
            if antwoord.status_code != 200:
                raise BronFout("http_status", "netwerk", f"{url} gaf {antwoord.status_code}")
            inhoud = bytearray()
            async for deel in antwoord.aiter_bytes():
                inhoud.extend(deel)
                if len(inhoud) > MAX_ANTWOORD:
                    raise BronFout("antwoord_te_groot", "ongeldig", url)
            return httpx2.Response(
                200, content=bytes(inhoud), headers=antwoord.headers, request=antwoord.request
            )


def _max_age(antwoord: httpx2.Response, standaard: int) -> int | None:
    """Cacheduur uit `Cache-Control`; None bij `no-store`."""
    cc = antwoord.headers.get("cache-control", "")
    if "no-store" in cc:
        return None
    gevonden = re.search(r"max-age=(\d+)", cc)
    return min(standaard, int(gevonden.group(1))) if gevonden else standaard


def _json(antwoord: httpx2.Response, reden: str) -> Any:
    try:
        return antwoord.json()
    except ValueError as fout:
        raise BronFout(reden, "ongeldig", "antwoord is geen JSON") from fout


@dataclass
class JwksCache:
    """Sleutels van één uitgever, via de metadata op `/.well-known/jwt-vc-issuer`."""

    sleutels: dict[str, ECKey] = field(default_factory=dict)
    geldig_tot: float = 0.0
    laatste_poging: float = 0.0
    slot: asyncio.Lock = field(default_factory=asyncio.Lock)


class Sleutelbron:
    """Uitgeverssleutels per `iss`, met cache en begrensde gedwongen verversing."""

    def __init__(self, ophaler: Ophaler) -> None:
        self.ophaler = ophaler
        self._caches: dict[str, JwksCache] = {}

    async def sleutel(self, uitgever: Uitgever, kid: str) -> ECKey:
        """Sleutel bij `kid`.

        Alleen een sleutel uit een nog geldige cache of uit een zojuist geslaagde ophaalactie is
        bruikbaar. Haalt hoogstens eens per 10 seconden op, ook als de cache leeg of verlopen is;
        gelijktijdige aanvragen wachten op één ophaalactie. Binnen die 10 seconden wordt
        geweigerd: `kid_onbekend` bij een geldige cache zonder deze kid, anders
        `jwks_niet_beschikbaar` (klasse `netwerk`).
        """
        cache = self._caches.setdefault(uitgever.iss, JwksCache())
        async with cache.slot:
            nu = time.time()
            geldig = cache.geldig_tot > nu
            if geldig and kid in cache.sleutels:
                return cache.sleutels[kid]
            if cache.laatste_poging + JWKS_HERHAAL_S > nu:
                if geldig:
                    raise BronFout("kid_onbekend", "ongeldig", kid)
                raise BronFout("jwks_niet_beschikbaar", "netwerk", f"{uitgever.iss}: wacht {kid}")
            cache.laatste_poging = nu
            sleutels = await self._ververs(uitgever, cache)
            if kid not in sleutels:
                raise BronFout("kid_onbekend", "ongeldig", kid)
            return sleutels[kid]

    async def _ververs(self, uitgever: Uitgever, cache: JwksCache) -> dict[str, ECKey]:
        """Haal de sleutels op; bewaar ze alleen als het antwoord caching toestaat."""
        meta_url = f"{uitgever.iss}/.well-known/jwt-vc-issuer"
        antwoord = await self.ophaler.haal(meta_url, uitgever.iss, "application/json")
        meta = _json(antwoord, "uitgever_metadata_onjuist")
        if not isinstance(meta, dict) or meta.get("issuer") != uitgever.iss:
            raise BronFout("uitgever_metadata_onjuist", "ongeldig", f"issuer ≠ {uitgever.iss}")
        if "jwks" in meta and "jwks_uri" in meta:
            raise BronFout("uitgever_metadata_onjuist", "ongeldig", "jwks én jwks_uri aanwezig")
        if "jwks" in meta:
            jwks, duur = meta["jwks"], _max_age(antwoord, JWKS_CACHE_S)
        else:
            jwks_uri = str(meta.get("jwks_uri", ""))
            antwoord = await self.ophaler.haal(jwks_uri, uitgever.iss, "application/json")
            jwks, duur = _json(antwoord, "jwks_ongeldig"), _max_age(antwoord, JWKS_CACHE_S)
        sleutels = _lees_jwks(jwks)
        # `no-store` of `max-age=0`: alleen voor deze aanvraag, niet voor volgende.
        cache.sleutels = sleutels if duur else {}
        cache.geldig_tot = time.time() + duur if duur else 0.0
        return sleutels


def _lees_jwks(jwks: Any) -> dict[str, ECKey]:
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise BronFout("jwks_ongeldig", "ongeldig", "geen keys-lijst")
    sleutels: dict[str, ECKey] = {}
    for jwk in jwks["keys"]:
        if not isinstance(jwk, dict) or not isinstance(jwk.get("kid"), str):
            raise BronFout("jwks_ongeldig", "ongeldig", "sleutel zonder kid")
        try:
            sleutels[jwk["kid"]] = publieke_sleutel(jwk)
        except (ValueError, JoseError, TypeError, KeyError) as fout:
            raise BronFout("jwks_ongeldig", "ongeldig", str(fout)) from fout
    return sleutels


@dataclass
class Statuscache:
    """Cache van één statuslijst."""

    token: Statustoken | None = None
    opgehaald: float = 0.0
    onbruikbaar: bool = False
    uitgever: Uitgever | None = None
    slot: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass(frozen=True)
class Statusuitkomst:
    """Statuswaarde op `idx` en de bron ervan (`vers`, `cache` of `cache-verouderd`)."""

    waarde: int
    bron: str


class Statusbron:
    """Statuslijsten per URI, met de cacheregels uit ONTWERP §7."""

    def __init__(self, ophaler: Ophaler, sleutelbron: Sleutelbron) -> None:
        self.ophaler = ophaler
        self.sleutelbron = sleutelbron
        self._caches: dict[str, Statuscache] = {}

    @property
    def bekende_uris(self) -> list[str]:
        """URI's die ooit zijn opgevraagd (voor de achtergrondverversing)."""
        return list(self._caches)

    def _bruikbaar(self, cache: Statuscache, nu: float) -> bool:
        t = cache.token
        return (
            t is not None and not cache.onbruikbaar and cache.opgehaald + t.ttl > nu and nu < t.exp
        )

    async def ververs(self, uri: str, uitgever: Uitgever) -> None:
        """Haal de lijst op; een ongeldig token maakt de cache onbruikbaar, een netwerkfout niet.

        Gelijktijdige verversingen van dezelfde URI wachten op elkaar; wie na het wachten een
        zojuist ververste, bruikbare cache aantreft, haalt niet opnieuw op.
        """
        cache = self._caches.setdefault(uri, Statuscache())
        cache.uitgever = uitgever
        self.ophaler.controleer_url(uri, uitgever.iss)
        begin = time.time()
        async with cache.slot:
            if cache.opgehaald >= begin and self._bruikbaar(cache, time.time()):
                return
            try:
                antwoord = await self.ophaler.haal(uri, uitgever.iss, MEDIATYPE)
                mediatype = antwoord.headers.get("content-type", "")
                if not mediatype.startswith(MEDIATYPE):
                    raise BronFout("mediatype_onjuist", "netwerk", mediatype)
                token = await self._lees(antwoord.text, uitgever, uri)
            except BronFout as fout:
                if fout.klasse == "ongeldig":
                    cache.onbruikbaar = True
                raise
            self._vergelijk_met_cache(cache, token)
            cache.token, cache.opgehaald, cache.onbruikbaar = token, time.time(), False

    @staticmethod
    @staticmethod
    def _vergelijk_met_cache(cache: Statuscache, token: Statustoken) -> None:
        """Weiger een token dat het gecachete token (hoogste `iat`) zou terugdraaien.

        Dat geldt ook als de cache onbruikbaar is. Een ouder token (bijvoorbeeld van een
        vertraagde download) telt als mislukte verversing van klasse `netwerk`: de cache wordt
        niet vervangen en ook niet als vers bevestigd. Hetzelfde token opnieuw (zelfde `iat`,
        zelfde lijst) bevestigt een bruikbare cache, maar herstelt een onbruikbare niet; daarvoor
        is een nieuwer token nodig. Dezelfde `iat` met een andere lijst kan bij deze uitgever
        niet (zijn `iat` stijgt strikt) en maakt de cache onbruikbaar.
        """
        oud = cache.token
        if oud is None or token.iat > oud.iat:
            return
        zelfde = (token.lijst.bits, token.lijst.inhoud) == (oud.lijst.bits, oud.lijst.inhoud)
        if token.iat == oud.iat and zelfde and not cache.onbruikbaar:
            return
        if token.iat < oud.iat or zelfde:
            raise BronFout("statustoken_verouderd", "netwerk", f"iat {token.iat}, cache {oud.iat}")
        cache.onbruikbaar = True
        raise BronFout("statustoken_tegenstrijdig", "ongeldig", f"twee lijsten met iat {oud.iat}")

    async def _lees(self, tekst: str, uitgever: Uitgever, uri: str) -> Statustoken:
        from joserfc import jws  # noqa: PLC0415

        try:
            kid = jws.extract_compact(tekst.encode()).protected.get("kid")
        except (JoseError, ValueError) as fout:
            raise BronFout("statustoken_ongeldig", "ongeldig", str(fout)) from fout
        if not isinstance(kid, str):
            raise BronFout("statustoken_ongeldig", "ongeldig", "geen kid")
        sleutel = await self.sleutelbron.sleutel(uitgever, kid)
        try:
            return lees_token(tekst, sleutel, uri)
        except StatuslijstFout as fout:
            raise BronFout(f"statustoken_{fout.reden}", "ongeldig", str(fout)) from fout

    async def status(self, uri: str, idx: int, uitgever: Uitgever) -> Statusuitkomst:
        """Statuswaarde op `idx` volgens de cacheregels.

        Raises:
            BronFout: `status_onbekend` als er geen bruikbare lijst is.
        """
        # Ook bij een cachehit: de lijst moet van dezelfde oorsprong zijn als de uitgever van de
        # credential, anders kan een credential naar de (gecachete) lijst van een ander wijzen.
        if not _zelfde_oorsprong(uri, uitgever.iss):
            raise BronFout(
                "url_andere_oorsprong", "ongeldig", f"{uri} hoort niet bij {uitgever.iss}"
            )
        cache = self._caches.setdefault(uri, Statuscache())
        if self._bruikbaar(cache, time.time()):
            return Statusuitkomst(self._lees_idx(cache, idx), "cache")
        try:
            await self.ververs(uri, uitgever)
        except BronFout as fout:
            t = cache.token
            nu = time.time()  # na de (mislukte) download, niet ervoor: overbrugging stopt op exp
            if fout.klasse == "netwerk" and not cache.onbruikbaar and t is not None and nu < t.exp:
                return Statusuitkomst(self._lees_idx(cache, idx), "cache-verouderd")
            raise BronFout("status_onbekend", fout.klasse, str(fout)) from fout
        return Statusuitkomst(self._lees_idx(cache, idx), "vers")

    @staticmethod
    def _lees_idx(cache: Statuscache, idx: int) -> int:
        if cache.token is None:
            raise BronFout("status_onbekend", "ongeldig", "geen token")
        if cache.token.lijst.bits != 1:
            raise BronFout("status_onbekend", "ongeldig", "bits ≠ 1")
        try:
            return cache.token.lijst.lees(idx)
        except StatuslijstFout as fout:
            raise BronFout("status_onbekend", "ongeldig", str(fout)) from fout

    async def ververs_alles(self) -> None:
        """Achtergrondverversing van alle bekende lijsten; fouten blijven in de cachetoestand."""
        for uri, cache in list(self._caches.items()):
            if cache.uitgever is None:
                continue
            try:
                await self.ververs(uri, cache.uitgever)
            except BronFout:
                continue
