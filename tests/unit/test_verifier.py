"""De verifier: bronnen (metadata, JWKS, statuslijst, cache) en de verificatiestappen."""

from __future__ import annotations

import asyncio
import json
import math
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx2
import pytest
from starlette.testclient import TestClient

from mandaatbewijs.houder.portemonnee import Portemonnee
from mandaatbewijs.sdjwt import Credential, geef_uit, presenteer
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.statuslijst import Statuslijst, Tokenbeleid, maak_token
from mandaatbewijs.uitgever.app import Dienst
from mandaatbewijs.uitgever.gegevens import VCT
from mandaatbewijs.uitgever.uitgifte import PER_ELEMENT, VERBORGEN
from mandaatbewijs.verifier import bronnen, gegevens
from mandaatbewijs.verifier.bronnen import BronFout, Ophaler, Sleutelbron, Statusbron
from mandaatbewijs.verifier.gegevens import inkomen
from mandaatbewijs.verifier.nonces import Nonces
from mandaatbewijs.verifier.verificatie import Verificatie, Weigering
from mandaatbewijs.verifier.vertrouwenslijst import Uitgever, Vertrouwenslijst
from tests.unit.conftest import ISS, login, verleen

AUD = "http://inkomensregister:8000"
LINDEVOORT = Uitgever(ISS, "Lindevoort", frozenset({VCT}))


def _verificatie(tmp_path: Path, transport: httpx2.AsyncBaseTransport) -> Verificatie:
    ophaler = Ophaler(True, frozenset({"localhost"}), httpx2.AsyncClient(transport=transport))
    sleutelbron = Sleutelbron(ophaler)
    return Verificatie(
        AUD,
        Vertrouwenslijst([LINDEVOORT]),
        sleutelbron,
        Statusbron(ophaler, sleutelbron),
        Nonces(tmp_path / "nonces.db"),
    )


def _agent(client: TestClient, uitgever: Dienst, dossiers: list[str] | None = None) -> Portemonnee:
    sleutel = Sleutelpaar.nieuw("agent")
    serialisatie, _ = verleen(client, uitgever, sleutel, dossiers)
    return Portemonnee(sleutel, ISS, Credential.uit_serialisatie(serialisatie))


def _presenteer(v: Verificatie, agent: Portemonnee, dossier: str, met_doel: bool = True) -> str:
    gekozen = agent.disclosures_voor("inkomen:lezen", dossier, met_doel)
    return agent.presentatie(AUD, v.nonces.nieuw(), gekozen)


def _idx(agent: Portemonnee) -> int:
    assert agent.credential is not None
    return int(agent.credential.payload["status"]["status_list"]["idx"])


def _loop(coro: Any) -> Any:
    return asyncio.run(coro)


def test_toegestaan_binnen_mandaat(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    toelating = _loop(
        v.verifieer(_presenteer(v, agent, "2026-0142"), "inkomen_opvragen", "2026-0142")
    )
    assert toelating.iss == ISS
    assert toelating.uitgever == "Lindevoort"
    assert toelating.jkt == agent.jkt
    assert toelating.actie == "inkomen:lezen"
    assert toelating.doel == "aanvraag-levensonderhoud"
    assert toelating.status_bron == "vers"
    # Bekendgemaakte lijstelementen tellen onder de naam van hun lijstclaim.
    assert toelating.bekendgemaakt == ["acties", "doel", "dossiers"]


def _weigering(
    v: Verificatie,
    presentatie: str,
    tool: str = "inkomen_opvragen",
    dossier: str | None = "2026-0142",
) -> Weigering:
    with pytest.raises(Weigering) as info:
        _loop(v.verifieer(presentatie, tool, dossier))
    return info.value


def test_bereik_en_doel(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    assert agent.credential is not None
    jti = agent.credential.payload["jti"]
    w = _weigering(v, _presenteer(v, agent, "2026-0157"), dossier="2026-0157")
    assert (w.reden, w.status) == ("dossier_buiten_mandaat", 403)
    bereik = [w]
    w = _weigering(v, _presenteer(v, agent, "2026-0142"), tool="correctie_indienen")
    assert (w.reden, w.status) == ("actie_buiten_mandaat", 403)
    bereik.append(w)
    w = _weigering(v, _presenteer(v, agent, "2026-0142", met_doel=False))
    assert w.reden == "doel_niet_geaccepteerd"
    bereik.append(w)
    # Bij een bereikweigering is de credential geverifieerd: (iss, jti) staan bevestigd in de audit,
    # met de bekendgemaakte claimnamen, de statusbron en de actie die de tool vraagt.
    # Een dossier buiten het mandaat kan de agent niet bekendmaken; zonder doel ontbreekt `doel`.
    verwacht = [
        (["acties", "doel"], "vers", "inkomen:lezen"),
        (["acties", "doel", "dossiers"], "cache", "inkomen:corrigeren"),
        (["acties", "dossiers"], "cache", "inkomen:lezen"),
    ]
    for w, (bekend, bron, actie) in zip(bereik, verwacht, strict=True):
        assert w.bevestigd == {
            "iss": ISS,
            "jti": jti,
            "jkt": agent.jkt,
            "bekendgemaakt": bekend,
            "status_bron": bron,
            "actie": actie,
        }, w.reden
        assert w.onbevestigd == {}
    w = _weigering(v, _presenteer(v, agent, "2026-0142"), tool="onbekend")
    assert w.reden == "tool_onbekend"
    w = _weigering(v, _presenteer(v, agent, "2026-0142"), dossier=None)
    assert w.reden == "dossier_ontbreekt"


def test_nonce_eenmalig_en_aud(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    presentatie = _presenteer(v, agent, "2026-0142")
    _loop(v.verifieer(presentatie, "inkomen_opvragen", "2026-0142"))
    assert _weigering(v, presentatie).reden == "nonce_onbekend_of_gebruikt"
    onbekend = agent.presentatie(
        AUD, "verzonnen", agent.disclosures_voor("inkomen:lezen", "2026-0142", True)
    )
    assert _weigering(v, onbekend).reden == "nonce_onbekend_of_gebruikt"
    andere_aud = agent.presentatie(
        "http://ander:8000",
        v.nonces.nieuw(),
        agent.disclosures_voor("inkomen:lezen", "2026-0142", True),
    )
    assert _weigering(v, andere_aud).reden == "aud_onjuist"


def _zelf_getekend(v: Verificatie, uitgever: Dienst, agent: Sleutelpaar, **claims: Any) -> str:
    """Presentatie van een door de echte uitgeverssleutel getekende credential met eigen claims."""
    nu = int(time.time())
    payload = {
        "iss": ISS,
        "vct": VCT,
        "jti": "m-zelf",
        "iat": nu,
        "nbf": nu,
        "exp": nu + 60,
        "cnf": {"jwk": agent.publieke_jwk},
        "status": {"status_list": {"idx": 0, "uri": f"{ISS}/statuslijsten/1"}},
        "doel": "aanvraag-levensonderhoud",
        "acties": ["inkomen:lezen"],
        "dossiers": ["2026-0142"],
    }
    for naam, waarde in claims.items():
        if waarde is _WEG:
            payload.pop(naam)
        else:
            payload[naam] = waarde
    jwt = uitgever.uitgifte.sleutel.teken({"typ": "dc+sd-jwt"}, payload)
    return presenteer(Credential(jwt, [], payload), [], agent, AUD, v.nonces.nieuw())


_WEG = object()


@pytest.mark.parametrize(
    ("claims", "velden"),
    [
        ({"jti": _WEG}, "jti"),
        ({"jti": ""}, "jti"),
        ({"jti": 7}, "jti"),
        ({"iat": _WEG}, "iat"),
        ({"iat": "nu"}, "iat"),
        ({"iat": True}, "iat"),
        ({"nbf": _WEG}, "nbf"),
        ({"acties": "inkomen:lezen"}, "acties"),
        ({"acties": [["inkomen:lezen"]]}, "acties"),
        ({"dossiers": _WEG}, "dossiers"),
        ({"dossiers": [2026]}, "dossiers"),
        ({"doel": ["aanvraag-levensonderhoud"]}, "doel"),
        ({"jti": None, "acties": {}}, "jti, acties"),
    ],
)
def test_credential_buiten_het_profiel_wordt_na_de_handtekening_geweigerd(
    tmp_path: Path,
    uitgever: Dienst,
    uitgever_transport: Any,
    claims: dict[str, Any],
    velden: str,
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = Sleutelpaar.nieuw("agent")
    w = _weigering(v, _zelf_getekend(v, uitgever, agent, **claims))
    assert (w.reden, w.status) == ("profiel_ongeldig", 401)
    assert w.detail == f"ontbreekt of verkeerd type: {velden}"
    assert (w.bevestigd["iss"], w.bevestigd["jkt"]) == (ISS, agent.jkt)
    # Alleen een jti die een string is, komt als bevestigd in het auditrecord.
    jti = claims.get("jti", "m-zelf")
    assert w.bevestigd.get("jti") == (jti if isinstance(jti, str) else None)


def test_credential_binnen_het_profiel_wordt_toegelaten(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    """Positieve controle op `_zelf_getekend`: zonder afwijking slaagt alles tot de statuslijst."""
    v = _verificatie(tmp_path, uitgever_transport)
    _agent(uitgever_client, uitgever)
    agent = Sleutelpaar.nieuw("agent")
    toelating = _loop(
        v.verifieer(_zelf_getekend(v, uitgever, agent), "inkomen_opvragen", "2026-0142")
    )
    assert (toelating.jti, toelating.jkt) == ("m-zelf", agent.jkt)


def test_key_binding_met_andere_sleutel(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    dief = Portemonnee(Sleutelpaar.nieuw("dief"), ISS, agent.credential)
    w = _weigering(v, _presenteer(v, dief, "2026-0142"))
    assert w.reden == "kb_handtekening_ongeldig"
    assert w.onbevestigd["iss"] == ISS


def test_uitgever_niet_vertrouwd_zonder_netwerk(tmp_path: Path) -> None:
    def geen_netwerk(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError(f"onverwacht netwerkverkeer naar {request.url}")

    v = _verificatie(tmp_path, httpx2.MockTransport(geen_netwerk))
    elsweerd, agent = Sleutelpaar.nieuw("elsweerd"), Sleutelpaar.nieuw("agent")
    nu = int(time.time())
    claims = {
        "iss": "http://elsweerd:8000",
        "vct": VCT,
        "jti": "m-1",
        "iat": nu,
        "nbf": nu,
        "exp": nu + 60,
        "cnf": {"jwk": agent.publieke_jwk},
        "status": {"status_list": {"idx": 1, "uri": "http://elsweerd:8000/statuslijsten/1"}},
        "doel": "heronderzoek",
        "medewerker": {"id": "x"},
        "afdeling": "y",
        "acties": ["inkomen:lezen"],
        "dossiers": ["2026-0142"],
    }
    serialisatie, _ = geef_uit(elsweerd, claims, set(VERBORGEN), set(PER_ELEMENT))
    p = Portemonnee(agent, "http://elsweerd:8000", Credential.uit_serialisatie(serialisatie))
    w = _weigering(v, _presenteer(v, p, "2026-0142"))
    assert w.reden == "uitgever_niet_vertrouwd"
    assert (w.bevestigd, w.onbevestigd) == ({}, {"iss": "http://elsweerd:8000"})
    # Zelfde uitgever, maar een onbekend credentialtype.
    v2 = _verificatie(tmp_path / "2", httpx2.MockTransport(geen_netwerk))
    v2.vertrouwenslijst = Vertrouwenslijst(
        [Uitgever("http://elsweerd:8000", "E", frozenset({"x"}))]
    )
    assert _weigering(v2, _presenteer(v2, p, "2026-0142")).reden == "vct_niet_toegestaan"


def test_ingetrokken_via_statuslijst_na_verversing(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    sleutel = Sleutelpaar.nieuw("agent")
    serialisatie, mandaat_id = verleen(uitgever_client, uitgever, sleutel)
    agent = Portemonnee(sleutel, ISS, Credential.uit_serialisatie(serialisatie))
    _loop(v.verifieer(_presenteer(v, agent, "2026-0142"), "inkomen_opvragen", "2026-0142"))
    uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    # Binnen de ttl (1 s) nog uit de cache toegestaan; daarna geweigerd.
    t = _loop(v.verifieer(_presenteer(v, agent, "2026-0142"), "inkomen_opvragen", "2026-0142"))
    assert t.status_bron == "cache"
    time.sleep(1.1)
    w = _weigering(v, _presenteer(v, agent, "2026-0142"))
    assert (w.reden, w.status) == ("mandaat_ingetrokken", 403)
    assert w.bevestigd["jti"] == mandaat_id
    assert w.onbevestigd == {}


def test_statuscache_overbrugt_netwerkfout_maar_niet_ongeldig_token(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    uri = f"{ISS}/statuslijsten/1"
    idx = _idx(agent)
    _loop(v.statusbron.ververs(uri, LINDEVOORT))
    time.sleep(1.1)
    # Netwerkfout: overbrugging tot exp.
    weg = httpx2.MockTransport(lambda r: (_ for _ in ()).throw(httpx2.ConnectError("weg")))
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=weg)  # type: ignore[arg-type]
    uitkomst = _loop(v.statusbron.status(uri, idx, LINDEVOORT))
    assert uitkomst.bron == "cache-verouderd"
    # Ongeldig token: cache onbruikbaar, ook bij een latere netwerkfout.
    rommel = httpx2.MockTransport(
        lambda r: httpx2.Response(
            200, text="a.b.c", headers={"content-type": "application/statuslist+jwt"}
        )
    )
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=rommel)  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(v.statusbron.ververs(uri, LINDEVOORT))
    assert info.value.klasse == "ongeldig"
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=weg)  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(v.statusbron.status(uri, idx, LINDEVOORT))
    assert info.value.reden == "status_onbekend"
    assert _weigering(v, _presenteer(v, agent, "2026-0142")).reden == "status_onbekend"
    # Een geldige verversing herstelt de cache.
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=uitgever_transport)
    assert _loop(v.statusbron.status(uri, idx, LINDEVOORT)).bron == "vers"


def test_geen_cache_en_onbereikbaar_is_status_onbekend(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    uri = f"{ISS}/statuslijsten/1"
    idx = _idx(agent)
    weg = httpx2.MockTransport(lambda r: httpx2.Response(503))
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=weg)  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(v.statusbron.status(uri, idx, LINDEVOORT))
    assert (info.value.reden, info.value.klasse) == ("status_onbekend", "netwerk")


def test_metadata_issuer_moet_kloppen(tmp_path: Path) -> None:
    def antwoord(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"issuer": "http://ander:8000", "jwks": {"keys": []}})

    ophaler = Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(antwoord))
    )  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(Sleutelbron(ophaler).sleutel(LINDEVOORT, "kid"))
    assert info.value.reden == "uitgever_metadata_onjuist"


def test_jwks_via_jwks_uri_en_onbekende_kid_begrensd(tmp_path: Path) -> None:
    sleutel = Sleutelpaar.nieuw("k1")
    teller = {"meta": 0}

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            teller["meta"] += 1
            return httpx2.Response(200, json={"issuer": ISS, "jwks_uri": f"{ISS}/jwks.json"})
        return httpx2.Response(
            200, json={"keys": [sleutel.jwks_lid]}, headers={"cache-control": "max-age=1000"}
        )

    ophaler = Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(antwoord))
    )  # type: ignore[arg-type]
    bron = Sleutelbron(ophaler)
    assert _loop(bron.sleutel(LINDEVOORT, "k1")).thumbprint() == sleutel.jkt
    with pytest.raises(BronFout):
        _loop(bron.sleutel(LINDEVOORT, "k2"))
    assert teller["meta"] == 1  # net opgehaald: een onbekende kid dwingt geen nieuwe ophaalactie af
    bron._caches[ISS].laatste_poging = 0
    with pytest.raises(BronFout):
        _loop(bron.sleutel(LINDEVOORT, "k2"))
    assert teller["meta"] == 2  # na 10 s wel opnieuw opgehaald
    with pytest.raises(BronFout):
        _loop(bron.sleutel(LINDEVOORT, "k3"))
    assert teller["meta"] == 2  # en daarna weer begrensd


def test_url_controles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bronnen.socket, "getaddrinfo", lambda host, *_a: [(0, 0, 0, "", ("10.0.0.5", 0))]
    )
    leeg = httpx2.MockTransport(lambda r: httpx2.Response(200, json={}))
    ophaler = Ophaler(True, frozenset({"uitgever"}), httpx2.AsyncClient(transport=leeg))  # type: ignore[arg-type]
    ophaler.controleer_url("http://uitgever:8000/jwks.json", "http://uitgever:8000")
    _loop(
        ophaler.haal("http://uitgever:8000/jwks.json", "http://uitgever:8000", "application/json")
    )
    for url, iss, reden in [
        ("http://ander:8000/jwks.json", "http://uitgever:8000", "url_andere_oorsprong"),
        ("http://uitgever:9000/jwks.json", "http://uitgever:8000", "url_andere_oorsprong"),
        ("ftp://uitgever:8000/x", "http://uitgever:8000", "url_schema_ongeldig"),
    ]:
        with pytest.raises(BronFout) as info:
            ophaler.controleer_url(url, iss)
        assert info.value.reden == reden
    streng = Ophaler(False, frozenset({"uitgever"}), httpx2.AsyncClient(transport=leeg))  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        streng.controleer_url("http://uitgever:8000/jwks.json", "http://uitgever:8000")
    assert info.value.reden == "url_schema_ongeldig"
    # De adrescontrole gebeurt bij het ophalen, na naamresolutie.
    with pytest.raises(BronFout) as info:
        _loop(streng.haal("https://uitgever:8000/jwks.json", "https://uitgever:8000", "*/*"))
    assert (info.value.reden, info.value.klasse) == ("adres_niet_toegestaan", "ongeldig")
    # Privé-adres van een host die niet op de lijst staat: ook met STA_HTTP_TOE geweigerd.
    los = Ophaler(True, frozenset(), httpx2.AsyncClient(transport=leeg))  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(los.haal("http://uitgever:8000/x", "http://uitgever:8000", "*/*"))
    assert info.value.reden == "adres_niet_toegestaan"


def test_onbekende_host_is_netwerkfout(monkeypatch: pytest.MonkeyPatch) -> None:
    def faal(host: str, *_a: object, **_k: object) -> list[object]:
        raise bronnen.socket.gaierror(8, f"{host}: nodename nor servname provided")

    monkeypatch.setattr(bronnen.socket, "getaddrinfo", faal)
    ophaler = Ophaler(True, frozenset({"uitgever"}))
    with pytest.raises(BronFout) as info:
        _loop(ophaler.haal("http://uitgever:8000/x", "http://uitgever:8000", "*/*"))
    assert (info.value.reden, info.value.klasse) == ("adres_onbekend", "netwerk")


def test_trage_bron_valt_binnen_de_tijdslimiet_af(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bronnen, "TIMEOUT_S", 0.05)

    async def traag(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(0.5)
        return httpx2.Response(200, json={})

    ophaler = Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(traag))
    )  # type: ignore[arg-type]
    begin = time.monotonic()
    with pytest.raises(BronFout) as info:
        _loop(ophaler.haal(f"{ISS}/x", ISS, "*/*"))
    assert (info.value.reden, info.value.klasse) == ("netwerkfout", "netwerk")
    assert time.monotonic() - begin < 0.4


def test_adres_publiek_toegestaan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bronnen.socket, "getaddrinfo", lambda host, *_a: [(0, 0, 0, "", ("93.184.216.34", 0))]
    )
    assert bronnen._adres_toegestaan("voorbeeld.nl", False, frozenset())
    # Link-local (cloudmetadata), shared address space en andere niet-publieke adressen: nooit.
    nooit = ("169.254.169.254", "100.64.0.1", "fe80::1", "0.1.2.3", "192.0.0.8")
    for adres in (*nooit, "224.0.0.1", "239.1.2.3", "ff02::1", "ff0e::1"):
        monkeypatch.setattr(
            bronnen.socket,
            "getaddrinfo",
            lambda host, *_a, adres=adres: [(0, 0, 0, "", (adres, 0))],
        )
        assert not bronnen._adres_toegestaan("meta", True, frozenset({"meta"})), adres
        assert not bronnen._adres_toegestaan("meta", False, frozenset({"meta"})), adres
    # RFC 1918 en loopback alleen in de demomodus én voor een host op de vertrouwenslijst.
    monkeypatch.setattr(
        bronnen.socket, "getaddrinfo", lambda host, *_a: [(0, 0, 0, "", ("127.0.0.1", 0))]
    )
    assert bronnen._adres_toegestaan("uitgever", True, frozenset({"uitgever"}))
    assert not bronnen._adres_toegestaan("uitgever", True, frozenset({"ander"}))
    assert not bronnen._adres_toegestaan("uitgever", False, frozenset({"uitgever"}))


def test_antwoord_te_groot(tmp_path: Path) -> None:
    groot = httpx2.MockTransport(
        lambda r: httpx2.Response(200, content=b"x" * (bronnen.MAX_ANTWOORD + 1))
    )
    ophaler = Ophaler(True, frozenset({"localhost"}), httpx2.AsyncClient(transport=groot))  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(ophaler.haal(f"{ISS}/jwks.json", ISS, "application/json"))
    assert info.value.reden == "antwoord_te_groot"


def test_vertrouwenslijst_laden(tmp_path: Path) -> None:
    pad = tmp_path / "lijst.json"
    pad.write_text('[{"iss": "http://uitgever:8000/", "naam": "L", "vct": ["a"]}]')
    lijst = Vertrouwenslijst.laad(pad)
    assert lijst.uitgever("http://uitgever:8000") is not None
    assert lijst.hosts == frozenset({"uitgever"})
    pad.write_text('[{"iss": "uitgever", "vct": []}]')
    with pytest.raises(ValueError, match="http"):
        Vertrouwenslijst.laad(pad)


@pytest.mark.parametrize(
    ("tweede", "veld"),
    [
        ({"iss": "http://elsweerd:8000", "naam": "L"}, "naam"),
        ({"iss": "http://uitgever:8000/", "naam": "E"}, "iss"),
    ],
)
def test_vertrouwenslijst_weigert_dubbele_iss_of_naam(
    tmp_path: Path, tweede: dict[str, str], veld: str
) -> None:
    pad = tmp_path / "lijst.json"
    eerste = {"iss": "http://uitgever:8000", "naam": "L", "vct": ["a"]}
    pad.write_text(json.dumps([eerste, {**tweede, "vct": ["a"]}]))
    with pytest.raises(ValueError, match=f"{veld} komt meer dan eens voor"):
        Vertrouwenslijst.laad(pad)


def test_hetzelfde_dossiernummer_bij_twee_gemeenten_is_een_ander_dossier() -> None:
    lindevoort = inkomen(gegevens.LINDEVOORT, "2026-0142")
    elsweerd = inkomen(gegevens.ELSWEERD, "2026-0142")
    assert lindevoort is not None
    assert elsweerd is not None
    assert lindevoort != elsweerd
    assert inkomen(gegevens.ELSWEERD, "2026-0157") is None
    # De meegeleverde vertrouwenslijst noemt de gemeente zoals het register haar kent.
    lijst = Vertrouwenslijst.laad(Path(__file__).parents[2] / "vertrouwenslijst.json")
    uitgever = lijst.uitgever("http://uitgever:8000")
    assert uitgever is not None
    assert inkomen(uitgever.naam, "2026-0142") == lindevoort


def test_nonces_sluiten_elke_verbinding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    geopend: list[sqlite3.Connection] = []
    origineel = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        geopend.append(origineel(*args, **kwargs))
        return geopend[-1]

    monkeypatch.setattr(sqlite3, "connect", connect)
    nonces = Nonces(tmp_path / "n.db")
    assert nonces.verbruik(nonces.nieuw())
    assert len(geopend) == 3
    for db in geopend:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            db.execute("SELECT 1")


def test_nonces_eenmalig(tmp_path: Path) -> None:
    nonces = Nonces(tmp_path / "n.db")
    n = nonces.nieuw()
    assert nonces.verbruik(n)
    assert not nonces.verbruik(n)
    assert not nonces.verbruik("onbekend")


def test_cachehit_controleert_oorsprong(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    """Een credential van uitgever B mag niet naar de gecachete lijst van uitgever A wijzen."""
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    uri = f"{ISS}/statuslijsten/1"
    _loop(v.statusbron.ververs(uri, LINDEVOORT))
    ander = Uitgever("http://elsweerd:8000", "E", frozenset({VCT}))
    with pytest.raises(BronFout) as info:
        _loop(v.statusbron.status(uri, _idx(agent), ander))
    assert info.value.reden == "url_andere_oorsprong"


def test_nonce_verloopt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nonces = Nonces(tmp_path / "n.db")
    n = nonces.nieuw()
    echte_tijd = time.time
    monkeypatch.setattr("mandaatbewijs.verifier.nonces.time.time", lambda: echte_tijd() + 61)
    assert not nonces.verbruik(n)


def _jwks_ophaler(antwoord: Any, teller: dict[str, int]) -> Ophaler:
    def handler(request: httpx2.Request) -> httpx2.Response:
        teller[request.url.path] = teller.get(request.url.path, 0) + 1
        return antwoord(request)

    return Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    )  # type: ignore[arg-type]


def test_jwks_koude_start_haalt_eenmaal_op_bij_gelijktijdige_aanvragen() -> None:
    sleutel = Sleutelpaar.nieuw("k1")
    teller: dict[str, int] = {}

    async def traag(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(0.05)
        return httpx2.Response(200, json={"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}})

    bron = Sleutelbron(_jwks_ophaler(traag, teller))

    async def acht() -> list[Any]:
        return await asyncio.gather(*(bron.sleutel(LINDEVOORT, "k1") for _ in range(8)))

    uitkomsten = _loop(acht())
    assert all(s.thumbprint() == sleutel.jkt for s in uitkomsten)
    assert teller["/.well-known/jwt-vc-issuer"] == 1


def test_jwks_mislukte_pogingen_worden_begrensd_en_no_store_wordt_niet_bewaard() -> None:
    sleutel = Sleutelpaar.nieuw("k1")
    teller: dict[str, int] = {}
    toestand = {"kapot": True}

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        if toestand["kapot"]:
            return httpx2.Response(503)
        return httpx2.Response(
            200,
            json={"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}},
            headers={"cache-control": "no-store"},
        )

    bron = Sleutelbron(_jwks_ophaler(antwoord, teller))
    for _ in range(5):
        with pytest.raises(BronFout):
            _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert teller["/.well-known/jwt-vc-issuer"] == 1  # zonder cache toch hoogstens eens per 10 s
    bron._caches[ISS].laatste_poging = 0
    toestand["kapot"] = False
    assert _loop(bron.sleutel(LINDEVOORT, "k1")).thumbprint() == sleutel.jkt
    assert teller["/.well-known/jwt-vc-issuer"] == 2
    # `no-store` op inline jwks: alleen voor die ene aanvraag; niets bewaard voor de volgende.
    assert bron._caches[ISS].sleutels == {}
    with pytest.raises(BronFout) as info:
        _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert (info.value.reden, info.value.klasse) == ("jwks_niet_beschikbaar", "netwerk")
    assert teller["/.well-known/jwt-vc-issuer"] == 2


def test_metadata_met_jwks_en_jwks_uri_of_zonder_json_is_onjuist() -> None:
    sleutel = Sleutelpaar.nieuw("k1")
    beide = {"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}, "jwks_uri": f"{ISS}/jwks.json"}
    bron = Sleutelbron(_jwks_ophaler(lambda r: httpx2.Response(200, json=beide), {}))
    with pytest.raises(BronFout) as info:
        _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert info.value.reden == "uitgever_metadata_onjuist"
    bron = Sleutelbron(_jwks_ophaler(lambda r: httpx2.Response(200, text="<html>"), {}))
    with pytest.raises(BronFout) as info:
        _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert info.value.reden == "uitgever_metadata_onjuist"

    def jwks_rommel(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            return httpx2.Response(200, json={"issuer": ISS, "jwks_uri": f"{ISS}/jwks.json"})
        return httpx2.Response(200, text="niet json")

    bron = Sleutelbron(_jwks_ophaler(jwks_rommel, {}))
    with pytest.raises(BronFout) as info:
        _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert info.value.reden == "jwks_ongeldig"


def test_te_groot_statusantwoord_maakt_de_cache_onbruikbaar(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    v = _verificatie(tmp_path, uitgever_transport)
    agent = _agent(uitgever_client, uitgever)
    uri = f"{ISS}/statuslijsten/1"
    idx = _idx(agent)
    _loop(v.statusbron.ververs(uri, LINDEVOORT))
    time.sleep(1.1)
    groot = httpx2.MockTransport(
        lambda r: httpx2.Response(
            200,
            content=b"x" * (bronnen.MAX_ANTWOORD + 1),
            headers={"content-type": "application/statuslist+jwt"},
        )
    )
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=groot)  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(v.statusbron.status(uri, idx, LINDEVOORT))
    assert (info.value.reden, info.value.klasse) == ("status_onbekend", "ongeldig")
    weg = httpx2.MockTransport(lambda r: (_ for _ in ()).throw(httpx2.ConnectError("weg")))
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=weg)  # type: ignore[arg-type]
    with pytest.raises(BronFout) as info:
        _loop(v.statusbron.status(uri, idx, LINDEVOORT))
    assert info.value.reden == "status_onbekend"  # geen overbrugging na een ongeldig antwoord


def test_ouder_statustoken_overschrijft_nieuwer_niet(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst, uitgever_transport: Any
) -> None:
    """Een vertraagde, oudere download vervangt een al gecachet nieuwer token niet."""
    v = _verificatie(tmp_path, uitgever_transport)
    sleutel = Sleutelpaar.nieuw("agent")
    serialisatie, mandaat_id = verleen(uitgever_client, uitgever, sleutel)
    agent = Portemonnee(sleutel, ISS, Credential.uit_serialisatie(serialisatie))
    uri = f"{ISS}/statuslijsten/1"
    idx = _idx(agent)
    oud_tekst = uitgever_client.get(uri).text  # token vóór de intrekking (bit 0)
    time.sleep(1.1)
    uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    assert _loop(v.statusbron.status(uri, idx, LINDEVOORT)).waarde == 1
    cache = v.statusbron._caches[(ISS, uri)]
    assert cache.token is not None
    nieuw_iat = cache.token.iat
    # Nu komt (alsnog) het oudere token binnen: de cache houdt het nieuwere, de bit blijft 1.
    cache.opgehaald = 0
    oud = httpx2.MockTransport(
        lambda r: httpx2.Response(
            200, text=oud_tekst, headers={"content-type": "application/statuslist+jwt"}
        )
    )
    v.statusbron.ophaler.client = httpx2.AsyncClient(transport=oud)  # type: ignore[arg-type]
    uitkomst = _loop(v.statusbron.status(uri, idx, LINDEVOORT))
    # Het oudere token bevestigt de cache niet: geen `vers`, maar overbrugging tot exp.
    assert (uitkomst.waarde, uitkomst.bron) == (1, "cache-verouderd")
    assert cache.token.iat == nieuw_iat
    assert cache.opgehaald == 0


def test_gelijktijdige_statusverversingen_halen_eenmaal_op(
    tmp_path: Path, uitgever_client: TestClient, uitgever: Dienst
) -> None:
    teller = {"n": 0}
    lijst_token = uitgever_client.get(f"{ISS}/statuslijsten/1").text
    jwks = uitgever_client.get(f"{ISS}/jwks.json").json()

    async def antwoord(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            return httpx2.Response(200, json={"issuer": ISS, "jwks": jwks})
        teller["n"] += 1
        await asyncio.sleep(0.05)
        return httpx2.Response(
            200, text=lijst_token, headers={"content-type": "application/statuslist+jwt"}
        )

    v = _verificatie(tmp_path, httpx2.MockTransport(antwoord))
    uri = f"{ISS}/statuslijsten/1"

    async def acht() -> None:
        await asyncio.gather(*(v.statusbron.ververs(uri, LINDEVOORT) for _ in range(8)))

    _loop(acht())
    assert teller["n"] == 1


class _Klok:
    """Instelbare `time.time` voor bron- en statuslijstcode."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, nu: float) -> None:
        self.nu = nu
        monkeypatch.setattr(time, "time", lambda: self.nu)


STATUS_URI = f"{ISS}/statuslijsten/1"
STATUS_KOP = {"content-type": "application/statuslist+jwt"}


def _statustoken(sleutel: Sleutelpaar, bit: int, iat: int, exp: int, ttl: int = 5) -> str:
    lijst = Statuslijst.leeg(16)
    lijst.zet(3, bit)
    return maak_token(sleutel, STATUS_URI, lijst, Tokenbeleid(ttl, exp - iat), nu=iat)


def _statusbron(sleutel: Sleutelpaar, huidig: dict[str, str]) -> Statusbron:
    """Statusbron waarvan de uitgever `huidig["token"]` serveert; JWKS lang gecachet.

    Met `huidig["age"]` stuurt het antwoord die `Age`-header mee, zoals een HTTP-cache.
    """

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            return httpx2.Response(
                200,
                json={"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}},
                headers={"cache-control": "max-age=100000"},
            )
        kop = {**STATUS_KOP, **({"age": huidig["age"]} if "age" in huidig else {})}
        return httpx2.Response(200, text=huidig["token"], headers=kop)

    ophaler = Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(antwoord))
    )  # type: ignore[arg-type]
    return Statusbron(ophaler, Sleutelbron(ophaler))


def _status_fout(bron: Statusbron) -> BronFout:
    with pytest.raises(BronFout) as info:
        _loop(bron.status(STATUS_URI, 3, LINDEVOORT))
    return info.value


def test_ouder_token_draait_een_intrekking_niet_terug_ook_niet_na_een_ongeldig_antwoord(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    huidig = {"token": _statustoken(sleutel, 1, iat=950, exp=2000)}
    bron = _statusbron(sleutel, huidig)
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)).waarde == 1
    huidig["token"] = "a.b.c"  # ongeldig antwoord: cache onbruikbaar
    klok.nu = 1006
    assert _status_fout(bron).klasse == "ongeldig"
    # Een geldig getekend maar ouder token met bit 0 herstelt de cache niet.
    huidig["token"] = _statustoken(sleutel, 0, iat=900, exp=2000)
    assert _status_fout(bron).reden == "status_onbekend"
    cache = bron._caches[(ISS, STATUS_URI)]
    assert cache.token is not None
    assert cache.token.iat == 950
    assert cache.onbruikbaar
    # Pas een nieuwer token maakt de cache weer bruikbaar.
    huidig["token"] = _statustoken(sleutel, 1, iat=1006, exp=2000)
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)) == bronnen.Statusuitkomst(1, "vers")


def test_tegenstrijdig_token_met_dezelfde_iat_maakt_de_cache_onbruikbaar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    huidig = {"token": _statustoken(sleutel, 1, iat=1000, exp=2000)}
    bron = _statusbron(sleutel, huidig)
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)).waarde == 1
    # Hetzelfde token opnieuw (zelfde iat, zelfde lijst) bevestigt de cache gewoon.
    klok.nu = 1006
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)) == bronnen.Statusuitkomst(1, "vers")
    # Zelfde iat, andere lijst (bit 1 → 0): geweigerd, en daarna geen overbrugging.
    huidig["token"] = _statustoken(sleutel, 0, iat=1000, exp=2000)
    klok.nu = 1012
    fout = _status_fout(bron)
    assert (fout.reden, fout.klasse) == ("status_onbekend", "ongeldig")
    assert "statustoken_tegenstrijdig" in str(fout)
    # Ook het oorspronkelijke token (zelfde iat) herstelt de cache niet; alleen een nieuwer.
    huidig["token"] = _statustoken(sleutel, 1, iat=1000, exp=2000)
    assert _status_fout(bron).reden == "status_onbekend"
    huidig["token"] = _statustoken(sleutel, 1, iat=1012, exp=2000)
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)).waarde == 1


def test_ouder_token_bevestigt_een_verlopen_cache_niet(monkeypatch: pytest.MonkeyPatch) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    huidig = {"token": _statustoken(sleutel, 1, iat=950, exp=1010, ttl=1)}
    bron = _statusbron(sleutel, huidig)
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)).waarde == 1
    huidig["token"] = _statustoken(sleutel, 0, iat=900, exp=2000)
    # ttl om, exp niet: het oudere token telt als mislukte verversing, overbrugging tot exp.
    klok.nu = 1005
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)) == bronnen.Statusuitkomst(
        1, "cache-verouderd"
    )
    assert bron._caches[(ISS, STATUS_URI)].opgehaald == 1000
    # exp van het gecachete token voorbij: geen uitkomst uit het verlopen token, en zeker geen
    # `vers` met de bit uit het oudere token.
    klok.nu = 1010
    assert _status_fout(bron).reden == "status_onbekend"


def test_jwks_verlopen_sleutel_blijft_na_mislukte_verversing_onbruikbaar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("k1")
    teller: dict[str, int] = {}
    toestand = {"kapot": False}
    klok = _Klok(monkeypatch, 1000)

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        if toestand["kapot"]:
            return httpx2.Response(503)
        return httpx2.Response(
            200,
            json={"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}},
            headers={"cache-control": "max-age=5"},
        )

    bron = Sleutelbron(_jwks_ophaler(antwoord, teller))
    assert _loop(bron.sleutel(LINDEVOORT, "k1")).thumbprint() == sleutel.jkt
    klok.nu = 1004
    assert _loop(bron.sleutel(LINDEVOORT, "k1")).thumbprint() == sleutel.jkt  # uit de cache
    toestand["kapot"] = True
    # Elke 11 s een mislukte verversing, steeds gevolgd door een aanvraag een seconde later: de
    # verlopen sleutel komt nooit terug, ook niet doordat de downloadrem de poging begrenst.
    for poging in (1011, 1022):
        klok.nu = poging
        with pytest.raises(BronFout) as info:
            _loop(bron.sleutel(LINDEVOORT, "k1"))
        assert (info.value.reden, info.value.klasse) == ("http_status", "netwerk")
        klok.nu = poging + 1
        with pytest.raises(BronFout) as info:
            _loop(bron.sleutel(LINDEVOORT, "k1"))
        assert (info.value.reden, info.value.klasse) == ("jwks_niet_beschikbaar", "netwerk")
    assert teller["/.well-known/jwt-vc-issuer"] == 3  # 1000, 1011, 1022: één per 10 s


def _b64(data: bytes) -> str:
    import base64  # noqa: PLC0415

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.mark.parametrize(
    "antwoord",
    [
        f"{_b64(b'["alg"]')}.{_b64(b'{}')}.c2ln",  # JOSE-kop is een lijst
        f"{_b64(b'7')}.{_b64(b'{}')}.c2ln",  # JOSE-kop is een getal
        "geen-jws",
    ],
)
def test_misvormd_statusantwoord_maakt_de_cache_onbruikbaar(
    monkeypatch: pytest.MonkeyPatch, antwoord: str
) -> None:
    """Ook een kop die geen JSON-object is: daarna geen cachehit en geen overbrugging meer."""
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    huidig = {"token": _statustoken(sleutel, 0, iat=1000, exp=2000)}
    bron = _statusbron(sleutel, huidig)
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)).waarde == 0
    huidig["token"] = antwoord
    klok.nu = 1001  # cache nog bruikbaar: de achtergrondtaak ververst
    _loop(bron.ververs_alles())
    assert bron._caches[(ISS, STATUS_URI)].onbruikbaar
    assert _status_fout(bron).reden == "status_onbekend"  # geen cachehit
    weg = httpx2.MockTransport(lambda r: (_ for _ in ()).throw(httpx2.ConnectError("weg")))
    bron.ophaler.client = httpx2.AsyncClient(transport=weg)  # type: ignore[arg-type]
    assert _status_fout(bron).reden == "status_onbekend"  # geen overbrugging


def test_onverwachte_fout_bij_verwerken_maakt_de_cache_onbruikbaar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    bron = _statusbron(sleutel, {"token": _statustoken(sleutel, 0, iat=1000, exp=2000)})
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)).waarde == 0

    def kapot(*_: Any) -> None:
        raise RuntimeError("onvoorzien")

    monkeypatch.setattr(bronnen, "lees_token", kapot)
    klok.nu = 1001
    with pytest.raises(BronFout) as info:
        _loop(bron.ververs(STATUS_URI, LINDEVOORT))
    assert (info.value.reden, info.value.klasse) == ("statusverwerking_mislukt", "ongeldig")
    assert _status_fout(bron).reden == "status_onbekend"


def test_statuscache_is_per_uitgever_ook_op_dezelfde_oorsprong(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Uitgever B mag niet de gecachete lijst van uitgever A (zelfde URI) gebruiken.

    Dekt ook de metadata-URL voor een uitgever met pad: `/.well-known/jwt-vc-issuer/<pad>`.
    """
    _Klok(monkeypatch, 1000)
    a = Uitgever(f"{ISS}/a", "A", frozenset({VCT}))
    b = Uitgever(f"{ISS}/b", "B", frozenset({VCT}))
    sleutels = {"a": Sleutelpaar.nieuw("ka"), "b": Sleutelpaar.nieuw("kb")}
    uri = f"{a.iss}/statuslijsten/1"
    lijst = Statuslijst.leeg(16)
    token = maak_token(sleutels["a"], uri, lijst, Tokenbeleid(5, 1000), nu=1000)
    paden: list[str] = []

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        paden.append(request.url.path)
        for naam, sleutel in sleutels.items():
            if request.url.path == f"/.well-known/jwt-vc-issuer/{naam}":
                jwks = {"keys": [sleutel.jwks_lid]}
                return httpx2.Response(200, json={"issuer": f"{ISS}/{naam}", "jwks": jwks})
        return httpx2.Response(
            200, text=token, headers={"content-type": "application/statuslist+jwt"}
        )

    ophaler = Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(antwoord))
    )  # type: ignore[arg-type]
    bron = Statusbron(ophaler, Sleutelbron(ophaler))
    assert _loop(bron.status(uri, 3, a)) == bronnen.Statusuitkomst(0, "vers")
    with pytest.raises(BronFout) as info:
        _loop(bron.status(uri, 3, b))  # geen cachehit: opnieuw opgehaald, sleutel van B past niet
    assert info.value.reden == "status_onbekend"
    assert "kid_onbekend" in str(info.value)
    assert paden.count("/a/statuslijsten/1") == 2
    assert "/.well-known/jwt-vc-issuer/b" in paden


def test_mislukte_verversing_wordt_gedeeld_door_wie_wachtte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    bron = _statusbron(sleutel, {"token": _statustoken(sleutel, 0, iat=1000, exp=2000)})
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)).waarde == 0
    teller = {"n": 0}

    async def traag_en_weg(request: httpx2.Request) -> httpx2.Response:
        teller["n"] += 1
        await asyncio.sleep(0.05)
        raise httpx2.ConnectError("weg")

    bron.ophaler.client = httpx2.AsyncClient(transport=httpx2.MockTransport(traag_en_weg))  # type: ignore[arg-type]
    klok.nu = 1006  # ttl om: elke aanvraag wil verversen

    async def acht() -> list[Any]:
        return await asyncio.gather(*(bron.status(STATUS_URI, 3, LINDEVOORT) for _ in range(8)))

    uitkomsten = _loop(acht())
    assert teller["n"] == 1
    assert uitkomsten == [bronnen.Statusuitkomst(0, "cache-verouderd")] * 8


def _vertraagde_statusbron(
    sleutel: Sleutelpaar, klok: _Klok, lever: Any
) -> tuple[Statusbron, dict[str, Any]]:
    """Statusbron achter `lever(teller)` → (token, Age); de eerste statusdownload wacht.

    Die eerste download meldt zich via `stand["onderweg"]` en levert pas na `stand["door"]`,
    waarna de klok op `stand["aankomst"]` staat. Latere downloads zijn direct.
    """
    stand: dict[str, Any] = {"n": 0, "onderweg": asyncio.Event(), "door": asyncio.Event()}

    async def antwoord(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            return httpx2.Response(
                200,
                json={"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}},
                headers={"cache-control": "max-age=100000"},
            )
        stand["n"] += 1
        token, age = lever(stand["n"])
        if stand["n"] == 1:
            stand["onderweg"].set()
            await stand["door"].wait()
            klok.nu = stand["aankomst"]
        kop = {**STATUS_KOP, "cache-control": "max-age=5", "age": age}
        return httpx2.Response(200, text=token, headers=kop)

    ophaler = Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(antwoord))
    )  # type: ignore[arg-type]
    return Statusbron(ophaler, Sleutelbron(ophaler)), stand


async def _tijdens_download(
    bron: Statusbron, stand: dict[str, Any], klok: _Klok, later: float, aantal: int
) -> list[bronnen.Statusuitkomst]:
    """Eén aanroep start de download; `aantal` aanroepen beginnen op `later` en wachten erop."""
    eerste = asyncio.create_task(bron.status(STATUS_URI, 3, LINDEVOORT))
    await stand["onderweg"].wait()
    klok.nu = later
    wachtend = [asyncio.create_task(bron.status(STATUS_URI, 3, LINDEVOORT)) for _ in range(aantal)]
    for _ in range(5):
        await asyncio.sleep(0)  # elke wachtende staat nu bij het slot, met zijn aanvraagtijd
    stand["door"].set()
    return list(await asyncio.gather(eerste, *wachtend))


def test_wie_op_een_te_oude_download_wacht_maar_later_aanvroeg_haalt_zelf_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Een cache zonder grace sloeg de oude lijst op om 999,9; de intrekking volgt op T = 1000.

    Aanroep A begint om 1004,8 en krijgt het nog verse antwoord met `Age: 4`, dat om 1005,2
    aankomt en dan te oud is. Aanroep B begint precies op T + ttl = 1005,0 en wacht op die
    download. A begon vóór T + ttl en mag overbruggen; B moet de intrekking zien. Voorheen deelde
    B de uitkomst van A en werd hij toegelaten.
    """
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1004.8)
    oud = _statustoken(sleutel, 0, iat=999, exp=1059)
    nieuw = _statustoken(sleutel, 1, iat=1000, exp=1060)
    cache: dict[str, Any] = {"tijd": 999.9, "token": oud}

    def lever(_: int) -> tuple[str, str]:
        if klok.nu - cache["tijd"] >= 5:  # niet meer vers voor de cache: naar de uitgever
            cache.update(tijd=klok.nu, token=nieuw)
        return cache["token"], str(math.floor(klok.nu - cache["tijd"]))

    bron, stand = _vertraagde_statusbron(sleutel, klok, lever)
    stand["aankomst"] = 1005.2
    a, b = _loop(_tijdens_download(bron, stand, klok, 1005.0, 1))
    assert a == bronnen.Statusuitkomst(0, "cache-verouderd")
    assert b == bronnen.Statusuitkomst(1, "vers")
    assert stand["n"] == 2


def test_te_oud_antwoord_kost_per_groep_wachtenden_hoogstens_een_extra_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Een cache die steeds te oud levert (grace): wie later aanvroeg, haalt één keer zelf op.

    De eerste wachtende haalt opnieuw op; de anderen vroegen vóór het begin van die tweede
    download aan en delen de uitkomst. Zo blijven het twee downloads, niet één per aanroep.
    """
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    token = _statustoken(sleutel, 0, iat=990, exp=2000)
    bron, stand = _vertraagde_statusbron(sleutel, klok, lambda _: (token, "9"))
    stand["aankomst"] = 1000.2
    uitkomsten = _loop(_tijdens_download(bron, stand, klok, 1000.1, 7))
    assert uitkomsten == [bronnen.Statusuitkomst(0, "cache-verouderd")] * 8
    assert stand["n"] == 2


def test_opgehaald_is_het_begin_van_de_download(monkeypatch: pytest.MonkeyPatch) -> None:
    """De cacheduur telt vanaf het begin van de download: een trage download verlengt niets."""
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    token = _statustoken(sleutel, 0, iat=1000, exp=2000)
    jwks = {"keys": [sleutel.jwks_lid]}

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            return httpx2.Response(
                200, json={"issuer": ISS, "jwks": jwks}, headers={"cache-control": "max-age=999"}
            )
        klok.nu += 3  # de download duurt drie seconden
        return httpx2.Response(
            200, text=token, headers={"content-type": "application/statuslist+jwt"}
        )

    ophaler = Ophaler(
        True, frozenset({"localhost"}), httpx2.AsyncClient(transport=httpx2.MockTransport(antwoord))
    )  # type: ignore[arg-type]
    bron = Statusbron(ophaler, Sleutelbron(ophaler))
    _loop(bron.ververs(STATUS_URI, LINDEVOORT))
    cache = bron._caches[(ISS, STATUS_URI)]
    assert cache.opgehaald == 1000
    klok.nu = 1005  # ttl (5) na het begin van de download: niet meer bruikbaar
    assert not bron._bruikbaar(cache, klok.nu)


def test_gecomprimeerd_antwoord_wordt_eenmaal_gedecodeerd() -> None:
    import gzip  # noqa: PLC0415

    sleutel = Sleutelpaar.nieuw("k1")
    meta = json.dumps({"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}}).encode()
    gevraagd: list[str | None] = []

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        gevraagd.append(request.headers.get("accept-encoding"))
        return httpx2.Response(
            200,
            content=gzip.compress(meta),
            headers={"content-encoding": "gzip", "content-type": "application/json"},
        )

    bron = Sleutelbron(_jwks_ophaler(antwoord, {}))
    assert _loop(bron.sleutel(LINDEVOORT, "k1")).thumbprint() == sleutel.jkt
    assert gevraagd == ["identity"]


def test_gecomprimeerd_antwoord_valt_onder_de_grens_na_decompressie() -> None:
    import gzip  # noqa: PLC0415

    bom = gzip.compress(b" " * (bronnen.MAX_ANTWOORD + 1))
    assert len(bom) < bronnen.MAX_ANTWOORD
    ophaler = _jwks_ophaler(
        lambda r: httpx2.Response(200, content=bom, headers={"content-encoding": "gzip"}), {}
    )
    with pytest.raises(BronFout) as info:
        _loop(ophaler.haal(f"{ISS}/x", ISS, "application/json"))
    assert info.value.reden == "antwoord_te_groot"


@pytest.mark.parametrize(
    ("headers", "verwacht"),
    [
        ({}, 300),
        ({"cache-control": "max-age=60"}, 60),
        ({"cache-control": "max-age=999999"}, 300),
        ({"cache-control": "no-store"}, 0),
        ({"cache-control": "No-Store"}, 0),
        ({"cache-control": "public, NO-CACHE"}, 0),
        ({"cache-control": 'no-cache="set-cookie"'}, 0),
        ({"cache-control": 'max-age="1"'}, 1),
        ({"cache-control": "MAX-AGE=7"}, 7),
        ({"cache-control": "max-age=60", "age": "0"}, 59),  # Age in hele seconden: plus 1
        ({"cache-control": "max-age=60", "age": "49"}, 10),
        ({"cache-control": "max-age=60", "age": "59"}, 0),
        ({"cache-control": "max-age=60", "age": "70"}, 0),
        ({"cache-control": "max-age=60", "age": "x"}, 0),
        ({"cache-control": "max-age=60", "age": "5, 6"}, 0),  # twee Age-headers
        ({"cache-control": "max-age=999999", "age": "100"}, 199),
        ({"age": "290"}, 9),  # zonder max-age telt de ouderdom ook
        ({"age": "400"}, 0),
        ({"age": "x"}, 0),
        ({"cache-control": "max-age=abc"}, 0),
        ({"cache-control": "max-age=²".encode()}, 0),
        ({"cache-control": "max-age=-1"}, 0),
        ({"cache-control": "max-age=5, max-age=10"}, 0),
        ({"cache-control": "max-age=" + "9" * 5000}, 300),
    ],
)
def test_cacheduur_volgt_rfc_9111(headers: dict[str, Any], verwacht: int) -> None:
    antwoord = httpx2.Response(200, headers=headers)
    assert bronnen._cacheduur(antwoord, bronnen.JWKS_CACHE_S) == verwacht


@pytest.mark.parametrize(
    ("headers", "verwacht"),
    [
        ([], 0),  # geen cache ertussen
        ([("age", "0")], 1),  # afgerond naar beneden: tot een seconde oud
        ([("age", "4")], 5),
        ([("age", "x")], None),
        ([("age", "-1")], None),
        ([("age", "5"), ("age", "6")], None),  # eigen beleid, strenger dan RFC 9111 §5.1
    ],
)
def test_leeftijd_telt_de_afrondingsseconde_mee(
    headers: list[tuple[str, str]], verwacht: int | None
) -> None:
    antwoord = httpx2.Response(200, headers=headers)
    assert bronnen._leeftijd(antwoord) == verwacht
    if verwacht is None:
        assert bronnen._cacheduur(antwoord, bronnen.JWKS_CACHE_S) == 0


@pytest.mark.parametrize(
    ("opgeslagen_op", "eerste"),
    [(999.95, 1000.5), (999.95, 1002.9), (999.5, 1003.4), (999.05, 1001.0), (999.0, 1003.0)],
)
def test_tussenliggende_http_cache_verlengt_het_intrekkingsvenster_niet(
    monkeypatch: pytest.MonkeyPatch, opgeslagen_op: float, eerste: float
) -> None:
    """Een gedeelde HTTP-cache (RFC 9111 §4) bewaarde de lijst vlak voor de intrekking op T = 1000.

    De cache levert dat oude antwoord met `Age` in hele seconden, naar beneden afgerond zoals
    Varnish, en haalt pas na `max-age` opnieuw op (geen grace). De verifier vraagt vanaf `eerste`
    elke 0,05 s. Elke aanroep vanaf T + ttl (1005) moet de intrekking zien. Zonder `Age` gold de
    oude lijst tot ruim na 1005; met `Age` zonder de afrondingsseconde bij (999.95, 1000.5) nog
    tot 1005.5.
    """
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, eerste)
    na_intrekking = _statustoken(sleutel, 1, iat=1000, exp=1060)
    cache: dict[str, Any] = {
        "tijd": opgeslagen_op,
        "token": _statustoken(sleutel, 0, iat=999, exp=1059),
    }

    def http_cache(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            return httpx2.Response(
                200,
                json={"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}},
                headers={"cache-control": "max-age=100000"},
            )
        if klok.nu - cache["tijd"] >= 5:  # niet meer vers voor de cache: naar de uitgever
            cache.update(tijd=klok.nu, token=na_intrekking)
        kop = {**STATUS_KOP, "cache-control": "max-age=5"}
        age = str(math.floor(klok.nu - cache["tijd"]))
        return httpx2.Response(200, text=cache["token"], headers={**kop, "age": age})

    ophaler = Ophaler(
        True,
        frozenset({"localhost"}),
        httpx2.AsyncClient(transport=httpx2.MockTransport(http_cache)),
    )  # type: ignore[arg-type]
    bron = Statusbron(ophaler, Sleutelbron(ophaler))
    uitkomsten: list[tuple[float, bronnen.Statusuitkomst]] = []
    for tik in range(round(eerste * 20), 1012 * 20 + 1):
        klok.nu = tik / 20
        uitkomsten.append((klok.nu, _loop(bron.status(STATUS_URI, 3, LINDEVOORT))))
    assert any(t == 1005 for t, _ in uitkomsten)  # ook een aanroep precies op T + ttl
    assert [(t, u) for t, u in uitkomsten if t >= 1005 and u.waarde != 1] == []
    assert any(u.waarde == 0 for _, u in uitkomsten)  # de oude lijst is echt geleverd


def test_te_oud_antwoord_bewaart_de_intrekking_maar_telt_nooit_als_vers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 995)
    huidig = {"token": _statustoken(sleutel, 0, iat=990, exp=2000)}
    bron = _statusbron(sleutel, huidig)
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)) == bronnen.Statusuitkomst(0, "vers")
    # Nieuwer token met de intrekking, maar via een cache al 6 s oud (ttl 5).
    huidig.update(token=_statustoken(sleutel, 1, iat=1000, exp=2000), age="6")
    klok.nu = 1001
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)) == bronnen.Statusuitkomst(
        1, "cache-verouderd"
    )
    cache = bron._caches[(ISS, STATUS_URI)]
    assert cache.token is not None
    assert cache.token.iat == 1000
    assert cache.laatste_fout is not None
    assert cache.laatste_fout.reden == "statusantwoord_verouderd"
    # Pas een vers antwoord (zonder ouderdom) geeft weer `vers`.
    del huidig["age"]
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)) == bronnen.Statusuitkomst(1, "vers")


@pytest.mark.parametrize("age", ["x", "-1", "5, 6"])
def test_ongeldige_age_telt_als_verouderd(monkeypatch: pytest.MonkeyPatch, age: str) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    _Klok(monkeypatch, 1000)
    bron = _statusbron(sleutel, {"token": _statustoken(sleutel, 1, iat=1000, exp=2000), "age": age})
    assert _loop(bron.status(STATUS_URI, 3, LINDEVOORT)) == bronnen.Statusuitkomst(
        1, "cache-verouderd"
    )


def test_hetzelfde_token_met_meer_ouderdom_verkort_de_cache_niet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    klok = _Klok(monkeypatch, 1000)
    huidig = {"token": _statustoken(sleutel, 0, iat=1000, exp=2000)}
    bron = _statusbron(sleutel, huidig)
    _loop(bron.ververs(STATUS_URI, LINDEVOORT))
    huidig["age"] = "4"  # achtergrondverversing krijgt hetzelfde token uit een cache
    klok.nu = 1002
    _loop(bron.ververs(STATUS_URI, LINDEVOORT))
    assert bron._caches[(ISS, STATUS_URI)].opgehaald == 1000


def _jwks_bron(klok: _Klok, kop: dict[str, str], duur: float = 0.0) -> Sleutelbron:
    sleutel = Sleutelpaar.nieuw("k1")

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        klok.nu += duur
        return httpx2.Response(
            200, json={"issuer": ISS, "jwks": {"keys": [sleutel.jwks_lid]}}, headers=kop
        )

    return Sleutelbron(_jwks_ophaler(antwoord, {}))


def test_jwks_grens_telt_age_en_transporttijd(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 9111 §4.2.3: begin van de aanvraag plus levensduur min `Age` en de afrondingsseconde."""
    klok = _Klok(monkeypatch, 1000)
    bron = _jwks_bron(klok, {"cache-control": "max-age=10", "age": "2"}, duur=3)
    _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert bron._caches[ISS].geldig_tot == 1007


def test_jwks_die_bij_aankomst_al_verlopen_is_wordt_niet_bewaard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    klok = _Klok(monkeypatch, 1000)
    bron = _jwks_bron(klok, {"cache-control": "max-age=1"}, duur=4)
    _loop(bron.sleutel(LINDEVOORT, "k1"))  # deze aanvraag mag de sleutel gebruiken
    assert (bron._caches[ISS].sleutels, bron._caches[ISS].geldig_tot) == ({}, 0.0)
    klok.nu = 1004.5
    with pytest.raises(BronFout) as info:
        _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert info.value.reden == "jwks_niet_beschikbaar"


def test_jwks_uri_geldt_tot_de_kortste_van_metadata_en_jwks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleutel = Sleutelpaar.nieuw("k1")
    _Klok(monkeypatch, 1000)

    def antwoord(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("jwt-vc-issuer"):
            return httpx2.Response(
                200,
                json={"issuer": ISS, "jwks_uri": f"{ISS}/jwks.json"},
                headers={"cache-control": "max-age=5"},
            )
        return httpx2.Response(
            200, json={"keys": [sleutel.jwks_lid]}, headers={"cache-control": "max-age=1000"}
        )

    bron = Sleutelbron(_jwks_ophaler(antwoord, {}))
    _loop(bron.sleutel(LINDEVOORT, "k1"))
    assert bron._caches[ISS].geldig_tot == 1005
