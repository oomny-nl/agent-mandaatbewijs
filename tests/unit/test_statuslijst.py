"""Token Status List: testvector uit draft-21 §4.1, token maken en lezen, weigeringen."""

from __future__ import annotations

import json
import time
import zlib

import pytest

from mandaatbewijs.sdjwt import b64url
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.statuslijst import (
    GELDIG,
    INGETROKKEN,
    MAX_BYTES,
    Statuslijst,
    StatuslijstFout,
    Tokenbeleid,
    lees_token,
    maak_token,
)

URI = "http://uitgever:8000/statuslijsten/1"
BELEID = Tokenbeleid(ttl_s=5, geldig_s=60)


def test_testvector_uit_de_draft() -> None:
    lijst = Statuslijst.decodeer("eNrbuRgAAhcBXQ", 1)
    assert bytes(lijst.inhoud) == bytes.fromhex("b9a3")
    assert [lijst.lees(i) for i in range(16)] == [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]


def test_zetten_en_lezen_lsb_eerst() -> None:
    lijst = Statuslijst.leeg(16)
    for i in (0, 3, 4, 5, 7, 8, 9, 13, 15):
        lijst.zet(i, INGETROKKEN)
    assert bytes(lijst.inhoud) == bytes.fromhex("b9a3")
    lijst.zet(0, GELDIG)
    assert lijst.lees(0) == GELDIG
    assert Statuslijst.decodeer(lijst.lst, 1).inhoud == lijst.inhoud


def test_index_buiten_de_lijst() -> None:
    lijst = Statuslijst.leeg(16)
    with pytest.raises(StatuslijstFout, match="idx_buiten_lijst"):
        lijst.lees(16)
    with pytest.raises(StatuslijstFout, match="idx_buiten_lijst"):
        lijst.lees(-1)
    with pytest.raises(StatuslijstFout, match="idx_buiten_lijst"):
        lijst.zet(16, 1)


def test_twee_bits_per_positie() -> None:
    lijst = Statuslijst.leeg(4, bits=2)
    lijst.zet(1, 2)
    lijst.zet(3, 3)
    assert [lijst.lees(i) for i in range(4)] == [0, 2, 0, 3]
    with pytest.raises(ValueError, match="past niet"):
        lijst.zet(0, 4)


def test_token_maken_en_lezen() -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    lijst = Statuslijst.leeg(1 << 16)
    lijst.zet(48213, INGETROKKEN)
    nu = int(time.time())
    token = maak_token(sleutel, URI, lijst, BELEID, nu=nu)
    gelezen = lees_token(token, sleutel.sleutel, URI, nu=nu)
    assert gelezen.ttl == 5
    assert gelezen.exp == nu + 60
    assert gelezen.claims["iss"] == "http://uitgever:8000"
    assert gelezen.lijst.lees(48213) == INGETROKKEN
    assert gelezen.lijst.lees(48212) == GELDIG
    assert gelezen.lijst.posities == 1 << 16


def test_token_met_andere_sleutel() -> None:
    token = maak_token(Sleutelpaar.nieuw("u1"), URI, Statuslijst.leeg(8), BELEID)
    with pytest.raises(StatuslijstFout, match="handtekening_ongeldig"):
        lees_token(token, Sleutelpaar.nieuw("u2").sleutel, URI)


def test_token_met_verkeerde_sub() -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    token = maak_token(sleutel, "http://elders:8000/statuslijsten/1", Statuslijst.leeg(8), BELEID)
    with pytest.raises(StatuslijstFout, match="sub_onjuist"):
        lees_token(token, sleutel.sleutel, URI)


def test_verlopen_token() -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    nu = int(time.time())
    token = maak_token(sleutel, URI, Statuslijst.leeg(8), BELEID, nu=nu - 120)
    with pytest.raises(StatuslijstFout, match="token_verlopen"):
        lees_token(token, sleutel.sleutel, URI, nu=nu)
    # Precies op exp is het token al verlopen; één seconde ervoor nog niet.
    token = maak_token(sleutel, URI, Statuslijst.leeg(8), BELEID, nu=nu - BELEID.geldig_s)
    with pytest.raises(StatuslijstFout, match="token_verlopen"):
        lees_token(token, sleutel.sleutel, URI, nu=nu)
    assert lees_token(token, sleutel.sleutel, URI, nu=nu - 1).exp == nu


def teken(sleutel: Sleutelpaar, kop: dict, claims: dict) -> str:
    return sleutel.teken(kop, claims)


def basisclaims(nu: int) -> dict:
    return {
        "sub": URI,
        "iat": nu,
        "exp": nu + 60,
        "ttl": 5,
        "status_list": {"bits": 1, "lst": Statuslijst.leeg(8).lst},
    }


def test_verkeerde_typ() -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    nu = int(time.time())
    token = teken(sleutel, {"typ": "JWT"}, basisclaims(nu))
    with pytest.raises(StatuslijstFout, match="typ_onjuist"):
        lees_token(token, sleutel.sleutel, URI, nu=nu)


@pytest.mark.parametrize("ontbreekt", ["sub", "iat", "exp", "ttl", "status_list"])
def test_ontbrekende_claim(ontbreekt: str) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    nu = int(time.time())
    claims = basisclaims(nu)
    claims.pop(ontbreekt)
    token = teken(sleutel, {"typ": "statuslist+jwt"}, claims)
    with pytest.raises(StatuslijstFout, match="claim_ontbreekt"):
        lees_token(token, sleutel.sleutel, URI, nu=nu)


@pytest.mark.parametrize(
    ("veld", "waarde"), [("ttl", 0), ("ttl", "5"), ("exp", True), ("iat", 1.5)]
)
def test_verkeerd_getypte_claims(veld: str, waarde: object) -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    nu = int(time.time())
    claims = basisclaims(nu) | {veld: waarde}
    token = teken(sleutel, {"typ": "statuslist+jwt"}, claims)
    with pytest.raises(StatuslijstFout, match="claim_ongeldig"):
        lees_token(token, sleutel.sleutel, URI, nu=nu)


def test_status_list_zonder_lst() -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    nu = int(time.time())
    claims = basisclaims(nu) | {"status_list": {"bits": 1}}
    token = teken(sleutel, {"typ": "statuslist+jwt"}, claims)
    with pytest.raises(StatuslijstFout, match="status_list_ongeldig"):
        lees_token(token, sleutel.sleutel, URI, nu=nu)


def test_ongeldige_lst() -> None:
    with pytest.raises(StatuslijstFout, match="lst_ongeldig"):
        Statuslijst.decodeer(b64url(b"geen zlib"), 1)
    with pytest.raises(StatuslijstFout, match="bits_ongeldig"):
        Statuslijst.decodeer("eNrbuRgAAhcBXQ", 3)
    afgeknot = zlib.compress(b"\xff" * 64)[:-6]  # zonder adler32-controlesom en eindblok
    with pytest.raises(StatuslijstFout, match="lst_ongeldig"):
        Statuslijst.decodeer(b64url(afgeknot), 1)


def test_decompressiebom_wordt_begrensd() -> None:
    bom = b64url(zlib.compress(b"\0" * (MAX_BYTES + 1), 9))
    with pytest.raises(StatuslijstFout, match="lst_te_groot"):
        Statuslijst.decodeer(bom, 1)


def test_token_payload_is_json_object() -> None:
    sleutel = Sleutelpaar.nieuw("u1")
    token = sleutel.teken({"typ": "statuslist+jwt"}, {"sub": URI})
    kop, _, sig = token.split(".")
    vals = f"{kop}.{b64url(json.dumps([1]).encode())}.{sig}"
    with pytest.raises(StatuslijstFout, match="handtekening_ongeldig"):
        lees_token(vals, sleutel.sleutel, URI)
