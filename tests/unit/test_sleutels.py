"""Sleutels: JWK-vormen, thumbprint, bewaren en laden, weigering van privé-JWK's."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

import pytest

from mandaatbewijs.sleutels import (
    Sleutelpaar,
    jose_kop,
    lees_afgeschermd,
    maak_afgeschermd,
    publieke_sleutel,
    thumbprint,
)


def test_publieke_jwk_bevat_geen_privelid() -> None:
    paar = Sleutelpaar.nieuw("u1")
    assert set(paar.publieke_jwk) == {"kty", "crv", "x", "y"}
    assert paar.jwks_lid["kid"] == "u1"
    assert paar.jwks_lid["alg"] == "ES256"
    assert "d" not in paar.jwks_lid
    assert thumbprint(paar.publieke_jwk) == paar.jkt


def test_bewaren_en_laden(tmp_path: Path) -> None:
    paar = Sleutelpaar.nieuw("u1")
    pad = tmp_path / "geheimen" / "uitgever.jwk"
    paar.bewaar(pad)
    assert oct(pad.stat().st_mode & 0o777) == "0o600"
    geladen = Sleutelpaar.laad(pad)
    assert geladen.jkt == paar.jkt
    assert geladen.kid == "u1"


def test_publieke_sleutel_weigert_prive_en_andere_typen() -> None:
    paar = Sleutelpaar.nieuw()
    prive = paar.sleutel.as_dict(private=True)
    with pytest.raises(ValueError, match="publieke P-256"):
        publieke_sleutel(prive)
    with pytest.raises(ValueError, match="publieke P-256"):
        publieke_sleutel({"kty": "RSA", "n": "x", "e": "AQAB"})
    assert publieke_sleutel(paar.publieke_jwk).thumbprint() == paar.jkt


@pytest.mark.parametrize(
    "beperking",
    [{"use": "enc"}, {"alg": "ECDH-ES"}, {"key_ops": ["deriveKey"]}, {"key_ops": "verify"}],
)
def test_publieke_sleutel_respecteert_gebruiksbeperkingen(beperking: dict[str, Any]) -> None:
    """RFC 7517 §4.2-4.4: een sleutel voor iets anders dan ES256-verificatie wordt geweigerd."""
    paar = Sleutelpaar.nieuw()
    with pytest.raises(ValueError, match=r"use|alg|key_ops"):
        publieke_sleutel(paar.publieke_jwk | beperking)


def test_publieke_sleutel_met_passende_beperkingen() -> None:
    paar = Sleutelpaar.nieuw("u1")
    passend = paar.jwks_lid | {"key_ops": ["verify"]}
    assert publieke_sleutel(passend).thumbprint() == paar.jkt


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.mark.parametrize("kop", [b'["alg"]', b"[]", b'"ES256"'])
def test_jose_kop_eist_een_object(kop: bytes) -> None:
    with pytest.raises(ValueError, match=r"JSON-object|compacte JWS"):
        jose_kop(f"{_b64(kop)}.{_b64(b'{}')}.")


def test_jose_kop_van_een_echte_jws() -> None:
    paar = Sleutelpaar.nieuw("u1")
    assert jose_kop(paar.teken({"typ": "x"}, {})) == {"alg": "ES256", "typ": "x", "kid": "u1"}


def test_geheim_bestaat_vanaf_de_eerste_byte_met_rechten_0600(tmp_path: Path) -> None:
    oud = os.umask(0)
    try:
        assert maak_afgeschermd(tmp_path / "map" / "geheim", "inhoud")
    finally:
        os.umask(oud)
    assert oct((tmp_path / "map" / "geheim").stat().st_mode & 0o777) == "0o600"
    assert [p.name for p in (tmp_path / "map").iterdir()] == ["geheim"]


def test_bestaand_geheim_wordt_niet_overschreven(tmp_path: Path) -> None:
    pad = tmp_path / "geheim"
    assert maak_afgeschermd(pad, "eerste")
    assert not maak_afgeschermd(pad, "tweede")
    assert lees_afgeschermd(pad) == "eerste"
    assert [p.name for p in tmp_path.iterdir()] == ["geheim"]


def test_geheim_met_ruime_rechten_wordt_niet_gelezen(tmp_path: Path) -> None:
    pad = tmp_path / "uitgever.jwk"
    Sleutelpaar.nieuw("u1").bewaar(pad)
    pad.chmod(0o644)
    with pytest.raises(PermissionError, match="chmod 600"):
        Sleutelpaar.laad(pad)
