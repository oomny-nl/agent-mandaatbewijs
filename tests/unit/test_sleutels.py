"""Sleutels: JWK-vormen, thumbprint, bewaren en laden, weigering van privé-JWK's."""

from __future__ import annotations

from pathlib import Path

import pytest

from mandaatbewijs.sleutels import Sleutelpaar, publieke_sleutel, thumbprint


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
