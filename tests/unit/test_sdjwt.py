"""SD-JWT: testvectoren uit RFC 9901 en alle weigeringen uit §7.1."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from mandaatbewijs import sdjwt
from mandaatbewijs.sdjwt import (
    Credential,
    Disclosure,
    SdJwtFout,
    b64url,
    digest,
    geef_uit,
    ontleed,
    presenteer,
    serialiseer,
    verifieer,
)
from mandaatbewijs.sleutels import Sleutelpaar

AUD = "https://inkomensregister.test"


def test_testvector_disclosure_uit_rfc_9901() -> None:
    gecodeerd = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
    assert digest(gecodeerd) == "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
    d = Disclosure.decodeer(gecodeerd)
    assert (d.zout, d.naam, d.waarde) == ("_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius")
    # De ontvangen tekst (met spaties in de JSON) blijft leidend voor de digest.
    assert d.gecodeerd == gecodeerd
    assert d.digest == "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"


def test_testvector_array_element_uit_rfc_9901() -> None:
    gecodeerd = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"
    d = Disclosure.decodeer(gecodeerd)
    assert d.naam is None
    assert d.waarde == "FR"
    assert d.digest == "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"


@pytest.fixture
def uitgever() -> Sleutelpaar:
    return Sleutelpaar.nieuw("u1")


@pytest.fixture
def agent() -> Sleutelpaar:
    return Sleutelpaar.nieuw()


def claims_voor(agent: Sleutelpaar, nu: int) -> dict[str, Any]:
    return {
        "iss": "http://uitgever:8000",
        "vct": "https://oomny.nl/vct/agentmandaat/v1",
        "jti": "m-1",
        "iat": nu,
        "nbf": nu,
        "exp": nu + 3600,
        "cnf": {"jwk": agent.publieke_jwk},
        "status": {"status_list": {"idx": 7, "uri": "http://uitgever:8000/statuslijsten/1"}},
        "doel": "aanvraag-levensonderhoud",
        "medewerker": {"id": "sanne", "naam": "Sanne de Vries"},
        "afdeling": "Werk en Inkomen",
        "acties": ["inkomen:lezen"],
        "dossiers": ["2026-0142", "2026-0143"],
    }


VERBORGEN = {"doel", "medewerker", "afdeling"}
PER_ELEMENT = {"acties", "dossiers"}


@pytest.fixture
def credential(uitgever: Sleutelpaar, agent: Sleutelpaar) -> Credential:
    nu = int(time.time())
    uitgifte, _ = geef_uit(uitgever, claims_voor(agent, nu), VERBORGEN, PER_ELEMENT)
    return Credential.uit_serialisatie(uitgifte)


def kies(credential: Credential, dossier: str = "2026-0142") -> list[Disclosure]:
    gekozen = [
        credential.disclosure_voor("doel"),
        credential.disclosure_voor("acties", "inkomen:lezen"),
        credential.disclosure_voor("dossiers", dossier),
    ]
    assert all(gekozen)
    return [d for d in gekozen if d is not None]


def test_uitgifte_verbergt_waarden_en_toont_structuur(credential: Credential) -> None:
    payload = credential.payload
    assert "doel" not in payload
    assert "medewerker" not in payload
    assert len(payload["_sd"]) == 5  # drie claims + twee decoys
    assert payload["_sd"] == sorted(payload["_sd"])
    assert [set(e) for e in payload["dossiers"]] == [{"..."}, {"..."}]
    assert payload["_sd_alg"] == "sha-256"
    assert credential.verborgen_namen == ["afdeling", "doel", "medewerker"]
    assert len(credential.disclosures) == 6
    assert all(len(sdjwt.b64url_decode(d.zout)) == 16 for d in credential.disclosures)


def test_presentatie_wordt_geverifieerd_met_alleen_gekozen_claims(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    pres = presenteer(credential, kies(credential), agent, AUD, "n-1")
    uitkomst = verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert uitkomst.nonce == "n-1"
    assert uitkomst.jkt == agent.jkt
    # Een bekendgemaakt lijstelement telt onder de naam van zijn lijstclaim, zonder herhaling.
    assert uitkomst.bekendgemaakt == ["acties", "doel", "dossiers"]
    assert uitkomst.claims["doel"] == "aanvraag-levensonderhoud"
    assert uitkomst.claims["acties"] == ["inkomen:lezen"]
    assert uitkomst.claims["dossiers"] == ["2026-0142"]
    assert "medewerker" not in uitkomst.claims
    assert "_sd" not in uitkomst.claims
    assert "_sd_alg" not in uitkomst.claims


def test_ontleed_toont_iss_en_vct_zonder_controle(
    credential: Credential, agent: Sleutelpaar
) -> None:
    pres = presenteer(credential, [], agent, AUD, "n-1")
    o = ontleed(pres)
    assert o.iss == "http://uitgever:8000"
    assert o.vct == "https://oomny.nl/vct/agentmandaat/v1"
    assert o.kop["kid"] == "u1"
    assert o.kop["typ"] == "dc+sd-jwt"


def test_uitgiftevorm_met_kb_wordt_geweigerd(credential: Credential, agent: Sleutelpaar) -> None:
    pres = presenteer(credential, [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout, match="credential_ongeldig"):
        Credential.uit_serialisatie(pres)


def reden(fout: pytest.ExceptionInfo[SdJwtFout]) -> str:
    return fout.value.reden


def test_presentatie_zonder_kb_wordt_geweigerd(credential: Credential) -> None:
    with pytest.raises(SdJwtFout) as fout:
        ontleed(serialiseer(credential.jwt, credential.disclosures, None))
    assert reden(fout) == "kb_ontbreekt"


def test_te_grote_presentatie_wordt_geweigerd(credential: Credential, agent: Sleutelpaar) -> None:
    pres = presenteer(credential, [], agent, AUD, "n-1") + "x" * sdjwt.MAX_PRESENTATIE
    with pytest.raises(SdJwtFout) as fout:
        ontleed(pres)
    assert reden(fout) == "presentatie_te_groot"


def test_verkeerde_uitgeverssleutel(credential: Credential, agent: Sleutelpaar) -> None:
    pres = presenteer(credential, kies(credential), agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), Sleutelpaar.nieuw("u2").sleutel, AUD)
    assert reden(fout) == "handtekening_ongeldig"


def test_verkeerde_typ_op_issuer_jwt(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    claims = claims_voor(agent, nu) | {"_sd_alg": "sha-256"}
    jwt = uitgever.teken({"typ": "JWT"}, claims)
    pres = presenteer(Credential(jwt, [], claims), [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "typ_onjuist"


def test_alg_none_wordt_geweigerd(
    credential: Credential, agent: Sleutelpaar, uitgever: Sleutelpaar
) -> None:
    kop = b64url(json.dumps({"alg": "none", "typ": "dc+sd-jwt"}).encode())
    payload = credential.jwt.split(".")[1]
    jwt = f"{kop}.{payload}."
    pres = presenteer(Credential(jwt, [], {}), [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "alg_onjuist"


def test_kb_met_andere_sleutel(credential: Credential, uitgever: Sleutelpaar) -> None:
    pres = presenteer(credential, kies(credential), Sleutelpaar.nieuw(), AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "kb_handtekening_ongeldig"


def test_kb_met_verkeerde_aud(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    pres = presenteer(credential, kies(credential), agent, "https://ander.test", "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "aud_onjuist"


def test_kb_aud_als_lijst_wordt_geweigerd(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    kb = agent.teken(
        {"typ": "kb+jwt"},
        {
            "iat": int(time.time()),
            "aud": [AUD],
            "nonce": "n",
            "sd_hash": sdjwt.sd_hash(credential.jwt, []),
        },
    )
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(serialiseer(credential.jwt, [], kb)), uitgever.sleutel, AUD)
    assert reden(fout) == "aud_onjuist"


def test_kb_te_oud(credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    pres = presenteer(credential, kies(credential), agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD, nu=int(time.time()) + 120)
    assert reden(fout) == "kb_verlopen"


def test_kb_typ_onjuist(credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    kb = agent.teken(
        {"typ": "JWT"},
        {
            "iat": int(time.time()),
            "aud": AUD,
            "nonce": "n",
            "sd_hash": sdjwt.sd_hash(credential.jwt, []),
        },
    )
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(serialiseer(credential.jwt, [], kb)), uitgever.sleutel, AUD)
    assert reden(fout) == "kb_typ_onjuist"


def test_kb_zonder_nonce(credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    kb = agent.teken(
        {"typ": "kb+jwt"},
        {"iat": int(time.time()), "aud": AUD, "sd_hash": sdjwt.sd_hash(credential.jwt, [])},
    )
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(serialiseer(credential.jwt, [], kb)), uitgever.sleutel, AUD)
    assert reden(fout) == "nonce_ontbreekt"


def test_disclosure_toegevoegd_na_tekenen_breekt_sd_hash(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    gekozen = kies(credential)
    pres = presenteer(credential, gekozen, agent, AUD, "n-1")
    extra = credential.disclosure_voor("dossiers", "2026-0143")
    assert extra is not None
    jwt, *_, kb = pres.split("~")
    gemanipuleerd = serialiseer(jwt, [*gekozen, extra], kb)
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(gemanipuleerd), uitgever.sleutel, AUD)
    assert reden(fout) == "sd_hash_onjuist"


def test_disclosure_weggelaten_na_tekenen_breekt_sd_hash(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    gekozen = kies(credential)
    pres = presenteer(credential, gekozen, agent, AUD, "n-1")
    jwt, *_, kb = pres.split("~")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(serialiseer(jwt, gekozen[:-1], kb)), uitgever.sleutel, AUD)
    assert reden(fout) == "sd_hash_onjuist"


def test_disclosure_van_andere_credential(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    a, _ = geef_uit(uitgever, claims_voor(agent, nu), VERBORGEN, PER_ELEMENT)
    b, _ = geef_uit(uitgever, claims_voor(agent, nu) | {"jti": "m-2"}, VERBORGEN, PER_ELEMENT)
    ca, cb = Credential.uit_serialisatie(a), Credential.uit_serialisatie(b)
    vreemd = cb.disclosure_voor("doel")
    assert vreemd is not None
    pres = presenteer(ca, [vreemd], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "disclosure_onbekend"


def test_dubbele_disclosure(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    doel = credential.disclosure_voor("doel")
    assert doel is not None
    pres = presenteer(credential, [doel, doel], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "disclosure_dubbel"


def teken_met_payload(uitgever: Sleutelpaar, payload: dict[str, Any]) -> str:
    return uitgever.teken({"typ": "dc+sd-jwt"}, payload)


def test_dubbele_digest_zonder_disclosure(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    """RFC 9901 §7.1: een digest die twee keer voorkomt is ongeldig, ook zonder disclosure."""
    nu = int(time.time())
    decoy = digest(b64url(b"x" * 16))
    payload = claims_voor(agent, nu) | {"_sd_alg": "sha-256", "_sd": [decoy, decoy]}
    for naam in VERBORGEN | PER_ELEMENT:
        payload.pop(naam)
    jwt = teken_met_payload(uitgever, payload)
    pres = presenteer(Credential(jwt, [], payload), [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "digest_dubbel"


def test_disclosure_met_vc_claimnaam_wordt_geweigerd(
    uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    nu = int(time.time())
    d = Disclosure.nieuw("exp", nu + 999999)
    payload = claims_voor(agent, nu) | {"_sd_alg": "sha-256", "_sd": [d.digest]}
    for naam in VERBORGEN | PER_ELEMENT:
        payload.pop(naam)
    jwt = teken_met_payload(uitgever, payload)
    pres = presenteer(Credential(jwt, [d], payload), [d], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "claimnaam_ongeldig"


def test_disclosure_met_bestaande_claimnaam_wordt_geweigerd(
    uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    nu = int(time.time())
    d = Disclosure.nieuw("doel", "ander-doel")
    payload = claims_voor(agent, nu) | {"_sd_alg": "sha-256", "_sd": [d.digest]}
    for naam in {"medewerker", "afdeling"} | PER_ELEMENT:
        payload.pop(naam)
    jwt = teken_met_payload(uitgever, payload)
    pres = presenteer(Credential(jwt, [d], payload), [d], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "claimnaam_ongeldig"


def test_array_disclosure_in_sd_wordt_geweigerd(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    d = Disclosure.nieuw(None, "los")
    payload = claims_voor(agent, nu) | {"_sd_alg": "sha-256", "_sd": [d.digest]}
    for naam in VERBORGEN | PER_ELEMENT:
        payload.pop(naam)
    jwt = teken_met_payload(uitgever, payload)
    pres = presenteer(Credential(jwt, [d], payload), [d], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "disclosure_ongeldig"


def test_ongeldige_disclosure_tekst(credential: Credential, agent: Sleutelpaar) -> None:
    pres = presenteer(credential, [], agent, AUD, "n-1")
    jwt, kb = pres.split("~")
    with pytest.raises(SdJwtFout) as fout:
        ontleed("~".join([jwt, b64url(b'{"geen": "lijst"}'), kb]))
    assert reden(fout) == "disclosure_ongeldig"


def test_verlopen_credential(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    claims = claims_voor(agent, nu - 7200)
    uitgifte, _ = geef_uit(uitgever, claims, VERBORGEN, PER_ELEMENT)
    c = Credential.uit_serialisatie(uitgifte)
    pres = presenteer(c, kies(c), agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "credential_verlopen"


def test_nog_niet_geldige_credential(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    uitgifte, _ = geef_uit(uitgever, claims_voor(agent, nu + 600), VERBORGEN, PER_ELEMENT)
    c = Credential.uit_serialisatie(uitgifte)
    pres = presenteer(c, [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "credential_nog_niet_geldig"


def test_klokmarge_van_dertig_seconden(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    uitgifte, _ = geef_uit(uitgever, claims_voor(agent, nu + 20), VERBORGEN, PER_ELEMENT)
    c = Credential.uit_serialisatie(uitgifte)
    pres = presenteer(c, [], agent, AUD, "n-1")
    assert verifieer(ontleed(pres), uitgever.sleutel, AUD).claims["jti"] == "m-1"


def test_cnf_ontbreekt(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    claims = claims_voor(agent, nu)
    claims.pop("cnf")
    uitgifte, _ = geef_uit(uitgever, claims, VERBORGEN, PER_ELEMENT)
    c = Credential.uit_serialisatie(uitgifte)
    pres = presenteer(c, [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "cnf_ontbreekt"


def test_status_idx_moet_niet_negatief_geheel_getal_zijn(
    uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    nu = int(time.time())
    claims = claims_voor(agent, nu)
    claims["status"]["status_list"]["idx"] = -1
    uitgifte, _ = geef_uit(uitgever, claims, VERBORGEN, PER_ELEMENT)
    c = Credential.uit_serialisatie(uitgifte)
    pres = presenteer(c, [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "status_ongeldig"


def test_sd_alg_anders_dan_sha256(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    payload = claims_voor(agent, nu) | {"_sd_alg": "sha-512"}
    for naam in VERBORGEN | PER_ELEMENT:
        payload.pop(naam)
    jwt = teken_met_payload(uitgever, payload)
    pres = presenteer(Credential(jwt, [], payload), [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "sd_alg_onjuist"


def test_disclosure_voor_onbekend_element_is_none(credential: Credential) -> None:
    assert credential.disclosure_voor("dossiers", "2026-9999") is None
    assert credential.disclosure_voor("acties", "inkomen:corrigeren") is None
    assert credential.disclosure_voor("bestaat_niet") is None


def test_selectieve_subclaim_in_beschermde_claim_wordt_geweigerd(
    uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    """SD-JWT VC §2.2.2.3: ook subclaims van cnf en status mogen niet selectief zijn."""
    nu = int(time.time())
    d = Disclosure.nieuw("idx", 7)
    payload = claims_voor(agent, nu) | {"_sd_alg": "sha-256"}
    for naam in VERBORGEN | PER_ELEMENT:
        payload.pop(naam)
    payload["status"] = {
        "status_list": {"uri": "http://uitgever:8000/statuslijsten/1", "_sd": [d.digest]}
    }
    jwt = teken_met_payload(uitgever, payload)
    pres = presenteer(Credential(jwt, [d], payload), [d], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "claimnaam_ongeldig"
    assert "status" in fout.value.detail


def test_array_digest_in_cnf_wordt_geweigerd(uitgever: Sleutelpaar, agent: Sleutelpaar) -> None:
    nu = int(time.time())
    payload = claims_voor(agent, nu) | {"_sd_alg": "sha-256"}
    for naam in VERBORGEN | PER_ELEMENT:
        payload.pop(naam)
    payload["cnf"] = {"jwk": agent.publieke_jwk, "extra": [{"...": digest("x")}]}
    jwt = teken_met_payload(uitgever, payload)
    pres = presenteer(Credential(jwt, [], payload), [], agent, AUD, "n-1")
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(pres), uitgever.sleutel, AUD)
    assert reden(fout) == "claimnaam_ongeldig"


@pytest.mark.parametrize("kb", ["a.b.c", "!!!.!!!.!!!", "YWJj.YWJj.YWJj", "e30.e30.AA"])
def test_misvormde_kb_jwt_is_een_gewone_weigering(
    credential: Credential, uitgever: Sleutelpaar, kb: str
) -> None:
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(serialiseer(credential.jwt, [], kb)), uitgever.sleutel, AUD)
    assert reden(fout) in ("kb_jwt_ongeldig", "kb_typ_onjuist")


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_kb_jwt_met_ander_alg_wordt_geweigerd(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar, alg: str
) -> None:
    """Ook de key binding JWT accepteert alleen ES256 (DREIGINGSMODEL: `alg: none`)."""
    pres = presenteer(credential, kies(credential), agent, AUD, "n-1")
    jwt, *disclosures, kb = pres.split("~")
    kop = b64url(json.dumps({"alg": alg, "typ": "kb+jwt"}).encode())
    payload = kb.split(".")[1]
    handtekening = b64url(b"\x00" * 32) if alg == "HS256" else ""
    vervalst = "~".join([jwt, *disclosures, f"{kop}.{payload}.{handtekening}"])
    with pytest.raises(SdJwtFout) as fout:
        verifieer(ontleed(vervalst), uitgever.sleutel, AUD)
    assert reden(fout) in ("kb_alg_onjuist", "kb_jwt_ongeldig")


def test_controleer_uitgifte_aan_houderskant(
    credential: Credential, uitgever: Sleutelpaar, agent: Sleutelpaar
) -> None:
    claims = sdjwt.controleer_uitgifte(
        credential, uitgever.sleutel, "http://uitgever:8000", agent.jkt
    )
    assert claims["doel"] == "aanvraag-levensonderhoud"
    assert claims["dossiers"] == ["2026-0142", "2026-0143"]
    # Verkeerde uitgever, andere sleutelbinding, vervalste handtekening, gewijzigde disclosure.
    with pytest.raises(SdJwtFout) as fout:
        sdjwt.controleer_uitgifte(credential, uitgever.sleutel, "http://ander:8000", agent.jkt)
    assert reden(fout) == "iss_onjuist"
    with pytest.raises(SdJwtFout) as fout:
        sdjwt.controleer_uitgifte(
            credential, uitgever.sleutel, "http://uitgever:8000", Sleutelpaar.nieuw().jkt
        )
    assert reden(fout) == "cnf_onjuist"
    with pytest.raises(SdJwtFout) as fout:
        sdjwt.controleer_uitgifte(
            credential, Sleutelpaar.nieuw("u2").sleutel, "http://uitgever:8000", agent.jkt
        )
    assert reden(fout) == "handtekening_ongeldig"
    doel = credential.disclosure_voor("doel")
    assert doel is not None
    vervalst = Disclosure.decodeer(b64url(json.dumps([doel.zout, "doel", "fraude"]).encode()))
    disclosures = [vervalst if d is doel else d for d in credential.disclosures]
    with pytest.raises(SdJwtFout) as fout:
        sdjwt.controleer_uitgifte(
            Credential(credential.jwt, disclosures, credential.payload),
            uitgever.sleutel,
            "http://uitgever:8000",
            agent.jkt,
        )
    assert reden(fout) == "disclosure_onbekend"
