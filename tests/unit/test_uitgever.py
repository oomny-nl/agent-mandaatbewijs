"""De uitgever: metadata, verzoek, toestemming, ophalen met proof, intrekking en noodstop."""

from __future__ import annotations

import json
import time

import pytest
from starlette.testclient import TestClient

from mandaatbewijs.sdjwt import Credential
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.statuslijst import INGETROKKEN, MEDIATYPE, lees_token
from mandaatbewijs.uitgever import register
from mandaatbewijs.uitgever.app import Dienst
from mandaatbewijs.uitgever.gegevens import VCT
from tests.unit.conftest import ISS, audit, login, proof, verleen


def test_metadata_en_jwks(uitgever_client: TestClient, uitgever: Dienst) -> None:
    meta = uitgever_client.get("/.well-known/jwt-vc-issuer").json()
    assert meta["issuer"] == ISS
    jwks = uitgever_client.get("/jwks.json").json()
    assert [k["kid"] for k in jwks["keys"]] == [uitgever.uitgifte.sleutel.kid]
    assert "d" not in jwks["keys"][0]


def test_statuslijst_token_en_cache_control(uitgever_client: TestClient, uitgever: Dienst) -> None:
    antwoord = uitgever_client.get("/statuslijsten/1")
    assert antwoord.headers["content-type"].startswith(MEDIATYPE)
    assert antwoord.headers["cache-control"] == "max-age=1"
    token = lees_token(antwoord.text, uitgever.uitgifte.sleutel.sleutel, f"{ISS}/statuslijsten/1")
    assert token.ttl == 1


def test_volledige_uitgifte_met_verborgen_claims(
    uitgever_client: TestClient, uitgever: Dienst
) -> None:
    sleutel = Sleutelpaar.nieuw("agent")
    serialisatie, mandaat_id = verleen(uitgever_client, uitgever, sleutel)
    c = Credential.uit_serialisatie(serialisatie)
    assert c.payload["iss"] == ISS
    assert c.payload["vct"] == VCT
    assert c.payload["jti"] == mandaat_id
    assert c.payload["cnf"]["jwk"] == sleutel.publieke_jwk
    assert set(c.verborgen_namen) == {"doel", "medewerker", "afdeling"}
    assert c.disclosure_voor("acties", "inkomen:lezen") is not None
    assert c.disclosure_voor("dossiers", "2026-0142") is not None
    assert "medewerker" not in c.payload
    gebeurtenissen = [r["gebeurtenis"] for r in audit(uitgever)]
    assert gebeurtenissen == ["verzoek", "uitgegeven", "opgehaald"]


def test_toestemmingsscherm_alleen_eigen_verzoek(
    uitgever_client: TestClient, uitgever: Dienst
) -> None:
    sleutel = Sleutelpaar.nieuw()
    v = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0143"],
        },
    ).json()
    scherm = uitgever_client.get(f"/mandaatverzoeken/{v['id']}", auth=login(uitgever, "sanne"))
    assert scherm.status_code == 200
    assert scherm.json()["agent_jkt"] == sleutel.jkt
    ander = uitgever_client.get(f"/mandaatverzoeken/{v['id']}", auth=login(uitgever, "bram"))
    assert ander.status_code == 403
    fout = uitgever_client.get(f"/mandaatverzoeken/{v['id']}", auth=("sanne", "fout"))
    assert fout.status_code == 401


def test_nee_op_het_scherm(uitgever_client: TestClient, uitgever: Dienst) -> None:
    sleutel = Sleutelpaar.nieuw()
    v = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0143"],
        },
    ).json()
    nee = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "nee", "geldigheid_s": 600},
        auth=login(uitgever, "sanne"),
    )
    assert nee.status_code == 200
    assert nee.json()["status"] == "geweigerd"
    c = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/credential", json={"proof": proof(sleutel, v["id"])}
    )
    assert c.status_code != 200


def test_bevoegdheid_van_de_medewerker_begrenst_het_mandaat(
    uitgever_client: TestClient, uitgever: Dienst
) -> None:
    sleutel = Sleutelpaar.nieuw()
    gevallen = [
        ({"medewerker": "bram", "acties": ["inkomen:lezen"], "dossiers": ["2026-0157"]}, "rol"),
        (
            {"medewerker": "sanne", "acties": ["inkomen:corrigeren"], "dossiers": ["2026-0142"]},
            "rol",
        ),
        (
            {"medewerker": "sanne", "acties": ["inkomen:lezen"], "dossiers": ["2026-0157"]},
            "caseload",
        ),
        ({"medewerker": "sanne", "acties": ["inkomen:lezen"], "dossiers": []}, "minstens"),
    ]
    for velden, fragment in gevallen:
        v = uitgever_client.post(
            "/mandaatverzoeken",
            json={"agent_jwk": sleutel.publieke_jwk, "doel": "heronderzoek", **velden},
        ).json()
        t = uitgever_client.post(
            f"/mandaatverzoeken/{v['id']}/toestemming",
            json={"besluit": "ja", "geldigheid_s": 600},
            auth=login(uitgever, str(velden["medewerker"])),
        )
        assert t.status_code == 403, velden
        assert t.json()["detail"]["error"] == "bevoegdheid_ontbreekt"
        assert fragment in t.json()["detail"]["reden"]


def test_geldigheid_begrensd(uitgever_client: TestClient, uitgever: Dienst) -> None:
    sleutel = Sleutelpaar.nieuw()
    v = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0142"],
        },
    ).json()
    t = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "ja", "geldigheid_s": 86400},
        auth=login(uitgever, "sanne"),
    )
    assert t.status_code == 422


def test_proof_controles(uitgever_client: TestClient, uitgever: Dienst) -> None:
    sleutel, ander = Sleutelpaar.nieuw("a"), Sleutelpaar.nieuw("b")
    v = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0142"],
        },
    ).json()
    uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "ja", "geldigheid_s": 600},
        auth=login(uitgever, "sanne"),
    )
    url = f"/mandaatverzoeken/{v['id']}/credential"
    gevallen = {
        "proof_handtekening_ongeldig": proof(ander, v["id"]),
        "proof_aud_of_nonce_onjuist": proof(sleutel, "v-anders"),
        "proof_verlopen": proof(sleutel, v["id"], iat=int(time.time()) - 600),
        "proof_typ_of_alg_onjuist": sleutel.teken({"typ": "JWT"}, {"aud": ISS, "nonce": v["id"]}),
    }
    for reden, p in gevallen.items():
        antwoord = uitgever_client.post(url, json={"proof": p})
        assert antwoord.status_code == 401, reden
        assert antwoord.json()["detail"]["error"] == reden
    goed = uitgever_client.post(url, json={"proof": proof(sleutel, v["id"])})
    assert goed.status_code == 200
    # Eenmalig ophalen: een tweede keer is er geen credential meer.
    nogmaals = uitgever_client.post(url, json={"proof": proof(sleutel, v["id"])})
    assert nogmaals.status_code != 200


def test_intrekken_zet_het_bit(uitgever_client: TestClient, uitgever: Dienst) -> None:
    sleutel = Sleutelpaar.nieuw()
    serialisatie, mandaat_id = verleen(uitgever_client, uitgever, sleutel)
    idx = Credential.uit_serialisatie(serialisatie).payload["status"]["status_list"]["idx"]
    assert uitgever.register.status_van(idx) == 0
    ander = uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "bram"))
    assert ander.status_code == 403
    weg = uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    assert weg.status_code == 200
    assert uitgever.register.status_van(idx) == INGETROKKEN
    nogmaals = uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    assert nogmaals.status_code in (404, 409)
    sl = uitgever_client.get("/statuslijsten/1")
    token = lees_token(sl.text, uitgever.uitgifte.sleutel.sleutel, f"{ISS}/statuslijsten/1")
    assert token.lijst.lees(idx) == INGETROKKEN


def test_statustoken_iat_stijgt_strikt_ook_bij_intrekking_in_dezelfde_seconde(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Een intrekking in dezelfde seconde als de ondertekening geeft toch een hogere `iat`."""
    monkeypatch.setattr(time, "time", lambda: 1_800_000_000.0)  # de klok staat stil
    uri, sleutel = f"{ISS}/statuslijsten/1", uitgever.uitgifte.sleutel.sleutel
    _, mandaat_id = verleen(uitgever_client, uitgever, Sleutelpaar.nieuw())
    eerste_tekst = uitgever_client.get("/statuslijsten/1").text
    eerste = lees_token(eerste_tekst, sleutel, uri)
    assert uitgever_client.get("/statuslijsten/1").text == eerste_tekst  # ongewijzigd: zelfde token
    uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    tweede = lees_token(uitgever_client.get("/statuslijsten/1").text, sleutel, uri)
    assert tweede.iat == eerste.iat + 1
    assert tweede.lijst.inhoud != eerste.lijst.inhoud


def test_noodstop_blokkeert_sleutel_en_trekt_in(
    uitgever_client: TestClient, uitgever: Dienst
) -> None:
    sleutel = Sleutelpaar.nieuw()
    serialisatie, mandaat_id = verleen(uitgever_client, uitgever, sleutel)
    idx = Credential.uit_serialisatie(serialisatie).payload["status"]["status_list"]["idx"]
    geen = uitgever_client.post(
        "/noodstop", json={"jkt": sleutel.jkt}, auth=login(uitgever, "sanne")
    )
    assert geen.status_code == 403
    stop = uitgever_client.post(
        "/noodstop", json={"jkt": sleutel.jkt}, auth=login(uitgever, "kees")
    )
    assert stop.status_code == 200
    assert stop.json()["ingetrokken"] == [mandaat_id]
    assert uitgever.register.status_van(idx) == INGETROKKEN
    v = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0142"],
        },
    )
    assert v.status_code == 403
    assert v.json()["detail"]["error"] == "sleutel_geblokkeerd"
    assert audit(uitgever)[-1]["gebeurtenis"] == "verzoek_geweigerd"
    alle = uitgever_client.get("/mandaten/alle", auth=login(uitgever, "kees")).json()
    assert alle[0]["status"] == "ingetrokken"
    beheer = uitgever_client.get("/audit", auth=login(uitgever, "kees"))
    assert json.dumps(beheer.json()).count('"noodstop"') == 1


def test_agent_jwk_moet_publiek_en_p256_zijn(uitgever_client: TestClient) -> None:
    privaat = Sleutelpaar.nieuw().sleutel.as_dict(private=True)
    antwoord = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": privaat,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0142"],
        },
    )
    assert antwoord.status_code == 400


def test_ophalen_na_de_verzoektermijn_wordt_geweigerd(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Een goedgekeurd verzoek dat niet binnen de termijn is opgehaald, vervalt (410)."""
    sleutel = Sleutelpaar.nieuw()
    v = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0142"],
        },
    ).json()
    t = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "ja", "geldigheid_s": 300},
        auth=login(uitgever, "sanne"),
    )
    assert t.status_code == 200
    echte_tijd = time.time
    monkeypatch.setattr(register.time, "time", lambda: echte_tijd() + register.VERZOEK_GELDIG_S + 1)
    c = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/credential", json={"proof": proof(sleutel, v["id"])}
    )
    assert c.status_code == 410
    assert c.json()["detail"]["error"] == "verzoek_verlopen"
    assert uitgever.register.verzoek(v["id"]).credential is None


def test_toestemming_door_andere_medewerker_wordt_geweigerd(
    uitgever_client: TestClient, uitgever: Dienst
) -> None:
    sleutel = Sleutelpaar.nieuw()
    v = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0142"],
        },
    ).json()
    ander = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "ja", "geldigheid_s": 300},
        auth=login(uitgever, "bram"),
    )
    assert ander.status_code == 403
    assert ander.json()["detail"]["error"] == "verzoek_hoort_bij_andere_medewerker"
    assert uitgever.register.verzoek(v["id"]).status == "ingediend"
