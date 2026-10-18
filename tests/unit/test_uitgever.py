"""De uitgever: metadata, verzoek, toestemming, ophalen met proof, intrekking en noodstop."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from mandaatbewijs.audit import controleer
from mandaatbewijs.sdjwt import Credential, b64url
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.statuslijst import INGETROKKEN, MEDIATYPE, Tokenbeleid, lees_token
from mandaatbewijs.uitgever import register
from mandaatbewijs.uitgever.app import Dienst, Instellingen, maak_app
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
    ingetrokken = [r for r in audit(uitgever) if r["gebeurtenis"] == "ingetrokken"]
    assert [(r["mandaat"], r["medewerker"]) for r in ingetrokken] == [(mandaat_id, "sanne")]
    nogmaals = uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    assert nogmaals.status_code in (404, 409)
    sl = uitgever_client.get("/statuslijsten/1")
    token = lees_token(sl.text, uitgever.uitgifte.sleutel.sleutel, f"{ISS}/statuslijsten/1")
    assert token.lijst.lees(idx) == INGETROKKEN


class _Klok:
    """Een stilstaande klok die alleen verspringt als iemand slaapt (of de test hem verzet)."""

    def __init__(self, nu: float) -> None:
        self.nu = nu
        self.geslapen = 0.0

    def time(self) -> float:
        return self.nu

    def sleep(self, seconden: float) -> None:
        self.geslapen += seconden
        self.nu += seconden


def test_statustoken_iat_is_de_echte_tijd_ook_bij_intrekking_in_dezelfde_seconde(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Een intrekking in de seconde van de vorige ondertekening wacht op de volgende seconde."""
    klok = _Klok(1_800_000_000.0)
    monkeypatch.setattr(time, "time", klok.time)
    monkeypatch.setattr(time, "sleep", klok.sleep)
    uri, sleutel = f"{ISS}/statuslijsten/1", uitgever.uitgifte.sleutel.sleutel
    _, mandaat_id = verleen(uitgever_client, uitgever, Sleutelpaar.nieuw())
    eerste_tekst = uitgever_client.get("/statuslijsten/1").text
    eerste = lees_token(eerste_tekst, sleutel, uri)
    assert eerste.iat == 1_800_000_000
    assert uitgever_client.get("/statuslijsten/1").text == eerste_tekst  # ongewijzigd: zelfde token
    uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    tweede = lees_token(uitgever_client.get("/statuslijsten/1").text, sleutel, uri)
    assert tweede.iat == 1_800_000_001 == klok.nu
    assert tweede.exp == tweede.iat + uitgever.inst.beleid.geldig_s
    assert tweede.lijst.inhoud != eerste.lijst.inhoud


def test_statustoken_loopt_bij_een_reeks_intrekkingen_niet_voor_op_de_klok(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Twintig intrekkingen met elk een ophaling: `iat` stijgt, maar nooit voorbij de klok."""
    klok = _Klok(1_800_000_000.0)
    monkeypatch.setattr(time, "time", klok.time)
    monkeypatch.setattr(time, "sleep", klok.sleep)
    uri, sleutel = f"{ISS}/statuslijsten/1", uitgever.uitgifte.sleutel.sleutel
    mandaten = [verleen(uitgever_client, uitgever, Sleutelpaar.nieuw())[1] for _ in range(20)]
    vorige = lees_token(uitgever_client.get("/statuslijsten/1").text, sleutel, uri).iat
    for mandaat_id in mandaten:
        uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
        token = lees_token(uitgever_client.get("/statuslijsten/1").text, sleutel, uri)
        assert vorige < token.iat <= klok.nu
        assert token.exp - klok.nu <= uitgever.inst.beleid.geldig_s
        vorige = token.iat
    assert klok.geslapen <= 20


def test_statustoken_weigert_als_de_klok_terugloopt(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    klok = _Klok(1_800_000_000.0)
    monkeypatch.setattr(time, "time", klok.time)
    monkeypatch.setattr(time, "sleep", klok.sleep)
    _, mandaat_id = verleen(uitgever_client, uitgever, Sleutelpaar.nieuw())
    uitgever_client.get("/statuslijsten/1")
    uitgever_client.delete(f"/mandaten/{mandaat_id}", auth=login(uitgever, "sanne"))
    klok.nu -= 5
    antwoord = uitgever_client.get("/statuslijsten/1")
    assert antwoord.status_code == 503
    assert antwoord.json()["detail"]["error"] == "klok_loopt_achter"
    assert klok.geslapen == 0
    klok.nu += 6
    assert uitgever_client.get("/statuslijsten/1").status_code == 200


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
    noodstop = [r for r in audit(uitgever) if r["gebeurtenis"] == "noodstop"]
    assert [(r["beheerder"], r["jkt"]) for r in noodstop] == [("kees", sleutel.jkt)]


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


def _verzoek(client: TestClient, sleutel: Sleutelpaar, **velden: object) -> dict[str, object]:
    body = {
        "agent_jwk": sleutel.publieke_jwk,
        "medewerker": "sanne",
        "doel": "heronderzoek",
        "acties": ["inkomen:lezen"],
        "dossiers": ["2026-0142"],
        **velden,
    }
    antwoord = client.post("/mandaatverzoeken", json=body)
    assert antwoord.status_code == 201, antwoord.text
    return antwoord.json()


def test_uitgifte_en_auditevent_zijn_atomair_bij_uitval_van_het_log(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valt het JSONL-log uit, dan blijft het event in de outbox en volgt het later, één keer."""
    sleutel = Sleutelpaar.nieuw()
    v = _verzoek(uitgever_client, sleutel)

    def vol_volume(nr: int, velden: dict[str, object]) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(uitgever.audit, "schrijf_uitgaand", vol_volume)
    t = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "ja", "geldigheid_s": 300},
        auth=login(uitgever, "sanne"),
    )
    assert t.status_code == 200  # de goedkeuring is gecommit, samen met haar auditevent
    assert [e["gebeurtenis"] for _, e in uitgever.register.uitgaand()] == ["uitgegeven"]
    assert "uitgegeven" not in [r["gebeurtenis"] for r in audit(uitgever)]
    monkeypatch.undo()
    c = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/credential", json={"proof": proof(sleutel, str(v["id"]))}
    )
    assert c.status_code == 200
    records = audit(uitgever)
    assert [r["gebeurtenis"] for r in records] == ["verzoek", "uitgegeven", "opgehaald"]
    assert [r["uitgaand"] for r in records] == [1, 2, 3]
    assert records[1]["mandaat"] == t.json()["mandaat_id"]
    assert controleer(records) == (True, "intact")
    assert uitgever.register.uitgaand() == []


def test_herstart_na_schrijven_maar_voor_opruimen_geeft_geen_dubbel_record(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleutel = Sleutelpaar.nieuw()
    monkeypatch.setattr(uitgever.register, "verwijder_uitgaand", lambda nr: None)  # crash
    _verzoek(uitgever_client, sleutel)
    assert [e["gebeurtenis"] for _, e in uitgever.register.uitgaand()] == ["verzoek"]
    assert [r["gebeurtenis"] for r in audit(uitgever)] == ["verzoek"]
    herstart = Dienst(uitgever.inst)
    maak_app(herstart)
    assert herstart.register.uitgaand() == []
    records = audit(herstart)
    assert [r["gebeurtenis"] for r in records] == ["verzoek"]
    assert controleer(records) == (True, "intact")


def test_een_teruggedraaide_overgang_laat_geen_auditevent_achter(
    uitgever_client: TestClient, uitgever: Dienst
) -> None:
    sleutel = Sleutelpaar.nieuw()
    uitgever_client.post("/noodstop", json={"jkt": sleutel.jkt}, auth=login(uitgever, "kees"))
    geblokkeerd = uitgever_client.post(
        "/mandaatverzoeken",
        json={
            "agent_jwk": sleutel.publieke_jwk,
            "medewerker": "sanne",
            "doel": "heronderzoek",
            "acties": ["inkomen:lezen"],
            "dossiers": ["2026-0142"],
        },
    )
    assert geblokkeerd.status_code == 403
    assert uitgever.register.uitgaand() == []
    records = audit(uitgever)
    assert [(r["gebeurtenis"], r.get("reden")) for r in records] == [
        ("noodstop", None),
        ("verzoek_geweigerd", "sleutel_geblokkeerd"),
    ]
    assert "uitgaand" not in records[1]


def test_maak_app_bouwt_register_en_audit_voor_het_eerste_verzoek(tmp_path: Path) -> None:
    """`cached_property` is niet threadveilig: de onderdelen bestaan vóór de eerste aanvraag."""
    dienst = Dienst(Instellingen(ISS, tmp_path / "u", Tokenbeleid(1, 60)))
    client = TestClient(maak_app(dienst))
    assert {"register", "audit", "uitgifte", "wachtwoorden"} <= set(vars(dienst))
    sleutels = [Sleutelpaar.nieuw() for _ in range(16)]
    with ThreadPoolExecutor(8) as pool:
        for antwoord in pool.map(
            lambda s: client.post(
                "/mandaatverzoeken",
                json={
                    "agent_jwk": s.publieke_jwk,
                    "medewerker": "sanne",
                    "doel": "heronderzoek",
                    "acties": ["inkomen:lezen"],
                    "dossiers": ["2026-0142"],
                },
            ),
            sleutels,
        ):
            assert antwoord.status_code == 201
    records = audit(dienst)
    assert [r["nr"] for r in records] == list(range(1, 17))
    assert controleer(records) == (True, "intact")


def test_herhaalde_toestemming_na_bevoegdheidsweigering_geeft_409_met_audit(
    uitgever_client: TestClient, uitgever: Dienst
) -> None:
    v = _verzoek(uitgever_client, Sleutelpaar.nieuw(), medewerker="bram")
    url = f"/mandaatverzoeken/{v['id']}/toestemming"
    eerste = uitgever_client.post(url, json={"besluit": "ja"}, auth=login(uitgever, "bram"))
    assert eerste.status_code == 403
    assert eerste.json()["detail"]["error"] == "bevoegdheid_ontbreekt"
    tweede = uitgever_client.post(url, json={"besluit": "ja"}, auth=login(uitgever, "bram"))
    assert tweede.status_code == 409
    assert tweede.json()["detail"]["error"] == "verzoek_al_afgehandeld:geweigerd"
    _, onmogelijk, herhaald = audit(uitgever)
    assert onmogelijk["gebeurtenis"] == "toestemming_onmogelijk"
    assert "rol intake" in onmogelijk["reden"]
    assert (herhaald["gebeurtenis"], herhaald["reden"]) == (
        "toestemming_geweigerd",
        "verzoek_al_afgehandeld:geweigerd",
    )


def test_verlopen_verzoek_wordt_vastgelegd_en_geauditeerd(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    v = _verzoek(uitgever_client, Sleutelpaar.nieuw())
    echte_tijd = time.time
    monkeypatch.setattr(time, "time", lambda: echte_tijd() + register.VERZOEK_GELDIG_S + 1)
    scherm = uitgever_client.get(f"/mandaatverzoeken/{v['id']}", auth=login(uitgever, "sanne"))
    assert scherm.json()["status"] == "verlopen"  # weergave, nog niet opgeslagen
    assert uitgever.register.verzoek(str(v["id"])).status == "ingediend"
    t = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "ja"},
        auth=login(uitgever, "sanne"),
    )
    assert t.status_code == 410
    assert uitgever.register.verzoek(str(v["id"])).status == "verlopen"
    laatste = audit(uitgever)[-1]
    assert (laatste["gebeurtenis"], laatste["reden"], laatste["verzoek"]) == (
        "toestemming_geweigerd",
        "verzoek_verlopen",
        v["id"],
    )


def test_mandaat_voorbij_exp_heet_verlopen(
    uitgever_client: TestClient, uitgever: Dienst, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, mandaat_id = verleen(uitgever_client, uitgever, Sleutelpaar.nieuw(), geldigheid_s=60)
    eigen = uitgever_client.get("/mandaten", auth=login(uitgever, "sanne")).json()
    assert [(m["id"], m["status"]) for m in eigen] == [(mandaat_id, "actief")]
    echte_tijd = time.time
    monkeypatch.setattr(time, "time", lambda: echte_tijd() + 61)
    eigen = uitgever_client.get("/mandaten", auth=login(uitgever, "sanne")).json()
    assert [(m["id"], m["status"]) for m in eigen] == [(mandaat_id, "verlopen")]


@pytest.mark.parametrize("kop", [["alg"], "ES256", 7, None])
def test_proof_met_jose_kop_die_geen_object_is_geeft_401_met_audit(
    uitgever_client: TestClient, uitgever: Dienst, kop: object
) -> None:
    sleutel = Sleutelpaar.nieuw()
    v = _verzoek(uitgever_client, sleutel)
    uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/toestemming",
        json={"besluit": "ja"},
        auth=login(uitgever, "sanne"),
    )
    goed = proof(sleutel, str(v["id"]))
    misvormd = ".".join([b64url(json.dumps(kop).encode()), *goed.split(".")[1:]])
    antwoord = uitgever_client.post(
        f"/mandaatverzoeken/{v['id']}/credential", json={"proof": misvormd}
    )
    assert antwoord.status_code == 401
    assert antwoord.json()["detail"]["error"] == "proof_handtekening_ongeldig"
    laatste = audit(uitgever)[-1]
    assert (laatste["gebeurtenis"], laatste["reden"]) == (
        "ophalen_geweigerd",
        "proof_handtekening_ongeldig",
    )
