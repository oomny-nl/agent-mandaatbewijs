"""Integratietests tegen de echte keten: de zes scenario's, gelijktijdige replay, caches, audit."""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import httpx2
import pytest

from mandaatbewijs.audit import controleer
from mandaatbewijs.houder.graaf import Gereedschap, bouw_graaf, toolbeleid, voer_opdracht_uit
from mandaatbewijs.houder.planner import deterministische_planner
from mandaatbewijs.houder.portemonnee import Portemonnee, PortemonneeFout
from mandaatbewijs.houder.verbinding import verbind
from mandaatbewijs.sdjwt import geef_uit, ontleed
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.uitgever.gegevens import VCT
from mandaatbewijs.uitgever.uitgifte import PER_ELEMENT, VERBORGEN
from tests.integratie.conftest import (
    Omgeving,
    Verlener,
    aanroep,
    inkomen,
    nonce,
    presentatie,
    tot_weigering,
)

pytestmark = pytest.mark.integratie


def test_toegestaan_binnen_mandaat(omgeving: Omgeving, verleen: Verlener) -> None:
    m = verleen(["2026-0142"])
    p = presentatie(omgeving, m.agent, "2026-0142")
    o = ontleed(p)
    assert len(o.disclosures) == 3  # doel, één actie, één dossier
    assert "medewerker" not in o.claims_zonder_controle
    uitkomst = inkomen(aanroep(omgeving, p, "2026-0142"))
    assert uitkomst["bruto_per_maand"] == 1430.0
    record = omgeving.audit("register")[-1]
    assert (record["gebeurtenis"], record["jti"], record["reden"]) == (
        "toegestaan",
        m.mandaat_id,
        "binnen_mandaat",
    )
    assert record["bekendgemaakt"] == ["acties", "doel", "dossiers"]
    assert record["status_bron"] in ("vers", "cache")


def test_buiten_mandaat_dossier_en_actie(omgeving: Omgeving, verleen: Verlener) -> None:
    m = verleen(["2026-0143"])
    ander = aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0157"), "2026-0157")
    assert (ander.status, ander.reden) == (403, "dossier_buiten_mandaat")
    correctie = aanroep(
        omgeving,
        presentatie(omgeving, m.agent, "2026-0143", "inkomen:corrigeren"),
        "2026-0143",
        "correctie_indienen",
    )
    assert (correctie.status, correctie.reden) == (403, "actie_buiten_mandaat")
    assert inkomen(aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0143"), "2026-0143"))


def test_ander_dossier_uit_de_caseload_blijft_buiten_het_mandaat(
    omgeving: Omgeving, verleen: Verlener
) -> None:
    """Sanne mag 2026-0143 wel mandateren, maar dit mandaat noemt alleen 2026-0142."""
    m = verleen(["2026-0142"])
    ander = aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0143"), "2026-0143")
    assert (ander.status, ander.reden) == (403, "dossier_buiten_mandaat")
    assert inkomen(aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0142"), "2026-0142"))


def test_gekaapte_agent_via_mcp_client(omgeving: Omgeving, verleen: Verlener) -> None:
    """De LangGraph-agent volgt de ingevoegde instructie; het register begrenst de schade."""
    m = verleen(["2026-0143"])
    gezien: list[dict[str, object]] = []

    async def draai() -> None:
        async with verbind(omgeving.verifier) as (client, auth):
            beleid, _ = await toolbeleid(client)
            gereedschap = Gereedschap(
                client, auth, m.agent, omgeving.verifier, beleid, gezien.append
            )
            graaf = bouw_graaf(deterministische_planner, gereedschap)
            await voer_opdracht_uit(graaf, "Controleer het inkomen in dossier 2026-0143.")

    asyncio.run(draai())
    weigeringen = [str(g["tekst"]) for g in gezien if g["soort"] == "register_weigert"]
    assert any("dossier_buiten_mandaat" in w for w in weigeringen)
    assert any("actie_buiten_mandaat" in w for w in weigeringen)
    resultaten = [g["tool"] for g in gezien if g["soort"] == "resultaat"]
    assert resultaten == ["dossier_lezen", "inkomen_opvragen"]


def test_replay_en_gestolen_presentatie(omgeving: Omgeving, verleen: Verlener) -> None:
    m = verleen(["2026-0142"])
    p = presentatie(omgeving, m.agent, "2026-0142")
    assert inkomen(aanroep(omgeving, p, "2026-0142"))
    opnieuw = aanroep(omgeving, p, "2026-0142")
    assert (opnieuw.status, opnieuw.reden) == (401, "nonce_onbekend_of_gebruikt")
    dief = Portemonnee(Sleutelpaar.nieuw("dief"), omgeving.uitgever, m.agent.credential)
    gestolen = aanroep(omgeving, presentatie(omgeving, dief, "2026-0142"), "2026-0142")
    assert (gestolen.status, gestolen.reden) == (401, "kb_handtekening_ongeldig")
    zonder = aanroep(omgeving, None, "2026-0142")
    assert (zonder.status, zonder.reden) == (401, "presentatie_ontbreekt")


def test_gelijktijdige_replay_slaagt_precies_een_keer(
    omgeving: Omgeving, verleen: Verlener
) -> None:
    m = verleen(["2026-0142"])
    p = presentatie(omgeving, m.agent, "2026-0142")
    with ThreadPoolExecutor(max_workers=8) as pool:
        uitkomsten = list(pool.map(lambda _: aanroep(omgeving, p, "2026-0142"), range(8)))
    statussen = sorted(u.status for u in uitkomsten)
    assert statussen == [200, *([401] * 7)]
    assert {u.reden for u in uitkomsten if u.status == 401} == {"nonce_onbekend_of_gebruikt"}


def test_ingetrokken_geen_toegang_meer_na_ttl(omgeving: Omgeving, verleen: Verlener) -> None:
    m = verleen(["2026-0142"])
    assert inkomen(aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0142"), "2026-0142"))
    ingetrokken_op = omgeving.portaal().trek_in(m.mandaat_id)
    u = tot_weigering(
        lambda: aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0142"), "2026-0142"),
        ingetrokken_op,
        omgeving.status_ttl,
    )
    assert (u.status, u.reden) == (403, "mandaat_ingetrokken")
    record = omgeving.audit("register")[-1]
    assert (record["gebeurtenis"], record["reden"], record["jti"]) == (
        "geweigerd",
        "mandaat_ingetrokken",
        m.mandaat_id,
    )


def test_uitgever_niet_vertrouwd(omgeving: Omgeving) -> None:
    elsweerd, agent = Sleutelpaar.nieuw("elsweerd-01"), Sleutelpaar.nieuw("agent")
    nu = int(time.time())
    claims = {
        "iss": "http://elsweerd:8000",
        "vct": VCT,
        "jti": "m-elsweerd",
        "iat": nu,
        "nbf": nu,
        "exp": nu + 300,
        "cnf": {"jwk": agent.publieke_jwk},
        "status": {"status_list": {"idx": 3, "uri": "http://elsweerd:8000/statuslijsten/1"}},
        "doel": "aanvraag-levensonderhoud",
        "medewerker": {"id": "x"},
        "afdeling": "y",
        "acties": ["inkomen:lezen"],
        "dossiers": ["2026-0142"],
    }
    serialisatie, _ = geef_uit(elsweerd, claims, set(VERBORGEN), set(PER_ELEMENT))
    from mandaatbewijs.sdjwt import Credential  # noqa: PLC0415

    p = Portemonnee(agent, "http://elsweerd:8000", Credential.uit_serialisatie(serialisatie))
    u = aanroep(omgeving, presentatie(omgeving, p, "2026-0142"), "2026-0142")
    assert (u.status, u.reden) == (401, "uitgever_niet_vertrouwd")
    record = omgeving.audit("register")[-1]
    assert record["reden"] == "uitgever_niet_vertrouwd"
    assert record["iss"] == "http://elsweerd:8000"


def test_noodstop_blokkeert_sleutel(omgeving: Omgeving, verleen: Verlener) -> None:
    m = verleen(["2026-0142"])
    assert inkomen(aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0142"), "2026-0142"))
    ingetrokken = omgeving.portaal("kees").noodstop(m.agent.jkt)
    ingetrokken_op = time.time()
    assert ingetrokken == [m.mandaat_id]
    with pytest.raises(PortemonneeFout, match="sleutel_geblokkeerd"):
        m.agent.vraag_mandaat("sanne", "heronderzoek", ["inkomen:lezen"], ["2026-0142"])

    u = tot_weigering(
        lambda: aanroep(omgeving, presentatie(omgeving, m.agent, "2026-0142"), "2026-0142"),
        ingetrokken_op,
        omgeving.status_ttl,
    )
    assert (u.status, u.reden) == (403, "mandaat_ingetrokken")
    nieuw = verleen(["2026-0142"])  # met een nieuw sleutelpaar werkt het weer
    assert inkomen(aanroep(omgeving, presentatie(omgeving, nieuw.agent, "2026-0142"), "2026-0142"))


def test_toestemming_en_bevoegdheid_bij_de_uitgever(omgeving: Omgeving) -> None:
    agent = Portemonnee(Sleutelpaar.nieuw("agent"), omgeving.uitgever)
    verzoek_id = agent.vraag_mandaat("sanne", "heronderzoek", ["inkomen:lezen"], ["2026-0157"])
    scherm = omgeving.portaal().scherm(verzoek_id)
    assert scherm["agent_jkt"] == agent.jkt
    assert scherm["dossiers"] == ["2026-0157"]
    buiten_caseload = omgeving.portaal().beslis(verzoek_id, "ja")
    assert buiten_caseload.status_code == 403
    assert buiten_caseload.json()["detail"]["error"] == "bevoegdheid_ontbreekt"
    verzoek_id = agent.vraag_mandaat("sanne", "heronderzoek", ["inkomen:lezen"], ["2026-0142"])
    assert omgeving.portaal().beslis(verzoek_id, "nee").status_code == 200
    with pytest.raises(PortemonneeFout):
        agent.haal_op(verzoek_id)
    # Bram (intake) mag het inkomen niet zelf lezen: ook zijn agent krijgt dat niet.
    verzoek_id = agent.vraag_mandaat("bram", "heronderzoek", ["inkomen:lezen"], ["2026-0142"])
    assert omgeving.portaal("bram").beslis(verzoek_id, "ja").status_code == 403


def test_metadata_jwks_en_statuslijst_publiek(omgeving: Omgeving) -> None:
    meta = httpx2.get(f"{omgeving.uitgever}/.well-known/jwt-vc-issuer", timeout=10).json()
    assert meta["issuer"] == omgeving.uitgever
    jwks = httpx2.get(f"{omgeving.uitgever}/jwks.json", timeout=10).json()
    assert all("d" not in k for k in jwks["keys"])
    sl = httpx2.get(f"{omgeving.uitgever}/statuslijsten/1", timeout=10)
    assert sl.headers["content-type"].startswith("application/statuslist+jwt")
    assert f"max-age={omgeving.status_ttl}" in sl.headers["cache-control"]


def test_verzonnen_nonce_en_aud(omgeving: Omgeving, verleen: Verlener) -> None:
    m = verleen(["2026-0142"])
    gekozen = m.agent.disclosures_voor("inkomen:lezen", "2026-0142", True)
    verzonnen = m.agent.presentatie(omgeving.verifier, "verzonnen-nonce", gekozen)
    assert aanroep(omgeving, verzonnen, "2026-0142").reden == "nonce_onbekend_of_gebruikt"
    andere_aud = m.agent.presentatie("http://ander:8000", nonce(omgeving), gekozen)
    assert aanroep(omgeving, andere_aud, "2026-0142").reden == "aud_onjuist"
    zonder_doel = m.agent.presentatie(
        omgeving.verifier,
        nonce(omgeving),
        m.agent.disclosures_voor("inkomen:lezen", "2026-0142", False),
    )
    assert aanroep(omgeving, zonder_doel, "2026-0142").reden == "doel_niet_geaccepteerd"


def test_poort_laat_alleen_bekende_methoden_door(omgeving: Omgeving) -> None:
    lijst = httpx2.post(
        f"{omgeving.verifier}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
        timeout=10,
    )
    assert lijst.status_code == 200
    namen = {t["name"] for t in lijst.json()["result"]["tools"]}
    assert namen == {"inkomen_opvragen", "correctie_indienen"}
    anders = httpx2.post(
        f"{omgeving.verifier}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "resources/list"},
        timeout=10,
    )
    assert anders.status_code == 403


def test_auditketens_intact(omgeving: Omgeving) -> None:
    for organisatie in ("uitgever", "register"):
        records = omgeving.audit(organisatie)
        assert records, organisatie
        intact, reden = controleer(records)
        assert intact, f"{organisatie}: {reden}"
        assert {r["organisatie"] for r in records} == {
            "lindevoort" if organisatie == "uitgever" else "lir"
        }
