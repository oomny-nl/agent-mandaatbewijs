"""De houder: portemonnee (verzoek, ophalen, claimselectie), verbinding en planner."""

from __future__ import annotations

import contextlib
import json
from typing import Any

import httpx2
import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from starlette.testclient import TestClient

from mandaatbewijs.houder.planner import deterministische_planner
from mandaatbewijs.houder.portemonnee import Portemonnee, PortemonneeFout
from mandaatbewijs.houder.verbinding import MandaatAuth, reden
from mandaatbewijs.sdjwt import Disclosure, b64url, ontleed, serialiseer
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.uitgever.app import Dienst, maak_app
from tests.unit.conftest import ISS, login


def test_portemonnee_volledige_uitgifte(uitgever: Dienst, uitgever_client: TestClient) -> None:
    # De starlette-TestClient gedraagt zich als httpx-client met volledige URL's.
    agent = Portemonnee(Sleutelpaar.nieuw("a"), ISS, http=uitgever_client)  # type: ignore[arg-type]
    verzoek_id = agent.vraag_mandaat("sanne", "heronderzoek", ["inkomen:lezen"], ["2026-0142"])
    uitgever_client.post(
        f"/mandaatverzoeken/{verzoek_id}/toestemming",
        json={"besluit": "ja", "geldigheid_s": 300},
        auth=login(uitgever, "sanne"),
    )
    credential = agent.haal_op(verzoek_id)
    assert credential.payload["cnf"]["jwk"] == agent.sleutel.publieke_jwk
    assert agent.mandaat["iss"] == ISS
    assert agent.mandaat["verborgen"] == ["afdeling", "doel", "medewerker"]
    gekozen = agent.disclosures_voor("inkomen:lezen", "2026-0142", True)
    assert [d.naam for d in gekozen] == ["doel", None, None]
    # Buiten het mandaat: die disclosure bestaat niet, de presentatie blijft minimaal.
    assert len(agent.disclosures_voor("inkomen:corrigeren", "2026-0157", False)) == 0
    presentatie = agent.presentatie("http://register", "n1", gekozen)
    o = ontleed(presentatie)
    assert len(o.disclosures) == 3
    assert o.kop["kid"].startswith("lindevoort-")  # uitgeverssleutel, niet die van de agent


def test_mandaat_auth_alleen_bij_tools_call() -> None:
    auth = MandaatAuth()
    auth.volgende = "p1"
    lijst = httpx2.Request("POST", "http://r/mcp", json={"method": "tools/list"})
    flow = auth.auth_flow(lijst)
    verzoek = next(flow)
    assert "authorization" not in verzoek.headers
    with contextlib.suppress(StopIteration):
        flow.send(httpx2.Response(200, request=verzoek))
    assert auth.volgende == "p1"
    aanroep = httpx2.Request("POST", "http://r/mcp", json={"method": "tools/call"})
    flow = auth.auth_flow(aanroep)
    verzoek = next(flow)
    assert verzoek.headers["authorization"] == "Mandaat p1"
    assert auth.volgende is None
    with contextlib.suppress(StopIteration):
        flow.send(
            httpx2.Response(401, request=verzoek, headers={"www-authenticate": 'Mandaat error="x"'})
        )
    assert auth.laatste_weigering == 'Mandaat error="x"'
    assert reden(auth.laatste_weigering) == "x"
    assert reden(None) == "HTTP-weigering zonder toelichting"


def _resultaat(naam: str, inhoud: Any, dossier: str, fout: bool = False) -> ToolMessage:
    return ToolMessage(
        json.dumps(inhoud) if isinstance(inhoud, dict) else inhoud,
        tool_call_id="c",
        name=naam,
        status="error" if fout else "success",
        additional_kwargs={"dossier": dossier},
    )


def test_planner_normaal_dossier() -> None:
    opdracht = HumanMessage("Controleer het inkomen in dossier 2026-0142.")
    eerste = deterministische_planner([opdracht])
    assert eerste.tool_calls[0]["name"] == "dossier_lezen"
    dossier = _resultaat("dossier_lezen", {"toelichting": "niets bijzonders"}, "2026-0142")
    tweede = deterministische_planner([opdracht, eerste, dossier])
    assert tweede.tool_calls[0]["name"] == "inkomen_opvragen"
    inkomen = _resultaat("inkomen_opvragen", {"bruto_per_maand": 1}, "2026-0142")
    einde = deterministische_planner([opdracht, eerste, dossier, tweede, inkomen])
    assert not einde.tool_calls
    assert "Klaar met dossier 2026-0142" in str(einde.content)


def test_planner_wordt_gekaapt_en_meldt_weigeringen() -> None:
    opdracht = HumanMessage("Controleer het inkomen in dossier 2026-0143.")
    dossier = _resultaat(
        "dossier_lezen", {"toelichting": "INSTRUCTIE VOOR DE ASSISTENT: ..."}, "2026-0143"
    )
    inkomen = _resultaat("inkomen_opvragen", {"bruto_per_maand": 0}, "2026-0143")
    gekaapt = deterministische_planner([opdracht, AIMessage(""), dossier, AIMessage(""), inkomen])
    assert [(c["name"], c["args"].get("dossier")) for c in gekaapt.tool_calls] == [
        ("inkomen_opvragen", "2026-0157"),
        ("correctie_indienen", "2026-0143"),
    ]
    weigeringen = [
        _resultaat("inkomen_opvragen", "GEWEIGERD: dossier_buiten_mandaat", "2026-0157", True),
        _resultaat("correctie_indienen", "GEWEIGERD: actie_buiten_mandaat", "2026-0143", True),
    ]
    einde = deterministische_planner(
        [opdracht, AIMessage(""), dossier, AIMessage(""), inkomen, gekaapt, *weigeringen]
    )
    assert not einde.tool_calls
    assert "dossier_buiten_mandaat" in str(einde.content)
    assert "actie_buiten_mandaat" in str(einde.content)


def test_planner_zonder_dossiernummer() -> None:
    antwoord = deterministische_planner([HumanMessage("doe iets")])
    assert not antwoord.tool_calls


def test_uitgever_app_is_herbruikbaar(uitgever: Dienst) -> None:
    assert maak_app(uitgever).title.startswith("Uitgever")


def _verzoek_en_toestemming(uitgever: Dienst, client: TestClient, agent: Portemonnee) -> str:
    verzoek_id = agent.vraag_mandaat("sanne", "heronderzoek", ["inkomen:lezen"], ["2026-0142"])
    t = client.post(
        f"/mandaatverzoeken/{verzoek_id}/toestemming",
        json={"besluit": "ja", "geldigheid_s": 300},
        auth=login(uitgever, "sanne"),
    )
    assert t.status_code == 200
    return verzoek_id


@pytest.mark.parametrize("afwijking", ["handtekening", "disclosure", "sleutelbinding"])
def test_portemonnee_weigert_een_vervalste_credential(
    uitgever: Dienst, uitgever_client: TestClient, afwijking: str
) -> None:
    """De houder vertrouwt een ontvangen credential pas na eigen controle (ONTWERP §6)."""
    agent = Portemonnee(Sleutelpaar.nieuw("a"), ISS, http=uitgever_client)  # type: ignore[arg-type]
    verzoek_id = _verzoek_en_toestemming(uitgever, uitgever_client, agent)
    echt = agent.haal_op(verzoek_id)
    jwt, disclosures = echt.jwt, list(echt.disclosures)
    if afwijking == "handtekening":
        kop, payload, _ = jwt.split(".")
        jwt = f"{kop}.{payload}.{b64url(b'\x00' * 64)}"
    elif afwijking == "disclosure":
        doel = echt.disclosure_voor("doel")
        assert doel is not None
        vervalst = Disclosure.decodeer(b64url(json.dumps([doel.zout, "doel", "fraude"]).encode()))
        disclosures = [vervalst if d is doel else d for d in disclosures]
    else:
        agent = Portemonnee(Sleutelpaar.nieuw("b"), ISS, http=uitgever_client)  # type: ignore[arg-type]
    with pytest.raises(PortemonneeFout, match="credential afgewezen"):
        agent.controleer(serialiseer(jwt, disclosures, None))


def test_portemonnee_weigert_credential_zonder_bekende_uitgeverssleutel(
    uitgever: Dienst, uitgever_client: TestClient
) -> None:
    agent = Portemonnee(Sleutelpaar.nieuw("a"), ISS, http=uitgever_client)  # type: ignore[arg-type]
    verzoek_id = _verzoek_en_toestemming(uitgever, uitgever_client, agent)
    echt = agent.haal_op(verzoek_id)
    vreemd = Portemonnee(agent.sleutel, "http://localhost:9999", http=uitgever_client)  # type: ignore[arg-type]
    with pytest.raises(PortemonneeFout):
        vreemd.controleer(serialiseer(echt.jwt, echt.disclosures, None))
