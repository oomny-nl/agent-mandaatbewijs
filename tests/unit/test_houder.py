"""De houder: portemonnee (verzoek, ophalen, claimselectie), verbinding en planner."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

import httpx2
import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from mcp.shared.exceptions import MCPError
from mcp_types import INTERNAL_ERROR, INVALID_PARAMS
from starlette.testclient import TestClient

from mandaatbewijs.houder.graaf import Gereedschap, Toolbeleid
from mandaatbewijs.houder.planner import LLM_OMGEVING, deterministische_planner, llm_model
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


def test_llm_model_behandelt_lege_omgevingsvariabelen_als_niet_gezet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compose geeft niet-ingevulde variabelen leeg door; dan gelden de standaardwaarden."""
    pytest.importorskip("langchain_openai")
    for naam in LLM_OMGEVING:
        monkeypatch.setenv(naam, "")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    model = llm_model()
    assert type(model).__name__ == "ChatOpenAI"
    assert model.model_name == "gpt-4.1-mini"
    assert str(model.root_client.base_url) == "https://api.openai.com/v1/"


def test_llm_model_kiest_azure_met_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("langchain_openai")
    for naam in LLM_OMGEVING:
        monkeypatch.setenv(naam, "")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://voorbeeld.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "assistent")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test")
    monkeypatch.setenv("OPENAI_API_VERSION", "2024-10-21")
    model = llm_model()
    assert type(model).__name__ == "AzureChatOpenAI"
    assert model.deployment_name == "assistent"
    assert str(model.root_client.base_url).startswith(
        "https://voorbeeld.openai.azure.com/openai/deployments/assistent"
    )


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


def test_mandaat_auth_weigering_hoort_bij_de_laatste_aanroep() -> None:
    """Een oude 401 blijft niet hangen: een volgende aanroep zonder weigering wist hem."""
    auth = MandaatAuth()
    for status, kop, verwacht in [
        (403, 'Mandaat error="mandaat_ingetrokken"', 'Mandaat error="mandaat_ingetrokken"'),
        (200, None, None),
        (500, None, None),
    ]:
        auth.volgende = "p"
        flow = auth.auth_flow(httpx2.Request("POST", "http://r/mcp", json={"method": "tools/call"}))
        verzoek = next(flow)
        koppen = {"www-authenticate": kop} if kop else {}
        with contextlib.suppress(StopIteration):
            flow.send(httpx2.Response(status, request=verzoek, headers=koppen))
        assert auth.laatste_weigering == verwacht


class _Inhoud:
    def __init__(self, text: str) -> None:
        self.text = text


class _Antwoord:
    def __init__(self, text: str, is_error: bool) -> None:
        self.content = [_Inhoud(text)]
        self.is_error = is_error


class _Register:
    """MCP-client die een vooraf gekozen uitkomst geeft, zoals de echte client die doorgeeft."""

    def __init__(self, auth: MandaatAuth, uitkomst: Any, weigering: str | None = None) -> None:
        self.auth, self.uitkomst, self.weigering = auth, uitkomst, weigering

    async def call_tool(self, naam: str, argumenten: dict[str, Any]) -> _Antwoord:
        if self.weigering is not None:  # wat MandaatAuth bij een 401/403 op deze aanroep vastlegt
            self.auth.laatste_weigering = self.weigering
        if isinstance(self.uitkomst, Exception):
            raise self.uitkomst
        return self.uitkomst


class _Portemonnee:
    def disclosures_voor(self, actie: str, dossier: str, met_doel: bool) -> list[Disclosure]:
        return []

    def presentatie(self, aud: str, nonce: str, gekozen: list[Disclosure]) -> str:
        return "presentatie"


@pytest.mark.parametrize(
    ("uitkomst", "weigering", "soort", "tekst"),
    [
        (
            MCPError(INTERNAL_ERROR, "Server returned an error response"),
            'Mandaat error="dossier_buiten_mandaat"',
            "register_weigert",
            "GEWEIGERD door het register: dossier_buiten_mandaat",
        ),
        (
            MCPError(INVALID_PARAMS, "Unknown tool: verwijder_alles"),
            None,
            "register_fout",
            f"protocolfout (MCP {INVALID_PARAMS}): Unknown tool: verwijder_alles",
        ),
        (
            _Antwoord("geen inkomensgegevens voor dossier 2026-0142", True),
            None,
            "register_fout",
            "toolfout: geen inkomensgegevens voor dossier 2026-0142",
        ),
        (_Antwoord('{"bruto_per_maand": 1}', False), None, "resultaat", '{"bruto_per_maand": 1}'),
    ],
)
def test_toolknoop_onderscheidt_weigering_protocolfout_en_toolfout(
    uitkomst: Any, weigering: str | None, soort: str, tekst: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Een MCP-fout is pas een registerweigering als de poort juist deze aanroep weigerde."""
    auth = MandaatAuth()
    # Een weigering van een eerdere aanroep mag de uitkomst van deze aanroep niet kleuren.
    auth.laatste_weigering = 'Mandaat error="mandaat_ingetrokken"'
    gezien: list[dict[str, Any]] = []
    register: Any = _Register(auth, uitkomst, weigering)
    portemonnee: Any = _Portemonnee()
    gereedschap = Gereedschap(
        register,
        auth,
        portemonnee,
        "http://register",
        {"inkomen_opvragen": Toolbeleid("inkomen:lezen", ())},
        gezien.append,
    )

    async def nonce() -> str:
        return "n"

    monkeypatch.setattr(gereedschap, "nonce", nonce)
    bericht = asyncio.run(gereedschap.voer_uit("inkomen_opvragen", {"dossier": "2026-0142"}))
    assert gezien[-1] == {"soort": soort, "tool": "inkomen_opvragen", "tekst": tekst}
    assert bericht.content == tekst
    assert bericht.status == ("success" if soort == "resultaat" else "error")


def test_portemonnee_weigert_credential_met_kop_die_geen_object_is() -> None:
    """Een JOSE-kop als JSON-lijst is een leesfout, geen AttributeError (RFC 7515 §4)."""
    agent = Portemonnee(Sleutelpaar.nieuw("a"), ISS, http=httpx2.Client())
    with agent, pytest.raises(PortemonneeFout, match="credential onleesbaar"):
        agent.controleer(f"{b64url(b'[1]')}.{b64url(b'{}')}.{b64url(b'x')}~")
    assert agent.http.is_closed


def test_portemonnee_vindt_metadata_onder_het_pad_van_iss() -> None:
    """SD-JWT VC §4: het well-known-pad staat vóór het pad van `iss`, niet erachter."""
    gevraagd: list[str] = []

    def antwoord(verzoek: httpx2.Request) -> httpx2.Response:
        gevraagd.append(str(verzoek.url))
        return httpx2.Response(404)

    iss = "https://uitgever.example/gemeente/lindevoort"
    http = httpx2.Client(transport=httpx2.MockTransport(antwoord))
    with Portemonnee(Sleutelpaar.nieuw("a"), iss, http=http) as agent:
        with pytest.raises(PortemonneeFout, match="HTTP 404"):
            agent._uitgeverssleutel("k1")
        geen_query = Portemonnee(agent.sleutel, f"{iss}?x=1", http=http)
        with pytest.raises(PortemonneeFout, match="query of fragment"):
            geen_query._uitgeverssleutel("k1")
    assert gevraagd == ["https://uitgever.example/.well-known/jwt-vc-issuer/gemeente/lindevoort"]
