"""De inkomensassistent als LangGraph-graaf: planner en toolknoop in een lus.

De toolknoop leest het dossier lokaal (eigen organisatie) en roept het inkomensregister aan via MCP.
Voor elke registeraanroep haalt hij een nonce bij de verifier, kiest hij uit het mandaat alleen de
claims die de tool nodig heeft (actie, dossier en, als de tool dat vraagt, doel) en tekent hij de
key-binding-JWT. Weigert het register, dan komt de reden terug in het toolbericht; een protocol- of
toolfout blijft als zodanig herkenbaar.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

import httpx2
from langchain_core.messages import AnyMessage, HumanMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from mcp.client.client import Client
from mcp.shared.exceptions import MCPError
from pydantic import BaseModel, Field

from mandaatbewijs.houder.dossiers import DOSSIERS
from mandaatbewijs.houder.planner import LOKALE_TOOL, Planner
from mandaatbewijs.houder.portemonnee import Portemonnee, PortemonneeFout
from mandaatbewijs.houder.verbinding import MandaatAuth, reden
from mandaatbewijs.sdjwt import Disclosure

Waarnemer = Callable[[dict[str, Any]], None]


class Toestand(BaseModel):
    """Toestand van de graaf: alleen de berichten."""

    berichten: Annotated[list[AnyMessage], add_messages] = Field(default_factory=list)


@dataclass(frozen=True)
class Toolbeleid:
    """Wat het register per tool vraagt (uit de MCP-toolmetadata)."""

    actie: str
    doelen: tuple[str, ...]


@dataclass
class Gereedschap:
    """Wat de toolknoop nodig heeft.

    Attributes:
        client: Open MCP-sessie met het register.
        auth: Authenticatie van die sessie (krijgt per aanroep de presentatie).
        portemonnee: Sleutel en mandaat van de agent.
        verifier: Basis-URL van het register (ook de `aud`).
        toolbeleid: Toolnaam naar vereiste actie en geaccepteerde doelen.
        waarnemer: Ontvangt gebeurtenissen voor de vertelling in de demo.
    """

    client: Client
    auth: MandaatAuth
    portemonnee: Portemonnee
    verifier: str
    toolbeleid: dict[str, Toolbeleid]
    waarnemer: Waarnemer

    async def nonce(self) -> str:
        """Haal een verse nonce bij de verifier."""
        async with httpx2.AsyncClient(timeout=10) as http:
            antwoord = await http.post(f"{self.verifier}/nonces")
        antwoord.raise_for_status()
        return str(antwoord.json()["nonce"])

    def _bericht(
        self, tekst: str, naam: str, oproep_id: str, dossier: str, fout: bool
    ) -> ToolMessage:
        return ToolMessage(
            tekst,
            tool_call_id=oproep_id,
            name=naam,
            status="error" if fout else "success",
            additional_kwargs={"dossier": dossier},
        )

    async def voer_uit(
        self, naam: str, argumenten: dict[str, Any], oproep_id: str = "handmatig"
    ) -> ToolMessage:
        """Voer één toolaanroep uit: lokaal, of bij het register met een eigen presentatie."""
        dossier = str(argumenten.get("dossier", ""))
        self.waarnemer({"soort": "aanroep", "tool": naam, "argumenten": argumenten})
        if naam == LOKALE_TOOL:
            inhoud = DOSSIERS.get(dossier)
            if inhoud is None:
                return self._bericht(f"dossier {dossier} onbekend", naam, oproep_id, dossier, True)
            tekst = json.dumps(inhoud, ensure_ascii=False, indent=2)
            self.waarnemer({"soort": "resultaat", "tool": naam, "tekst": tekst})
            return self._bericht(tekst, naam, oproep_id, dossier, False)
        beleid = self.toolbeleid.get(naam, Toolbeleid("", ()))
        try:
            gekozen = self.portemonnee.disclosures_voor(beleid.actie, dossier, bool(beleid.doelen))
            nonce = await self.nonce()
            self.auth.volgende = self.portemonnee.presentatie(self.verifier, nonce, gekozen)
        except (PortemonneeFout, httpx2.HTTPError) as fout:
            self.waarnemer({"soort": "geen_presentatie", "tool": naam, "fout": str(fout)})
            return self._bericht(f"GEEN PRESENTATIE: {fout}", naam, oproep_id, dossier, True)
        self.waarnemer({"soort": "presentatie", "tool": naam, "bekendgemaakt": _labels(gekozen)})
        soort, tekst = await self._registeraanroep(naam, argumenten)
        self.waarnemer({"soort": soort, "tool": naam, "tekst": tekst})
        return self._bericht(tekst, naam, oproep_id, dossier, soort != "resultaat")

    async def _registeraanroep(self, naam: str, argumenten: dict[str, Any]) -> tuple[str, str]:
        """Roep de registertool aan en geef (soort, tekst).

        Drie uitkomsten naast een resultaat: `register_weigert` als de poort precies deze
        aanroep met 401 of 403 weigerde (mandaatcontrole), `register_fout` met "protocolfout"
        voor elke andere MCP-fout en met "toolfout" als de tool zelf een fout teruggaf.
        """
        self.auth.laatste_weigering = None
        try:
            resultaat = await self.client.call_tool(naam, argumenten)
        except MCPError as fout:
            if self.auth.laatste_weigering is not None:
                return (
                    "register_weigert",
                    f"GEWEIGERD door het register: {reden(self.auth.laatste_weigering)}",
                )
            return "register_fout", f"protocolfout (MCP {fout.code}): {fout.error.message}"
        tekst = "\n".join(getattr(d, "text", "") for d in resultaat.content)
        if resultaat.is_error:
            return "register_fout", f"toolfout: {tekst}"
        return "resultaat", tekst


def _labels(gekozen: list[Disclosure]) -> list[str]:
    """Leesbare namen: objectclaims bij naam, lijstelementen bij waarde."""
    return [d.naam if d.naam is not None else f"{d.waarde}" for d in gekozen]


def bouw_graaf(planner: Planner, gereedschap: Gereedschap) -> Any:
    """Bouw en compileer de graaf.

    Args:
        planner: Deterministische of LLM-planner.
        gereedschap: Toolknoop-afhankelijkheden.

    Returns:
        De gecompileerde LangGraph-graaf.
    """

    def plan(state: Toestand) -> dict[str, Any]:
        return {"berichten": [planner(state.berichten)]}

    async def gereedschapsknoop(state: Toestand) -> dict[str, Any]:
        laatste = state.berichten[-1]
        antwoorden = [
            await gereedschap.voer_uit(o["name"], o["args"], str(o["id"]))
            for o in getattr(laatste, "tool_calls", [])
        ]
        return {"berichten": antwoorden}

    def verder(state: Toestand) -> str:
        return "tools" if getattr(state.berichten[-1], "tool_calls", None) else END

    graaf = StateGraph(Toestand)
    graaf.add_node("planner", plan)
    graaf.add_node("tools", gereedschapsknoop)
    graaf.add_edge(START, "planner")
    graaf.add_conditional_edges("planner", verder, {"tools": "tools", END: END})
    graaf.add_edge("tools", "planner")
    return graaf.compile()


LOKALE_FUNCTIE = {
    "type": "function",
    "function": {
        "name": LOKALE_TOOL,
        "description": "Lees een dossier van de eigen gemeente.",
        "parameters": {
            "type": "object",
            "properties": {"dossier": {"type": "string"}},
            "required": ["dossier"],
        },
    },
}


async def toolbeleid(client: Client) -> tuple[dict[str, Toolbeleid], list[dict[str, Any]]]:
    """Lees tools en hun beleid uit het register; geeft ook het OpenAI-functieformaat."""
    lijst = await client.list_tools()
    beleid = {
        t.name: Toolbeleid(
            str((t.meta or {}).get("actie", "")),
            tuple(str(d) for d in (t.meta or {}).get("doelen", [])),
        )
        for t in lijst.tools
    }
    functies: list[dict[str, Any]] = [LOKALE_FUNCTIE]
    functies += [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema,
            },
        }
        for t in lijst.tools
    ]
    return beleid, functies


async def voer_opdracht_uit(graaf: Any, opdracht: str) -> list[AnyMessage]:
    """Laat de agent een opdracht uitvoeren en geef de berichten terug."""
    uitkomst = await graaf.ainvoke({"berichten": [HumanMessage(opdracht)]}, {"recursion_limit": 20})
    return list(uitkomst["berichten"])
