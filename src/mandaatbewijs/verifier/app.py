"""Landelijk Inkomensregister (fictief) als MCP-server achter de Mandaatpoort.

- `/mcp`: MCP-tools `inkomen_opvragen` en `correctie_indienen`; elke `tools/call` draagt een
  presentatie (ONTWERP §6 en §7).
- `POST /nonces`: nonce voor de key-binding-JWT.
- `GET /gezond`: gezondheidscontrole.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mandaatbewijs.audit import Auditlog
from mandaatbewijs.verifier.bronnen import Ophaler, Sleutelbron, Statusbron
from mandaatbewijs.verifier.gegevens import INKOMENS, TOOLBELEID, VERIFIER_NAAM
from mandaatbewijs.verifier.nonces import NONCE_GELDIG_S, Nonces
from mandaatbewijs.verifier.poort import Achtergrondtaak, Mandaatpoort, Poortinstellingen
from mandaatbewijs.verifier.verificatie import Toelating, Verificatie
from mandaatbewijs.verifier.vertrouwenslijst import Vertrouwenslijst

log = logging.getLogger("inkomensregister")


@dataclass(frozen=True)
class Instellingen:
    """Instellingen uit de omgeving."""

    aud: str
    datamap: Path
    vertrouwenslijst: Path
    http_toe: bool
    ververs_s: float

    @classmethod
    def uit_omgeving(cls) -> Instellingen:
        """Lees VERIFIER_AUD, VERIFIER_DATA, VERTROUWENSLIJST, STA_HTTP_TOE en STATUS_VERVERS_S."""
        return cls(
            os.environ.get("VERIFIER_AUD", "http://inkomensregister:8000").rstrip("/"),
            Path(os.environ.get("VERIFIER_DATA", "/data")),
            Path(os.environ.get("VERTROUWENSLIJST", "/app/vertrouwenslijst.json")),
            os.environ.get("STA_HTTP_TOE", "0") == "1",
            float(os.environ.get("STATUS_VERVERS_S", "5")),
        )


@dataclass
class Dienst:
    """Gedeelde onderdelen (lui opgebouwd)."""

    inst: Instellingen

    @cached_property
    def vertrouwenslijst(self) -> Vertrouwenslijst:
        """Vertrouwde uitgevers."""
        return Vertrouwenslijst.laad(self.inst.vertrouwenslijst)

    @cached_property
    def ophaler(self) -> Ophaler:
        """Begrensde HTTP-client voor uitgeversbronnen."""
        return Ophaler(self.inst.http_toe, self.vertrouwenslijst.hosts)

    @cached_property
    def sleutelbron(self) -> Sleutelbron:
        """JWKS-cache."""
        return Sleutelbron(self.ophaler)

    @cached_property
    def statusbron(self) -> Statusbron:
        """Statuslijstcache."""
        return Statusbron(self.ophaler, self.sleutelbron)

    @cached_property
    def nonces(self) -> Nonces:
        """Nonce-opslag."""
        return Nonces(self.inst.datamap / "nonces.db")

    @cached_property
    def audit(self) -> Auditlog:
        """Auditlog van de verifier."""
        return Auditlog(self.inst.datamap / "audit.jsonl", "lir")

    @cached_property
    def verificatie(self) -> Verificatie:
        """De verificatiestappen."""
        return Verificatie(
            self.inst.aud, self.vertrouwenslijst, self.sleutelbron, self.statusbron, self.nonces
        )

    @property
    def nonce_url(self) -> str:
        """URL van het nonce-endpoint."""
        return f"{self.inst.aud}/nonces"


def _toelating(ctx: Context) -> Toelating:
    request = ctx.request_context.request
    toelating = request.scope["state"].get("toelating") if request is not None else None
    if toelating is None:
        raise ToolError("geen toelating bij deze toolaanroep; alleen streamable HTTP via de poort")
    return toelating


def maak_mcp(dienst: Dienst) -> MCPServer:
    """Bouw de MCP-server met tools en routes."""
    mcp = MCPServer(
        "inkomensregister",
        instructions=f"{VERIFIER_NAAM}; elke tool vereist een mandaatpresentatie.",
    )

    @mcp.tool(
        meta=TOOLBELEID["inkomen_opvragen"].meta,
        description="Vraag het geregistreerde inkomen bij een gemeentelijk dossiernummer op.",
    )
    async def inkomen_opvragen(dossier: str, ctx: Context) -> str:
        toelating = _toelating(ctx)
        if toelating.dossier != dossier:
            raise ToolError("dossier in de aanroep wijkt af van de toegelaten aanroep")
        inkomen = INKOMENS.get(dossier)
        if inkomen is None:
            raise ToolError(f"geen inkomensgegevens voor dossier {dossier}")
        return json.dumps(inkomen, ensure_ascii=False, indent=2)

    @mcp.tool(
        meta=TOOLBELEID["correctie_indienen"].meta,
        description="Dien een correctie op geregistreerd inkomen in (schrijfactie).",
    )
    async def correctie_indienen(dossier: str, tekst: str, ctx: Context) -> str:
        _toelating(ctx)
        return "onbereikbaar: het register accepteert geen correcties van een agent"

    _routes(mcp, dienst)
    return mcp


def _routes(mcp: MCPServer, dienst: Dienst) -> None:
    @mcp.custom_route("/nonces", methods=["POST"])
    async def nonce(_: Request) -> Response:
        return JSONResponse(
            {"nonce": dienst.nonces.nieuw(), "aud": dienst.inst.aud, "geldig_s": NONCE_GELDIG_S}
        )

    @mcp.custom_route("/gezond", methods=["GET"])
    async def gezond(_: Request) -> Response:
        return JSONResponse({"status": "ok", "verifier": VERIFIER_NAAM})


def maak_app(dienst: Dienst, achtergrond: bool = True) -> Mandaatpoort:
    """De volledige ASGI-app: MCP plus routes, achter de Mandaatpoort."""
    mcp = maak_mcp(dienst)
    app = mcp.streamable_http_app(stateless_http=True, json_response=True, host="0.0.0.0")  # noqa: S104
    taak = Achtergrondtaak(dienst.statusbron.ververs_alles, dienst.inst.ververs_s)
    inst = Poortinstellingen(
        dienst.verificatie, dienst.audit, dienst.nonce_url, taak if achtergrond else None
    )
    return Mandaatpoort(app, inst)


def main() -> None:
    """Start het register (in de container op poort 8000)."""
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(maak_app(Dienst(Instellingen.uit_omgeving())), host="0.0.0.0", port=8000)  # noqa: S104


def toolbeleid_uit_meta(meta: dict[str, Any] | None) -> tuple[str, list[str]]:
    """(actie, doelen) uit de `meta` van een tool, zoals de houder die via `tools/list` ziet."""
    if not isinstance(meta, dict):
        return "", []
    return str(meta.get("actie", "")), [str(d) for d in meta.get("doelen", [])]
