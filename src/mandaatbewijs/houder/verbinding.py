"""MCP-verbinding van de agent met het inkomensregister: per `tools/call` één presentatie.

Protocolverzoeken (`initialize`, `tools/list`) dragen niets. Een `tools/call` draagt de presentatie
die de agent vlak ervoor voor precies die aanroep heeft gemaakt (`MandaatAuth.volgende`); die wordt
bij gebruik meteen weggegooid.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

SCHEMA = "Mandaat"


@dataclass
class MandaatAuth(httpx2.Auth):
    """httpx2-authenticatie: zet `Authorization: Mandaat <presentatie>` op een `tools/call`."""

    requires_request_body = True
    volgende: str | None = field(default=None, init=False)
    laatste_presentatie: str | None = field(default=None, init=False)
    laatste_weigering: str | None = field(default=None, init=False)

    def auth_flow(self, request: httpx2.Request) -> Generator[httpx2.Request, httpx2.Response]:
        """Voeg de presentatie toe aan een `tools/call`."""
        methode = None
        if request.content:
            try:
                methode = json.loads(request.content).get("method")
            except (ValueError, AttributeError):
                methode = None
        if methode == "tools/call":
            gereed, self.volgende = self.volgende, None
            if gereed is None:
                raise RuntimeError("tools/call zonder vooraf gemaakte presentatie")
            request.headers["Authorization"] = f"{SCHEMA} {gereed}"
            self.laatste_presentatie = gereed
        antwoord = yield request
        if antwoord.status_code in (401, 403):
            self.laatste_weigering = antwoord.headers.get("www-authenticate", "")


def reden(challenge: str | None) -> str:
    """Haal `error` uit een WWW-Authenticate-waarde."""
    gevonden = re.search(r'error="([^"]*)"', challenge or "")
    return gevonden.group(1) if gevonden else "HTTP-weigering zonder toelichting"


@asynccontextmanager
async def verbind(verifier: str) -> AsyncGenerator[tuple[Client, MandaatAuth]]:
    """Open een MCP-sessie met het inkomensregister."""
    auth = MandaatAuth()
    async with (
        httpx2.AsyncClient(auth=auth, timeout=30) as http,
        Client(streamable_http_client(f"{verifier}/mcp", http_client=http)) as client,
    ):
        yield client, auth
