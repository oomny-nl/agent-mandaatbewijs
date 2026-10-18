"""ASGI-poort voor het MCP-endpoint van het inkomensregister.

Elke `tools/call` op `/mcp` draagt een presentatie in `Authorization: Mandaat <sd-jwt+kb>` en wordt
vóór de tool door de acht stappen van ONTWERP §7 gehaald. Zonder presentatie zijn alleen de
JSON-RPC-methoden uit de allowlist toegestaan (`initialize`, `notifications/initialized`, `ping`,
`tools/list`). Elke beslissing krijgt een auditrecord, ook een te grote body of een misvormde
header; headers en bodies worden nooit gelogd.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mandaatbewijs.audit import Auditlog
from mandaatbewijs.sdjwt import MAX_PRESENTATIE
from mandaatbewijs.verifier.verificatie import Toelating, Verificatie, Weigering

log = logging.getLogger("inkomensregister")
MAX_BODY = 64 * 1024
SCHEMA = "Mandaat"
ZONDER_PRESENTATIE = frozenset(
    {"initialize", "notifications/initialized", "ping", "tools/list", "server/discover"}
)


class TeGroot(Exception):
    """Verzoek groter dan MAX_BODY."""


async def _lees_body(receive: Receive) -> bytes:
    delen: list[bytes] = []
    grootte = 0
    while True:
        bericht = await receive()
        deel = bericht.get("body", b"")
        grootte += len(deel)
        if grootte > MAX_BODY:
            raise TeGroot
        delen.append(deel)
        if not bericht.get("more_body"):
            return b"".join(delen)


def ontleed_rpc(body: bytes) -> tuple[str | None, str | None, str | None]:
    """(methode, tool, dossier) uit een JSON-RPC-verzoek; methode None als het geen object is."""
    try:
        verzoek = json.loads(body)
    except ValueError:
        return None, None, None
    if not isinstance(verzoek, dict) or not isinstance(verzoek.get("method"), str):
        return None, None, None
    methode = verzoek["method"]
    if methode != "tools/call":
        return methode, None, None
    params = verzoek.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return methode, "(ongeldig)", None
    argumenten = params.get("arguments")
    dossier = argumenten.get("dossier") if isinstance(argumenten, dict) else None
    return methode, params["name"], dossier if isinstance(dossier, str) and dossier else None


def challenge(reden: str, nonce_url: str) -> str:
    """`WWW-Authenticate`-waarde met de reden en waar een nonce te halen is."""
    return f'{SCHEMA} error="{reden}", nonce_url="{nonce_url}"'


def _auditvelden(weigering: Weigering) -> dict[str, Any]:
    """Velden van een weigering; die uit nog niet gevalideerde delen staan in `onbevestigd`."""
    velden = {**weigering.bevestigd, **weigering.onbevestigd}
    if weigering.onbevestigd:
        velden["onbevestigd"] = sorted(weigering.onbevestigd)
    return velden


def _presentatie(headers: list[tuple[bytes, bytes]]) -> str:
    """De presentatie uit precies één `Authorization: Mandaat ...`-header (ASGI: ruwe bytes).

    Raises:
        Weigering: Bij geen of een ander schema (`presentatie_ontbreekt`), meer dan één header
            of bytes buiten US-ASCII (`presentatie_ongeldig`) en een te lange waarde.
    """
    waarden = [v for k, v in headers if k.lower() == b"authorization"]
    if not waarden:
        raise Weigering("presentatie_ontbreekt")
    if len(waarden) > 1:
        raise Weigering("presentatie_ongeldig", 401, "meer dan één Authorization-header")
    try:
        waarde = waarden[0].decode("ascii")
    except UnicodeDecodeError as fout:
        raise Weigering("presentatie_ongeldig", 401, "header buiten US-ASCII") from fout
    schema, _, rest = waarde.partition(" ")
    if schema.lower() != SCHEMA.lower() or not rest.strip():
        raise Weigering("presentatie_ontbreekt")
    if len(rest.strip()) > MAX_PRESENTATIE:
        raise Weigering("presentatie_te_groot", 401, f"meer dan {MAX_PRESENTATIE} tekens")
    return rest.strip()


@dataclass(frozen=True)
class Achtergrondtaak:
    """Een coroutine die elke `interval_s` seconden draait zolang de app leeft."""

    werk: Callable[[], Awaitable[None]]
    interval_s: float

    async def draai(self) -> None:
        """Draai tot de taak wordt geannuleerd; een fout stopt de taak niet."""
        while True:
            await asyncio.sleep(self.interval_s)
            try:
                await self.werk()
            except Exception:
                log.exception("achtergrondverversing mislukt")


@dataclass(frozen=True)
class Poortinstellingen:
    """Wat de poort naast de app nodig heeft."""

    verificatie: Verificatie
    audit: Auditlog
    nonce_url: str
    achtergrond: Achtergrondtaak | None = None
    afsluiten: Callable[[], Awaitable[None]] | None = None


class Mandaatpoort:
    """ASGI-middleware die `/mcp` afschermt en de achtergrondverversing van statuslijsten draait."""

    def __init__(self, app: ASGIApp, inst: Poortinstellingen) -> None:
        self.app = app
        self.inst = inst
        self._taak: asyncio.Task[None] | None = None

    async def _lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def ontvang() -> Message:
            bericht = await receive()
            if bericht["type"] == "lifespan.startup" and self.inst.achtergrond is not None:
                self._taak = asyncio.create_task(self.inst.achtergrond.draai())
            elif bericht["type"] == "lifespan.shutdown":
                await self._stop()
            return bericht

        await self.app(scope, ontvang, send)

    async def _stop(self) -> None:
        """Stop de achtergrondtaak en sluit daarna de verbindingen (`afsluiten`)."""
        if self._taak is not None:
            self._taak.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._taak
            self._taak = None
        if self.inst.afsluiten is not None:
            try:
                await self.inst.afsluiten()
            except Exception:
                log.exception("afsluiten van de poort mislukt")

    async def _antwoord(self, send: Send, status: int, reden: str, headers: list[Any]) -> None:
        body = json.dumps({"error": reden}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), *headers],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def _weiger(self, send: Send, status: int, reden: str) -> None:
        kop = (b"www-authenticate", challenge(reden, self.inst.nonce_url).encode())
        await self._antwoord(send, status, reden, [kop])

    def _audit(self, beslissing: str, tool: str | None, dossier: str | None, **velden: Any) -> None:
        self.inst.audit.schrijf(
            gebeurtenis=beslissing, laag="poort", tool=tool, dossier=dossier, **velden
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Verwerk een ASGI-verzoek."""
        if scope["type"] == "lifespan":
            await self._lifespan(scope, receive, send)
            return
        if scope["type"] != "http" or not scope["path"].startswith("/mcp"):
            await self.app(scope, receive, send)
            return
        try:
            body = await _lees_body(receive)
        except TeGroot:
            self._audit("geweigerd", None, None, reden="verzoek_te_groot", grens=MAX_BODY)
            await self._antwoord(send, 413, "verzoek_te_groot", [])
            return
        if scope["method"] == "POST":
            methode, tool, dossier = ontleed_rpc(body)
        else:
            methode, tool, dossier = scope["method"], None, None
        if methode == "tools/call":
            await self._toolaanroep(scope, body, receive, send, (tool, dossier))
        elif methode is None or methode not in ZONDER_PRESENTATIE:
            self._audit("geweigerd", None, None, reden="methode_niet_toegestaan", methode=methode)
            await self._antwoord(send, 403, "methode_niet_toegestaan", [])
        else:
            await self._doorgeven(scope, body, receive, send, None)

    async def _toolaanroep(
        self,
        scope: Scope,
        body: bytes,
        receive: Receive,
        send: Send,
        aanroep: tuple[str | None, str | None],
    ) -> None:
        tool, dossier = aanroep
        try:
            presentatie = _presentatie(scope["headers"])
            toelating = await self.inst.verificatie.verifieer(presentatie, tool or "", dossier)
        except Weigering as weigering:
            self._audit(
                "geweigerd", tool, dossier, reden=weigering.reden, **_auditvelden(weigering)
            )
            await self._weiger(send, weigering.status, weigering.reden)
            return
        except Exception:
            # Een fout in de verificatie zelf mag nooit doorlaten: weigeren, loggen, auditen.
            log.exception("verificatie mislukt voor %s", tool)
            self._audit("geweigerd", tool, dossier, reden="verificatie_mislukt")
            await self._weiger(send, 401, "verificatie_mislukt")
            return
        velden = {k: v for k, v in asdict(toelating).items() if k not in ("nonce", "dossier")}
        self._audit("toegestaan", tool, dossier, reden="binnen_mandaat", **velden)
        await self._doorgeven(scope, body, receive, send, toelating)

    async def _doorgeven(
        self, scope: Scope, body: bytes, receive: Receive, send: Send, toelating: Toelating | None
    ) -> None:
        scope.setdefault("state", {})["toelating"] = toelating
        verzonden = False

        async def herhaal() -> Message:
            nonlocal verzonden
            if verzonden:
                return await receive()
            verzonden = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, herhaal, send)
