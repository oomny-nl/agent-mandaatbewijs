"""De Mandaatpoort: allowlist, challenge, bodygrens en auditrecords."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mandaatbewijs.audit import Auditlog, lees
from mandaatbewijs.verifier.poort import MAX_BODY, Mandaatpoort, Poortinstellingen, ontleed_rpc
from mandaatbewijs.verifier.verificatie import Toelating, Verificatie, Weigering

NONCE_URL = "http://inkomensregister:8000/nonces"


class _Verificatie:
    def __init__(self, weigering: Weigering | None = None) -> None:
        self.weigering = weigering
        self.gezien: list[tuple[str, str, str | None]] = []

    async def verifieer(self, presentatie: str, tool: str, dossier: str | None) -> Toelating:
        self.gezien.append((presentatie, tool, dossier))
        if self.weigering:
            raise self.weigering
        return Toelating(
            "iss", "L", "m-1", "jkt", "doel", "inkomen:lezen", dossier or "", ["doel"], "vers", "n"
        )


def _app(tmp_path: Path, verificatie: _Verificatie) -> tuple[TestClient, Path]:
    async def mcp(request: Any) -> JSONResponse:
        toelating = request.scope["state"]["toelating"]
        return JSONResponse({"toelating": toelating.jti if toelating else None})

    binnen = Starlette(routes=[Route("/mcp", mcp, methods=["POST", "GET"])])
    pad = tmp_path / "audit.jsonl"
    inst = Poortinstellingen(cast(Verificatie, verificatie), Auditlog(pad, "lir"), NONCE_URL)
    return TestClient(Mandaatpoort(binnen, inst)), pad


def _aanroep(tool: str = "inkomen_opvragen", dossier: str | None = "2026-0142") -> dict[str, Any]:
    argumenten = {"dossier": dossier} if dossier else {}
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": argumenten},
    }


def test_allowlist_zonder_presentatie(tmp_path: Path) -> None:
    client, pad = _app(tmp_path, _Verificatie())
    for methode in ("initialize", "tools/list", "ping", "server/discover"):
        antwoord = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": methode})
        assert antwoord.status_code == 200, methode
        assert antwoord.json() == {"toelating": None}
    for methode in ("resources/list", "prompts/get", "tools/call/x"):
        antwoord = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": methode})
        assert antwoord.status_code == 403, methode
        assert antwoord.json()["error"] == "methode_niet_toegestaan"
    assert client.post("/mcp", content=b"[]").status_code == 403
    assert client.post("/mcp", content=b"geen json").status_code == 403
    assert client.get("/mcp").status_code == 403
    assert [r["methode"] for r in lees(pad) if r.get("methode")] == [
        "resources/list",
        "prompts/get",
        "tools/call/x",
        "GET",
    ]


def test_tools_call_zonder_presentatie(tmp_path: Path) -> None:
    client, pad = _app(tmp_path, _Verificatie())
    antwoord = client.post("/mcp", json=_aanroep())
    assert antwoord.status_code == 401
    kop = antwoord.headers["www-authenticate"]
    assert kop.startswith('Mandaat error="presentatie_ontbreekt"')
    assert f'nonce_url="{NONCE_URL}"' in kop
    ander = client.post("/mcp", json=_aanroep(), headers={"Authorization": "Bearer x"})
    assert ander.status_code == 401
    assert lees(pad)[-1]["reden"] == "presentatie_ontbreekt"


def test_tools_call_toegestaan_en_audit(tmp_path: Path) -> None:
    verificatie = _Verificatie()
    client, pad = _app(tmp_path, verificatie)
    antwoord = client.post("/mcp", json=_aanroep(), headers={"Authorization": "Mandaat a~b~c"})
    assert antwoord.status_code == 200
    assert antwoord.json() == {"toelating": "m-1"}
    assert verificatie.gezien == [("a~b~c", "inkomen_opvragen", "2026-0142")]
    record = lees(pad)[-1]
    assert record["gebeurtenis"] == "toegestaan"
    assert record["tool"] == "inkomen_opvragen"
    assert record["dossier"] == "2026-0142"
    assert record["jti"] == "m-1"
    assert "nonce" not in record
    assert "a~b~c" not in json.dumps(record)


def test_weigering_geeft_status_en_reden(tmp_path: Path) -> None:
    weigering = Weigering("dossier_buiten_mandaat", 403, "2026-0157", bevestigd={"jti": "m-9"})
    client, pad = _app(tmp_path, _Verificatie(weigering))
    antwoord = client.post(
        "/mcp", json=_aanroep(dossier="2026-0157"), headers={"Authorization": "Mandaat p"}
    )
    assert antwoord.status_code == 403
    assert 'error="dossier_buiten_mandaat"' in antwoord.headers["www-authenticate"]
    record = lees(pad)[-1]
    assert (record["gebeurtenis"], record["reden"], record["jti"]) == (
        "geweigerd",
        "dossier_buiten_mandaat",
        "m-9",
    )


def test_body_te_groot_en_presentatie_te_groot(tmp_path: Path) -> None:
    client, _ = _app(tmp_path, _Verificatie())
    assert client.post("/mcp", content=b"x" * (MAX_BODY + 1)).status_code == 413
    lang = client.post("/mcp", json=_aanroep(), headers={"Authorization": "Mandaat " + "a" * 20000})
    assert lang.status_code == 401


def test_andere_paden_vrij(tmp_path: Path) -> None:
    client, _ = _app(tmp_path, _Verificatie())
    assert (
        client.get("/gezond").status_code == 404
    )  # de binnenste app kent het pad niet; de poort laat door


def test_ontleed_rpc() -> None:
    assert ontleed_rpc(b"{") == (None, None, None)
    assert ontleed_rpc(b'{"method": 1}') == (None, None, None)
    assert ontleed_rpc(b'{"method": "ping"}') == ("ping", None, None)
    assert ontleed_rpc(b'{"method": "tools/call"}') == ("tools/call", "(ongeldig)", None)
    assert ontleed_rpc(
        b'{"method": "tools/call", "params": {"name": "t", "arguments": {"dossier": 5}}}'
    ) == ("tools/call", "t", None)
    assert ontleed_rpc(json.dumps(_aanroep()).encode()) == (
        "tools/call",
        "inkomen_opvragen",
        "2026-0142",
    )


class _KapotteVerificatie(_Verificatie):
    async def verifieer(self, presentatie: str, tool: str, dossier: str | None) -> Toelating:
        raise KeyError("status_list")


def test_fout_in_de_verificatie_is_een_weigering(tmp_path: Path) -> None:
    """Een programmeerfout of onverwachte invoer laat nooit door: 401, gelogd en geauditeerd."""
    client, pad = _app(tmp_path, _KapotteVerificatie())
    antwoord = client.post("/mcp", json=_aanroep(), headers={"Authorization": "Mandaat x~y~z"})
    assert antwoord.status_code == 401
    assert 'error="verificatie_mislukt"' in antwoord.headers["www-authenticate"]
    records = lees(pad)
    assert records[-1]["gebeurtenis"] == "geweigerd"
    assert records[-1]["reden"] == "verificatie_mislukt"


def test_onbevestigde_velden_worden_gemarkeerd(tmp_path: Path) -> None:
    """Velden uit een nog niet geverifieerde presentatie staan als `onbevestigd` in de audit."""
    weigering = Weigering("uitgever_niet_vertrouwd", 401, iss="http://elsweerd:8000", jti="m-x")
    client, pad = _app(tmp_path, _Verificatie(weigering))
    client.post("/mcp", json=_aanroep(), headers={"Authorization": "Mandaat x~y~z"})
    record = lees(pad)[-1]
    assert record["iss"] == "http://elsweerd:8000"
    assert record["onbevestigd"] == ["iss", "jti"]
    client, pad = _app(tmp_path / "b", _Verificatie(Weigering("presentatie_ongeldig")))
    client.post("/mcp", json=_aanroep(), headers={"Authorization": "Mandaat x~y~z"})
    assert "onbevestigd" not in lees(pad)[-1]
    # Na de handtekening van de uitgever: (iss, jti) bevestigd, niet als onbevestigd gemarkeerd.
    bevestigd = {"iss": "http://uitgever:8000", "jti": "m-1", "jkt": "abc"}
    weigering = Weigering("dossier_buiten_mandaat", 403, bevestigd=bevestigd)
    client, pad = _app(tmp_path / "c", _Verificatie(weigering))
    client.post("/mcp", json=_aanroep(), headers={"Authorization": "Mandaat x~y~z"})
    record = lees(pad)[-1]
    assert (record["iss"], record["jti"], record["jkt"]) == ("http://uitgever:8000", "m-1", "abc")
    assert "onbevestigd" not in record
