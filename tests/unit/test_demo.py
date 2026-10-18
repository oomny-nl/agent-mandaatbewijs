"""De demoregie: verwachtingen, bewijsrijen en samenvouwen van herhaalde rijen."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import ToolMessage
from rich.table import Table

from mandaatbewijs import demo
from mandaatbewijs.audit import Auditlog


def test_verwacht_in_volgorde() -> None:
    demo.GEBEURTENISSEN[:] = [
        {"soort": "aanroep", "tool": "dossier_lezen"},
        {"soort": "resultaat", "tool": "dossier_lezen", "tekst": "{}"},
        {"soort": "presentatie", "tool": "inkomen_opvragen", "bekendgemaakt": ["doel"]},
        {"soort": "resultaat", "tool": "inkomen_opvragen"},
        {"soort": "register_weigert", "tekst": "GEWEIGERD: dossier_buiten_mandaat"},
    ]
    demo.verwacht("s", [("resultaat", "inkomen_opvragen"), ("register_weigert", "dossier_buiten")])
    assert demo.GEBEURTENISSEN == []
    demo.GEBEURTENISSEN[:] = [{"soort": "register_weigert", "tekst": "x"}, {"soort": "resultaat"}]
    with pytest.raises(demo.DemoAfwijking, match="op plaats 1 verwacht resultaat"):
        demo.verwacht("s", [("resultaat", ""), ("register_weigert", "")])


@pytest.mark.parametrize(
    ("extra", "positie"),
    [({"soort": "resultaat", "tool": "inkomen_opvragen"}, 0), ({"soort": "resultaat"}, 2)],
)
def test_verwacht_weigert_een_onverwacht_succes(extra: dict[str, str], positie: int) -> None:
    """Een extra succes vóór of na de verwachte beslissingen is een afwijking, geen deelmatch."""
    gebeurtenissen = [
        {"soort": "resultaat", "tool": "inkomen_opvragen"},
        {"soort": "register_weigert", "tekst": "GEWEIGERD: mandaat_ingetrokken"},
    ]
    gebeurtenissen.insert(positie, extra)
    demo.GEBEURTENISSEN[:] = gebeurtenissen
    with pytest.raises(demo.DemoAfwijking):
        demo.verwacht("s", [("resultaat", "inkomen_opvragen"), ("register_weigert", "ingetrokken")])
    assert demo.GEBEURTENISSEN == []


def test_verwacht_meldt_ontbrekende_beslissing() -> None:
    demo.GEBEURTENISSEN[:] = [{"soort": "resultaat", "tool": "inkomen_opvragen"}]
    with pytest.raises(demo.DemoAfwijking, match="niet gezien"):
        demo.verwacht("s", [("resultaat", "inkomen_opvragen"), ("register_weigert", "x")])


def test_rij_en_samenvouwen() -> None:
    record = {
        "tijd": "2026-10-17T15:40:33+00:00",
        "organisatie": "lir",
        "gebeurtenis": "toegestaan",
        "tool": "inkomen_opvragen",
        "dossier": "2026-0142",
        "jti": "m-abcdefghijkl",
        "reden": "binnen_mandaat",
    }
    rij = demo._rij(record)
    assert rij[1:] == (
        "register",
        "toegestaan",
        "inkomen_opvragen",
        "2026-0142",
        "m-abcdefgh",
        "binnen_mandaat",
    )
    tabel = Table()
    for _ in range(7):
        tabel.add_column("k")
    demo._voeg_toe(tabel, rij, 3)
    demo._voeg_toe(tabel, rij, 0)
    demo._voeg_toe(tabel, None, 0)
    assert tabel.row_count == 2
    assert tabel.columns[-1]._cells[0] == "binnen_mandaat ×4"
    assert tabel.columns[-1]._cells[1] == "binnen_mandaat"


def test_waarnemer_registreert(capsys: pytest.CaptureFixture[str]) -> None:
    demo.GEBEURTENISSEN.clear()
    demo.waarnemer(
        {"soort": "aanroep", "tool": "inkomen_opvragen", "argumenten": {"dossier": "2026-0142"}}
    )
    demo.waarnemer(
        {
            "soort": "presentatie",
            "tool": "inkomen_opvragen",
            "bekendgemaakt": ["doel", "inkomen:lezen"],
        }
    )
    demo.waarnemer(
        {
            "soort": "register_weigert",
            "tool": "inkomen_opvragen",
            "tekst": "GEWEIGERD door het register: mandaat_ingetrokken",
        }
    )
    demo.waarnemer(
        {
            "soort": "resultaat",
            "tool": "inkomen_opvragen",
            "tekst": '{"dossier": "2026-0142", "bruto_per_maand": 1430.0}',
        }
    )
    demo.waarnemer({"soort": "resultaat", "tool": "dossier_lezen", "tekst": '{"aanvrager": "J"}'})
    uit = capsys.readouterr().out
    assert "wil inkomen_opvragen(2026-0142)" in uit
    assert "doel, inkomen:lezen" in uit
    assert "mandaat_ingetrokken" in uit
    assert "1430.00 per maand" in uit
    assert "dossier gelezen (J)" in uit
    assert len(demo.GEBEURTENISSEN) == 5
    demo.GEBEURTENISSEN.clear()


def test_waarnemer_toont_protocolfout_met_eigen_tekst(capsys: pytest.CaptureFixture[str]) -> None:
    demo.GEBEURTENISSEN.clear()
    demo.waarnemer(
        {
            "soort": "register_fout",
            "tool": "inkomen_opvragen",
            "tekst": "protocolfout (MCP -32602): Unknown tool: x",
        }
    )
    uit = capsys.readouterr().out
    assert "FOUT: protocolfout (MCP -32602): Unknown tool: x" in uit
    assert "WEIGERT" not in uit
    demo.GEBEURTENISSEN.clear()


def _log(pad: Path, *records: dict[str, Any]) -> Path:
    log = Auditlog(pad, "lir")
    for velden in records:
        log.schrijf(**velden)
    return pad


def test_controleer_log_eist_bestaand_gevuld_en_volledig_log(tmp_path: Path) -> None:
    """Een ontbrekend of leeg log is geen bewijs, ook al is een lege keten technisch intact."""
    verwacht = [
        {"gebeurtenis": "toegestaan", "jti": "m-1"},
        {"gebeurtenis": "geweigerd", "reden": "mandaat_ingetrokken", "jti": "m-1"},
    ]
    with pytest.raises(demo.DemoAfwijking, match="ontbreekt"):
        demo.controleer_log("register", tmp_path / "weg.jsonl", verwacht)
    (tmp_path / "leeg.jsonl").touch()
    with pytest.raises(demo.DemoAfwijking, match="leeg"):
        demo.controleer_log("register", tmp_path / "leeg.jsonl", verwacht)
    deels = _log(tmp_path / "deels.jsonl", {"gebeurtenis": "toegestaan", "jti": "m-1"})
    with pytest.raises(demo.DemoAfwijking, match="mandaat_ingetrokken"):
        demo.controleer_log("register", deels, verwacht)
    omgekeerd = _log(
        tmp_path / "omgekeerd.jsonl",
        {"gebeurtenis": "geweigerd", "reden": "mandaat_ingetrokken", "jti": "m-1"},
        {"gebeurtenis": "toegestaan", "jti": "m-1"},
    )
    with pytest.raises(demo.DemoAfwijking, match="niet op zijn plaats"):
        demo.controleer_log("register", omgekeerd, verwacht)
    ander_mandaat = _log(
        tmp_path / "ander.jsonl",
        {"gebeurtenis": "toegestaan", "jti": "m-1"},
        {"gebeurtenis": "geweigerd", "reden": "mandaat_ingetrokken", "jti": "m-2"},
    )
    with pytest.raises(demo.DemoAfwijking, match="ontbreekt of staat niet"):
        demo.controleer_log("register", ander_mandaat, verwacht)
    goed = _log(
        tmp_path / "goed.jsonl",
        {"gebeurtenis": "toegestaan", "jti": "m-1"},
        {"gebeurtenis": "toegestaan", "jti": "m-1"},  # binnen het cache-interval: mag ertussen
        {"gebeurtenis": "geweigerd", "reden": "mandaat_ingetrokken", "jti": "m-1", "tool": "t"},
    )
    assert len(demo.controleer_log("register", goed, verwacht)) == 3
    regels = goed.read_text(encoding="utf-8").splitlines()
    goed.write_text("\n".join([regels[0], regels[2]]) + "\n", encoding="utf-8")
    with pytest.raises(demo.DemoAfwijking, match="auditketen register"):
        demo.controleer_log("register", goed, verwacht)


class _Gereedschap:
    def __init__(self, statussen: list[str]) -> None:
        self.statussen = statussen

    async def voer_uit(self, naam: str, argumenten: dict[str, Any]) -> ToolMessage:
        return ToolMessage("x", tool_call_id="c", status=self.statussen.pop(0))


def test_tot_geweigerd_bewaakt_de_ttl_grens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Na `ttl` seconden mag geen aanroep meer slagen; daarvoor wel (gecachete statuslijst)."""

    async def geen_pauze(_: float) -> None:
        return None

    monkeypatch.setattr(demo.asyncio, "sleep", geen_pauze)
    monkeypatch.setattr(demo, "STATUS_TTL_S", 5)
    nu = time.time()
    gereedschap: Any = _Gereedschap(["success", "success", "error"])
    geweigerd_op, laatste = asyncio.run(demo._tot_geweigerd(gereedschap, "2026-0142", nu))
    assert laatste is not None
    assert nu <= laatste <= geweigerd_op
    te_laat: Any = _Gereedschap(["success"])
    with pytest.raises(demo.DemoAfwijking, match="later dan de ttl van 5 s"):
        asyncio.run(demo._tot_geweigerd(te_laat, "2026-0142", nu - 5))
    meteen: Any = _Gereedschap(["error"])
    _, geen = asyncio.run(demo._tot_geweigerd(meteen, "2026-0142", nu))
    assert geen is None
