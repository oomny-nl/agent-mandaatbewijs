"""De demoregie: verwachtingen, bewijsrijen en samenvouwen van herhaalde rijen."""

from __future__ import annotations

import pytest
from rich.table import Table

from mandaatbewijs import demo


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
