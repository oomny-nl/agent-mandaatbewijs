"""Auditlog: hashketen schrijven, lezen, controleren en manipulatie herkennen."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from mandaatbewijs import audit
from mandaatbewijs.audit import GENESIS, Auditlog, controleer, ketenhash, lees
from tests.unit.conftest import VolVolume


def test_keten_is_intact_en_hervat_na_herstart(tmp_path: Path) -> None:
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lindevoort")
    r1 = log.schrijf(gebeurtenis="verzoek", mandaat="m-1")
    r2 = log.schrijf(gebeurtenis="toestemming", mandaat="m-1")
    assert r1["nr"] == 1
    assert r1["vorige"] == GENESIS
    assert r2["vorige"] == r1["hash"]
    assert r1["organisatie"] == "lindevoort"

    log2 = Auditlog(pad, "lindevoort")
    r3 = log2.schrijf(gebeurtenis="intrekking", mandaat="m-1")
    assert r3["nr"] == 3
    assert r3["vorige"] == r2["hash"]
    assert controleer(lees(pad)) == (True, "intact")


def test_gewijzigd_record_breekt_de_keten(tmp_path: Path) -> None:
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lir")
    log.schrijf(beslissing="toegestaan")
    log.schrijf(beslissing="geweigerd")
    records = lees(pad)
    records[1]["beslissing"] = "toegestaan"
    ok, melding = controleer(records)
    assert not ok
    assert "record 2 is gewijzigd" in melding


def test_weggelaten_record_breekt_de_keten(tmp_path: Path) -> None:
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lir")
    for i in range(3):
        log.schrijf(nr_test=i)
    records = lees(pad)
    del records[1]
    ok, melding = controleer(records)
    assert not ok
    assert "record 2" in melding


def test_verwijderde_staart_blijft_onopgemerkt(tmp_path: Path) -> None:
    """Bekende beperking (ONTWERP §9): zonder extern anker valideert een afgeknotte keten."""
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lir")
    for i in range(3):
        log.schrijf(nr_test=i)
    records = lees(pad)[:2]
    assert controleer(records) == (True, "intact")


def test_ketenhash_is_deterministisch_en_negeert_hash_veld() -> None:
    record = {"nr": 1, "a": 1, "b": [1, 2]}
    h = ketenhash(GENESIS, record)
    assert h == ketenhash(GENESIS, {**record, "hash": "x"})
    assert h == ketenhash(GENESIS, json.loads(json.dumps(record)))
    assert h != ketenhash("1" * 64, record)


def test_half_geschreven_regel_wordt_teruggezet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lindevoort")
    log.schrijf_uitgaand(1, {"gebeurtenis": "verzoek"})
    voor = pad.read_bytes()
    grens = VolVolume(monkeypatch, pad, deel=20)
    with pytest.raises(OSError, match="No space"):
        log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    assert pad.read_bytes() == voor  # de halve regel is weg
    grens.actief = False
    assert log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"}) is not None
    assert log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"}) is None  # één keer
    records = lees(pad)
    assert [(r["nr"], r["uitgaand"]) for r in records] == [(1, 1), (2, 2)]
    assert controleer(records) == (True, "intact")
    Auditlog(pad, "lindevoort")  # herstart leest het bestand zonder fout


def test_fout_bij_fsync_na_volledige_regel_geeft_geen_dubbel_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """De regel staat er helemaal, maar `fsync` faalt: niet bevestigd, dus terugzetten."""
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lindevoort")
    log.schrijf_uitgaand(1, {"gebeurtenis": "verzoek"})
    echt, pogingen = audit.os.fsync, []

    def fsync(fd: int) -> None:
        pogingen.append(fd)
        if len(pogingen) == 1:
            raise OSError(5, "Input/output error")
        echt(fd)

    monkeypatch.setattr(audit.os, "fsync", fsync)
    with pytest.raises(OSError, match="Input/output"):
        log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    assert len(lees(pad)) == 1
    log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    records = lees(pad)
    assert [r["uitgaand"] for r in records] == [1, 2]
    assert controleer(records) == (True, "intact")


def test_onvolledige_laatste_regel_wordt_bij_de_start_verwijderd(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Een crash midden in een append laat een regel zonder einde achter; nooit bevestigd."""
    pad = tmp_path / "audit.jsonl"
    Auditlog(pad, "lindevoort").schrijf_uitgaand(1, {"gebeurtenis": "verzoek"})
    with pad.open("ab") as f:
        f.write(b'{"nr": 2, "tijd": "2026-')
    with caplog.at_level(logging.WARNING, logger="mandaatbewijs.audit"):
        log = Auditlog(pad, "lindevoort")
    assert "onvolledige laatste regel (24 bytes) verwijderd" in caplog.text
    log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    records = lees(pad)
    assert [r["nr"] for r in records] == [1, 2]
    assert controleer(records) == (True, "intact")


def test_mislukt_terugzetten_herstelt_bij_de_volgende_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lindevoort")
    log.schrijf_uitgaand(1, {"gebeurtenis": "verzoek"})
    grens = VolVolume(monkeypatch, pad, deel=20, truncate_faalt=True)
    with pytest.raises(OSError, match="No space") as info:
        log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    assert "terugzetten van het auditlog mislukte ook" in str(info.value.__notes__)
    assert not pad.read_bytes().endswith(b"\n")  # de halve regel staat er nog
    grens.actief = False
    log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    records = lees(pad)
    assert [(r["nr"], r["uitgaand"]) for r in records] == [(1, 1), (2, 2)]
    assert controleer(records) == (True, "intact")


def test_fout_bij_sluiten_na_volledige_regel_geeft_geen_dubbel_nummer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """De regel staat al op schijf als het sluiten faalt; de volgende append telt hem mee."""
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lindevoort")
    log.schrijf_uitgaand(1, {"gebeurtenis": "verzoek"})
    grens = VolVolume(monkeypatch, pad, deel=None, sluiten_faalt=True)
    with pytest.raises(OSError, match="Input/output"):
        log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    grens.actief = False
    assert log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"}) is None  # stond er al
    log.schrijf(gebeurtenis="daarna")
    records = lees(pad)
    assert [(r["nr"], r.get("uitgaand")) for r in records] == [(1, 1), (2, 2), (3, None)]
    assert controleer(records) == (True, "intact")


def test_volledige_regel_die_niet_terug_te_zetten_is_wordt_niet_dubbel_geschreven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fsync faalt na een volledige regel en ook het terugzetten mislukt: de regel blijft staan."""
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lindevoort")
    log.schrijf_uitgaand(1, {"gebeurtenis": "verzoek"})
    grens = VolVolume(monkeypatch, pad, deel=None, truncate_faalt=True)
    echt_fsync, fouten = os.fsync, [OSError(5, "Input/output error")]

    def fsync(fd: int) -> None:
        if fouten:
            raise fouten.pop()
        echt_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OSError, match="Input/output") as info:
        log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"})
    assert "terugzetten van het auditlog mislukte ook" in " ".join(info.value.__notes__)
    grens.actief = False
    assert log.schrijf_uitgaand(2, {"gebeurtenis": "uitgegeven"}) is None  # stond er al
    log.schrijf(gebeurtenis="daarna")
    records = lees(pad)
    assert [(r["nr"], r.get("uitgaand")) for r in records] == [(1, 1), (2, 2), (3, None)]
    assert controleer(records) == (True, "intact")


def test_outboxevent_houdt_zijn_eigen_tijd(tmp_path: Path) -> None:
    pad = tmp_path / "audit.jsonl"
    log = Auditlog(pad, "lindevoort")
    record = log.schrijf_uitgaand(1, {"tijd": "2026-01-01T00:00:00.000+00:00", "gebeurtenis": "x"})
    assert record is not None
    assert record["tijd"] == "2026-01-01T00:00:00.000+00:00"
    assert record["geschreven"] > record["tijd"]
