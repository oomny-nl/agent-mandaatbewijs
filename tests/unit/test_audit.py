"""Auditlog: hashketen schrijven, lezen, controleren en manipulatie herkennen."""

from __future__ import annotations

import json
from pathlib import Path

from mandaatbewijs.audit import GENESIS, Auditlog, controleer, ketenhash, lees


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
