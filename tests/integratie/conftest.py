"""Fixtures voor integratietests tegen de echte compose-keten (uitgever en inkomensregister).

Omgeving: `UITGEVER_ISS`, `VERIFIER_AUD`, `UITGEVER_DATA` (met `wachtwoorden.json` en het auditlog
van de uitgever), `VERIFIER_DATA` (auditlog van het register) en `STATUSLIJST_TTL`.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest

from mandaatbewijs.audit import lees
from mandaatbewijs.demo import Portaal
from mandaatbewijs.houder.portemonnee import Portemonnee
from mandaatbewijs.sdjwt import Disclosure
from mandaatbewijs.sleutels import Sleutelpaar

MCP_KOPPEN = {"Accept": "application/json, text/event-stream"}


@dataclass(frozen=True)
class Omgeving:
    """Adressen en datamappen van de keten."""

    uitgever: str
    verifier: str
    uitgever_data: Path
    verifier_data: Path
    status_ttl: int

    @property
    def wachtwoorden(self) -> dict[str, str]:
        """Wachtwoorden van de fictieve medewerkers, door de uitgever bij de start gegenereerd."""
        return json.loads((self.uitgever_data / "wachtwoorden.json").read_text())

    def portaal(self, naam: str = "sanne") -> Portaal:
        """Portaal van een medewerker bij de uitgever."""
        return Portaal(self.uitgever, naam, self.wachtwoorden[naam])

    def audit(self, organisatie: str) -> list[dict[str, Any]]:
        """Auditrecords van `uitgever` of `register`."""
        map_ = self.uitgever_data if organisatie == "uitgever" else self.verifier_data
        return lees(map_ / "audit.jsonl")


@pytest.fixture(scope="session")
def omgeving() -> Omgeving:
    return Omgeving(
        os.environ.get("UITGEVER_ISS", "http://uitgever:8000"),
        os.environ.get("VERIFIER_AUD", "http://inkomensregister:8000"),
        Path(os.environ.get("UITGEVER_DATA", "/data-uitgever")),
        Path(os.environ.get("VERIFIER_DATA", "/data-verifier")),
        int(os.environ.get("STATUSLIJST_TTL", "5")),
    )


@dataclass
class Mandaat:
    """Een agent met een uitgegeven mandaat."""

    agent: Portemonnee
    mandaat_id: str
    medewerker: str


Verlener = Callable[..., Mandaat]


@pytest.fixture
def verleen(omgeving: Omgeving) -> Verlener:
    """Fabriek: agent vraagt, medewerker zegt ja, agent haalt op."""

    def maak(
        dossiers: list[str] | None = None,
        naam: str = "sanne",
        doel: str = "aanvraag-levensonderhoud",
        agent: Portemonnee | None = None,
    ) -> Mandaat:
        agent = agent or Portemonnee(Sleutelpaar.nieuw("test-agent"), omgeving.uitgever)
        verzoek_id = agent.vraag_mandaat(naam, doel, ["inkomen:lezen"], dossiers or ["2026-0142"])
        antwoord = omgeving.portaal(naam).beslis(verzoek_id, "ja", 300)
        assert antwoord.status_code == 200, antwoord.text
        agent.haal_op(verzoek_id)
        return Mandaat(agent, antwoord.json()["mandaat_id"], naam)

    return maak


def nonce(omgeving: Omgeving) -> str:
    """Verse nonce van het register."""
    antwoord = httpx2.post(f"{omgeving.verifier}/nonces", timeout=10)
    antwoord.raise_for_status()
    return str(antwoord.json()["nonce"])


def presentatie(
    omgeving: Omgeving, agent: Portemonnee, dossier: str, actie: str = "inkomen:lezen"
) -> str:
    """Presentatie met doel, één actie en één dossier, voor het register, met verse nonce."""
    gekozen: list[Disclosure] = agent.disclosures_voor(actie, dossier, True)
    return agent.presentatie(omgeving.verifier, nonce(omgeving), gekozen)


@dataclass(frozen=True)
class Uitkomst:
    """Antwoord van het register op een `tools/call`."""

    status: int
    reden: str
    inhoud: dict[str, Any]


def aanroep(
    omgeving: Omgeving, presentatie_: str | None, dossier: str, tool: str = "inkomen_opvragen"
) -> Uitkomst:
    """Stuur één `tools/call` rechtstreeks naar het register (stateless MCP over HTTP)."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"dossier": dossier}},
    }
    koppen = dict(MCP_KOPPEN)
    if presentatie_ is not None:
        koppen["Authorization"] = f"Mandaat {presentatie_}"
    antwoord = httpx2.post(f"{omgeving.verifier}/mcp", json=body, headers=koppen, timeout=10)
    challenge = antwoord.headers.get("www-authenticate", "")
    reden = challenge.split('error="', 1)[1].split('"', 1)[0] if 'error="' in challenge else ""
    inhoud = (
        antwoord.json()
        if antwoord.headers.get("content-type", "").startswith("application/json")
        else {}
    )
    return Uitkomst(antwoord.status_code, reden, inhoud)


def inkomen(uitkomst: Uitkomst) -> dict[str, Any]:
    """Het inkomen uit een geslaagd MCP-antwoord."""
    assert uitkomst.status == 200, uitkomst
    resultaat = uitkomst.inhoud["result"]
    assert not resultaat.get("isError"), resultaat
    return json.loads(resultaat["content"][0]["text"])


def wacht_tot(conditie: Callable[[], bool], max_s: float, stap_s: float = 0.5) -> float:
    """Wacht tot de conditie waar is; geeft de verstreken tijd. Faalt na `max_s`."""
    start = time.time()
    while True:
        if conditie():
            return time.time() - start
        if time.time() - start > max_s:
            raise AssertionError(f"conditie niet waar binnen {max_s} s")
        time.sleep(stap_s)
