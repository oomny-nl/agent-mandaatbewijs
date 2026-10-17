"""Gedeelde fixtures: een in-process uitgever (FastAPI) en een agent met sleutel."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx2
import pytest
from starlette.testclient import TestClient

from mandaatbewijs.houder.portemonnee import TYP_PROOF
from mandaatbewijs.sleutels import Sleutelpaar
from mandaatbewijs.statuslijst import Tokenbeleid
from mandaatbewijs.uitgever.app import Dienst, Instellingen, maak_app

ISS = "http://localhost:8000"


@pytest.fixture
def uitgever(tmp_path: Path) -> Dienst:
    """Uitgever met eigen datamap; ttl 1 s zodat statustests snel zijn."""
    return Dienst(Instellingen(ISS, tmp_path / "uitgever", Tokenbeleid(1, 60)))


@pytest.fixture
def uitgever_client(uitgever: Dienst) -> TestClient:
    """Synchrone testclient op de uitgever."""
    return TestClient(maak_app(uitgever))


@pytest.fixture
def uitgever_transport(uitgever: Dienst) -> httpx2.ASGITransport:
    """ASGI-transport voor de asynchrone verifier-bronnen."""
    return httpx2.ASGITransport(app=maak_app(uitgever))


def login(uitgever: Dienst, naam: str) -> tuple[str, str]:
    """HTTP Basic-gegevens van een medewerker."""
    return naam, uitgever.wachtwoorden[naam]


def proof(sleutel: Sleutelpaar, verzoek_id: str, iss: str = ISS, **extra: Any) -> str:
    """Bewijs van sleutelbezit voor het ophalen."""
    claims = {"aud": iss, "nonce": verzoek_id, "iat": int(time.time()), **extra}
    return sleutel.teken({"typ": TYP_PROOF}, claims)


def verleen(
    client: TestClient,
    uitgever: Dienst,
    sleutel: Sleutelpaar,
    dossiers: list[str] | None = None,
    **velden: Any,
) -> tuple[str, str]:
    """Volledige uitgifte: verzoek, toestemming, ophalen. Geeft (credential, mandaat_id)."""
    body = {
        "agent_jwk": sleutel.publieke_jwk,
        "medewerker": velden.get("medewerker", "sanne"),
        "doel": velden.get("doel", "aanvraag-levensonderhoud"),
        "acties": velden.get("acties", ["inkomen:lezen"]),
        "dossiers": dossiers or ["2026-0142"],
    }
    v = client.post("/mandaatverzoeken", json=body)
    assert v.status_code == 201, v.text
    verzoek_id = v.json()["id"]
    t = client.post(
        f"/mandaatverzoeken/{verzoek_id}/toestemming",
        json={"besluit": "ja", "geldigheid_s": velden.get("geldigheid_s", 600)},
        auth=login(uitgever, body["medewerker"]),
    )
    assert t.status_code == 200, t.text
    c = client.post(
        f"/mandaatverzoeken/{verzoek_id}/credential", json={"proof": proof(sleutel, verzoek_id)}
    )
    assert c.status_code == 200, c.text
    return c.json()["credential"], t.json()["mandaat_id"]


def audit(uitgever: Dienst) -> list[dict[str, Any]]:
    """Auditrecords van de uitgever."""
    pad = uitgever.inst.datamap / "audit.jsonl"
    return [json.loads(r) for r in pad.read_text().splitlines()] if pad.exists() else []
