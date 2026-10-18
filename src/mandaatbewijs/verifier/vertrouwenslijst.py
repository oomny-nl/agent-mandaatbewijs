"""Vertrouwenslijst van de verifier: welke uitgevers en credentialtypen hij accepteert.

Een lokaal beheerd JSON-bestand. In productie is dit een vertrouwensregister met eigen governance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Uitgever:
    """Een vertrouwde uitgever."""

    iss: str
    naam: str
    vct: frozenset[str]

    @property
    def host(self) -> str:
        """Hostnaam van de uitgever."""
        return urlsplit(self.iss).hostname or ""


class Vertrouwenslijst:
    """Vertrouwde uitgevers op `iss`; `iss` en naam zijn elk uniek.

    De naam is de organisatie waaronder de verifier gegevens zoekt (een gemeentelijk dossiernummer
    hoort bij één gemeente); twee uitgevers met dezelfde naam zouden elkaars dossiers delen.
    """

    def __init__(self, uitgevers: list[Uitgever]) -> None:
        for veld in ("iss", "naam"):
            waarden = [getattr(u, veld) for u in uitgevers]
            dubbel = sorted({w for w in waarden if waarden.count(w) > 1})
            if dubbel:
                raise ValueError(f"vertrouwenslijst: {veld} komt meer dan eens voor: {dubbel}")
        self._per_iss = {u.iss: u for u in uitgevers}

    @classmethod
    def laad(cls, pad: Path) -> Vertrouwenslijst:
        """Lees `[{"iss": …, "naam": …, "vct": […]}, …]`."""
        inhoud = json.loads(pad.read_text(encoding="utf-8"))
        if not isinstance(inhoud, list):
            raise ValueError(f"{pad}: verwacht een lijst van uitgevers")
        uitgevers = []
        for item in inhoud:
            iss = str(item["iss"]).rstrip("/")
            if urlsplit(iss).scheme not in ("http", "https") or not urlsplit(iss).hostname:
                raise ValueError(f"{pad}: iss {iss!r} is geen http(s)-URL")
            uitgevers.append(Uitgever(iss, str(item.get("naam", iss)), frozenset(item["vct"])))
        return cls(uitgevers)

    def uitgever(self, iss: str) -> Uitgever | None:
        """De vertrouwde uitgever bij deze `iss`, of None."""
        return self._per_iss.get(iss)

    @property
    def hosts(self) -> frozenset[str]:
        """Hostnamen van alle vertrouwde uitgevers (voor de adrescontrole in Compose)."""
        return frozenset(u.host for u in self._per_iss.values())
