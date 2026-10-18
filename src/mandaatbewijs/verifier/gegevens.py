"""Fictieve gegevens van het Landelijk Inkomensregister (LIR).

Een dossiernummer is gemeentelijk: hetzelfde nummer bij twee gemeenten is een ander dossier. Het
register zoekt daarom op (gemeente, dossiernummer), met de gemeente zoals de vertrouwenslijst haar
noemt bij de geverifieerde `iss`.
"""

from __future__ import annotations

from dataclasses import dataclass

VERIFIER_NAAM = "Landelijk Inkomensregister (fictief)"
LINDEVOORT = "Gemeente Lindevoort (fictief)"
ELSWEERD = "Gemeente Elsweerd (fictief)"

INKOMENS: dict[tuple[str, str], dict[str, object]] = {
    (LINDEVOORT, "2026-0142"): {
        "dossier": "2026-0142",
        "periode": "2026-07 t/m 2026-09",
        "bron": "loonaangifte",
        "bruto_per_maand": 1430.00,
        "werkgever": "Schoonmaakbedrijf Helder B.V.",
    },
    (LINDEVOORT, "2026-0143"): {
        "dossier": "2026-0143",
        "periode": "2026-07 t/m 2026-09",
        "bron": "loonaangifte",
        "bruto_per_maand": 0.00,
        "werkgever": None,
    },
    (LINDEVOORT, "2026-0157"): {
        "dossier": "2026-0157",
        "periode": "2026-07 t/m 2026-09",
        "bron": "loonaangifte",
        "bruto_per_maand": 2875.00,
        "werkgever": "Transportgroep Van Dijk",
    },
    (ELSWEERD, "2026-0142"): {
        "dossier": "2026-0142",
        "periode": "2026-07 t/m 2026-09",
        "bron": "uitkering",
        "bruto_per_maand": 1210.00,
        "werkgever": None,
    },
}


def inkomen(gemeente: str, dossier: str) -> dict[str, object] | None:
    """Inkomensgegevens bij een gemeentelijk dossier, of None als het register het niet kent."""
    return INKOMENS.get((gemeente, dossier))


@dataclass(frozen=True)
class Toolbeleid:
    """Vereiste actie van een tool en de doelen die het register daarvoor accepteert."""

    actie: str
    doelen: frozenset[str]

    @property
    def meta(self) -> dict[str, object]:
        """Voor `tools/list`, zodat de houder weet welke claims hij bekend moet maken."""
        return {"actie": self.actie, "doelen": sorted(self.doelen)}


TOOLBELEID: dict[str, Toolbeleid] = {
    "inkomen_opvragen": Toolbeleid(
        "inkomen:lezen", frozenset({"aanvraag-levensonderhoud", "heronderzoek"})
    ),
    "correctie_indienen": Toolbeleid("inkomen:corrigeren", frozenset()),
}
