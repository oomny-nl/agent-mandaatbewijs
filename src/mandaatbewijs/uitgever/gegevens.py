"""Fictieve gegevens van gemeente Lindevoort: medewerkers, rollen, caseload en doelen.

De uitgever toetst hier wat een medewerker zelf mag: een agent kan nooit meer krijgen dan de
medewerker kan geven.
"""

from __future__ import annotations

from dataclasses import dataclass

ORGANISATIE = "Gemeente Lindevoort (fictief)"
VCT = "https://oomny.nl/vct/agentmandaat/v1"


@dataclass(frozen=True)
class Medewerker:
    """Een medewerker van de gemeente."""

    id: str
    naam: str
    rol: str
    afdeling: str
    caseload: tuple[str, ...]


MEDEWERKERS: dict[str, Medewerker] = {
    "sanne": Medewerker(
        "sanne", "Sanne de Vries", "klantmanager", "Werk en Inkomen", ("2026-0142", "2026-0143")
    ),
    "bram": Medewerker(
        "bram", "Bram Jansen", "intake", "Werk en Inkomen", ("2026-0142", "2026-0143", "2026-0157")
    ),
    "kees": Medewerker("kees", "Kees Mulder", "functioneel beheerder", "Informatievoorziening", ()),
}

# Welke acties bij het inkomensregister een rol mag mandateren. Niemand mag `inkomen:corrigeren`
# aan een agent geven: dat is een eigen handeling van een mens.
ROLACTIES: dict[str, frozenset[str]] = {
    "klantmanager": frozenset({"inkomen:lezen"}),
    "intake": frozenset(),
    "functioneel beheerder": frozenset(),
}
BEHEERDERS = frozenset({"kees"})
DOELEN = frozenset({"aanvraag-levensonderhoud", "heronderzoek"})
MAX_GELDIGHEID_S = 3600


def mag_verlenen(
    medewerker: Medewerker, doel: str, acties: list[str], dossiers: list[str]
) -> str | None:
    """Reden waarom deze medewerker dit mandaat niet kan verlenen, of None als het mag."""
    if doel not in DOELEN:
        return f"doel {doel!r} is onbekend"
    if not acties or not dossiers:
        return "een mandaat heeft minstens één actie en één dossier"
    toegestaan = ROLACTIES.get(medewerker.rol, frozenset())
    buiten_rol = sorted(set(acties) - toegestaan)
    if buiten_rol:
        return f"rol {medewerker.rol} mag niet mandateren: {', '.join(buiten_rol)}"
    buiten_caseload = sorted(set(dossiers) - set(medewerker.caseload))
    if buiten_caseload:
        return f"niet in de caseload van {medewerker.naam}: {', '.join(buiten_caseload)}"
    return None
