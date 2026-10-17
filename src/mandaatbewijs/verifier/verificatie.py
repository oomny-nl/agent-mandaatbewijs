"""De acht verificatiestappen van ONTWERP §7, in volgorde; de eerste weigering telt."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mandaatbewijs.sdjwt import Geverifieerd, Ontleed, SdJwtFout, ontleed, verifieer
from mandaatbewijs.statuslijst import GELDIG
from mandaatbewijs.verifier.bronnen import BronFout, Sleutelbron, Statusbron
from mandaatbewijs.verifier.gegevens import TOOLBELEID, Toolbeleid
from mandaatbewijs.verifier.nonces import Nonces
from mandaatbewijs.verifier.vertrouwenslijst import Uitgever, Vertrouwenslijst


class Weigering(Exception):
    """Een presentatie is geweigerd.

    Attributes:
        reden: Korte code voor audit en `WWW-Authenticate`.
        status: HTTP-status (401 voor de presentatie zelf, 403 voor het bereik).
        bevestigd: Gegevens uit de geverifieerde credential (na de handtekening van de
            uitgever), voor het auditrecord; bij een weigering ná stap 5 minstens `iss` en `jti`.
        onbevestigd: Gegevens uit nog niet gevalideerde delen, voor het auditrecord.
    """

    def __init__(
        self,
        reden: str,
        status: int = 401,
        detail: str = "",
        bevestigd: dict[str, Any] | None = None,
        **onbevestigd: Any,
    ) -> None:
        super().__init__(f"{reden}: {detail}" if detail else reden)
        self.reden = reden
        self.status = status
        self.detail = detail
        self.bevestigd = bevestigd or {}
        self.onbevestigd = onbevestigd


@dataclass(frozen=True)
class Toelating:
    """Uitkomst van een geslaagde verificatie, voor het auditrecord en de tool."""

    iss: str
    uitgever: str
    jti: str
    jkt: str
    doel: str
    actie: str
    dossier: str
    bekendgemaakt: list[str]
    status_bron: str
    nonce: str


@dataclass
class Verificatie:
    """Verifieert presentaties voor één verifier-identifier (`aud`)."""

    aud: str
    vertrouwenslijst: Vertrouwenslijst
    sleutelbron: Sleutelbron
    statusbron: Statusbron
    nonces: Nonces
    toolbeleid: dict[str, Toolbeleid] = field(default_factory=lambda: dict(TOOLBELEID))

    async def verifieer(self, presentatie: str, tool: str, dossier: str | None) -> Toelating:
        """Doorloop stap 1 tot en met 7; stap 8 (audit) doet de aanroeper.

        Raises:
            Weigering: Bij de eerste afwijking.
        """
        beleid = self.toolbeleid.get(tool)
        if beleid is None:
            raise Weigering("tool_onbekend", 403, tool)
        if not dossier:
            raise Weigering("dossier_ontbreekt", 403, "tools/call zonder dossier")
        # Stap 1 en 2: syntax, uitgever op de vertrouwenslijst, vct toegestaan.
        o, uitgever = self._ontleed(presentatie)
        # Stap 3, 4 en 5: handtekening, disclosures, tijdvenster, key binding, nonce.
        g = await self._verifieer_handtekeningen(o, uitgever)
        # Stap 6: statuslijst.
        status_bron = await self._status(g, uitgever)
        # Stap 7: bereik.
        return _toelating(g, uitgever.naam, beleid, dossier, status_bron)

    def _ontleed(self, presentatie: str) -> tuple[Ontleed, Uitgever]:
        try:
            o = ontleed(presentatie)
        except SdJwtFout as fout:
            raise Weigering(fout.reden, 401, fout.detail) from fout
        uitgever = self.vertrouwenslijst.uitgever(o.iss)
        if uitgever is None:
            raise Weigering("uitgever_niet_vertrouwd", 401, o.iss, iss=o.iss)
        if o.vct not in uitgever.vct:
            raise Weigering("vct_niet_toegestaan", 401, o.vct, iss=o.iss)
        return o, uitgever

    async def _verifieer_handtekeningen(self, o: Ontleed, uitgever: Uitgever) -> Geverifieerd:
        kid = o.kop.get("kid")
        if not isinstance(kid, str):
            raise Weigering("kid_ontbreekt", 401, iss=o.iss)
        try:
            sleutel = await self.sleutelbron.sleutel(uitgever, kid)
        except BronFout as fout:
            raise Weigering(fout.reden, 401, str(fout), iss=o.iss) from fout
        try:
            g = verifieer(o, sleutel, self.aud)
        except SdJwtFout as fout:
            raise Weigering(fout.reden, 401, fout.detail, iss=o.iss) from fout
        if not self.nonces.verbruik(g.nonce):
            raise Weigering("nonce_onbekend_of_gebruikt", 401, bevestigd=_bevestigd(g))
        return g

    async def _status(self, g: Geverifieerd, uitgever: Uitgever) -> str:
        bevestigd = _bevestigd(g)
        status = g.claims.get("status")
        if status is None:
            raise Weigering("status_ontbreekt", 401, bevestigd=bevestigd)
        sl = status["status_list"]
        try:
            uitkomst = await self.statusbron.status(str(sl["uri"]), int(sl["idx"]), uitgever)
        except BronFout as fout:
            raise Weigering(fout.reden, 401, str(fout), bevestigd=bevestigd) from fout
        if uitkomst.waarde != GELDIG:
            raise Weigering(
                "mandaat_ingetrokken", 403, f"status {uitkomst.waarde}", bevestigd=bevestigd
            )
        return uitkomst.bron


def _bevestigd(g: Geverifieerd) -> dict[str, Any]:
    """`iss`, `jti` en sleutel-thumbprint uit een credential waarvan de handtekening klopt."""
    return {"iss": g.claims.get("iss"), "jti": g.claims.get("jti"), "jkt": g.jkt}


def _toelating(
    g: Geverifieerd, naam: str, beleid: Toolbeleid, dossier: str, status_bron: str
) -> Toelating:
    claims = g.claims
    jti = str(claims.get("jti", ""))
    actie = beleid.actie
    bevestigd = _bevestigd(g)
    if actie not in _lijst(claims.get("acties")):
        raise Weigering("actie_buiten_mandaat", 403, actie, bevestigd=bevestigd)
    if dossier not in _lijst(claims.get("dossiers")):
        raise Weigering("dossier_buiten_mandaat", 403, dossier, bevestigd=bevestigd)
    doel = claims.get("doel")
    if not isinstance(doel, str) or doel not in beleid.doelen:
        raise Weigering("doel_niet_geaccepteerd", 403, str(doel), bevestigd=bevestigd)
    return Toelating(
        iss=str(claims["iss"]),
        uitgever=naam,
        jti=jti,
        jkt=g.jkt,
        doel=doel,
        actie=actie,
        dossier=dossier,
        bekendgemaakt=g.bekendgemaakt,
        status_bron=status_bron,
        nonce=g.nonce,
    )


def _lijst(waarde: Any) -> list[str]:
    return [str(x) for x in waarde] if isinstance(waarde, list) else []
