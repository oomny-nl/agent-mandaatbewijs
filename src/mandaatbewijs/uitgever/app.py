"""Uitgever van gemeente Lindevoort als FastAPI-dienst.

Publiek: uitgeversmetadata, JWKS en de statuslijst. Agent: mandaatverzoek indienen en de credential
ophalen met bewijs van sleutelbezit. Medewerker (HTTP Basic): toestemmingsscherm, ja/nee, eigen
mandaten, intrekken. Beheerder: noodstop en auditlog.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Annotated, Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from joserfc import jws
from joserfc.errors import JoseError
from pydantic import BaseModel, Field

from mandaatbewijs.audit import Auditlog, lees
from mandaatbewijs.sleutels import ALG, jose_kop, publieke_sleutel, thumbprint
from mandaatbewijs.statuslijst import MEDIATYPE, Tokenbeleid
from mandaatbewijs.uitgever.gegevens import (
    BEHEERDERS,
    MAX_GELDIGHEID_S,
    MEDEWERKERS,
    ORGANISATIE,
    mag_verlenen,
)
from mandaatbewijs.uitgever.geheimen import uitgeverssleutel, wachtwoorden
from mandaatbewijs.uitgever.register import Register, RegisterFout, Verzoek
from mandaatbewijs.uitgever.uitgifte import Uitgifte

log = logging.getLogger("uitgever")
TYP_PROOF = "mandaatbewijs-proof+jwt"
PROOF_GELDIG_S = 60
basic = HTTPBasic(realm="uitgever-lindevoort")


@dataclass(frozen=True)
class Instellingen:
    """Instellingen uit de omgeving."""

    iss: str
    datamap: Path
    beleid: Tokenbeleid

    @classmethod
    def uit_omgeving(cls) -> Instellingen:
        """Lees `UITGEVER_ISS`, `UITGEVER_DATA`, `STATUSLIJST_TTL` en `STATUSLIJST_GELDIG`."""
        return cls(
            os.environ.get("UITGEVER_ISS", "http://uitgever:8000").rstrip("/"),
            Path(os.environ.get("UITGEVER_DATA", "/data")),
            Tokenbeleid(
                int(os.environ.get("STATUSLIJST_TTL", "5")),
                int(os.environ.get("STATUSLIJST_GELDIG", "60")),
            ),
        )


@dataclass
class Dienst:
    """Gedeelde onderdelen; `maak_app` bouwt ze allemaal bij de start, vóór het eerste verzoek.

    `functools.cached_property` beschermt een eerste gelijktijdige toegang niet (Python 3.12+):
    twee threads zouden twee `Auditlog`-objecten op hetzelfde bestand kunnen maken.
    """

    inst: Instellingen
    _uitgaand_slot: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

    @cached_property
    def register(self) -> Register:
        """Het mandaatregister."""
        return Register(self.inst.datamap / "register.db")

    @cached_property
    def uitgifte(self) -> Uitgifte:
        """Tekenaar."""
        return Uitgifte(uitgeverssleutel(self.inst.datamap), self.inst.iss, self.inst.beleid)

    @cached_property
    def wachtwoorden(self) -> dict[str, str]:
        """Wachtwoorden van de medewerkers."""
        return wachtwoorden(self.inst.datamap)

    @cached_property
    def audit(self) -> Auditlog:
        """Auditlog van de uitgever."""
        return Auditlog(self.inst.datamap / "audit.jsonl", "lindevoort")

    def verwerk_uitgaand(self, *, strikt: bool = False) -> None:
        """Schrijf de vastgelegde auditevents in volgorde naar het log en ruim de outbox op.

        Het event staat al in dezelfde transactie als de mutatie vast; mislukt het wegschrijven
        (vol volume), dan blijft het in de outbox en schrijft de volgende mutatie of de volgende
        start het alsnog, zonder dubbel record. Een verzoek waarvan de mutatie is gecommit,
        slaagt dus ook dan; de fout gaat naar het proceslog.

        Args:
            strikt: Laat een fout door in plaats van te loggen (bij de start).
        """
        with self._uitgaand_slot:
            try:
                for nr, velden in self.register.uitgaand():
                    self.audit.schrijf_uitgaand(nr, velden)
                    self.register.verwijder_uitgaand(nr)
            except Exception:
                if strikt:
                    raise
                log.exception(
                    "auditoutbox niet weggeschreven; volgende poging bij de volgende mutatie"
                )


class Mandaatverzoek(BaseModel):
    """Body van `POST /mandaatverzoeken`."""

    agent_jwk: dict[str, Any]
    medewerker: str = Field(min_length=1, max_length=64)
    doel: str = Field(min_length=1, max_length=64)
    acties: list[str] = Field(max_length=10)
    dossiers: list[str] = Field(max_length=20)


class Toestemming(BaseModel):
    """Body van `POST /mandaatverzoeken/{id}/toestemming`."""

    besluit: str = Field(pattern="^(ja|nee)$")
    geldigheid_s: int = Field(default=MAX_GELDIGHEID_S, ge=60, le=MAX_GELDIGHEID_S)


class Bewijs(BaseModel):
    """Body van `POST /mandaatverzoeken/{id}/credential`."""

    proof: str = Field(max_length=4096)


class Noodstop(BaseModel):
    """Body van `POST /noodstop`."""

    jkt: str = Field(min_length=20, max_length=64)


def _fout(fout: RegisterFout) -> HTTPException:
    return HTTPException(fout.status, {"error": fout.reden})


def _geweigerd(
    dienst: Dienst, fout: RegisterFout, gebeurtenis: str, **velden: Any
) -> HTTPException:
    """Audit een registerweigering en geef de HTTP-fout.

    Was de weigering zelf een overgang (`vastleggen`), dan staat haar event al in de outbox en
    wordt dat weggeschreven; anders schrijft deze functie het event direct.
    """
    if fout.vastleggen:
        dienst.verwerk_uitgaand()
    else:
        dienst.audit.schrijf(gebeurtenis=gebeurtenis, reden=fout.reden, **velden)
    return _fout(fout)


def _dienst(request: Request) -> Dienst:
    return request.app.state.dienst


def medewerker(request: Request, cred: Annotated[HTTPBasicCredentials, Depends(basic)]) -> str:
    """HTTP Basic-login van een medewerker; geeft de gebruikersnaam."""
    dienst = _dienst(request)
    verwacht = dienst.wachtwoorden.get(cred.username, "")
    if not verwacht or not secrets.compare_digest(cred.password, verwacht):
        dienst.audit.schrijf(gebeurtenis="login_geweigerd", medewerker=cred.username)
        raise HTTPException(401, {"error": "login_onjuist"}, {"WWW-Authenticate": "Basic"})
    return cred.username


def beheerder(request: Request, naam: Medewerker) -> str:
    """Alleen functioneel beheerders."""
    if naam not in BEHEERDERS:
        _dienst(request).audit.schrijf(gebeurtenis="beheer_geweigerd", medewerker=naam)
        raise HTTPException(403, {"error": "geen_beheerder"})
    return naam


Medewerker = Annotated[str, Depends(medewerker)]
Beheerder = Annotated[str, Depends(beheerder)]


def maak_app(dienst: Dienst) -> FastAPI:
    """Bouw de FastAPI-app: alle onderdelen, sleutel en wachtwoorden (de demo leest ze) meteen.

    Daarna schrijft de outbox events weg die bij een eerdere run niet in het log kwamen.
    """
    dienst.uitgifte, dienst.wachtwoorden, dienst.register, dienst.audit  # noqa: B018
    dienst.verwerk_uitgaand(strikt=True)
    app = FastAPI(title="Uitgever gemeente Lindevoort (fictief)", docs_url=None, redoc_url=None)
    app.state.dienst = dienst
    _publieke_routes(app, dienst)
    _agentroutes(app, dienst)
    _medewerkerroutes(app, dienst)
    _beheerroutes(app, dienst)
    return app


def _publieke_routes(app: FastAPI, dienst: Dienst) -> None:
    @app.get("/.well-known/jwt-vc-issuer")
    def metadata() -> dict[str, Any]:
        return {"issuer": dienst.inst.iss, "jwks_uri": f"{dienst.inst.iss}/jwks.json"}

    @app.get("/jwks.json")
    def jwks() -> dict[str, Any]:
        return {"keys": [dienst.uitgifte.sleutel.jwks_lid]}

    @app.get("/statuslijsten/1")
    def statuslijst() -> Response:
        # Synchrone route, dus in de threadpool: `statustoken` mag hier tot een seconde wachten.
        try:
            token = dienst.register.statustoken(
                dienst.uitgifte.statustoken, dienst.inst.beleid.ttl_s
            )
        except RegisterFout as fout:
            raise _fout(fout) from fout
        return Response(
            token,
            media_type=MEDIATYPE,
            headers={"Cache-Control": f"max-age={dienst.inst.beleid.ttl_s}"},
        )

    @app.get("/gezond")
    def gezond() -> dict[str, str]:
        return {"status": "ok", "organisatie": ORGANISATIE}


def _agentroutes(app: FastAPI, dienst: Dienst) -> None:
    @app.post("/mandaatverzoeken", status_code=201)
    def dien_in(body: Mandaatverzoek) -> dict[str, Any]:
        return _dien_in(dienst, body)

    @app.post("/mandaatverzoeken/{verzoek_id}/credential")
    def haal_op(verzoek_id: str, body: Bewijs) -> dict[str, str]:
        return _haal_op(dienst, verzoek_id, body)


def _dien_in(dienst: Dienst, body: Mandaatverzoek) -> dict[str, Any]:
    try:
        jkt = thumbprint(publieke_sleutel(body.agent_jwk).as_dict(private=False))
    except (ValueError, JoseError, TypeError, KeyError) as fout:
        raise HTTPException(400, {"error": "agent_jwk_ongeldig"}) from fout
    if body.medewerker not in MEDEWERKERS:
        raise HTTPException(404, {"error": "medewerker_onbekend"})
    try:
        v = dienst.register.nieuw_verzoek(body.model_dump(), jkt)
    except RegisterFout as fout:
        raise _geweigerd(
            dienst, fout, "verzoek_geweigerd", medewerker=body.medewerker, jkt=jkt
        ) from fout
    dienst.verwerk_uitgaand()
    return v.openbaar()


def _haal_op(dienst: Dienst, verzoek_id: str, body: Bewijs) -> dict[str, str]:
    v = _verzoek(dienst, verzoek_id)
    reden = _controleer_proof(body.proof, v, dienst.inst.iss)
    if reden is not None:
        dienst.audit.schrijf(gebeurtenis="ophalen_geweigerd", verzoek=v.id, reden=reden)
        raise HTTPException(401, {"error": reden})
    try:
        credential = dienst.register.haal_op(verzoek_id, v.jkt)
    except RegisterFout as fout:
        http = _geweigerd(dienst, fout, "ophalen_geweigerd", verzoek=v.id)
        if fout.reden == "sleutel_geblokkeerd" and v.mandaat_id:
            _trek_in_na_blokkade(dienst, v.mandaat_id)
        raise http from fout
    dienst.verwerk_uitgaand()
    return {"credential": credential}


def _trek_in_na_blokkade(dienst: Dienst, mandaat_id: str) -> None:
    """Trek het mandaat van een geblokkeerde sleutel in; een al ingetrokken mandaat is goed zo."""
    try:
        dienst.register.trek_in(mandaat_id, None, reden="sleutel_geblokkeerd")
    except RegisterFout as fout:
        if fout.reden != "mandaat_al_ingetrokken":
            log.error("intrekking van %s na blokkade mislukt: %s", mandaat_id, fout.reden)
        return
    dienst.verwerk_uitgaand()


def _verzoek(dienst: Dienst, verzoek_id: str) -> Verzoek:
    try:
        return dienst.register.verzoek(verzoek_id)
    except RegisterFout as fout:
        raise _fout(fout) from fout


def _controleer_proof(proof: str, v: Verzoek, iss: str) -> str | None:
    """Reden van weigering van het bewijs van sleutelbezit, of None als het klopt."""
    try:
        kop = jose_kop(proof)
        if kop.get("typ") != TYP_PROOF or kop.get("alg") != ALG:
            return "proof_typ_of_alg_onjuist"
        claims = json.loads(
            jws.deserialize_compact(proof, publieke_sleutel(v.agent_jwk), algorithms=[ALG]).payload
        )
    except (JoseError, ValueError, TypeError):
        return "proof_handtekening_ongeldig"
    if not isinstance(claims, dict) or claims.get("aud") != iss or claims.get("nonce") != v.id:
        return "proof_aud_of_nonce_onjuist"
    iat = claims.get("iat")
    if not isinstance(iat, int) or abs(int(time.time()) - iat) > PROOF_GELDIG_S:
        return "proof_verlopen"
    return None


def _medewerkerroutes(app: FastAPI, dienst: Dienst) -> None:
    @app.get("/mandaatverzoeken/{verzoek_id}")
    def toestemmingsscherm(verzoek_id: str, naam: Medewerker) -> dict[str, Any]:
        v = _verzoek(dienst, verzoek_id)
        if v.medewerker != naam:
            raise HTTPException(403, {"error": "verzoek_hoort_bij_andere_medewerker"})
        m = MEDEWERKERS[naam]
        return {**v.openbaar(), "medewerker_naam": m.naam, "organisatie": ORGANISATIE}

    @app.post("/mandaatverzoeken/{verzoek_id}/toestemming")
    def toestemming(verzoek_id: str, body: Toestemming, naam: Medewerker) -> dict[str, Any]:
        return _beslis(dienst, verzoek_id, body, naam)

    @app.get("/mandaten")
    def mandaten(naam: Medewerker) -> list[dict[str, Any]]:
        return dienst.register.mandaten(naam)

    @app.delete("/mandaten/{mandaat_id}")
    def trek_in(mandaat_id: str, naam: Medewerker) -> dict[str, Any]:
        try:
            m = dienst.register.trek_in(mandaat_id, naam)
        except RegisterFout as fout:
            raise _geweigerd(
                dienst, fout, "intrekking_geweigerd", mandaat=mandaat_id, medewerker=naam
            ) from fout
        dienst.verwerk_uitgaand()
        return m


def _beslis(dienst: Dienst, verzoek_id: str, body: Toestemming, naam: str) -> dict[str, Any]:
    v = _verzoek(dienst, verzoek_id)
    reden = (
        mag_verlenen(MEDEWERKERS[naam], v.doel, v.acties, v.dossiers)
        if body.besluit == "ja" and v.medewerker == naam
        else None
    )
    if body.besluit == "nee" or reden is not None:
        try:
            v = dienst.register.weiger(verzoek_id, naam, reden)
        except RegisterFout as fout:
            raise _geweigerd(
                dienst, fout, "toestemming_geweigerd", verzoek=verzoek_id, medewerker=naam
            ) from fout
        dienst.verwerk_uitgaand()
        if reden is not None:
            raise HTTPException(403, {"error": "bevoegdheid_ontbreekt", "reden": reden})
        return v.openbaar()

    def maak(verzoek: Verzoek, mandaat_id: str, idx: int) -> tuple[str, int, int]:
        return dienst.uitgifte.credential(verzoek, mandaat_id, idx, body.geldigheid_s)

    try:
        v = dienst.register.keur_goed(verzoek_id, naam, maak)
    except RegisterFout as fout:
        raise _geweigerd(
            dienst, fout, "toestemming_geweigerd", verzoek=verzoek_id, medewerker=naam
        ) from fout
    dienst.verwerk_uitgaand()
    return v.openbaar()


def _beheerroutes(app: FastAPI, dienst: Dienst) -> None:
    @app.post("/noodstop")
    def noodstop(body: Noodstop, naam: Beheerder) -> dict[str, Any]:
        ingetrokken = dienst.register.noodstop(body.jkt, naam)
        dienst.verwerk_uitgaand()
        return {"jkt": body.jkt, "ingetrokken": ingetrokken}

    @app.get("/audit")
    def audit(_: Beheerder) -> list[dict[str, Any]]:
        dienst.verwerk_uitgaand()
        return lees(dienst.audit.pad)

    @app.get("/mandaten/alle")
    def alle(_: Beheerder) -> list[dict[str, Any]]:
        return dienst.register.mandaten()


def main() -> None:
    """Start de uitgever (in de container op poort 8000)."""
    logging.basicConfig(level=logging.INFO)
    dienst = Dienst(Instellingen.uit_omgeving())
    uvicorn.run(maak_app(dienst), host="0.0.0.0", port=8000, log_level="info")  # noqa: S104


__all__ = ["Dienst", "Instellingen", "Request", "maak_app", "main"]
