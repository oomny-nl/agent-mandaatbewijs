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
import time
from dataclasses import dataclass
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
from mandaatbewijs.sleutels import ALG, publieke_sleutel, thumbprint
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
    """Gedeelde onderdelen (lui opgebouwd)."""

    inst: Instellingen

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
    """Bouw de FastAPI-app; maakt sleutel en wachtwoorden meteen aan (de demo leest ze)."""
    dienst.uitgifte, dienst.wachtwoorden  # noqa: B018 - lui opgebouwd, hier bewust geraakt.
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
        token = dienst.register.statustoken(dienst.uitgifte.statustoken, dienst.inst.beleid.ttl_s)
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
        dienst.audit.schrijf(
            gebeurtenis="verzoek_geweigerd", medewerker=body.medewerker, jkt=jkt, reden=fout.reden
        )
        raise _fout(fout) from fout
    dienst.audit.schrijf(gebeurtenis="verzoek", verzoek=v.id, medewerker=v.medewerker, jkt=jkt)
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
        dienst.audit.schrijf(gebeurtenis="ophalen_geweigerd", verzoek=v.id, reden=fout.reden)
        if fout.reden == "sleutel_geblokkeerd" and v.mandaat_id:
            _trek_in_na_blokkade(dienst, v.mandaat_id)
        raise _fout(fout) from fout
    dienst.audit.schrijf(gebeurtenis="opgehaald", verzoek=v.id, mandaat=v.mandaat_id, jkt=v.jkt)
    return {"credential": credential}


def _trek_in_na_blokkade(dienst: Dienst, mandaat_id: str) -> None:
    try:
        dienst.register.trek_in(mandaat_id, None)
    except RegisterFout:
        return


def _verzoek(dienst: Dienst, verzoek_id: str) -> Verzoek:
    try:
        return dienst.register.verzoek(verzoek_id)
    except RegisterFout as fout:
        raise _fout(fout) from fout


def _controleer_proof(proof: str, v: Verzoek, iss: str) -> str | None:
    """Reden van weigering van het bewijs van sleutelbezit, of None als het klopt."""
    try:
        kop = jws.extract_compact(proof.encode()).protected
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
            dienst.audit.schrijf(
                gebeurtenis="intrekking_geweigerd",
                mandaat=mandaat_id,
                medewerker=naam,
                reden=fout.reden,
            )
            raise _fout(fout) from fout
        dienst.audit.schrijf(
            gebeurtenis="ingetrokken", mandaat=mandaat_id, medewerker=naam, idx=m["idx"]
        )
        return m


def _beslis(dienst: Dienst, verzoek_id: str, body: Toestemming, naam: str) -> dict[str, Any]:
    v = _verzoek(dienst, verzoek_id)
    if body.besluit == "nee":
        try:
            v = dienst.register.weiger(verzoek_id, naam)
        except RegisterFout as fout:
            raise _fout(fout) from fout
        dienst.audit.schrijf(gebeurtenis="toestemming_geweigerd", verzoek=v.id, medewerker=naam)
        return v.openbaar()
    reden = (
        mag_verlenen(MEDEWERKERS[naam], v.doel, v.acties, v.dossiers)
        if v.medewerker == naam
        else None
    )
    if reden is not None:
        dienst.register.weiger(verzoek_id, naam)
        dienst.audit.schrijf(
            gebeurtenis="toestemming_onmogelijk", verzoek=v.id, medewerker=naam, reden=reden
        )
        raise HTTPException(403, {"error": "bevoegdheid_ontbreekt", "reden": reden})

    def maak(verzoek: Verzoek, mandaat_id: str, idx: int) -> tuple[str, int, int]:
        return dienst.uitgifte.credential(verzoek, mandaat_id, idx, body.geldigheid_s)

    try:
        v = dienst.register.keur_goed(verzoek_id, naam, maak)
    except RegisterFout as fout:
        dienst.audit.schrijf(
            gebeurtenis="toestemming_geweigerd",
            verzoek=verzoek_id,
            medewerker=naam,
            reden=fout.reden,
        )
        raise _fout(fout) from fout
    dienst.audit.schrijf(
        gebeurtenis="uitgegeven",
        verzoek=v.id,
        mandaat=v.mandaat_id,
        medewerker=naam,
        jkt=v.jkt,
        doel=v.doel,
        acties=v.acties,
        dossiers=v.dossiers,
        geldigheid_s=body.geldigheid_s,
    )
    return v.openbaar()


def _beheerroutes(app: FastAPI, dienst: Dienst) -> None:
    @app.post("/noodstop")
    def noodstop(body: Noodstop, naam: Beheerder) -> dict[str, Any]:
        ingetrokken = dienst.register.noodstop(body.jkt)
        dienst.audit.schrijf(
            gebeurtenis="noodstop", beheerder=naam, jkt=body.jkt, mandaten=ingetrokken
        )
        return {"jkt": body.jkt, "ingetrokken": ingetrokken}

    @app.get("/audit")
    def audit(_: Beheerder) -> list[dict[str, Any]]:
        return lees(dienst.audit.pad)

    @app.get("/mandaten/alle")
    def alle(_: Beheerder) -> list[dict[str, Any]]:
        return dienst.register.mandaten()


def main() -> None:
    """Start de uitgever (in de container op poort 8000)."""
    logging.basicConfig(level=logging.INFO)
    dienst = Dienst(Instellingen.uit_omgeving())
    dienst.wachtwoorden  # noqa: B018  # geheimen aanmaken vóór de eerste aanvraag
    uvicorn.run(maak_app(dienst), host="0.0.0.0", port=8000, log_level="info")  # noqa: S104


__all__ = ["Dienst", "Instellingen", "Request", "maak_app", "main"]
