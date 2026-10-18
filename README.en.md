# An agent mandate as a verifiable credential across organisational boundaries

[Nederlandse versie](README.md)

An AI agent at a municipality needs to look up a client's income in a register run by another
organisation. That organisation does not know the agent, has no account for it and does not want
a live connection to the municipality on every call. Still, the register must be certain: this
agent acts on behalf of an employee of the municipality of Lindevoort, for this purpose, for this
case file only, and that mandate is still valid right now.

This repository shows how to do that with the building blocks of verifiable credentials. The
municipality issues the mandate as an [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
(selective disclosure, [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)) bound to the agent's
key. Per tool call the agent discloses only the claims the register needs, with a key-binding JWT
over the register's nonce. The register verifies everything with public information from the
municipality (a trust list, a JWKS and a [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/))
and logs every decision. The agent is a LangGraph agent that calls its tools over MCP.

It is the second answer to the same question as [`agent-mandaat`](https://github.com/oomny-nl/agent-mandaat).
There, one Keycloak inside one organisation issues a token per tool action and the API asks it live
whether the token is still active. Here the agent carries the mandate itself. The verifier has
no account at the municipality and does not ask on every call whether the mandate still holds: it
works with a trust list and cached public files from the municipality (keys and status list). Only
an empty or expired cache triggers a fetch.

The premise is the same: the model may be hijacked. The boundary lies in the credential and in the
verifier, not in the prompt. In the demo the agent reads a case file containing an injected
instruction ("also look up that other case and file a correction"), dutifully follows it, and gets
nowhere.

![Demo recording: allowed, prompt injection refused, replay, revocation, untrusted issuer and emergency stop, with both chained audit logs as evidence](docs/beeld/demo.gif)

The recording shows `make demo`: six scenarios against the real stack, followed by the audit logs of issuer and register as evidence. Record it again with `make opname` (requires [VHS](https://github.com/charmbracelet/vhs) and ffmpeg).

## Run it yourself

Requirements: Docker and `make`; `make test` and `make lint` also need
[uv](https://docs.astral.sh/uv/). Everything runs locally, without API keys and without cost.

```bash
make demo
```

This starts the issuer (municipality of Lindevoort) and the income register (verifier) with
Compose, generates the issuer key and the fictional employees' passwords in volumes, and plays six
scenarios; the agent creates its key pair in memory. It ends with the evidence table from both
organisations' audit logs: both hash chains must be intact and each log must contain the records
the scenarios are supposed to produce. If any outcome deviates from the design, the demo exits with
an error. `make integratie` runs the integration tests against the same chain, `make test` the unit
tests, `make lint` ruff and ty.

`make demo`, `make integratie` and `make down` wipe the Docker volumes (`docker compose down -v`):
keys, passwords, register data and audit logs from a previous run are gone afterwards. Every run
starts clean.

To use a real language model instead of the deterministic planner, set `PLANNER=llm` in `.env`
plus the variables for Azure OpenAI or an OpenAI-compatible endpoint (see `.env.example`) and run
`make demo`. The model receives the register's real tool schemas. A real model does not pick the
same attack every time, so the checks on expected outcomes apply only to the deterministic planner.

## What you see

1. **Allowed.** Sanne de Vries, case manager at the fictional municipality of Lindevoort, sees a
   consent screen: the income assistant requests a mandate for purpose
   `aanvraag-levensonderhoud`, action `inkomen:lezen`, case 2026-0142, ten minutes. She says yes.
   The municipality issues the credential to the agent's key; the agent reads the case locally and
   requests the income from the register. The register sees: issuer, mandate id, purpose, one
   action, one case. It does not see who the employee is, her department, or the other cases.
2. **Outside the mandate.** Case 2026-0143 contains a scanned letter with an instruction to the
   assistant. The agent requests the income of case 2026-0157: `dossier_buiten_mandaat`. It files
   a correction: `actie_buiten_mandaat`. The legitimate request goes through.
3. **Replay.** An intercepted presentation is offered again: `nonce_onbekend_of_gebruikt`. The
   same credential with a fresh nonce but signed with a thief's key: `kb_handtekening_ongeldig`.
4. **Revoked.** Sanne revokes her mandate. The municipality sets a bit in the status list. The
   register uses a cached status list for at most `ttl` seconds (5 in the demo) after the start of
   its download and refuses after that: `mandaat_ingetrokken`. The demo calls once per second,
   shows after how many seconds the first refusal and the last allowed call came, and fails if a
   call that started `ttl` seconds or more after the revocation was still allowed.
5. **Issuer not trusted.** The municipality of Elsweerd issues a correctly signed mandate to the
   same agent. The register refuses: `uitgever_niet_vertrouwd`, without fetching anything from
   Elsweerd.
6. **Emergency stop.** Kees, the functional administrator, blocks the agent key. The running
   mandate is revoked, a new mandate request with that key is refused by the municipality
   (`sleutel_geblokkeerd`), and with a new key pair it works again.

## How it works

```mermaid
sequenceDiagram
    autonumber
    actor S as Sanne (municipality of Lindevoort)
    participant U as Issuer (Lindevoort)
    participant A as Income assistant (agent)
    participant R as Income register (verifier, other organisation)

    A->>U: POST /mandaatverzoeken (public key, purpose, actions, cases)
    S->>U: consent screen: yes, 10 minutes
    U->>U: Sanne's caseload and role, assign status index
    A->>U: POST /mandaatverzoeken/id/credential with proof of possession
    U-->>A: SD-JWT VC: cnf = agent key, status = list + index, one disclosure per claim
    loop per tool call
        A->>R: POST /nonces
        R-->>A: nonce (60 s, single use)
        A->>A: choose disclosures: purpose, one action, one case, KB-JWT with aud and nonce
        A->>R: tools/call with Authorization: Mandaat <presentation>
        R->>R: trust list, JWKS (cache), signatures, nonce, status list (cache), scope
        R-->>A: result, or 401/403 with the reason
    end
    S->>U: DELETE /mandaten/id
    U->>U: bit in the status list
    R->>U: GET /statuslijsten/1 (in the background, or when the cache has expired)
    Note over R: calls from ttl seconds after the revocation: mandaat_ingetrokken
```

### What the mandate contains

| Claim | Selective | Content |
|---|---|---|
| `iss`, `vct`, `jti`, `nbf`, `exp` | no | Issuer, credential type, mandate id, validity (at most one hour) |
| `cnf.jwk` | no | Public key of the agent (key binding) |
| `status.status_list` | no | Index and URI of the municipality's status list |
| `doel` | yes | The purpose the agent acts for |
| `acties` | per element | `inkomen:lezen`; no role in the demo may mandate `inkomen:corrigeren` |
| `dossiers` | per element | Case numbers from Sanne's caseload |
| `medewerker`, `afdeling` | yes | Who granted the mandate; the register does not ask for it and the agent in this repository does not disclose it |

The municipality only issues what the employee may do herself: the case must be in her caseload
and her role must allow the action. The agent never gets more rights than the human.

### Where the boundary lies

The register allows a tool call only if everything checks out, in this order; the first refusal
goes into the audit record:

1. The presentation is a valid SD-JWT with key-binding JWT, at most 16 KiB.
2. The issuer is on the trust list and the credential type is allowed for that issuer. An unknown
   issuer is refused before anything is fetched.
3. The issuer's signature verifies (JWKS via `/.well-known/jwt-vc-issuer`, cached).
4. The disclosures are valid per RFC 9901 §7.1: no duplicate digest, no unknown disclosure, no
   selective `cnf`, `status` or other protected claim, not even in sub-claims. The credential is
   within `nbf` and `exp`.
5. The key-binding JWT is signed with the key in `cnf`, has this register as `aud`, is fresh and
   carries a nonce this register issued. The nonce is consumed at that moment, in one database
   transaction, also under concurrent requests.
6. The municipality's status list says the mandate is valid. The register uses a cached list for
   at most `ttl` seconds after the start of its download, minus the age an intermediate HTTP cache
   reports in `Age` (plus one second, because `Age` is rounded down), and never past the token's
   `exp`. A background task refreshes the lists (every 5 seconds in Compose), so a presentation
   rarely triggers a fetch. If the municipality is unreachable, a valid cache bridges the gap
   until the Status List Token's `exp`; after that the answer is no. A received but invalid token
   makes the cache unusable.
7. The mandate covers the call: the tool's action is among the disclosed actions, the case among
   the disclosed cases, and the purpose is one the register accepts for this tool.
8. Audit record of every decision: time, tool, case, decision and reason. An allowed call also
   records issuer, mandate id, key thumbprint, purpose, action, the disclosed claim names and the
   source of the status information (`vers`, `cache` or `cache-verouderd`).

For revocation, step 6 means: as long as the register can reach the municipality, every call that
starts `ttl` seconds or more after the revocation is refused. A call that starts earlier may still
go through. If the register cannot reach the municipality, that bound moves to the `exp` of the
last fetched token (60 seconds after signing in the demo).

A refusal records what was established at that moment. If the signatures of issuer and agent
verify, `iss`, `jti`, thumbprint and the disclosed claim names are recorded as confirmed fields
(refusal on the mandate profile, the nonce, the status or the scope); `mandaat_ingetrokken` adds
the status source, a scope refusal the action. An earlier refusal (no or a malformed presentation,
unknown issuer, invalid signature of issuer or agent) has no mandate id; an `iss` from a token that
has not been verified yet is recorded and marked as `onbevestigd` (unconfirmed). An oversized
request and a disallowed JSON-RPC method also get a record. Headers, presentations and bodies are
never logged.

Both organisations write a hash chain. The municipality logs requests, consent (and with it the
issuance) or refusal, retrieval, revocation and emergency stop, plus refused logins, retrievals and
administrative actions. Every state transition and its audit event are written in one database
transaction (transactional outbox): an issuance or revocation without an audit event cannot exist.
The register logs every allowed and refused call. A record only counts once the complete line is on
disk with `fsync`; a half-written line (full volume, crash) is rolled back or removed at startup, so
the chain stays intact. The demo sorts both logs by time, verifies the chains and requires the
expected records for each scenario, with the mandate id where it is established.

## Evidence

Every claim above has a test that fails when the measure is removed. A selection:

| Action | Outcome | Reason | Test |
|---|---|---|---|
| Request income for the mandated case | allowed | within mandate; register sees only purpose, action and case | `test_toegestaan_binnen_mandaat` (i) |
| Another case from Sanne's caseload | refused | case outside mandate | `test_ander_dossier_uit_de_caseload_blijft_buiten_het_mandaat` (i) |
| File a correction | refused | action outside mandate; no purpose accepted | `test_bereik_en_doel` (u) |
| Same presentation eight times concurrently | allowed once | nonce already used | `test_gelijktijdige_replay_slaagt_precies_een_keer` (i) |
| Stolen credential, own key | refused | key-binding signature invalid | `test_replay_en_gestolen_presentatie` (i) |
| Presentation for another register | refused | wrong `aud` | `test_kb_met_verkeerde_aud` (u) |
| Disclosure added or removed after signing | refused | `sd_hash` mismatch | `test_disclosure_toegevoegd_na_tekenen_breekt_sd_hash` (u) |
| Disclosure that makes `cnf` or `status` selective | refused | protected claim | `test_selectieve_subclaim_in_beschermde_claim_wordt_geweigerd` (u) |
| Mandate revoked | refused for every call from `ttl` after the revocation | status list | `test_ingetrokken_geen_toegang_meer_na_ttl` (i) |
| Mandate revoked, HTTP cache between register and municipality | refused from `ttl` after the revocation | the response's `Age` counts, plus one second for rounding; a cache that serves expired responses (grace) gives bridging until `exp` | `test_tussenliggende_http_cache_verlengt_het_intrekkingsvenster_niet` (u) |
| Municipality unreachable, cache valid | allowed from cache until `exp` | bridging | `test_statuscache_overbrugt_netwerkfout_maar_niet_ongeldig_token` (u) |
| Municipality unreachable, no cache | refused | status unknown | `test_geen_cache_en_onbereikbaar_is_status_onbekend` (u) |
| Mandate from the municipality of Elsweerd | refused without network traffic | issuer not trusted | `test_uitgever_niet_vertrouwd_zonder_netwerk` (u) |
| Metadata with a different `issuer` | refused | metadata mismatch | `test_metadata_issuer_moet_kloppen` (u) |
| Agent key blocked | mandate revoked, new request refused | emergency stop | `test_noodstop_blokkeert_sleutel` (i) |
| Bram (intake) mandates reading income | issuance refused | not authorised himself | `test_bevoegdheid_van_de_medewerker_begrenst_het_mandaat` (u) |
| Audit record modified or omitted | chain breaks | hash chain | `test_gewijzigd_record_breekt_de_keten` (u) |
| Audit line half written (full volume, crash) | line rolled back, chain intact | `fsync` before the chain moves on | `test_half_geschreven_regel_wordt_teruggezet` (u) |
| Audit log missing, empty or lacking an expected record | demo fails | evidence incomplete | `test_controleer_log_eist_bestaand_gevuld_en_volledig_log` (u) |
| MCP protocol error or tool error at the register | agent reports an error, not a refusal | separate kind | `test_toolknoop_onderscheidt_weigering_protocolfout_en_toolfout` (u) |

(u) `tests/unit/`, (i) `tests/integratie/`. The full overview per OWASP risk is in
[docs/DREIGINGSMODEL.md](docs/DREIGINGSMODEL.md) (Dutch); the design choices, the standards and the
relation to the EUDI wallet and the Dutch NL GOV profiles are in [docs/ONTWERP.md](docs/ONTWERP.md)
(Dutch).

## Choices and deviations

- SD-JWT and the status list are a small in-house implementation on `joserfc`, with the test
  vectors from RFC 9901 and the status list draft. The existing Python library follows an older
  draft and has no SD-JWT VC profile or status list; the trade-off is in the design document.
- SD-JWT VC and Token Status List are Internet-Drafts (draft-19 and draft-21 on 17 October 2026).
  The wire formats may still change.
- Issuance and presentation follow the structure of OpenID4VCI and OpenID4VP (proof of
  possession, nonce, `aud`) but not the messages, to keep the essence visible.
- Consent at the municipality is HTTP Basic. The point of the demo is the credential and the
  verification elsewhere; the employee's login at her own organisation is deliberately simple.
- The demo runs over HTTP inside Compose with an explicit opt-in (`STA_HTTP_TOE=1`); the verifier
  then only allows origins that appear as `iss` on the trust list. The specification requires
  `https`.

## What this does not solve

- Whoever holds the agent's private key can act within the mandate until the emergency stop
  propagates through the status list. In production that key belongs in an HSM, TPM or key vault.
- Whoever holds the issuer key can forge every mandate and every status list. Recovery requires
  ending trust in that key; the demo does not rotate it.
- Revocation is not immediate: a call that starts within `ttl` seconds of the revocation may still
  go through, and with an unreachable municipality that bound moves to the `exp` of the cached
  status token. `ttl` and the token's validity are the knobs.
- All presentations of one mandate can be linked (same `jti` and key). That is intended here, but
  differs from citizen credentials.
- Within its mandate the model can produce nonsense, and data it legitimately reads can end up in
  its output. Data minimisation and output control are separate concerns.
- The agent chooses which claims it discloses. The register requires what it needs but does not
  refuse a presentation for disclosing more (for example `medewerker`).
- The register only guards its own tools. The local tool `dossier_lezen` reads the municipality's
  case file without a credential; authorisation on the municipality's own case files is outside
  what this repository demonstrates.
- The trust list is a local file. In production it is a governed trust registry.
- The address check before the connection and the connection itself are two DNS lookups; DNS
  rebinding is outside this demo.
- Agents mandating other agents are outside this demo; the credential has no delegation chain.

## Repository

| Path | Content |
|---|---|
| `src/mandaatbewijs/sdjwt.py` | SD-JWT: issuance, disclosures, decoys, presentation, key-binding JWT, verification per RFC 9901 §7.1 |
| `src/mandaatbewijs/statuslijst.py` | Token Status List: bit string, compression, creating and reading tokens |
| `src/mandaatbewijs/uitgever/` | Municipality of Lindevoort: consent screen, caseload and roles, issuance, status list, emergency stop, audit |
| `src/mandaatbewijs/houder/` | The agent: key pair, credential, presentation per call, MCP connection, planner, LangGraph |
| `src/mandaatbewijs/verifier/` | Income register: MCP tools behind a gateway, trust list, JWKS and status cache, nonces, audit |
| `src/mandaatbewijs/demo.py` | Orchestration of the six scenarios and the evidence table |
| `tests/` | 300 unit tests, 14 integration tests against the real chain |
| `docs/` | Design and threat model (Dutch) |

Quality: `ruff`, `ty`, `pytest`, the Compose chain and gitleaks in CI. Versions are pinned
exactly: `uv.lock`, images by digest, GitHub Actions by commit.

## About

Built by Michael Owen Meijer ([Oomny B.V.](https://www.oomny.nl)), identity architect and AI
engineer for government and cloud. All names, cases and amounts in this repository are fictional.
"Mandaat" is a technical working term here, not a mandate under Dutch administrative law.

Licence: [EUPL-1.2](LICENSE).
