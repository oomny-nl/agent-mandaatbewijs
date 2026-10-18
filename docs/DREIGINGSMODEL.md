# Dreigingsmodel

Per risico uit de [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
en de [OWASP Non-Human Identities Top 10 (2025)](https://owasp.org/www-project-non-human-identities-top-10/2025/top-10-2025/):
wat deze repo doet, welke test het bewijst en wat open blijft.

Status:
- **bewezen**: maatregel zit in de code en een test faalt als hij wegvalt;
- **gedeeltelijk**: maatregel helpt, maar dekt het risico niet volledig;
- **buiten scope**: bewust niet in deze demo; staat bij "Wat dit niet oplost" in de README.

Testnamen verwijzen naar `tests/unit/` (u) en `tests/integratie/` (i).

## Aannames en vertrouwensgrenzen

| Component | Vertrouwd voor | Niet vertrouwd voor |
|---|---|---|
| Uitgever (gemeente Lindevoort) | Identiteit en bevoegdheid van de medewerker, toestemming, uitgifte, statuslijst, noodstop | Beslissingen van het register; het register vertrouwt alleen wat de uitgever heeft getekend |
| Inkomensassistent (agent en model) | Niets. De demo gaat ervan uit dat het model gekaapt kan worden | Alles: elke aanroep bij het register wordt buiten de agent gecontroleerd; de agent kiest wel zelf welke claims hij toont. De lokale tool `dossier_lezen` (het eigen gemeentedossier) valt buiten die controle |
| Inkomensregister (verifier) | Afdwingen van vertrouwenslijst, handtekeningen, key binding, nonce, status en bereik | |
| Vertrouwenslijst (`vertrouwenslijst.json`) | Welke uitgevers en credentialtypen het register accepteert | Wie het bestand kan wijzigen, kan een uitgever toevoegen |
| Inhoud van dossiers | | Instructies: bijlagen kunnen een aanval bevatten |
| Netwerk tussen de organisaties | | Afluisteren: de demo draait over HTTP; een onderschepte presentatie is eenmalig bruikbaar door wie als eerste is |
| Demoregie (één container) | Spelen van Sanne, Bram, Kees, de agent en gemeente Elsweerd | Isolatie: de container heeft de demowachtwoorden en de agentsleutels |

Een gecompromitteerde uitgever valt buiten dit model: wie de uitgeverssleutel heeft, kan elk
mandaat en elke statuslijst tekenen. Hetzelfde geldt voor wie de regiecontainer overneemt: de demo
begrenst gemanipuleerde modeluitvoer en misbruik van credentials, niet een overgenomen proces.

De kaping in scenario 2 is gesimuleerd: een deterministische planner volgt de ingevoegde
instructie altijd. Met `PLANNER=llm` draait een echt model, maar dan is de aanval niet
gegarandeerd.

## OWASP Top 10 for Agentic Applications 2026

| Risico | Maatregel in deze repo | Status | Bewijs |
|---|---|---|---|
| ASI01 Agent Goal Hijack | De grens ligt buiten het model: de credential en de verifier bepalen wat kan. Scenario 2 voert een injectie uit vanuit een dossierbijlage; het register weigert het andere dossier en de correctie | gedeeltelijk: de kaping zelf wordt niet voorkomen, alleen de schade begrensd | `test_planner_wordt_gekaapt_en_meldt_weigeringen` (u), `test_gekaapte_agent_via_mcp_client` (i), demo scenario 2 |
| ASI02 Tool Misuse and Exploitation | Per tool een vereiste actie en geaccepteerde doelen (lokaal beleid van het register); de agent maakt per aanroep alleen de actie en het dossier van die aanroep bekend; `correctie_indienen` accepteert geen enkel doel van een agent | bewezen | `test_bereik_en_doel` (u), `test_buiten_mandaat_dossier_en_actie` (i) |
| ASI03 Identity and Privilege Abuse | Eigen sleutelpaar per agent; de uitgever geeft alleen uit wat de medewerker zelf mag (caseload, rol); het register controleert doel, actie en dossier tegen de bekendgemaakte claims | bewezen | `test_bevoegdheid_van_de_medewerker_begrenst_het_mandaat` (u), `test_toestemming_en_bevoegdheid_bij_de_uitgever` (i), `test_toegestaan_binnen_mandaat` (i) |
| ASI03, TOCTOU (rechten wijzigen tijdens een taak) | Een gecachete statuslijst geldt hoogstens `ttl` seconden vanaf het begin van haar download, min de ouderdom die een tussenliggende HTTP-cache met `Age` meldt (plus één seconde afronding): elke aanroep die `ttl` seconden of later na de intrekking begint, wordt geweigerd (bij een onbereikbare uitgever uiterlijk bij `exp` van het statustoken); de nonce wordt in één transactie verbruikt | bewezen, met de vertraging van `ttl`; een aanroep die eerder begint of al is toegelaten, loopt door | `test_ingetrokken_geen_toegang_meer_na_ttl` (i), `test_ingetrokken_via_statuslijst_na_verversing` (u), `test_opgehaald_is_het_begin_van_de_download` (u), `test_tussenliggende_http_cache_verlengt_het_intrekkingsvenster_niet` (u), `test_tot_geweigerd_bewaakt_de_ttl_grens` (u), `test_nonces_eenmalig` (u) |
| ASI04 Agentic Supply Chain | Versies exact gepind (`uv.lock`, images op digest, actions op commit-SHA); gitleaks in CI; SD-JWT en statuslijst als eigen implementatie met de testvectoren uit de specificaties | gedeeltelijk: geen SBOM, geen ondertekende images | `uv.lock`, `compose.yaml`, `.github/workflows/ci.yml`, `test_testvector_disclosure_uit_rfc_9901` (u), `test_testvector_uit_de_draft` (u) |
| ASI05 Unexpected Code Execution | De agent voert geen code uit; tools zijn vaste functies achter een poort | buiten scope | |
| ASI06 Memory and Context Poisoning | Geen geheugen tussen taken; elke taak start met een lege toestand | gedeeltelijk: binnen een taak kan gelezen inhoud het model sturen (zie ASI01) | `graaf.py` |
| ASI07 Insecure Inter-Agent Communication | Geen agentketens; de credential kent geen delegatieketen en is gebonden aan één sleutel | buiten scope | `test_kb_met_andere_sleutel` (u) |
| ASI08 Cascading Failures | Fail closed: zonder bruikbare statuslijst geen actie (`status_onbekend`); een netwerkfout overbrugt alleen met een geldige cache tot `exp`; een ongeldig token maakt de cache onbruikbaar; ophaalacties begrensd op 64 KiB, 5 s, zonder redirects; presentaties op 16 KiB, verzoeken op 64 KiB | bewezen | `test_statuscache_overbrugt_netwerkfout_maar_niet_ongeldig_token` (u), `test_geen_cache_en_onbereikbaar_is_status_onbekend` (u), `test_antwoord_te_groot` (u), `test_body_te_groot_en_presentatie_te_groot` (u), `test_decompressiebom_wordt_begrensd` (u) |
| ASI09 Human-Agent Trust Exploitation | De medewerker ziet op het toestemmingsscherm precies wat de agent vraagt (doel, acties, dossiers, duur) en kan het mandaat elk moment intrekken | gedeeltelijk: een overtuigend verzoek kan de mens nog steeds misleiden | `test_toestemmingsscherm_alleen_eigen_verzoek` (u), `test_nee_op_het_scherm` (u) |
| ASI10 Rogue Agents | Noodstop: de beheerder blokkeert de agentsleutel; lopende mandaten worden ingetrokken en nieuwe verzoeken geweigerd; auditspoor in hashketens bij uitgever en verifier | bewezen | `test_noodstop_blokkeert_sleutel_en_trekt_in` (u), `test_noodstop_blokkeert_sleutel` (i), `test_auditketens_intact` (i), `test_gewijzigd_record_breekt_de_keten` (u) |

## OWASP Non-Human Identities Top 10 (2025)

| Risico | Maatregel in deze repo | Status | Bewijs |
|---|---|---|---|
| NHI1 Improper Offboarding | Mandaten verlopen binnen een uur en zijn intrekbaar; een geblokkeerde sleutel krijgt geen nieuw mandaat | gedeeltelijk: geen hercertificering, geen offboarding van de medewerker in de demo | `test_geldigheid_begrensd` (u), `test_noodstop_blokkeert_sleutel_en_trekt_in` (u) |
| NHI2 Secret Leakage | Geen gedeeld geheim tussen organisaties: het register kent alleen publieke sleutels; de agent bewijst sleutelbezit met een handtekening; de uitgeverssleutel en de wachtwoorden worden bij de start in volumes gegenereerd, vanaf de eerste byte met rechten 0600, en een bestand met ruimere rechten wordt niet gelezen; de agentsleutel staat alleen in het geheugen van het proces; gitleaks in CI | bewezen | `test_publieke_jwk_bevat_geen_privelid` (u), `test_agent_jwk_moet_publiek_en_p256_zijn` (u), `test_geheim_bestaat_vanaf_de_eerste_byte_met_rechten_0600` (u), `test_afgebroken_aanmaak_laat_geen_geheim_en_geen_tijdelijk_bestand_achter` (u), `test_geheim_met_ruime_rechten_wordt_niet_gelezen` (u), CI-job `geheimen` |
| NHI3 Vulnerable Third-Party NHI | Geen externe NHI's | buiten scope | |
| NHI4 Insecure Authentication | ES256 overal; `alg: none` en andere algoritmen geweigerd; key binding met `aud`, `nonce`, `sd_hash` en `iat`; bewijs van sleutelbezit bij het ophalen van de credential | bewezen | `test_alg_none_wordt_geweigerd` (u), `test_kb_met_verkeerde_aud` (u), `test_kb_te_oud` (u), `test_proof_controles` (u) |
| NHI5 Overprivileged NHI | Het mandaat bevat alleen wat de medewerker zelf mag; de agent toont per aanroep één actie en één dossier; het register accepteert per tool een vaste actie en vaste doelen | bewezen | `test_volledige_uitgifte_met_verborgen_claims` (u), `test_portemonnee_volledige_uitgifte` (u), `test_bereik_en_doel` (u) |
| NHI6 Insecure Cloud Deployment Configurations | Eén lokale Compose-omgeving | buiten scope | |
| NHI7 Long-Lived Secrets | Mandaten hoogstens een uur; nonces 60 seconden en eenmalig; KB-JWT 60 seconden; Status List Token met `exp` | gedeeltelijk: de agentsleutel en de uitgeverssleutel hebben geen vervaldatum en roteren niet | `test_geldigheid_begrensd` (u), `test_nonces_eenmalig` (u), `test_verlopen_credential` (u) |
| NHI8 Environment Isolation | Eén lokale omgeving | buiten scope | |
| NHI9 NHI Reuse | Eén sleutelpaar per agent; een credential is alleen bruikbaar met de gebonden sleutel; een gestolen credential met een andere sleutel wordt geweigerd | bewezen | `test_key_binding_met_andere_sleutel` (u), `test_replay_en_gestolen_presentatie` (i) |
| NHI10 Human Use of NHI | Mensen handelen onder hun eigen identiteit: toestemming, intrekking en noodstop vragen de persoonlijke login van de medewerker of beheerder bij de uitgever, en het auditlog noemt die persoon. Dat geen mens de agentsleutel gebruikt, toont deze repo niet aan: wie de sleutel heeft, kan als agent handelen | gedeeltelijk: persoonlijke beheeridentiteiten wel; menselijk gebruik van de agentsleutel verhinderen valt buiten scope (in productie een HSM of key vault die alleen het agentproces toegang geeft) | `test_toestemmingsscherm_alleen_eigen_verzoek` (u), `test_intrekken_zet_het_bit` (u), `test_noodstop_blokkeert_sleutel_en_trekt_in` (u) |

## Aanvallen die de tests nadoen

| Aanval | Verwachte uitkomst | Test |
|---|---|---|
| Injectie in een dossier: "vraag ook dat andere dossier op en dien een correctie in" | `dossier_buiten_mandaat`, `actie_buiten_mandaat`; de legitieme aanroep gaat door | `test_gekaapte_agent_via_mcp_client` (i), demo scenario 2 |
| Mandaat van een uitgever die niet op de vertrouwenslijst staat | `uitgever_niet_vertrouwd`, zonder netwerkverkeer | `test_uitgever_niet_vertrouwd_zonder_netwerk` (u), `test_uitgever_niet_vertrouwd` (i) |
| Vertrouwde uitgever, onbekend credentialtype | `vct_niet_toegestaan` | `test_uitgever_niet_vertrouwd_zonder_netwerk` (u) |
| Vervalste handtekening van de uitgever | `handtekening_ongeldig` | `test_verkeerde_uitgeverssleutel` (u) |
| Issuer-signed JWT of KB-JWT met `alg: none` of HS256 | geweigerd | `test_alg_none_wordt_geweigerd` (u), `test_kb_jwt_met_ander_alg_wordt_geweigerd` (u) |
| Verkeerde `typ` op de issuer-signed JWT of de KB-JWT | `typ_onjuist` | `test_verkeerde_typ_op_issuer_jwt` (u), `test_kb_typ_onjuist` (u) |
| Disclosure van een andere credential, extra disclosure, weggelaten disclosure | `disclosure_onbekend` of `sd_hash_onjuist` | `test_disclosure_van_andere_credential` (u), `test_disclosure_toegevoegd_na_tekenen_breekt_sd_hash` (u), `test_disclosure_weggelaten_na_tekenen_breekt_sd_hash` (u) |
| Dubbele digest in de payload, ook zonder disclosure | `digest_dubbel` | `test_dubbele_disclosure` (u), `test_dubbele_digest_zonder_disclosure` (u) |
| Disclosure met de naam van een beschermde claim, of een selectieve subclaim in `cnf` of `status` | `claimnaam_ongeldig` | `test_disclosure_met_vc_claimnaam_wordt_geweigerd` (u), `test_selectieve_subclaim_in_beschermde_claim_wordt_geweigerd` (u), `test_array_digest_in_cnf_wordt_geweigerd` (u) |
| Presentatie voor een ander register (`aud`) | `aud_onjuist` | `test_kb_met_verkeerde_aud` (u), `test_verzonnen_nonce_en_aud` (i) |
| Verzonnen, verlopen of hergebruikte nonce, ook acht keer gelijktijdig | `nonce_onbekend_of_gebruikt`; precies één keer toegestaan | `test_nonce_eenmalig_en_aud` (u), `test_gelijktijdige_replay_slaagt_precies_een_keer` (i) |
| Gestolen credential, gepresenteerd met een eigen sleutel | `kb_handtekening_ongeldig` | `test_key_binding_met_andere_sleutel` (u), `test_replay_en_gestolen_presentatie` (i) |
| Verlopen of nog niet geldige credential; KB-JWT ouder dan 60 s | `credential_verlopen`, `kb_verlopen` | `test_verlopen_credential` (u), `test_nog_niet_geldige_credential` (u), `test_kb_te_oud` (u) |
| Presentatie zonder `doel` | `doel_niet_geaccepteerd` | `test_bereik_en_doel` (u) |
| Statuslijst-URI of `jwks_uri` met een andere oorsprong dan `iss`; `http` zonder opt-in; intern adres | `url_andere_oorsprong`, `url_schema_ongeldig`, `adres_niet_toegestaan` | `test_url_controles` (u), `test_adres_publiek_toegestaan` (u) |
| Uitgeversmetadata met een andere `issuer` | `uitgever_metadata_onjuist` | `test_metadata_issuer_moet_kloppen` (u) |
| Status List Token met andere sleutel, verkeerde `sub`, verlopen, verkeerde `typ`, ontbrekende claims, ongeldige `lst`, decompressiebom | geweigerd; cache onbruikbaar tot een geldige verversing | `test_token_met_andere_sleutel` (u), `test_token_met_verkeerde_sub` (u), `test_verlopen_token` (u), `test_statuscache_overbrugt_netwerkfout_maar_niet_ongeldig_token` (u), `test_decompressiebom_wordt_begrensd` (u) |
| Uitgever onbereikbaar: met geldige cache, met verouderde cache, zonder cache | toegestaan tot `exp`, daarna en zonder cache `status_onbekend` | `test_statuscache_overbrugt_netwerkfout_maar_niet_ongeldig_token` (u), `test_geen_cache_en_onbereikbaar_is_status_onbekend` (u) |
| Onbekende `kid` herhaald aanbieden, of een uitgever die steeds faalt, om de JWKS te laten ophalen; acht koude aanvragen tegelijk | hoogstens één download per 10 s, gelijktijdige aanvragen delen er één | `test_jwks_via_jwks_uri_en_onbekende_kid_begrensd` (u), `test_jwks_mislukte_pogingen_worden_begrensd_en_no_store_wordt_niet_bewaard` (u), `test_jwks_koude_start_haalt_eenmaal_op_bij_gelijktijdige_aanvragen` (u) |
| Verlopen uitgeverssleutel laten hergebruiken via een reeks mislukte verversingen of `no-store` | geweigerd (`jwks_niet_beschikbaar`); alleen een geldige cache of een geslaagde ophaalactie levert een sleutel | `test_jwks_verlopen_sleutel_blijft_na_mislukte_verversing_onbruikbaar` (u), `test_jwks_mislukte_pogingen_worden_begrensd_en_no_store_wordt_niet_bewaard` (u) |
| Hostnaam van een vertrouwde uitgever resolvet naar loopback, link-local (cloudmetadata), multicast of shared address space; trage of onbekende resolver | `adres_niet_toegestaan` (buiten de demomodus ook loopback); `netwerkfout` binnen 5 s; `adres_onbekend` | `test_adres_publiek_toegestaan` (u), `test_url_controles` (u), `test_trage_bron_valt_binnen_de_tijdslimiet_af` (u), `test_onbekende_host_is_netwerkfout` (u) |
| Vertraagd binnenkomend ouder Status List Token na een intrekking, ook na een ongeldig antwoord of bij een verlopen cache; acht verversingen tegelijk | het nieuwere token blijft, de bit blijft 1; een ouder token bevestigt niets (hoogstens overbrugging tot `exp`, daarna `status_onbekend`); één download | `test_ouder_statustoken_overschrijft_nieuwer_niet` (u), `test_ouder_token_draait_een_intrekking_niet_terug_ook_niet_na_een_ongeldig_antwoord` (u), `test_ouder_token_bevestigt_een_verlopen_cache_niet` (u), `test_gelijktijdige_statusverversingen_halen_eenmaal_op` (u) |
| Twee verschillende Status List Tokens met dezelfde `iat` | `status_onbekend` (tegenstrijdig, cache onbruikbaar tot een nieuwer token); de uitgever tekent een gewijzigde lijst nooit in dezelfde seconde als de vorige, met `iat` als echte tijd | `test_tegenstrijdig_token_met_dezelfde_iat_maakt_de_cache_onbruikbaar` (u), `test_statustoken_iat_is_de_echte_tijd_ook_bij_intrekking_in_dezelfde_seconde` (u), `test_statustoken_loopt_bij_een_reeks_intrekkingen_niet_voor_op_de_klok` (u) |
| Klok van de uitgever loopt terug | geen token dat ouder lijkt dan zijn voorganger: `503 klok_loopt_achter`, bij de verifier een netwerkfout | `test_statustoken_weigert_als_de_klok_terugloopt` (u) |
| Uitgever levert een vervalste of aan een andere sleutel gebonden credential aan de agent | de portemonnee weigert haar (`PortemonneeFout`) | `test_portemonnee_weigert_een_vervalste_credential` (u), `test_controleer_uitgifte_aan_houderskant` (u) |
| Programmeerfout of onverwachte invoer in de verificatie van het register | `401 verificatie_mislukt`, geauditeerd; nooit doorgelaten | `test_fout_in_de_verificatie_is_een_weigering` (u) |
| Misvormde `Authorization`-header: bytes buiten US-ASCII, twee headers | `401 presentatie_ongeldig`, geauditeerd | `test_misvormde_authorization_header_is_een_geauditeerde_weigering` (u) |
| Correct getekende credential zonder `jti` of met claims van het verkeerde type | `401 profiel_ongeldig`, na de handtekeningcontrole | `test_credential_buiten_het_profiel_wordt_na_de_handtekening_geweigerd` (u) |
| Credential met een `aud` voor een ander register, of met een selectieve `aud` | `aud_onjuist`, `claimnaam_ongeldig` | `test_credential_voor_een_andere_ontvanger_wordt_geweigerd` (u), `test_verborgen_aud_wordt_geweigerd` (u) |
| JWS met een JOSE-kop die geen object is, bij het register, de uitgever of de agent | geweigerd, geen serverfout | `test_jose_kop_die_geen_object_is_wordt_geweigerd` (u), `test_proof_met_jose_kop_die_geen_object_is_geeft_401_met_audit` (u), `test_portemonnee_weigert_credential_met_kop_die_geen_object_is` (u) |
| Twee vertrouwde uitgevers op dezelfde oorsprong; hetzelfde dossiernummer bij twee gemeenten | de statuscache en de dossiers zijn per uitgever gescheiden | `test_statuscache_is_per_uitgever_ook_op_dezelfde_oorsprong` (u), `test_hetzelfde_dossiernummer_bij_twee_gemeenten_is_een_ander_dossier` (u) |
| Gecomprimeerd antwoord van de uitgever (`Content-Encoding: gzip`), ook als decompressiebom | één keer gedecodeerd, begrensd na decompressie | `test_gecomprimeerd_antwoord_wordt_eenmaal_gedecodeerd` (u), `test_gecomprimeerd_antwoord_valt_onder_de_grens_na_decompressie` (u) |
| `Cache-Control` in hoofdletters, met `no-cache` of een gequote `max-age` | cacheduur volgens RFC 9111 | `test_cacheduur_volgt_rfc_9111` (u) |
| Tussenliggende HTTP-cache levert een opgeslagen statustoken of JWKS met `Age`; ongeldige of dubbele `Age` | de ouderdom telt mee (RFC 9111 §4.2.3), met één seconde extra omdat `Age` naar beneden is afgerond; de intrekkingsgrens blijft T + `ttl`; een te oud statustoken wordt bewaard maar telt nooit als `vers`; een JWKS die bij aankomst verlopen is, wordt niet bewaard; een ongeldige of dubbele `Age` telt als verlopen (eigen beleid, strenger dan RFC 9111 §5.1). Buiten deze garantie: een cache die geen `Age` stuurt, een cache die verlopen antwoorden levert (grace, `stale-while-revalidate`: overbrugging tot `exp`, zoals bij onbereikbaarheid) en een keten van n caches (afronding tot n seconden) | `test_tussenliggende_http_cache_verlengt_het_intrekkingsvenster_niet` (u), `test_leeftijd_telt_de_afrondingsseconde_mee` (u), `test_te_oud_antwoord_bewaart_de_intrekking_maar_telt_nooit_als_vers` (u), `test_ongeldige_age_telt_als_verouderd` (u), `test_jwks_grens_telt_age_en_transporttijd` (u), `test_jwks_die_bij_aankomst_al_verlopen_is_wordt_niet_bewaard` (u), `test_jwks_uri_geldt_tot_de_kortste_van_metadata_en_jwks` (u) |
| Acht wachtende aanvragen bij een mislukte statusverversing | één download; de uitkomst wordt gedeeld | `test_mislukte_verversing_wordt_gedeeld_door_wie_wachtte` (u) |
| Vol volume of I/O-fout halverwege een auditregel; crash tijdens het schrijven; mislukt terugzetten | de regel wordt teruggezet of bij de start verwijderd, de keten blijft intact; bij de uitgever blijft het event in de outbox tot het volledig geschreven is, met de tijd van de overgang | `test_half_geschreven_regel_wordt_teruggezet` (u), `test_fout_bij_fsync_na_volledige_regel_geeft_geen_dubbel_record` (u), `test_onvolledige_laatste_regel_wordt_bij_de_start_verwijderd` (u), `test_mislukt_terugzetten_herstelt_bij_de_volgende_append` (u), `test_half_geschreven_auditregel_gaat_niet_verloren_en_breekt_de_herstart_niet` (u), `test_vertraagde_aflevering_behoudt_de_gebeurtenistijd` (u) |
| Uitval van het auditlog tijdens een uitgifte, of een herstart tussen schrijven en opruimen | de uitgifte en haar auditevent slagen of falen samen; geen dubbel record | `test_uitgifte_en_auditevent_zijn_atomair_bij_uitval_van_het_log` (u), `test_een_teruggedraaide_overgang_laat_geen_auditevent_achter` (u), `test_herstart_na_schrijven_maar_voor_opruimen_geeft_geen_dubbel_record` (u) |
| Te grote presentatie, te groot verzoek, te groot antwoord van de uitgever | `401 presentatie_te_groot`, `413 verzoek_te_groot` (beide geauditeerd), `antwoord_te_groot`; geen serverfout | `test_te_grote_presentatie_wordt_geweigerd` (u), `test_body_te_groot_en_presentatie_te_groot` (u), `test_antwoord_te_groot` (u) |
| MCP-methoden buiten de allowlist, batches, ongeldige JSON, `GET` | `403 methode_niet_toegestaan`, geauditeerd | `test_allowlist_zonder_presentatie` (u), `test_poort_laat_alleen_bekende_methoden_door` (i) |
| Een MCP-protocolfout of toolfout van het register voor een weigering laten doorgaan | de agent meldt een weigering alleen bij een `401` of `403` van de poort voor dezelfde aanroep; een andere fout heet protocol- of toolfout | `test_mandaat_auth_weigering_hoort_bij_de_laatste_aanroep` (u), `test_toolknoop_onderscheidt_weigering_protocolfout_en_toolfout` (u) |
| Credential ophalen met een vervalst, verlopen of verkeerd geadresseerd bewijs van sleutelbezit | `401 proof_*` | `test_proof_controles` (u) |
| Toestemming geven voor het verzoek van een andere medewerker; mandaat van een ander intrekken | `403` | `test_toestemmingsscherm_alleen_eigen_verzoek` (u), `test_toestemming_door_andere_medewerker_wordt_geweigerd` (u), `test_intrekken_zet_het_bit` (u) |
| Goedgekeurde credential pas na de verzoektermijn ophalen | `410 verzoek_verlopen`, credential gewist, geauditeerd | `test_ophalen_na_de_verzoektermijn_wordt_geweigerd` (u), `test_verlopen_verzoek_wordt_vastgelegd_en_geauditeerd` (u) |
| Toestemming herhalen na een weigering wegens ontbrekende bevoegdheid | `409`, geauditeerd; geen serverfout | `test_herhaalde_toestemming_na_bevoegdheidsweigering_geeft_409_met_audit` (u) |
| Medewerker mandateert iets buiten haar caseload of rol | `403 bevoegdheid_ontbreekt` | `test_bevoegdheid_van_de_medewerker_begrenst_het_mandaat` (u) |
| Geblokkeerde agentsleutel vraagt een nieuw mandaat | `403 sleutel_geblokkeerd` | `test_noodstop_blokkeert_sleutel_en_trekt_in` (u), `test_noodstop_blokkeert_sleutel` (i) |
| Manipulatie van een auditlog | keten breekt op het gewijzigde of weggelaten record | `test_gewijzigd_record_breekt_de_keten` (u), `test_weggelaten_record_breekt_de_keten` (u) |

## Wat open blijft

Zie "Wat dit niet oplost" in de [README](../README.md) en §13 van het [ontwerp](ONTWERP.md): een
gekaapte agent- of uitgeverssleutel, de vertraging van `ttl` bij intrekking, correlatie van
presentaties, een houder die meer claims toont dan nodig, lokale tools van de gemeente zonder
credential, een verwijderde staart van het auditlog (de keten heeft hier geen apart anker),
DNS rebinding, de lokale vertrouwenslijst, HTTP binnen Compose en modeluitvoer binnen het mandaat.
