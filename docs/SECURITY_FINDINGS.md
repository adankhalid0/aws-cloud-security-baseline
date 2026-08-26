# Security Findings Log

## 1. Summary

| Tool    | Date       | Scan scope                  | Total checks | Passed | Failed | Critical/High failed |
|---------|------------|------------------------------|---------------|--------|--------|------------------------|
| Checkov (before fixes) | 2026-08-25 | terraform/ (pre-deploy) | 196 | 174 | 21 | 0 |
| Checkov (after fixes, round 1)  | 2026-08-25 | terraform/ (pre-deploy) | 241 | 219 | 0  | 0 |
| Checkov (final)  | 2026-08-26 | terraform/ (pre-deploy) | 297 | 274 | 0  | 0 |
| Prowler (before S3 fix)       | 2026-08-25 19:08 | AWS account 728330702201 (post-deploy) | 87 | 59 | 28 | 2 (1 critical, 1 high) |
| Prowler (after S3 fix)        | 2026-08-25 19:18 | AWS account 728330702201 (post-deploy) | 87 | 60 | 27 | 1 (1 critical, 0 high) |
| Prowler (after CloudWatch fix) | 2026-08-25 20:27 | AWS account 728330702201 (post-deploy) | 87 | 74 | 13 | 1 (1 critical, 0 high) |
| Prowler (final) | 2026-08-26 05:28 | AWS account 728330702201 (post-deploy) | 88 | 81 | 7 | 1 (1 critical, 0 high) |

> `checkov -d terraform --config-file .checkov.yaml --compact` gir tallene rett i terminalen.

Prowler-funn per tjeneste (endelig, 2026-08-26 05:28):

| Service    | FAIL | Severity breakdown |
|------------|------|---------------------|
| account    | 0    | -- |
| cloudtrail | 1    | 1 medium |
| cloudwatch | 1    | 1 medium (verifisert falsk positiv, se seksjon 3) |
| iam        | 2    | 1 critical, 1 low |
| kms        | 0    | -- (4 PASS) |
| s3         | 3    | 3 medium |

CIS 2.0 AWS Foundations Benchmark-score: **92.05% PASS** (opp fra 67.82% ved første Prowler-scan).

---

## 2. Checkov findings (shift-left, før deploy)

### CKV_AWS_338 -- CloudWatch log retention under 1 år

- **Severity:** Medium
- **Resource:** `module.cloudtrail.aws_cloudwatch_log_group.cloudtrail`, `module.vpc.aws_cloudwatch_log_group.flow_logs`
- **What it means:** CloudWatch-loggruppene for CloudTrail og VPC Flow Logs var satt til 90 dagers oppbevaring, under Checkovs anbefalte minimum på 1 år.
- **Why it matters:** Ved et sikkerhetsincident kan man trenge å gå lenger tilbake enn 90 dager for å rekonstruere hva som skjedde.
- **Fix applied:** Endret `default` for `cloudwatch_retention_days` og `flow_log_retention_days` fra 90 til 365 dager.
- **Status:** ✅ Fixed

### CKV_AWS_300 -- S3 lifecycle mangler opprydding av avbrutte multipart-opplastinger

- **Severity:** Low
- **Resource:** `aws_s3_bucket_lifecycle_configuration.tfstate`, `module.logs_bucket.aws_s3_bucket_lifecycle_configuration.this`, `module.logs_bucket.aws_s3_bucket_lifecycle_configuration.logs[0]`
- **What it means:** Ingen regel for å slette rester etter avbrutte multipart-opplastinger, som ellers kan ligge for alltid og koste penger.
- **Fix applied:** La til `abort_incomplete_multipart_upload { days_after_initiation = 7 }` i alle tre lifecycle-konfigurasjonene.
- **Status:** ✅ Fixed

### CKV_AWS_21 -- Loggbucketen manglet en `aws_s3_bucket_versioning`-ressurs

- **Severity:** Medium
- **Resource:** `module.logs_bucket.aws_s3_bucket.this` (hovedbucketen -- fikset), `module.logs_bucket.aws_s3_bucket.logs[0]` (loggbucketen -- se falsk-positiv-notat under)
- **What it means:** Hovedbucketen manglet ganske enkelt versjonering fordi det ikke var med i den opprinnelige modul-koden.
- **Fix applied:** La til `aws_s3_bucket_versioning "logs"`-ressursen for loggbucketen (samme mønster som hovedbucketen).
- **Status:** ✅ Fixed (hovedbucket) / se "Falske positiver" under for loggbucketen

### CKV2_AWS_65 -- Loggbucketen tillot ACL-er (`BucketOwnerPreferred`)

- **Severity:** Medium
- **Resource:** `module.logs_bucket.aws_s3_bucket_ownership_controls.logs[0]`
- **What it means:** S3-tilgangslogging bruker tradisjonelt ACL-er for å gi S3s leveringstjeneste skrivetilgang til mål-bucketen, noe som krever at ACL-er er slått på.
- **Why it matters:** ACL-er er en eldre, mindre oversiktlig tilgangsmodell enn bucket-policyer -- AWS anbefaler nå BucketOwnerEnforced (ACL-er helt av) overalt.
- **Fix applied:** Satte `object_ownership = "BucketOwnerEnforced"` og erstattet ACL-leveransen med en eksplisitt bucket-policy (`aws_s3_bucket_policy.logs`) som gir `logging.s3.amazonaws.com` betinget skrivetilgang (kun fra kildebucketen, kun fra egen konto). Dette er AWS sin nyere, anbefalte metode for S3-tilgangslogging (tilgjengelig siden 2022).
- **Status:** ✅ Fixed og verifisert både i Checkov og i Prowler (`s3_bucket_secure_transport_policy`, se seksjon 3).

### CKV2_AWS_64 -- KMS-nøkler manglet eksplisitt policy

- **Severity:** Low
- **Resource:** `aws_kms_key.state`, `module.logs_bucket.aws_kms_key.this`, `module.vpc.aws_kms_key.flow_logs`
- **What it means:** Nøklene brukte AWS sin standard nøkkelpolicy (som i praksis kun gir root-kontoen tilgang) i stedet for en eksplisitt definert policy.
- **Fix applied:** La til en eksplisitt `data "aws_iam_policy_document"` per nøkkel med et `EnableRootPermissions`-statement, samme mønster som CloudTrail-nøkkelen allerede brukte.
- **Status:** ✅ Fixed

### CKV_AWS_356 / CKV_AWS_109 / CKV_AWS_111 -- KMS-nøkkelpolicyer med `Resource = "*"`

- **Severity:** Medium/High (etter Checkovs standard-alvorlighet)
- **Resource:** Alle 4 KMS-nøkkelpolicyene i prosjektet (state, cloudtrail, s3-secure, vpc flow-logs)
- **What it means:** Checkov flagger `Resource = "*"` som en generelt for bred IAM-tillatelse.
- **Why it matters normally:** I en vanlig IAM-policy betyr `Resource = "*"` "alle ressurser i kontoen" -- alvorlig.
- **Why it's different here:** Dette er en **KMS nøkkelpolicy** (resource policy), ikke en IAM-policy. I en KMS-nøkkelpolicy betyr `"*"` "denne spesifikke nøkkelen", ikke "alle AWS-ressurser". Å gi root-kontoen full kontroll over sin egen nøkkel er AWS sitt offisielt dokumenterte standardmønster.
- **Status:** ⚠️ Accepted risk -- begrunnet `checkov:skip` i koden, se seksjon 5.

### CKV_AWS_252 -- CloudTrail mangler SNS-varsling

- **Severity:** Low
- **Resource:** `module.cloudtrail.aws_cloudtrail.this`
- **What it means:** Ingen får sanntidsvarsel dersom CloudTrail-loggingen endres eller stoppes.
- **Status:** ⚠️ Accepted risk -- se seksjon 5.

### CKV2_AWS_62 -- S3-buckets mangler event-varsling

- **Severity:** Low
- **Resource:** Alle 3 S3-buckets i prosjektet
- **What it means:** Ingen SNS/SQS/Lambda-varsling ved nye objekter i bucketen.
- **Status:** ⚠️ Accepted risk -- se seksjon 5.

### CKV_AWS_145 / CKV_AWS_18 -- Loggbucketen bruker AES256 og har ikke egen access-logging

- **Severity:** Low
- **Resource:** `module.logs_bucket.aws_s3_bucket.logs[0]`
- **What it means:** Loggbucketen krypterer med AES256 (SSE-S3) i stedet for KMS, og har ikke selv en access-logging-konfigurasjon.
- **Why it's expected:** S3s access-logging-tjeneste kan historisk ikke skrive til KMS-krypterte mål-buckets -- AES256 er en reell AWS-begrensning, ikke en glipp. Å logge tilgang til selve loggbucketen (til seg selv) er sirkulært og gir ingen sikkerhetsverdi.
- **Status:** ⚠️ Accepted risk (arkitektonisk nødvendig) -- se seksjon 5.

### CKV_AWS_274 -- IAM-roller uten permissions boundary

- **Severity:** Low
- **Resource:** `module.iam.aws_iam_role.auditor`, `module.iam.aws_iam_role.support`
- **What it means:** Checkov anbefaler en permissions boundary på IAM-roller for å begrense maksimal effektiv tilgang, selv om selve policyen er snever.
- **Why it's accepted:** Begge rollene har allerede minimal, veldefinert tilgang (auditor: `ReadOnlyAccess` + `SecurityAudit`; support: kun `AWSSupportAccess`), MFA-krav på assume-role, og maks 1 times økter. En permissions boundary gir marginal ekstra verdi for et portefølje-prosjekt med to nøye avgrensede roller.
- **Status:** ⚠️ Accepted risk -- begrunnet `checkov:skip` i koden, se seksjon 5.

### Falske positiver: CKV_AWS_21, CKV2_AWS_6, CKV2_AWS_61 på loggbucketen

- **Resource:** `module.logs_bucket.aws_s3_bucket.logs[0]`
- **What it means:** Checkov rapporterte at loggbucketen manglet versjonering, Public Access Block og lifecycle-konfigurasjon -- men alle tre ressursene **finnes faktisk** i koden (`aws_s3_bucket_versioning.logs`, `aws_s3_bucket_public_access_block.logs`, `aws_s3_bucket_lifecycle_configuration.logs`).
- **How we verified this was a false positive:** Vi la eksplisitt til `aws_s3_bucket_versioning.logs`-ressursen og kjørte Checkov på nytt -- funnet forsvant ikke. Dette bekreftet at Checkov sin statiske graf-analyse ikke klarer å koble ressurser som refererer til en `count`-indeksert bucket (`aws_s3_bucket.logs[0]`) tilbake til selve bucket-ressursen -- en kjent begrensning i verktøyet, ikke en reell mangel i infrastrukturen.
- **Status:** ⚠️ Accepted (verktøybegrensning, dokumentert med `checkov:skip` og henvisning til den faktiske ressursen).

---

## 3. Prowler findings (post-deploy, live AWS-konto)

> Kontoen ble først skannet 2026-08-25 19:08. Etter S3-fiksen, CloudWatch-alarmene,
> og til slutt en runde med fire målrettede funn (CloudTrail S3 data events,
> IAM Support-rolle, S3 transport-policy på alle tre buckets, og
> policy-attached-to-user), står kontoen igjen med **7 FAIL**, alle enten
> aksepterte risikoer eller verifiserte falske positiver -- se seksjon 5.

### iam_root_hardware_mfa_enabled -- Root-kontoen bruker virtuell MFA, ikke maskinvare-MFA

- **Severity:** Critical
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 1.6 (også CIS 1.4/1.5/3.0/4.0.1/5.0, AWS Foundational Security Best Practices IAM.6)
- **Resource:** `arn:aws:iam::728330702201:mfa` (root-kontoen)
- **What it means:** Root-kontoen har MFA aktivert, men det er en virtuell (app-basert) MFA-enhet, ikke en fysisk maskinvare-MFA-enhet slik CIS Level 2 krever.
- **Remediation:** Kan ikke gjøres via Terraform -- root-brukeren administreres ikke via IAM-API. Må gjøres manuelt: logg inn som root i AWS-konsollen, gå til IAM Dashboard > "Activate MFA on your root account", fjern den virtuelle MFA-enheten og registrer en fysisk maskinvarenøkkel i stedet.
- **Status:** ⚠️ Accepted risk for dette portefølje-prosjektet -- se seksjon 5 (krever kjøp av fysisk maskinvarenøkkel, som ikke er anskaffet for en demo-/øvingskonto).

### s3_account_level_public_access_blocks -- Ingen kontonivå Block Public Access

- **Severity:** High
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 2.1.4 (også AWS Foundational Security Best Practices S3.1)
- **Resource:** `arn:aws:s3:eu-north-1:728330702201:account` (kontonivå, ikke en enkelt bucket)
- **Fix applied:** La til `resource "aws_s3_account_public_access_block" "this"` i `terraform/environments/dev/main.tf` med alle fire flagg satt til `true`.
- **Status:** ✅ Fixed og verifisert.

### 15x cloudwatch_log_metric_filter_* / cloudwatch_changes_to_* -- manglende CIS 2.0 monitoring-alarmer

- **Severity:** Medium (alle 15)
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 3.1-3.15 (seksjon 4, Monitoring)
- **Resource:** CloudTrail-loggruppen `/cloudtrail/cloud-sec-baseline-dev-trail`
- **Fix applied:** Bygget en ny Terraform-modul `modules/cloudwatch-alarms` med `for_each` over alle 15 CIS-kontrollene (metric filter + alarm per kontroll), pluss et SNS-topic alarmene varsler til (KMS-kryptert med `alias/aws/sns`).
- **Status:** ✅ 14 av 15 fikset og verifisert. Den siste (`organizations_changes`) er en verifisert falsk positiv -- se eget punkt under.

### cloudwatch_log_metric_filter_aws_organizations_changes -- verifisert falsk positiv i Prowler

- **Severity:** Medium
- **What it means:** Prowler rapporterer fortsatt FAIL på denne ene kontrollen, til tross for at både metric filter og alarm er korrekt konfigurert og består alle uavhengige verifiseringer (Prowlers egen regex, `aws logs describe-metric-filters`, `aws cloudwatch describe-alarms`, konsistent over 3 uavhengige scans).
- **Status:** ⚠️ Accepted (verktøybegrensning i Prowler, dokumentert med full verifiseringskjede -- se seksjon 5).

### s3_bucket_secure_transport_policy -- manglet HTTPS-only-policy på loggbucketen og tfstate-bucketen

- **Severity:** Medium
- **Resource:** `cloud-sec-baseline-logs-khalid-4821-access-logs` (loggbucket), `tfstate-cloudsec-khalid-7291` (tfstate-bucket)
- **What it means:** Hovedbucketen hadde allerede en `DenyInsecureTransport`-regel (del av CloudTrail-policyen), men loggbucketen og tfstate-bucketen hadde ingen bucket-policy som nektet ukryptert HTTP-tilgang.
- **Fix applied:** La til et `DenyInsecureTransport`-statement (Deny `s3:*` når `aws:SecureTransport = false`) i bucket-policyen for begge bucketene. For loggbucketen ble dette kombinert med `log_delivery`-policyen (samme ressurs som gir `logging.s3.amazonaws.com` skrivetilgang, se CKV2_AWS_65 over).
- **Debugging note:** Etter første `terraform apply` viste `terraform plan` "No changes", men et direkte `aws s3api get-bucket-policy`-kall mot loggbucketen viste at `DenyInsecureTransport`-statementet likevel ikke var der -- kun `S3ServerAccessLogsPolicy`. Terraform sin state hadde altså ikke fanget opp at policyen manglet et statement. Løsningen var `terraform apply -replace="module.logs_bucket.aws_s3_bucket_policy.logs[0]"` for å tvinge en reell `DeleteBucketPolicy` + `PutBucketPolicy`, som løste det. **Lærdom:** ikke stol blindt på at "no changes" i `terraform plan` betyr at live-ressursen faktisk matcher koden -- verifiser kritiske IAM/bucket-policyer direkte mot AWS API når noe virker uventet.
- **Status:** ✅ Fixed og verifisert på alle tre buckets.

### cloudtrail_s3_dataevents_read_enabled / cloudtrail_s3_dataevents_write_enabled -- manglet S3-objektnivå-logging

- **Severity:** Medium/Low
- **Resource:** `module.cloudtrail.aws_cloudtrail.this`
- **What it means:** Trailen logget kun management events (opprette/slette/endre ressurser), ikke data events (GetObject/PutObject på objektnivå i S3).
- **Fix applied:** La til en ekstra `event_selector`-blokk med `data_resource { type = "AWS::S3::Object", values = ["arn:aws:s3"] }`, som dekker alle S3-buckets i kontoen.
- **Status:** ✅ Fixed og verifisert.

### iam_support_role_created -- manglet dedikert rolle for AWS Support

- **Severity:** Medium/Low
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 1.20
- **What it means:** Ingen rolle fantes for å håndtere AWS Support-saker uten å bruke en full admin-bruker.
- **Fix applied:** La til `aws_iam_role.support` (MFA-gated assume-role, samme prinsipp som auditor-rollen) med `AWSSupportAccess`-policyen tilknyttet.
- **Status:** ✅ Fixed og verifisert.

### iam_policy_attached_only_to_group_or_roles -- policy hengt direkte på terraform-deployer

- **Severity:** Low
- **Resource:** `arn:aws:iam::728330702201:user/terraform-deployer`
- **What it means:** Best practice i IAM er policy → gruppe → bruker, ikke policy direkte på en enkelt bruker.
- **Fix applied:** Opprettet IAM-gruppen `terraform-deployers` (manuelt via AWS CLI, siden `terraform-deployer`-brukeren selv ikke administreres av dette Terraform-prosjektet -- se `modules/iam/main.tf`), hengte `TerraformCloudSecBaselineDeployer`-policyen på gruppen, la brukeren i gruppen, og fjernet deretter den direkte tilknytningen. Verifisert med `terraform plan` etterpå at tilgangen fortsatt fungerte identisk via gruppen.
- **Status:** ✅ Fixed og verifisert.

### s3_bucket_no_mfa_delete (×3) / cloudtrail_bucket_requires_mfa_delete -- MFA Delete er ikke aktivert

- **Severity:** Medium
- **Resource:** Alle tre S3-buckets (`cloud-sec-baseline-logs-khalid-4821`, `-access-logs`, `tfstate-cloudsec-khalid-7291`)
- **What it means:** MFA Delete krever en ekstra MFA-kode for å endre versjoneringsstatus eller slette objektversjoner -- et ekstra sikkerhetslag mot kompromitterte legitimasjoner.
- **Why it's a hard AWS limitation:** MFA Delete kan **kun** aktiveres via AWS CLI/API med selve root-kontoens legitimasjon og en gyldig MFA-kode i API-kallet (`aws s3api put-bucket-versioning ... MFADelete=Enabled --mfa "..."`) -- verken IAM-brukere/roller (uansett rettigheter) eller Terraform kan gjøre dette, og AWS-konsollen støtter det heller ikke. Å aktivere dette ville krevd å midlertidig opprette root-tilgangsnøkler, noe AWS selv fraråder (og som Prowler flagger som egen risiko).
- **Status:** ⚠️ Accepted risk -- se seksjon 5.

### iam_check_saml_providers_sts -- ingen SAML identity provider konfigurert

- **Severity:** Low
- **Resource:** `arn:aws:iam::728330702201:root`
- **What it means:** Prowler anbefaler SAML/SSO-føderasjon med midlertidige legitimasjoner i stedet for langvarige IAM-brukerlegitimasjoner.
- **Why it's not applicable here:** Dette er en anbefaling for organisasjoner med en arbeidsstyrke som logger inn via en ekstern identity provider (Okta, Azure AD, osv.). For et portefølje-/øvingsprosjekt med én bruker er det ikke proporsjonalt å sette opp en full SAML IdP-integrasjon -- prosjektet bruker allerede midlertidige STS-legitimasjoner der det gir mening (auditor- og support-rollene, begge MFA-gated assume-role).
- **Status:** ⚠️ Accepted / ikke relevant for prosjektets omfang -- se seksjon 5.

---

## 4. Before / after comparison

| Metric                  | Start (19:08) | Etter S3-fiks (19:18) | Etter CloudWatch-fiks (20:27) | Endelig (26.08, 05:28) |
|--------------------------|--------|-------|-------|-------|
| Total FAIL               | 28     | 27    | 13    | **7** |
| CRITICAL severity FAIL   | 1      | 1 (accepted risk) | 1 (accepted risk) | 1 (accepted risk) |
| HIGH severity FAIL       | 1      | 0 ✅  | 0 ✅ | 0 ✅ |
| MEDIUM severity FAIL     | 19 (15 CloudWatch + 4 S3/IAM) | 19 | 5 (1 CloudWatch falsk positiv + 4 nye S3/IAM) | 2 (1 CloudWatch falsk positiv, 1 gruppe MFA-delete på 3 buckets = 3 funn, se pkt under) |
| LOW severity FAIL        | -      | -     | -     | 1 (SAML, accepted) |
| CIS 2.0 compliance score | 67.82% PASS | 68.97% PASS | 85.06% PASS | **92.05% PASS** |

---

## 5. Accepted risks

| Finding | Reason accepted | Compensating control |
|---------|------------------|------------------------|
| CKV_AWS_356/109/111 -- KMS policy `Resource=*` | AWS sitt anbefalte standardmønster for KMS nøkkelpolicyer; `"*"` betyr "denne nøkkelen", ikke alle ressurser | Kun root-kontoen og den spesifikke AWS-tjenesten har tilgang; nøkkelrotasjon er slått på |
| CKV_AWS_274 -- IAM-roller uten permissions boundary | Begge rollene (auditor, support) har allerede minimal, presist avgrenset tilgang, MFA-krav og korte økter | ReadOnlyAccess/SecurityAudit/AWSSupportAccess er i seg selv snevre AWS-managed policyer |
| CKV_AWS_252 -- CloudTrail uten SNS | Ingen aktiv drift/on-call i dette portefølje-prosjektet til å motta varsler | CloudWatch Logs-integrasjon gir fortsatt full, søkbar logging for manuell gjennomgang |
| CKV2_AWS_62 -- S3 uten event-varsling | Krever en SNS/SQS/Lambda-mottaker ingen abonnerer på; unødvendig kompleksitet for et demo-prosjekt | Access logging og CloudTrail dekker sporbarhet |
| CKV_AWS_145 -- Loggbucket bruker AES256 ikke KMS | S3 access-logging-leveranse støtter historisk ikke KMS-krypterte målbuckets | Bucketen er fullstendig privat (Public Access Block + BucketOwnerEnforced) |
| CKV_AWS_18 -- Loggbucket uten egen access-logging | Sirkulært å logge tilgang til loggbucketen selv | N/A -- arkitektonisk unødvendig |
| CKV_AWS_21 / CKV2_AWS_6 / CKV2_AWS_61 på logs[0] | Falske positiver -- ressursene finnes, men Checkov klarer ikke koble dem til en `count`-indeksert bucket i grafen sin | Verifisert manuelt ved å legge til ressursen og re-kjøre scan |
| Prowler `iam_root_hardware_mfa_enabled` (CRITICAL) -- root har virtuell MFA, ikke maskinvare-MFA | Krever kjøp av en fysisk maskinvarenøkkel; ikke anskaffet for et demo-/øvingsprosjekt | Root har likevel MFA aktivert (virtuell), pluss dedikerte MFA-gated IAM-roller brukes til daglig i stedet for root |
| Prowler `cloudwatch_log_metric_filter_aws_organizations_changes` (MEDIUM) -- falsk FAIL | Verifisert falsk positiv: metric filter og alarm er beviselig korrekt konfigurert (regex-test mot Prowlers egen kildekode + `aws logs describe-metric-filters` + `aws cloudwatch describe-alarms`) | Faktisk overvåkning finnes og fungerer; dette er utelukkende et rapporteringsproblem i Prowler |
| Prowler `s3_bucket_no_mfa_delete` (×3) / `cloudtrail_bucket_requires_mfa_delete` (MEDIUM) | MFA Delete kan kun aktiveres med root-kontoens legitimasjon via CLI, ikke via Terraform, IAM-roller eller AWS-konsollen | Bucketene er fullstendig private, versjonerte og kryptert; tilgang skjer kun via MFA-gated roller, ikke direkte brukerlegitimasjoner |
| Prowler `iam_check_saml_providers_sts` (LOW) | Enterprise-anbefaling for SSO-føderasjon; ikke proporsjonalt for et solo-portefølje-prosjekt | Midlertidige STS-legitimasjoner brukes allerede der det er relevant (auditor- og support-rollene) |

---

## 6. Lessons learned

Den mest lærerike delen av Fase 4 var ikke selve fiksene, men å skille reelle funn fra falske positiver og fra AWS-spesifikke arkitekturbegrensninger. Flere ting overrasket meg:

Først at "Resource = \*" betyr noe helt annet i en KMS-nøkkelpolicy enn i en vanlig IAM-policy -- Checkov flagger begge likt, så det krevde å faktisk forstå AWS sin dokumentasjon i stedet for å bare stole blindt på scanneren.

For det andre fant jeg en reell begrensning i Checkov selv: verktøyet klarer ikke alltid koble ressurser til en S3-bucket som er opprettet med `count`, selv når ressursen åpenbart finnes i koden. Jeg bekreftet dette empirisk ved å legge til en manglende ressurs og se at funnet ikke forsvant.

For det tredje, og kanskje viktigst: `terraform plan` som viser "No changes" er **ikke** et vanntett bevis på at live-ressursen faktisk matcher koden. Da jeg la til et `DenyInsecureTransport`-statement i en bucket-policy, viste `plan` ingen diff -- men et direkte `aws s3api get-bucket-policy`-kall avslørte at statementet rett og slett ikke var der i AWS. State hadde en verdi som ikke stemte med virkeligheten, og Terraform sin refresh fanget det ikke opp automatisk for denne ressurstypen. Løsningen var `terraform apply -replace=<ressurs>` for å tvinge en reell skriving. Lærdommen: for sikkerhetskritiske ressurser (bucket-policyer, IAM-trust-policyer) er det verdt å verifisere direkte mot AWS API i tillegg til å stole på `terraform plan` -- spesielt etter at en fil har blitt endret av flere runder med redigering.

For det fjerde: ikke alle Prowler-funn er like relevante for et solo-portefølje-prosjekt. MFA Delete (krever root + CLI) og SAML-føderasjon (krever en hel IdP-integrasjon for en arbeidsstyrke som ikke finnes) er gode eksempler på funn der riktig respons er å dokumentere en begrunnet akseptert risiko, ikke å tvinge frem en teknisk "fiks" som ikke gir reell sikkerhetsverdi i denne konteksten.

I en reell produksjonskonto ville jeg trolig fikset SNS-varsling og event-notifications med en gang i stedet for å akseptere risikoen, siden aktiv driftsvarsling er mye mer verdifull når det faktisk finnes et team som følger med. Jeg ville også prioritert fysisk MFA-nøkkel på root og MFA Delete på kritiske buckets tidlig i en reell prod-setup, siden begge er relativt billige tiltak mot svært alvorlige scenarier (fullstendig kontokompromittering).

## License

MIT -- se [LICENSE](LICENSE).
