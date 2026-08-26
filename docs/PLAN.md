# Trinn-for-trinn plan: Cloud Security-porteføljeprosjekt (Terraform + Checkov + Prowler på AWS)

Denne planen er skrevet for deg som er nyutdannet innen cybersikkerhet, har lite
praktisk AWS/Terraform-erfaring, og trenger et prosjekt til GitHub-porteføljen
som viser reell cloud security-kompetanse -- ikke bare "jeg fulgte en tutorial".

**Prosjektidé:** Bygg en liten, sikker AWS-grunnmur (VPC, S3, IAM, CloudTrail)
med Terraform. Skann koden med Checkov *før* du deployer (shift-left/DevSecOps).
Deploy til en ekte AWS free tier-konto. Kjør Prowler *etter* deploy for å
revidere kontoen som en sikkerhetsanalytiker ville gjort. Finn, prioriter og
fiks feil. Dokumenter alt. Sett det opp med CI/CD i GitHub Actions.

Dette demonstrerer nettopp de tre tingene arbeidsgivere innen cloud security
ser etter: **Infrastructure as Code, automatisert sikkerhetsskanning (shift-left),
og manuell/automatisert sikkerhetsrevisjon (shift-right/CSPM)** -- pluss evnen
til å dokumentere funn slik en reell sikkerhetsanalytiker gjør.

Filene som er generert sammen med denne planen (Terraform-moduler, Checkov-config,
GitHub Actions-workflow, Prowler-script) er et fungerende utgangspunkt -- se
`README.md` i rotmappen for hvordan alt henger sammen. Denne planen forklarer
**hvorfor** og **i hvilken rekkefølge**.

---

## Oversikt over fasene

| Fase | Innhold | Estimert tid |
|------|---------|--------------|
| 0 | Verktøy og AWS-konto | 1-2 timer |
| 1 | AWS-oppsett: IAM-bruker, MFA, budsjettvarsel | 1 time |
| 2 | Terraform: bootstrap remote state | 30-60 min |
| 3 | Terraform: skriv sikker infrastruktur | 3-6 timer |
| 4 | Checkov: shift-left-skanning | 1-2 timer |
| 5 | Deploy til AWS | 30 min |
| 6 | Prowler: sikkerhetsrevisjon | 2-3 timer |
| 7 | Remediering og før/etter-dokumentasjon | 2-4 timer |
| 8 | CI/CD med GitHub Actions | 1-2 timer |
| 9 | Dokumentasjon og polering av README | 2-3 timer |
| 10 | Opprydding (destroy) og kostnadskontroll | 30 min |
| 11 | Stretch goals (valgfritt) | åpent |

Totalt: realistisk et prosjekt du kan gjennomføre på **1-2 helger** eller
spredt over **1-2 uker kveldstid**. Ikke stress -- kvalitet og forståelse
slår tempo i et porteføljeprosjekt.

---

## Fase 0: Verktøy du trenger

Installer lokalt (macOS/Linux/WSL anbefales, men fungerer på Windows også):

1. **Git** -- `git --version` (installer via git-scm.com om nødvendig)
2. **AWS CLI v2** -- https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
3. **Terraform** -- https://developer.hashicorp.com/terraform/install (bruk `tfenv` om du vil håndtere versjoner)
4. **Checkov** -- `pip install checkov` (krever Python 3.8+)
5. **Prowler** -- `pip install prowler` (krever Python 3.9+)
6. **VS Code** (eller annen editor) + Terraform-extension for syntax highlighting

Sjekk at alt fungerer:

```bash
git --version
aws --version
terraform -version
checkov --version
prowler -v
```

---

## Fase 1: AWS-kontooppsett (sikkerhet fra dag én)

**Ikke bruk root-brukeren til noe som helst etter dette steget.** Det er selve
poenget med et cloud security-prosjekt å vise at du forstår hvorfor.

1. Opprett en AWS-konto på aws.amazon.com hvis du ikke har en (free tier).
2. Logg inn som **root**, aktiver **MFA på root-kontoen umiddelbart**
   (Security Credentials → Multi-factor authentication). Bruk en autentiseringsapp
   (Google Authenticator, Authy, 1Password osv.), ikke SMS.
3. Sett opp et **AWS Budget-varsel** (Billing → Budgets) på f.eks. 5-10 USD,
   slik at du får e-post hvis noe koster mer enn forventet. Dette er billig
   forsikring mot at et glemt "terraform destroy" koster deg penger.
4. Opprett en **IAM-bruker for deg selv** (Console access), aktiver MFA på den
   også, og slutt å bruke root.
5. Opprett en **egen IAM-bruker for Terraform** (programmatic access / access keys)
   med et minimum av rettigheter -- ikke AdministratorAccess om du kan unngå det.
   For dette prosjektets omfang holder det med en policy som gir
   `iam:*`, `s3:*`, `ec2:*` (for VPC), `cloudtrail:*`, `kms:*`,
   `logs:*`, `dynamodb:*` (for state-lock) begrenset til din region/konto.
   Skriv gjerne denne policyen selv som en øvelse i least privilege -- det er
   god trening og noe du kan referere til i README.
6. Konfigurer AWS CLI med en **profil** (ikke default), f.eks.:

   ```bash
   aws configure --profile terraform-deployer
   ```

7. Sett miljøvariabelen når du kjører Terraform:

   ```bash
   export AWS_PROFILE=terraform-deployer
   ```

**Hvorfor dette er viktig for porteføljen:** En rekruterer/hiring manager som
leser README-en din og ser at du bevisst har unngått root-bruk, satt opp MFA
og separert deployer-rettigheter fra din personlige bruker, skjønner umiddelbart
at du forstår IAM-hygiene -- ikke bare Terraform-syntaks.

---

## Fase 2: Bootstrap Terraform remote state

Terraform trenger et sted å lagre "state" (hva som faktisk er deployet). Vi
bruker en kryptert, versjonert S3-bucket + DynamoDB for låsing (unngår at to
samtidige `apply` ødelegger hverandre).

```bash
cd terraform/bootstrap
terraform init
terraform plan -var="state_bucket_name=tfstate-cloud-sec-baseline-dittnavn-1234"
terraform apply -var="state_bucket_name=tfstate-cloud-sec-baseline-dittnavn-1234"
```

Noter output-verdiene (`state_bucket_name`, `lock_table_name`). Fyll dem inn i
`terraform/environments/dev/versions.tf` sin `backend "s3" {}`-blokk (fjern
kommentartegnene), og kjør deretter:

```bash
cd ../environments/dev
terraform init
```

> **Merk:** bootstrap-stacken bruker bevisst lokal state (den kan jo ikke
> lagre sin egen state i bucketen den selv skal opprette). Det er greit --
> den endres sjelden etter første kjøring.

---

## Fase 3: Skriv/tilpass den sikre infrastrukturen

Modulene i `terraform/modules/` er allerede skrevet som et fungerende
utgangspunkt:

- **`iam/`** -- least-privilege auditor-rolle (assume-role med MFA-krav) +
  kontobred passordpolicy.
- **`s3-secure/`** -- gjenbrukbar "sikker som standard" S3-bucket: kryptert,
  versjonert, ingen offentlig tilgang, tilgangslogging.
- **`vpc/`** -- VPC med offentlige/private subnett, VPC Flow Logs, og en
  låst standard security group (klassisk CIS-sjekk).
- **`cloudtrail/`** -- multi-region CloudTrail med log file validation og
  CloudWatch Logs-integrasjon.

**Din oppgave i denne fasen** er ikke nødvendigvis å skrive alt fra bunnen,
men å:

1. Lese gjennom hver modul og **forstå hvert eneste resource-block** -- kunne
   forklare i et jobbintervju hvorfor `block_public_acls = true` finnes, hva
   `enable_log_file_validation` gjør, osv.
2. Justere variabler i `terraform/environments/dev/terraform.tfvars` (kopier
   fra `.example`-filen) til dine egne verdier (unike bucket-navn, din IAM-ARN).
3. Vurder å **utvide** prosjektet med noe eget (se Fase 11 "Stretch goals")
   for å gjøre det til "ditt" prosjekt og ikke bare en kopi av en mal.

```bash
cd terraform/environments/dev
cp terraform.tfvars.example terraform.tfvars
# rediger terraform.tfvars med dine verdier
terraform fmt -recursive
terraform validate
```

---

## Fase 4: Checkov -- shift-left-skanning FØR deploy

Dette er kjernen i "shift-left security": finn feilene mens de bare koster deg
noen minutter å fikse, ikke etter at de er live i produksjon.

```bash
cd ~/aws-cloud-security-baseline   # rotmappen
checkov -d terraform --config-file .checkov.yaml
```

1. Les output nøye. Checkov grupperer funn per sjekk-ID (f.eks. `CKV_AWS_18`).
2. For hvert FAIL: forstå kontrollen (Checkov-docs har en beskrivelse), vurder
   om den er relevant, og enten:
   - **Fiks den** i Terraform-koden (foretrukket), eller
   - **Skip den bevisst** med en inline-kommentar som begrunner hvorfor
     (`# checkov:skip=CKV_AWS_XXX: <begrunnelse>` -- se eksempler i
     `terraform/bootstrap/main.tf`).
3. Kjør på nytt til du har null ubegrunnede FAIL.
4. Dokumenter interessante funn i `docs/SECURITY_FINDINGS.md` (seksjon 2).

Dette er det du senere automatiserer i CI/CD (Fase 8), slik at fremtidige
endringer aldri kan introdusere usikre defaults igjen.

---

## Fase 5: Deploy til AWS

```bash
cd terraform/environments/dev
terraform plan    # les planen NØYE -- forstå hver ressurs som opprettes
terraform apply
```

Skriv `yes` for å bekrefte. Dette tar typisk 2-5 minutter (CloudTrail og KMS
tar litt tid).

Gå inn i AWS-konsollen og se på ressursene som ble opprettet -- bli kjent med
hvordan de faktisk ser ut i konsollen, ikke bare i kode. Dette hjelper deg
enormt når du senere ser Prowler-funn som refererer til spesifikke ressurser.

---

## Fase 6: Prowler -- sikkerhetsrevisjon av den live kontoen

Nå bytter vi hatt: fra "utvikler som bygger sikkert" til "sikkerhetsanalytiker
som reviderer en konto de ikke nødvendigvis stoler blindt på" -- selv om det
er din egen konto, er poenget å øve på arbeidsflyten.

```bash
./scripts/run_prowler.sh terraform-deployer
```

(Bruk gjerne en egen `security-auditor`-AWS CLI-profil basert på
`auditor`-rollen fra IAM-modulen, for å øve på assume-role også.)

Prowler sjekker **hele kontoen**, ikke bare det du selv deployet -- du vil
sannsynligvis se funn knyttet til kontoens standardoppsett (f.eks. manglende
GuardDuty, IAM-brukere uten MFA du kanskje har fra tidligere, osv.). Dette er
verdifullt: det viser at prosjektet ditt håndterer en *hel konto*, ikke bare
dine egne ressurser.

1. Åpne HTML-rapporten i `reports/prowler_<timestamp>/`.
2. Sorter på severity: start med CRITICAL og HIGH.
3. For hvert funn du velger å jobbe med: forstå det, vurder relevans, og
   bestem om det skal fikses eller aksepteres som risiko.

---

## Fase 7: Remediering + før/etter-dokumentasjon

Dette er fasen som skiller et sterkt porteføljeprosjekt fra et middelmådig ett.

1. Velg **5-10 av de viktigste Prowler-funnene** (prioriter Critical/High).
2. For hvert funn: fiks det, enten i Terraform (foretrukket -- hold alt som
   kode) eller manuelt i konsollen hvis det er kontonivå-innstillinger
   Terraform ikke dekker i dette prosjektet (f.eks. GuardDuty hvis du ikke
   la det til i Fase 11).
3. Kjør `terraform apply` på nytt for Terraform-baserte fikser.
4. Kjør Prowler på nytt: `./scripts/run_prowler.sh terraform-deployer`
5. Fyll ut `docs/SECURITY_FINDINGS.md` fullstendig, inkludert
   før/etter-tabellen med faktiske tall (antall FAIL, compliance-score).
6. Ta skjermbilder av Prowler-dashboardet før og etter, legg i
   `docs/screenshots/`.

**Dette dokumentet er det viktigste enkeltstående "beviset" i porteføljen din.**
Det viser hele sikkerhetsarbeidsflyten: oppdage → forstå → prioritere → fikse
→ verifisere.

---

## Fase 8: CI/CD med GitHub Actions

`.github/workflows/terraform-checkov.yml` er allerede satt opp til å kjøre
`terraform fmt`, `terraform validate` og Checkov på hver push/PR mot `main`.

1. Push prosjektet til GitHub (se Fase 9 for repo-oppsett).
2. Gå til "Actions"-fanen og se workflowen kjøre.
3. Prøv bevisst å introdusere en usikker endring (f.eks. sett
   `block_public_acls = false` midlertidig på en branch) og lag en Pull
   Request -- se at Checkov-jobben feiler og blokkerer merge. Ta et
   skjermbilde av dette for README-en din; det er et sterkt visuelt bevis på
   at shift-left faktisk virker.
4. Revert endringen.

**Valgfritt (stretch):** sett opp et eget scheduled workflow som kjører
Prowler ukentlig mot AWS-kontoen via **OIDC-føderasjon** (ikke lagrede
AWS-nøkler som GitHub-secrets) -- se Fase 11.

---

## Fase 9: Dokumentasjon og README

`README.md` i rotmappen er allerede skrevet som et portefølje-klart
utgangspunkt (på engelsk, siden de fleste porteføljeprosjekter leses av et
internasjonalt/engelsktalende publikum). Gå gjennom den og:

1. Fyll inn faktiske tall fra Fase 7 (før/etter-tabellen).
2. Legg til et enkelt arkitekturdiagram (f.eks. laget i draw.io / Excalidraw,
   eksportert som PNG til `docs/architecture.png`).
3. Legg til skjermbilder: Terraform apply-output, Checkov CLI-output,
   Prowler HTML-rapport, GitHub Actions som feiler på usikker kode.
4. Skriv en kort "Lessons learned"-seksjon med egne ord.
5. Sørg for at README svarer på: Hva bygde jeg? Hvorfor? Hvilke
   sikkerhetskontroller? Hvilke funn fant jeg og hvordan fikset jeg dem?
   Hvordan kjører noen andre dette selv?

---

## Fase 10: Opprydding og kostnadskontroll

For å unngå unødvendige kostnader når du er ferdig å demonstrere prosjektet:

```bash
cd terraform/environments/dev
terraform destroy

cd ../../bootstrap
terraform destroy   # kjør denne SIST, og bare når du er helt ferdig med prosjektet
```

De fleste ressursene i dette prosjektet (S3, IAM, CloudTrail uten
data events, VPC uten NAT gateway) ligger innenfor AWS free tier eller koster
brøkdeler av en dollar per måned. NAT gateway og GuardDuty (hvis du legger dem
til som stretch goals) koster mer -- husk å destroye dem når du er ferdig, og
hold øye med budsjettvarselet fra Fase 1.

---

## Fase 11: Stretch goals (valgfritt, men anbefalt for å skille deg ut)

Velg 1-3 av disse for å gjøre prosjektet til "ditt eget" og vise mer dybde:

1. **AWS Config + Config Rules** for kontinuerlig compliance-overvåking
   (ikke bare punktvise Prowler-kjøringer).
2. **GuardDuty** aktivert via Terraform, med SNS-varsling til e-post.
3. **Security Hub** som samler funn fra GuardDuty/Config/Prowler-lignende
   sjekker på ett sted.
4. **OIDC-føderasjon fra GitHub Actions til AWS** i stedet for lagrede
   access keys -- fjerner langlivede hemmeligheter helt. Sterkt signal om
   moden sikkerhetstenkning.
5. **Policy as Code med OPA/Conftest eller Sentinel** i tillegg til Checkov,
   for å vise at du kjenner flere verktøy i samme kategori.
6. **Et lite, hardnet EC2-eksempel** i det private subnettet (tilgang kun via
   AWS Systems Manager Session Manager -- ingen SSH, ingen public IP) for å
   vise at du også kan sikre kompute, ikke bare lagring/nettverk/IAM.
7. **tfsec eller Trivy** ved siden av Checkov, og sammenlign funnene --
   diskuter i README hvorfor ulike skannere finner ulike ting.
8. **Kostnadsestimering** med Infracost i CI-pipelinen.

---

## Sjekkliste du kan krysse av underveis

- [ ] AWS-konto opprettet, root MFA aktivert, budsjettvarsel satt
- [ ] Egen IAM-bruker + separat Terraform-deployer-bruker
- [ ] Terraform bootstrap (remote state) kjørt
- [ ] Alle moduler forstått og eventuelt tilpasset/utvidet
- [ ] Checkov kjørt lokalt, alle FAIL fikset eller begrunnet skippet
- [ ] Infrastruktur deployet (`terraform apply`)
- [ ] Prowler kjørt mot kontoen, HTML-rapport generert
- [ ] Minst 5-10 funn dokumentert i `docs/SECURITY_FINDINGS.md`
- [ ] Remediering gjennomført, Prowler kjørt på nytt (før/etter-tall)
- [ ] GitHub Actions CI kjører og blokkerer usikker kode (demonstrert med PR)
- [ ] README ferdig polert med skjermbilder og arkitekturdiagram
- [ ] Minst ett stretch goal implementert
- [ ] `terraform destroy` kjørt når du er ferdig å demonstrere (eller latt
      stå bevisst med kostnadskontroll -- din vurdering)
- [ ] Prosjektet pushet til et offentlig GitHub-repo, lenket fra CV/LinkedIn
