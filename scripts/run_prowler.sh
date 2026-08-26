#!/usr/bin/env bash
# Kjører Prowler mot AWS-kontoen din og lagrer rapporter i ./reports/.
#
# Forutsetninger:
#   - AWS CLI er konfigurert med en profil som har (minst) SecurityAudit +
#     ViewOnlyAccess-rettigheter -- IKKE administrator. Se docs/PLAN.md Fase 5.
#   - prowler er installert: pip install prowler   (eller: brew install prowler)
#
# Bruk:
#   ./scripts/run_prowler.sh <aws-profil-navn>
#
# Eksempel:
#   ./scripts/run_prowler.sh security-auditor

set -euo pipefail

PROFILE="${1:-default}"
TIMESTAMP="$(date +%Y-%m-%d_%H%M)"
OUTDIR="reports/prowler_${TIMESTAMP}"

echo "==> Kjører Prowler med AWS-profil: ${PROFILE}"
echo "==> Rapporter lagres i: ${OUTDIR}"

mkdir -p "${OUTDIR}"

prowler aws \
  --profile "${PROFILE}" \
  --output-formats csv json-ocsf html \
  --output-directory "${OUTDIR}" \
  --compliance cis_2.0_aws

echo ""
echo "==> Ferdig. Åpne HTML-rapporten i nettleser:"
echo "    ${OUTDIR}/$(basename "$(ls "${OUTDIR}"/*.html 2>/dev/null | head -n1)" 2>/dev/null || echo '<rapportnavn>.html')"
echo ""
echo "Neste steg:"
echo "  1. Gå gjennom FAIL-funn, prioriter CRITICAL/HIGH."
echo "  2. Fyll ut docs/SECURITY_FINDINGS.md med funn, risiko og fiks."
echo "  3. Rett opp i Terraform-koden, kjør 'terraform apply' på nytt."
echo "  4. Kjør dette scriptet igjen og sammenlign score før/etter."
