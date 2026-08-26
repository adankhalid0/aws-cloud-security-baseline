#!/usr/bin/env bash
# Runs Prowler against your AWS account and saves reports to ./reports/.
#
# Prerequisites:
#   - AWS CLI is configured with a profile that has (at least) SecurityAudit +
#     ViewOnlyAccess permissions -- NOT administrator. See docs/PLAN.md Phase 6.
#   - prowler is installed: pip install prowler   (or: brew install prowler)
#
# Usage:
#   ./scripts/run_prowler.sh <aws-profile-name>
#
# Example:
#   ./scripts/run_prowler.sh security-auditor

set -euo pipefail

PROFILE="${1:-default}"
TIMESTAMP="$(date +%Y-%m-%d_%H%M)"
OUTDIR="reports/prowler_${TIMESTAMP}"

echo "==> Running Prowler with AWS profile: ${PROFILE}"
echo "==> Reports will be saved to: ${OUTDIR}"

mkdir -p "${OUTDIR}"

prowler aws \
  --profile "${PROFILE}" \
  --output-formats csv json-ocsf html \
  --output-directory "${OUTDIR}" \
  --compliance cis_2.0_aws

echo ""
echo "==> Done. Open the HTML report in a browser:"
echo "    ${OUTDIR}/$(basename "$(ls "${OUTDIR}"/*.html 2>/dev/null | head -n1)" 2>/dev/null || echo '<report-name>.html')"
echo ""
echo "Next steps:"
echo "  1. Review FAIL findings, prioritize CRITICAL/HIGH."
echo "  2. Document findings, risk, and fix in docs/SECURITY_FINDINGS.md."
echo "  3. Fix the Terraform code, run 'terraform apply' again."
echo "  4. Run this script again and compare the before/after score."
