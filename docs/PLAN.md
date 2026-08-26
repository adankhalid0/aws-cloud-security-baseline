# Project Plan

This document describes the approach and phased structure I followed to build
this project, along with recommendations for anyone attempting something
similar.

## Approach

The goal was to build a small, secure AWS foundation (VPC, S3, IAM,
CloudTrail) with Terraform, scan it with Checkov before deploying
(shift-left), deploy it to a real AWS account, and then audit the live
account with Prowler the way a security analyst would (shift-right / CSPM).
Findings get prioritized, fixed, and documented with before/after evidence,
and the whole pipeline is enforced continuously with GitHub Actions so future
changes can't silently regress the security posture.

This mirrors the three things employers in cloud security actually look for:
Infrastructure as Code, automated static analysis, and security posture
auditing -- plus the ability to document findings the way a real security
analyst does.

## Phases

| Phase | Focus |
|---|---|
| 1 | AWS account setup: MFA, budget alert, least-privilege IAM user for Terraform |
| 2 | Terraform: bootstrap encrypted, versioned remote state (S3 + DynamoDB) |
| 3 | Terraform: write the secure infrastructure modules (VPC, S3, IAM, CloudTrail) |
| 4 | Checkov: shift-left scan, fix or justify every finding before deploying |
| 5 | Deploy to a live AWS account |
| 6 | Prowler: audit the live account, prioritize findings by severity |
| 7 | Remediate the highest-priority findings, re-scan, document before/after |
| 8 | Wire up GitHub Actions CI to run fmt/validate/Checkov on every push |
| 9 | Polish documentation: architecture diagram, results, lessons learned |
| 10 | Tear down (`terraform destroy`) when done demonstrating, to avoid cost |

## Recommendations for anyone building something similar

- Don't skip account-level hygiene. MFA, no root usage, and least-privilege
  deploy credentials are what a reviewer notices first, before they even
  look at the Terraform code.
- Run Checkov *before* you ever run `terraform apply`. Finding issues in
  code review costs minutes; finding them after deployment costs a lot more.
- Prowler audits the whole account, not just what you deployed -- expect
  findings unrelated to your own resources. That's a feature, not a bug:
  it's closer to how a real audit works.
- Document the before/after numbers, not just the final state. A findings
  count that goes from 21 to 0 tells a much clearer story than a repo that
  was always clean.
- Automate the check in CI as the last step, not the first. It only makes
  sense once you know what "passing" looks like.
- Pick one or two things to extend beyond the basics (OIDC federation for
  CI instead of static keys, GuardDuty, Security Hub, a second scanner like
  tfsec for comparison). It's what turns a template into a project that's
  actually yours.
