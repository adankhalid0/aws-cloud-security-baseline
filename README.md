# AWS Cloud Security Baseline

A secure-by-default AWS foundation (VPC, S3, IAM, CloudTrail) built with
**Terraform**, scanned pre-deploy with **Checkov** (shift-left IaC security),
audited post-deploy with **Prowler** (CIS AWS Foundations Benchmark), and
enforced continuously with a **GitHub Actions** CI pipeline.

> Portfolio project built to demonstrate practical cloud security engineering
> skills: Infrastructure as Code, automated static analysis, cloud security
> posture auditing, remediation, and DevSecOps automation.

## Why this project

Most "IaC portfolio projects" stop at `terraform apply`. This one goes further
and follows the full security lifecycle a cloud security engineer actually
works in:

1. **Design** infrastructure with security controls built in from the start.
2. **Shift-left scan** the code with Checkov before anything is deployed.
3. **Deploy** to a real (free-tier) AWS account.
4. **Audit** the live account with Prowler, the same way an assessor would.
5. **Remediate** findings and document the before/after, including accepted
   risks with justification.
6. **Automate** all of the above in CI so future changes can't silently
   regress security posture.

See [`docs/PLAN.md`](docs/PLAN.md) for the full step-by-step build plan, and
[`docs/SECURITY_FINDINGS.md`](docs/SECURITY_FINDINGS.md) for the documented
findings from this specific run.

## Architecture

```
                         ┌─────────────────────────────┐
                         │           AWS Account         │
                         │                               │
   ┌───────────┐         │  ┌────────────┐   ┌─────────┐ │
   │  GitHub    │  push   │  │   VPC      │   │  IAM    │ │
   │  Actions   ├────────►│  │ (2 AZ,     │   │ auditor │ │
   │  (Checkov, │  apply  │  │  flow logs,│   │ role +  │ │
   │  fmt,      │         │  │  no open   │   │ password│ │
   │  validate) │         │  │  SGs)      │   │ policy  │ │
   └───────────┘         │  └────────────┘   └─────────┘ │
                         │                               │
                         │  ┌────────────┐   ┌─────────┐ │
                         │  │ CloudTrail │──►│   S3    │ │
                         │  │ (multi-    │   │ (KMS,   │ │
                         │  │  region)   │   │ private,│ │
                         │  └────────────┘   │ logged) │ │
                         │                    └─────────┘ │
                         └─────────────────────────────┘
                                     ▲
                                     │ post-deploy audit
                              ┌─────────────┐
                              │   Prowler    │
                              │ (CIS 2.0 AWS)│
                              └─────────────┘
```

_(Replace with a proper diagram exported to `docs/architecture.png` -- see
`docs/PLAN.md` Phase 9.)_

## What gets deployed

| Component | Purpose | Key security controls |
|-----------|---------|------------------------|
| `modules/vpc` | Network foundation | VPC Flow Logs, locked-down default security group, no auto-assigned public IPs |
| `modules/s3-secure` | Reusable secure S3 bucket | KMS encryption, versioning, public access fully blocked, access logging, lifecycle rules |
| `modules/iam` | Identity foundation | Least-privilege, MFA-gated auditor role (assume-role, not shared keys); account password policy (CIS-aligned) |
| `modules/cloudtrail` | Audit trail | Multi-region, log file validation, KMS-encrypted, streamed to CloudWatch Logs |
| `terraform/bootstrap` | Remote state | Encrypted, versioned S3 backend + DynamoDB locking |

## Tooling

- **Terraform** (>= 1.6) -- Infrastructure as Code
- **Checkov** -- static analysis of the Terraform code before deployment
- **Prowler** -- security assessment of the live AWS account (CIS AWS
  Foundations Benchmark)
- **GitHub Actions** -- CI pipeline running `terraform fmt`,
  `terraform validate`, and Checkov on every push/PR

## Getting started

Full instructions with explanations: [`docs/PLAN.md`](docs/PLAN.md).
Quick version:

```bash
# 1. Bootstrap remote state (one-time)
cd terraform/bootstrap
terraform init
terraform apply -var="state_bucket_name=<your-unique-bucket-name>"

# 2. Fill in the backend block in terraform/environments/dev/versions.tf
#    with the outputs from step 1, then:
cd ../environments/dev
cp terraform.tfvars.example terraform.tfvars   # edit with your values
terraform init
terraform plan
terraform apply

# 3. Scan the code with Checkov (do this BEFORE apply in real workflows)
cd ../../..
checkov -d terraform --config-file .checkov.yaml

# 4. Audit the live account with Prowler
./scripts/run_prowler.sh <your-aws-cli-profile>
```

## Results

See [`docs/SECURITY_FINDINGS.md`](docs/SECURITY_FINDINGS.md) for full details.

| Metric | Before remediation | After remediation |
|--------|---------------------|--------------------|
| Checkov FAIL | 21 | 0 |
| Prowler FAIL (total) | 28 | 7 |
| Prowler FAIL (Critical/High) | 2 (1 critical, 1 high) | 1 (1 critical, 0 high) |
| CIS 2.0 AWS compliance score | 67.82% | 92.05% |

Prowler summary from the final audit run (CIS AWS Foundations Benchmark 2.0): 88 findings, 81 passed, 7 failed. The 7 remaining findings are documented as accepted risks.

![Prowler assessment overview after remediation](docs/images/prowler-after.png)

## Cleanup

```bash
cd terraform/environments/dev && terraform destroy
cd ../../bootstrap && terraform destroy
```

## Lessons learned

Building this end-to-end -- not just `terraform apply`, but scanning,
deploying, auditing, and fixing -- made it obvious how much a fresh AWS
account gets wrong by default: no CloudTrail data events, no account-wide
password policy, no metric filters wired up to alarms even though the logs
were already there. Checkov caught the structural issues before anything
was even deployed; Prowler caught the runtime/account-level ones that only
show up once real resources exist, which is exactly why the project runs
both instead of relying on just one.

The CI pipeline turned out to be its own small lesson: getting GitHub
Actions permissions right for the SARIF upload, and getting YAML
indentation exactly consistent, took more iterations than the Terraform
code itself. It was a good reminder that "the pipeline is part of the
security control" -- a workflow that silently fails to run is just as bad
as not having the check at all.

In a real production account I'd take this further: federate CI with AWS
via OIDC instead of long-lived access keys, add Service Control Policies
at the AWS Organizations level as a second guardrail on top of IAM, and
run Prowler on a schedule (not just once) so drift gets caught
automatically instead of only at deploy time.

## License

MIT -- see [LICENSE](LICENSE).
