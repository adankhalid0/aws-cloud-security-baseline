# Security Findings Log

## 1. Summary

| Tool    | Date       | Scan scope                  | Total checks | Passed | Failed | Critical/High failed |
|---------|------------|------------------------------|---------------|--------|--------|------------------------|
| Checkov (before fixes) | 2026-08-25 | terraform/ (pre-deploy) | 196 | 174 | 21 | 0 |
| Checkov (after fixes, round 1)  | 2026-08-25 | terraform/ (pre-deploy) | 241 | 219 | 0  | 0 |
| Checkov (final)  | 2026-08-26 | terraform/ (pre-deploy) | 297 | 274 | 0  | 0 |
| Prowler (before S3 fix)       | 2026-08-25 19:08 | AWS account &lt;account-id&gt; (post-deploy) | 87 | 59 | 28 | 2 (1 critical, 1 high) |
| Prowler (after S3 fix)        | 2026-08-25 19:18 | AWS account &lt;account-id&gt; (post-deploy) | 87 | 60 | 27 | 1 (1 critical, 0 high) |
| Prowler (after CloudWatch fix) | 2026-08-25 20:27 | AWS account &lt;account-id&gt; (post-deploy) | 87 | 74 | 13 | 1 (1 critical, 0 high) |
| Prowler (final) | 2026-08-26 05:28 | AWS account &lt;account-id&gt; (post-deploy) | 88 | 81 | 7 | 1 (1 critical, 0 high) |

> `checkov -d terraform --config-file .checkov.yaml --compact` prints the numbers straight to the terminal.

Prowler findings per service (final, 2026-08-26 05:28):

| Service    | FAIL | Severity breakdown |
|------------|------|---------------------|
| account    | 0    | -- |
| cloudtrail | 1    | 1 medium |
| cloudwatch | 1    | 1 medium (verified false positive, see section 3) |
| iam        | 2    | 1 critical, 1 low |
| kms        | 0    | -- (4 PASS) |
| s3         | 3    | 3 medium |

CIS 2.0 AWS Foundations Benchmark score: **92.05% PASS** (up from 67.82% on the first Prowler scan).

---

## 2. Checkov findings (shift-left, before deploy)

### CKV_AWS_338 -- CloudWatch log retention under 1 year

- **Severity:** Medium
- **Resource:** `module.cloudtrail.aws_cloudwatch_log_group.cloudtrail`, `module.vpc.aws_cloudwatch_log_group.flow_logs`
- **What it means:** The CloudWatch log groups for CloudTrail and VPC Flow Logs were set to 90 days of retention, below Checkov's recommended minimum of 1 year.
- **Why it matters:** During a security incident, you may need to go back further than 90 days to reconstruct what happened.
- **Fix applied:** Changed the `default` for `cloudwatch_retention_days` and `flow_log_retention_days` from 90 to 365 days.
- **Status:** ✅ Fixed

### CKV_AWS_300 -- S3 lifecycle missing cleanup of aborted multipart uploads

- **Severity:** Low
- **Resource:** `aws_s3_bucket_lifecycle_configuration.tfstate`, `module.logs_bucket.aws_s3_bucket_lifecycle_configuration.this`, `module.logs_bucket.aws_s3_bucket_lifecycle_configuration.logs[0]`
- **What it means:** No rule to delete leftovers from aborted multipart uploads, which can otherwise sit around forever and cost money.
- **Fix applied:** Added `abort_incomplete_multipart_upload { days_after_initiation = 7 }` to all three lifecycle configurations.
- **Status:** ✅ Fixed

### CKV_AWS_21 -- The log bucket was missing an `aws_s3_bucket_versioning` resource

- **Severity:** Medium
- **Resource:** `module.logs_bucket.aws_s3_bucket.this` (main bucket -- fixed), `module.logs_bucket.aws_s3_bucket.logs[0]` (log bucket -- see false-positive note below)
- **What it means:** The main bucket simply lacked versioning because it wasn't included in the original module code.
- **Fix applied:** Added the `aws_s3_bucket_versioning "logs"` resource for the log bucket (same pattern as the main bucket).
- **Status:** ✅ Fixed (main bucket) / see "False positives" below for the log bucket

### CKV2_AWS_65 -- The log bucket allowed ACLs (`BucketOwnerPreferred`)

- **Severity:** Medium
- **Resource:** `module.logs_bucket.aws_s3_bucket_ownership_controls.logs[0]`
- **What it means:** S3 access logging has traditionally used ACLs to give S3's delivery service write access to the target bucket, which requires ACLs to be enabled.
- **Why it matters:** ACLs are an older, less transparent access model than bucket policies -- AWS now recommends BucketOwnerEnforced (ACLs fully off) everywhere.
- **Fix applied:** Set `object_ownership = "BucketOwnerEnforced"` and replaced the ACL delivery with an explicit bucket policy (`aws_s3_bucket_policy.logs`) that grants `logging.s3.amazonaws.com` conditional write access (only from the source bucket, only from the account itself). This is AWS's newer, recommended method for S3 access logging (available since 2022).
- **Status:** ✅ Fixed and verified both in Checkov and in Prowler (`s3_bucket_secure_transport_policy`, see section 3).

### CKV2_AWS_64 -- KMS keys were missing an explicit policy

- **Severity:** Low
- **Resource:** `aws_kms_key.state`, `module.logs_bucket.aws_kms_key.this`, `module.vpc.aws_kms_key.flow_logs`
- **What it means:** The keys used AWS's default key policy (which in practice only grants access to the root account) instead of an explicitly defined policy.
- **Fix applied:** Added an explicit `data "aws_iam_policy_document"` per key with an `EnableRootPermissions` statement, the same pattern the CloudTrail key already used.
- **Status:** ✅ Fixed

### CKV_AWS_356 / CKV_AWS_109 / CKV_AWS_111 -- KMS key policies with `Resource = "*"`

- **Severity:** Medium/High (per Checkov's default severity)
- **Resource:** All 4 KMS key policies in the project (state, cloudtrail, s3-secure, vpc flow-logs)
- **What it means:** Checkov flags `Resource = "*"` as a generally overly broad IAM permission.
- **Why it's different here:** This is a **KMS key policy** (a resource policy), not an IAM policy. In a KMS key policy, `"*"` means "this specific key", not "all AWS resources". Giving the root account full control over its own key is AWS's officially documented default pattern.
- **Status:** ⚠️ Accepted risk -- justified `checkov:skip` in the code, see section 5.

### CKV_AWS_252 -- CloudTrail is missing SNS notification

- **Severity:** Low
- **Resource:** `module.cloudtrail.aws_cloudtrail.this`
- **What it means:** No one gets a real-time alert if CloudTrail logging is changed or stopped.
- **Status:** ⚠️ Accepted risk -- see section 5.

### CKV2_AWS_62 -- S3 buckets are missing event notifications

- **Severity:** Low
- **Resource:** All 3 S3 buckets in the project
- **What it means:** No SNS/SQS/Lambda notification when new objects land in the bucket.
- **Status:** ⚠️ Accepted risk -- see section 5.

### CKV_AWS_145 / CKV_AWS_18 -- The log bucket uses AES256 and has no access logging of its own

- **Severity:** Low
- **Resource:** `module.logs_bucket.aws_s3_bucket.logs[0]`
- **What it means:** The log bucket encrypts with AES256 (SSE-S3) instead of KMS, and doesn't have its own access-logging configuration.
- **Why it's expected:** S3's access-logging service historically cannot write to KMS-encrypted target buckets -- AES256 is a real AWS limitation, not an oversight. Logging access to the log bucket itself (to itself) is circular and provides no security value.
- **Status:** ⚠️ Accepted risk (architecturally necessary) -- see section 5.

### CKV_AWS_274 -- IAM roles without a permissions boundary

- **Severity:** Low
- **Resource:** `module.iam.aws_iam_role.auditor`, `module.iam.aws_iam_role.support`
- **What it means:** Checkov recommends a permissions boundary on IAM roles to cap the maximum effective access, even when the policy itself is narrow.
- **Why it's accepted:** Both roles already have minimal, well-defined access (auditor: `ReadOnlyAccess` + `SecurityAudit`; support: `AWSSupportAccess` only), an MFA requirement on assume-role, and a maximum 1-hour session. A permissions boundary adds marginal extra value for a portfolio project with two carefully scoped roles.
- **Status:** ⚠️ Accepted risk -- justified `checkov:skip` in the code, see section 5.

### False positives: CKV_AWS_21, CKV2_AWS_6, CKV2_AWS_61 on the log bucket

- **Resource:** `module.logs_bucket.aws_s3_bucket.logs[0]`
- **What it means:** Checkov reported that the log bucket was missing versioning, a Public Access Block, and a lifecycle configuration -- but all three resources **actually exist** in the code (`aws_s3_bucket_versioning.logs`, `aws_s3_bucket_public_access_block.logs`, `aws_s3_bucket_lifecycle_configuration.logs`).
- **How we verified this was a false positive:** I explicitly added the `aws_s3_bucket_versioning.logs` resource and re-ran Checkov -- the finding didn't disappear. That confirmed Checkov's static graph analysis can't connect resources that reference a `count`-indexed bucket (`aws_s3_bucket.logs[0]`) back to the bucket resource itself -- a known limitation of the tool, not an actual gap in the infrastructure.
- **Status:** ⚠️ Accepted (tool limitation, documented with `checkov:skip` and a reference to the actual resource).

---

## 3. Prowler findings (post-deploy, live AWS account)

> The account was first scanned 2026-08-25 19:08. After the S3 fix, the
> CloudWatch alarms, and finally a round covering four targeted findings
> (CloudTrail S3 data events, the IAM Support role, the S3 transport policy
> on all three buckets, and policy-attached-to-user), the account is left
> with **7 FAIL**, all either accepted risks or verified false positives --
> see section 5.

### iam_root_hardware_mfa_enabled -- The root account uses virtual MFA, not hardware MFA

- **Severity:** Critical
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 1.6 (also CIS 1.4/1.5/3.0/4.0.1/5.0, AWS Foundational Security Best Practices IAM.6)
- **Resource:** `arn:aws:iam::<account-id>:mfa` (root account)
- **What it means:** The root account has MFA enabled, but it's a virtual (app-based) MFA device, not a physical hardware MFA device as CIS Level 2 requires.
- **Remediation:** Can't be done via Terraform -- the root user isn't managed through the IAM API. Has to be done manually: log in as root in the AWS console, go to IAM Dashboard > "Activate MFA on your root account", remove the virtual MFA device and register a physical hardware key instead.
- **Status:** ⚠️ Accepted risk for this portfolio project -- see section 5 (requires purchasing a physical hardware key, which hasn't been acquired for a demo/practice account).

### s3_account_level_public_access_blocks -- No account-level Block Public Access

- **Severity:** High
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 2.1.4 (also AWS Foundational Security Best Practices S3.1)
- **Resource:** `arn:aws:s3:eu-north-1:<account-id>:account` (account level, not a single bucket)
- **Fix applied:** Added `resource "aws_s3_account_public_access_block" "this"` in `terraform/environments/dev/main.tf` with all four flags set to `true`.
- **Status:** ✅ Fixed and verified.

### 15x cloudwatch_log_metric_filter_* / cloudwatch_changes_to_* -- missing CIS 2.0 monitoring alarms

- **Severity:** Medium (all 15)
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 3.1-3.15 (section 4, Monitoring)
- **Resource:** CloudTrail log group `/cloudtrail/cloud-sec-baseline-dev-trail`
- **Fix applied:** Built a new Terraform module `modules/cloudwatch-alarms` with `for_each` over all 15 CIS controls (a metric filter + alarm per control), plus an SNS topic the alarms notify (KMS-encrypted with `alias/aws/sns`).
- **Status:** ✅ 14 of 15 fixed and verified. The last one (`organizations_changes`) is a verified false positive -- see the separate entry below.

### cloudwatch_log_metric_filter_aws_organizations_changes -- verified false positive in Prowler

- **Severity:** Medium
- **What it means:** Prowler still reports FAIL on this one control, despite both the metric filter and the alarm being correctly configured and passing every independent verification (Prowler's own regex, `aws logs describe-metric-filters`, `aws cloudwatch describe-alarms`, consistent across 3 independent scans).
- **Status:** ⚠️ Accepted (tool limitation in Prowler, documented with a full verification chain -- see section 5).

### s3_bucket_secure_transport_policy -- missing HTTPS-only policy on the log bucket and the tfstate bucket

- **Severity:** Medium
- **Resource:** `cloud-sec-baseline-logs-khalid-4821-access-logs` (log bucket), `tfstate-cloudsec-khalid-7291` (tfstate bucket)
- **What it means:** The main bucket already had a `DenyInsecureTransport` rule (part of the CloudTrail policy), but the log bucket and the tfstate bucket had no bucket policy denying unencrypted HTTP access.
- **Fix applied:** Added a `DenyInsecureTransport` statement (Deny `s3:*` when `aws:SecureTransport = false`) to the bucket policy for both buckets. For the log bucket this was combined with the `log_delivery` policy (the same resource that grants `logging.s3.amazonaws.com` write access, see CKV2_AWS_65 above).
- **Debugging note:** After the first `terraform apply`, `terraform plan` showed "No changes", but a direct `aws s3api get-bucket-policy` call against the log bucket showed the `DenyInsecureTransport` statement still wasn't there -- only `S3ServerAccessLogsPolicy`. Terraform's state hadn't picked up that the policy was missing a statement. The fix was `terraform apply -replace="module.logs_bucket.aws_s3_bucket_policy.logs[0]"` to force an actual `DeleteBucketPolicy` + `PutBucketPolicy`, which resolved it. **Lesson:** don't blindly trust that "no changes" in `terraform plan` means the live resource actually matches the code -- verify critical IAM/bucket policies directly against the AWS API when something looks off.
- **Status:** ✅ Fixed and verified on all three buckets.

### cloudtrail_s3_dataevents_read_enabled / cloudtrail_s3_dataevents_write_enabled -- missing S3 object-level logging

- **Severity:** Medium/Low
- **Resource:** `module.cloudtrail.aws_cloudtrail.this`
- **What it means:** The trail only logged management events (create/delete/modify resources), not data events (object-level GetObject/PutObject in S3).
- **Fix applied:** Added an extra `event_selector` block with `data_resource { type = "AWS::S3::Object", values = ["arn:aws:s3"] }`, which covers all S3 buckets in the account.
- **Status:** ✅ Fixed and verified.

### iam_support_role_created -- missing a dedicated role for AWS Support

- **Severity:** Medium/Low
- **Compliance mapping:** CIS 2.0 AWS Foundations Benchmark 1.20
- **What it means:** No role existed for handling AWS Support cases without using a full admin user.
- **Fix applied:** Added `aws_iam_role.support` (MFA-gated assume-role, same principle as the auditor role) with the `AWSSupportAccess` policy attached.
- **Status:** ✅ Fixed and verified.

### iam_policy_attached_only_to_group_or_roles -- policy attached directly to the terraform deployer

- **Severity:** Low
- **Resource:** `arn:aws:iam::<account-id>:user/terraform-deployer`
- **What it means:** IAM best practice is policy → group → user, not policy directly on a single user.
- **Fix applied:** Created the `terraform-deployers` IAM group (manually via AWS CLI, since the `terraform-deployer` user itself isn't managed by this Terraform project -- see `modules/iam/main.tf`), attached the `TerraformCloudSecBaselineDeployer` policy to the group, added the user to the group, and then removed the direct attachment. Verified afterward with `terraform plan` that access still worked identically through the group.
- **Status:** ✅ Fixed and verified.

### s3_bucket_no_mfa_delete (×3) / cloudtrail_bucket_requires_mfa_delete -- MFA Delete is not enabled

- **Severity:** Medium
- **Resource:** All three S3 buckets (`cloud-sec-baseline-logs-khalid-4821`, `-access-logs`, `tfstate-cloudsec-khalid-7291`)
- **What it means:** MFA Delete requires an extra MFA code to change versioning status or delete object versions -- an extra layer of security against compromised credentials.
- **Why it's a hard AWS limitation:** MFA Delete can **only** be enabled via the AWS CLI/API using the root account's own credentials and a valid MFA code in the API call (`aws s3api put-bucket-versioning ... MFADelete=Enabled --mfa "..."`) -- neither IAM users/roles (regardless of permissions) nor Terraform can do this, and the AWS console doesn't support it either. Enabling this would require temporarily creating root access keys, which AWS itself advises against (and which Prowler flags as its own risk).
- **Status:** ⚠️ Accepted risk -- see section 5.

### iam_check_saml_providers_sts -- no SAML identity provider configured

- **Severity:** Low
- **Resource:** `arn:aws:iam::<account-id>:root`
- **What it means:** Prowler recommends SAML/SSO federation with temporary credentials instead of long-lived IAM user credentials.
- **Why it's not applicable here:** This is a recommendation for organizations with a workforce that signs in through an external identity provider (Okta, Azure AD, etc.). For a solo portfolio/practice project it isn't proportionate to set up a full SAML IdP integration -- the project already uses temporary STS credentials where it makes sense (the auditor and support roles, both MFA-gated assume-role).
- **Status:** ⚠️ Accepted / not relevant to the project's scope -- see section 5.

---

## 4. Before / after comparison

| Metric                  | Start (19:08) | After S3 fix (19:18) | After CloudWatch fix (20:27) | Final (Aug 26, 05:28) |
|--------------------------|--------|-------|-------|-------|
| Total FAIL               | 28     | 27    | 13    | **7** |
| CRITICAL severity FAIL   | 1      | 1 (accepted risk) | 1 (accepted risk) | 1 (accepted risk) |
| HIGH severity FAIL       | 1      | 0 ✅  | 0 ✅ | 0 ✅ |
| MEDIUM severity FAIL     | 19 (15 CloudWatch + 4 S3/IAM) | 19 | 5 (1 CloudWatch false positive + 4 new S3/IAM) | 2 (1 CloudWatch false positive, 1 group of MFA-delete across 3 buckets = 3 findings, see entry above) |
| LOW severity FAIL        | -      | -     | -     | 1 (SAML, accepted) |
| CIS 2.0 compliance score | 67.82% PASS | 68.97% PASS | 85.06% PASS | **92.05% PASS** |

---

## 5. Accepted risks

| Finding | Reason accepted | Compensating control |
|---------|------------------|------------------------|
| CKV_AWS_356/109/111 -- KMS policy `Resource=*` | AWS's recommended default pattern for KMS key policies; `"*"` means "this key", not all resources | Only the root account and the specific AWS service have access; key rotation is enabled |
| CKV_AWS_274 -- IAM roles without a permissions boundary | Both roles (auditor, support) already have minimal, precisely scoped access, an MFA requirement, and short sessions | ReadOnlyAccess/SecurityAudit/AWSSupportAccess are themselves narrow AWS-managed policies |
| CKV_AWS_252 -- CloudTrail without SNS | No active operations/on-call in this portfolio project to receive alerts | CloudWatch Logs integration still provides full, searchable logging for manual review |
| CKV2_AWS_62 -- S3 without event notifications | Would require an SNS/SQS/Lambda receiver no one subscribes to; unnecessary complexity for a demo project | Access logging and CloudTrail cover traceability |
| CKV_AWS_145 -- Log bucket uses AES256, not KMS | S3 access-logging delivery has historically not supported KMS-encrypted target buckets | The bucket is fully private (Public Access Block + BucketOwnerEnforced) |
| CKV_AWS_18 -- Log bucket without its own access logging | Circular to log access to the log bucket itself | N/A -- architecturally unnecessary |
| CKV_AWS_21 / CKV2_AWS_6 / CKV2_AWS_61 on logs[0] | False positives -- the resources exist, but Checkov can't connect them to a `count`-indexed bucket in its graph | Verified manually by adding the resource and re-running the scan |
| Prowler `iam_root_hardware_mfa_enabled` (CRITICAL) -- root has virtual MFA, not hardware MFA | Requires purchasing a physical hardware key; not acquired for a demo/practice project | Root still has MFA enabled (virtual), plus dedicated MFA-gated IAM roles are used day-to-day instead of root |
| Prowler `cloudwatch_log_metric_filter_aws_organizations_changes` (MEDIUM) -- false FAIL | Verified false positive: the metric filter and alarm are demonstrably correctly configured (regex test against Prowler's own source code + `aws logs describe-metric-filters` + `aws cloudwatch describe-alarms`) | Actual monitoring exists and works; this is purely a reporting issue in Prowler |
| Prowler `s3_bucket_no_mfa_delete` (×3) / `cloudtrail_bucket_requires_mfa_delete` (MEDIUM) | MFA Delete can only be enabled with the root account's credentials via CLI, not via Terraform, IAM roles, or the AWS console | The buckets are fully private, versioned, and encrypted; access happens only via MFA-gated roles, not direct user credentials |
| Prowler `iam_check_saml_providers_sts` (LOW) | Enterprise recommendation for SSO federation; not proportionate for a solo portfolio project | Temporary STS credentials are already used where relevant (the auditor and support roles) |

---

## 6. Lessons learned

The most instructive part of the remediation work wasn't the fixes
themselves, but learning to separate real findings from false positives and
from AWS-specific architectural constraints. A few things surprised me:

First, that "Resource = *" means something completely different in a KMS
key policy than in a regular IAM policy -- Checkov flags both the same way,
so it took actually understanding AWS's documentation instead of just
trusting the scanner blindly.

Second, I found a real limitation in Checkov itself: the tool doesn't
always manage to connect resources to an S3 bucket created with `count`,
even when the resource is clearly present in the code. I confirmed this
empirically by adding a missing resource and watching that the finding
didn't go away.

Third, and maybe most important: `terraform plan` showing "No changes" is
**not** watertight proof that the live resource actually matches the code.
When I added a `DenyInsecureTransport` statement to a bucket policy, `plan`
showed no diff -- but a direct `aws s3api get-bucket-policy` call revealed
the statement simply wasn't there in AWS. State held a value that didn't
match reality, and Terraform's refresh didn't automatically catch it for
this resource type. The fix was `terraform apply -replace=<resource>` to
force an actual write. The lesson: for security-critical resources (bucket
policies, IAM trust policies), it's worth verifying directly against the
AWS API in addition to trusting `terraform plan` -- especially after a file
has gone through several rounds of edits.

Fourth: not every Prowler finding is equally relevant to a solo portfolio
project. MFA Delete (requires root + CLI) and SAML federation (requires a
full IdP integration for a workforce that doesn't exist) are good examples
of findings where the right response is to document a justified accepted
risk, not force through a technical "fix" that doesn't provide real
security value in this context.

In a real production account, I'd probably fix SNS notifications and event
notifications right away instead of accepting the risk, since active
operational alerting is much more valuable when there's actually a team
watching. I'd also prioritize a physical MFA key on root and MFA Delete on
critical buckets early in a real production setup, since both are
relatively cheap measures against very severe scenarios (full account
compromise).

## License

MIT -- see [LICENSE](LICENSE).
