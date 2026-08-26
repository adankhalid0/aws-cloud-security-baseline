# CIS AWS Foundations Benchmark 2.0 -- section 4 (Monitoring).
# Fixes 15 Prowler findings: cloudwatch_log_metric_filter_* / cloudwatch_changes_to_*
# All 15 shared the same root cause: "No CloudWatch log groups found with metric
# filters or alarms associated." -- i.e. the CloudTrail logging itself existed,
# but no metric filters/alarms were wired up to it.
#
# Each entry in local.cis_alarms corresponds to one CIS 2.0 control: a metric
# filter that counts matches in the CloudTrail logs, and an alarm that
# notifies via SNS when the filter matches at least once.
#
# The patterns below were verified directly against Prowler's source code
# (not just the CIS documentation, which turned out to diverge from the
# actual validation logic on three points: unauthorized_api_calls,
# route_table_changes, organizations_changes).

locals {
  cis_alarms = {
    unauthorized_api_calls = {
      cis_id      = "3.1"
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
      description = "Unauthorized API calls (AccessDenied / UnauthorizedOperation)."
    }
    console_signin_without_mfa = {
      cis_id      = "3.2"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
      description = "Sign-in to the AWS console without MFA."
    }
    root_account_usage = {
      cis_id      = "3.3"
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      description = "The root account was used directly."
    }
    iam_policy_changes = {
      cis_id      = "3.4"
      pattern     = "{ ($.eventName = \"DeleteGroupPolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachGroupPolicy\") || ($.eventName = \"DetachGroupPolicy\") }"
      description = "Changes to IAM policies."
    }
    cloudtrail_config_changes = {
      cis_id      = "3.5"
      pattern     = "{ ($.eventName = \"CreateTrail\") || ($.eventName = \"UpdateTrail\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"StartLogging\") || ($.eventName = \"StopLogging\") }"
      description = "Changes to the CloudTrail configuration."
    }
    console_auth_failures = {
      cis_id      = "3.6"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
      description = "Failed sign-in attempts to the AWS console."
    }
    kms_cmk_disable_or_delete = {
      cis_id      = "3.7"
      pattern     = "{ ($.eventSource = \"kms.amazonaws.com\") && (($.eventName = \"DisableKey\") || ($.eventName = \"ScheduleKeyDeletion\")) }"
      description = "Disabling or scheduled deletion of a KMS key."
    }
    s3_bucket_policy_changes = {
      cis_id      = "3.8"
      pattern     = "{ ($.eventSource = \"s3.amazonaws.com\") && (($.eventName = \"PutBucketAcl\") || ($.eventName = \"PutBucketPolicy\") || ($.eventName = \"PutBucketCors\") || ($.eventName = \"PutBucketLifecycle\") || ($.eventName = \"PutBucketReplication\") || ($.eventName = \"DeleteBucketPolicy\") || ($.eventName = \"DeleteBucketCors\") || ($.eventName = \"DeleteBucketLifecycle\") || ($.eventName = \"DeleteBucketReplication\")) }"
      description = "Changes to S3 bucket policies/ACLs."
    }
    aws_config_changes = {
      cis_id      = "3.9"
      pattern     = "{ ($.eventSource = \"config.amazonaws.com\") && (($.eventName = \"StopConfigurationRecorder\") || ($.eventName = \"DeleteDeliveryChannel\") || ($.eventName = \"PutDeliveryChannel\") || ($.eventName = \"PutConfigurationRecorder\")) }"
      description = "Changes to the AWS Config configuration."
    }
    security_group_changes = {
      cis_id      = "3.10"
      pattern     = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"
      description = "Changes to security groups."
    }
    network_acl_changes = {
      cis_id      = "3.11"
      pattern     = "{ ($.eventName = \"CreateNetworkAcl\") || ($.eventName = \"CreateNetworkAclEntry\") || ($.eventName = \"DeleteNetworkAcl\") || ($.eventName = \"DeleteNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclAssociation\") }"
      description = "Changes to Network ACLs."
    }
    network_gateway_changes = {
      cis_id      = "3.12"
      pattern     = "{ ($.eventName = \"CreateCustomerGateway\") || ($.eventName = \"DeleteCustomerGateway\") || ($.eventName = \"AttachInternetGateway\") || ($.eventName = \"CreateInternetGateway\") || ($.eventName = \"DeleteInternetGateway\") || ($.eventName = \"DetachInternetGateway\") }"
      description = "Changes to network gateways (IGW/customer gateway)."
    }
    route_table_changes = {
      cis_id      = "3.13"
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && (($.eventName = \"CreateRoute\") || ($.eventName = \"CreateRouteTable\") || ($.eventName = \"ReplaceRoute\") || ($.eventName = \"ReplaceRouteTableAssociation\") || ($.eventName = \"DeleteRouteTable\") || ($.eventName = \"DeleteRoute\") || ($.eventName = \"DisassociateRouteTable\")) }"
      description = "Changes to route tables."
    }
    vpc_changes = {
      cis_id      = "3.14"
      pattern     = "{ ($.eventName = \"CreateVpc\") || ($.eventName = \"DeleteVpc\") || ($.eventName = \"ModifyVpcAttribute\") || ($.eventName = \"AcceptVpcPeeringConnection\") || ($.eventName = \"CreateVpcPeeringConnection\") || ($.eventName = \"DeleteVpcPeeringConnection\") || ($.eventName = \"RejectVpcPeeringConnection\") || ($.eventName = \"AttachClassicLinkVpc\") || ($.eventName = \"DetachClassicLinkVpc\") || ($.eventName = \"DisableVpcClassicLink\") || ($.eventName = \"EnableVpcClassicLink\") }"
      description = "Changes to VPCs."
    }
    organizations_changes = {
      cis_id      = "3.15"
      pattern     = "{ ($.eventSource = \"organizations.amazonaws.com\") && (($.eventName = \"AcceptHandshake\") || ($.eventName = \"AttachPolicy\") || ($.eventName = \"CancelHandshake\") || ($.eventName = \"CreateAccount\") || ($.eventName = \"CreateOrganization\") || ($.eventName = \"CreateOrganizationalUnit\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeclineHandshake\") || ($.eventName = \"DeleteOrganization\") || ($.eventName = \"DeleteOrganizationalUnit\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"DetachPolicy\") || ($.eventName = \"DisablePolicyType\") || ($.eventName = \"EnableAllFeatures\") || ($.eventName = \"EnablePolicyType\") || ($.eventName = \"InviteAccountToOrganization\") || ($.eventName = \"LeaveOrganization\") || ($.eventName = \"MoveAccount\") || ($.eventName = \"RemoveAccountFromOrganization\") || ($.eventName = \"UpdateOrganizationalUnit\") || ($.eventName = \"UpdatePolicy\")) }"
      description = "Changes to AWS Organizations."
    }
  }
}

# SNS topic the alarms notify. AWS-managed KMS key (alias/aws/sns)
# provides encryption at rest without having to create and pay for another CMK.
resource "aws_sns_topic" "cis_alarms" {
  name              = "cis-benchmark-security-alarms"
  kms_master_key_id = "alias/aws/sns"
}

data "aws_iam_policy_document" "cis_alarms_topic" {
  statement {
    sid     = "AllowCloudWatchAlarmsToPublish"
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    resources = [aws_sns_topic.cis_alarms.arn]
  }
}

resource "aws_sns_topic_policy" "cis_alarms" {
  arn    = aws_sns_topic.cis_alarms.arn
  policy = data.aws_iam_policy_document.cis_alarms_topic.json
}

resource "aws_sns_topic_subscription" "cis_alarms_email" {
  count     = var.alarm_notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.cis_alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_notification_email
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each       = local.cis_alarms
  name           = "cis-${each.value.cis_id}-${each.key}"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name          = "cis-${each.value.cis_id}-${each.key}"
    namespace     = "CISBenchmark"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each            = local.cis_alarms
  alarm_name          = "CIS-${each.value.cis_id}-${each.key}"
  alarm_description   = "CIS 2.0 AWS Foundations Benchmark ${each.value.cis_id}: ${each.value.description}"
  namespace           = "CISBenchmark"
  metric_name         = "cis-${each.value.cis_id}-${each.key}"
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.cis]
}
