# CIS AWS Foundations Benchmark 2.0 -- seksjon 4 (Monitoring).
# Fikser 15 Prowler-funn: cloudwatch_log_metric_filter_* / cloudwatch_changes_to_*
# Alle 15 hadde samme rotårsak: "No CloudWatch log groups found with metric
# filters or alarms associated." -- dvs. selve CloudTrail-loggingen fantes,
# men ingen metric filters/alarmer var koblet til den.
#
# Hver oppføring i local.cis_alarms tilsvarer én CIS 2.0-kontroll: et metric
# filter som teller treff i CloudTrail-loggene, og en alarm som varsler via
# SNS når filteret treffer minst én gang.
#
# Mønstrene under er verifisert direkte mot Prowlers kildekode (ikke bare CIS-
# dokumentasjonen, som viste seg å avvike fra selve valideringslogikken på tre
# punkter: unauthorized_api_calls, route_table_changes, organizations_changes).

locals {
  cis_alarms = {
    unauthorized_api_calls = {
      cis_id      = "3.1"
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
      description = "Uautoriserte API-kall (AccessDenied / UnauthorizedOperation)."
    }
    console_signin_without_mfa = {
      cis_id      = "3.2"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
      description = "Innlogging i AWS-konsollen uten MFA."
    }
    root_account_usage = {
      cis_id      = "3.3"
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      description = "Root-kontoen ble brukt direkte."
    }
    iam_policy_changes = {
      cis_id      = "3.4"
      pattern     = "{ ($.eventName = \"DeleteGroupPolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachGroupPolicy\") || ($.eventName = \"DetachGroupPolicy\") }"
      description = "Endringer i IAM-policyer."
    }
    cloudtrail_config_changes = {
      cis_id      = "3.5"
      pattern     = "{ ($.eventName = \"CreateTrail\") || ($.eventName = \"UpdateTrail\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"StartLogging\") || ($.eventName = \"StopLogging\") }"
      description = "Endringer i CloudTrail-konfigurasjonen."
    }
    console_auth_failures = {
      cis_id      = "3.6"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
      description = "Mislykkede innloggingsforsøk i AWS-konsollen."
    }
    kms_cmk_disable_or_delete = {
      cis_id      = "3.7"
      pattern     = "{ ($.eventSource = \"kms.amazonaws.com\") && (($.eventName = \"DisableKey\") || ($.eventName = \"ScheduleKeyDeletion\")) }"
      description = "Deaktivering eller planlagt sletting av en KMS-nøkkel."
    }
    s3_bucket_policy_changes = {
      cis_id      = "3.8"
      pattern     = "{ ($.eventSource = \"s3.amazonaws.com\") && (($.eventName = \"PutBucketAcl\") || ($.eventName = \"PutBucketPolicy\") || ($.eventName = \"PutBucketCors\") || ($.eventName = \"PutBucketLifecycle\") || ($.eventName = \"PutBucketReplication\") || ($.eventName = \"DeleteBucketPolicy\") || ($.eventName = \"DeleteBucketCors\") || ($.eventName = \"DeleteBucketLifecycle\") || ($.eventName = \"DeleteBucketReplication\")) }"
      description = "Endringer i S3 bucket-policyer/ACL-er."
    }
    aws_config_changes = {
      cis_id      = "3.9"
      pattern     = "{ ($.eventSource = \"config.amazonaws.com\") && (($.eventName = \"StopConfigurationRecorder\") || ($.eventName = \"DeleteDeliveryChannel\") || ($.eventName = \"PutDeliveryChannel\") || ($.eventName = \"PutConfigurationRecorder\")) }"
      description = "Endringer i AWS Config-konfigurasjonen."
    }
    security_group_changes = {
      cis_id      = "3.10"
      pattern     = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"
      description = "Endringer i sikkerhetsgrupper."
    }
    network_acl_changes = {
      cis_id      = "3.11"
      pattern     = "{ ($.eventName = \"CreateNetworkAcl\") || ($.eventName = \"CreateNetworkAclEntry\") || ($.eventName = \"DeleteNetworkAcl\") || ($.eventName = \"DeleteNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclAssociation\") }"
      description = "Endringer i Network ACL-er."
    }
    network_gateway_changes = {
      cis_id      = "3.12"
      pattern     = "{ ($.eventName = \"CreateCustomerGateway\") || ($.eventName = \"DeleteCustomerGateway\") || ($.eventName = \"AttachInternetGateway\") || ($.eventName = \"CreateInternetGateway\") || ($.eventName = \"DeleteInternetGateway\") || ($.eventName = \"DetachInternetGateway\") }"
      description = "Endringer i nettverks-gatewayer (IGW/customer gateway)."
    }
    route_table_changes = {
      cis_id      = "3.13"
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && (($.eventName = \"CreateRoute\") || ($.eventName = \"CreateRouteTable\") || ($.eventName = \"ReplaceRoute\") || ($.eventName = \"ReplaceRouteTableAssociation\") || ($.eventName = \"DeleteRouteTable\") || ($.eventName = \"DeleteRoute\") || ($.eventName = \"DisassociateRouteTable\")) }"
      description = "Endringer i rutetabeller."
    }
    vpc_changes = {
      cis_id      = "3.14"
      pattern     = "{ ($.eventName = \"CreateVpc\") || ($.eventName = \"DeleteVpc\") || ($.eventName = \"ModifyVpcAttribute\") || ($.eventName = \"AcceptVpcPeeringConnection\") || ($.eventName = \"CreateVpcPeeringConnection\") || ($.eventName = \"DeleteVpcPeeringConnection\") || ($.eventName = \"RejectVpcPeeringConnection\") || ($.eventName = \"AttachClassicLinkVpc\") || ($.eventName = \"DetachClassicLinkVpc\") || ($.eventName = \"DisableVpcClassicLink\") || ($.eventName = \"EnableVpcClassicLink\") }"
      description = "Endringer i VPC-er."
    }
    organizations_changes = {
      cis_id      = "3.15"
      pattern     = "{ ($.eventSource = \"organizations.amazonaws.com\") && (($.eventName = \"AcceptHandshake\") || ($.eventName = \"AttachPolicy\") || ($.eventName = \"CancelHandshake\") || ($.eventName = \"CreateAccount\") || ($.eventName = \"CreateOrganization\") || ($.eventName = \"CreateOrganizationalUnit\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeclineHandshake\") || ($.eventName = \"DeleteOrganization\") || ($.eventName = \"DeleteOrganizationalUnit\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"DetachPolicy\") || ($.eventName = \"DisablePolicyType\") || ($.eventName = \"EnableAllFeatures\") || ($.eventName = \"EnablePolicyType\") || ($.eventName = \"InviteAccountToOrganization\") || ($.eventName = \"LeaveOrganization\") || ($.eventName = \"MoveAccount\") || ($.eventName = \"RemoveAccountFromOrganization\") || ($.eventName = \"UpdateOrganizationalUnit\") || ($.eventName = \"UpdatePolicy\")) }"
      description = "Endringer i AWS Organizations."
    }
  }
}

# SNS-topic alarmene varsler til. AWS-administrert KMS-nøkkel (alias/aws/sns)
# gir kryptering i hvile uten å måtte opprette og betale for enda en CMK.
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
