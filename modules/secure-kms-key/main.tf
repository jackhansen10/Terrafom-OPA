# KMS Key
resource "aws_kms_key" "this" {
  description                        = var.description
  deletion_window_in_days           = var.deletion_window_in_days
  enable_key_rotation               = var.enable_key_rotation
  key_usage                         = var.key_usage
  customer_master_key_spec          = var.customer_master_key_spec
  multi_region                     = var.multi_region
  bypass_policy_lockout_safety_check = var.bypass_policy_lockout_safety_check
  policy                           = var.key_policy != null ? var.key_policy : data.aws_iam_policy_document.kms_key_policy.json

  tags = merge(var.tags, {
    Name = var.key_alias
    Purpose = "encryption"
  })
}

# KMS Key Alias
resource "aws_kms_alias" "this" {
  name          = var.key_alias
  target_key_id = aws_kms_key.this.key_id
}

# Default secure key policy
data "aws_iam_policy_document" "kms_key_policy" {
  # Root account has full access
  statement {
    sid    = "EnableRootAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Allow specified principals to use the key
  dynamic "statement" {
    for_each = length(var.allowed_principals) > 0 ? [1] : []
    content {
      sid    = "AllowPrincipals"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.allowed_principals
      }
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = ["*"]
    }
  }

  # Allow specified services to use the key
  dynamic "statement" {
    for_each = length(var.allowed_services) > 0 ? [1] : []
    content {
      sid    = "AllowServices"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = var.allowed_services
      }
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = ["*"]
    }
  }

  # Enable CloudTrail logging if requested
  dynamic "statement" {
    for_each = var.enable_cloudtrail_logging ? [1] : []
    content {
      sid    = "EnableCloudTrailLogging"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      actions = [
        "kms:GenerateDataKey*"
      ]
      resources = ["*"]
      condition {
        test     = "StringLike"
        variable = "kms:EncryptionContext:aws:cloudtrail:arn"
        values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
      }
    }
  }
}

data "aws_caller_identity" "current" {}

# CloudWatch Log Group for KMS key usage (if CloudTrail logging enabled)
resource "aws_cloudwatch_log_group" "kms_logs" {
  count = var.enable_cloudtrail_logging ? 1 : 0
  
  name              = "/aws/kms/${replace(var.key_alias, "alias/", "")}"
  retention_in_days = 90
  
  tags = merge(var.tags, {
    Name = "${replace(var.key_alias, "alias/", "")}-logs"
    Purpose = "kms-audit-logs"
  })
}
