data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  trail_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"
  s3_key_prefix = trim(var.s3_key_prefix, "/")
  s3_logs_prefix = local.s3_key_prefix != "" ? "${local.s3_key_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}" : "AWSLogs/${data.aws_caller_identity.current.account_id}"
}

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log encryption"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.cloudtrail_kms_policy.json

  tags = merge(var.tags, {
    Name    = var.kms_key_alias
    Purpose = "cloudtrail-log-encryption"
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = var.kms_key_alias
  target_key_id = aws_kms_key.cloudtrail.key_id
}

data "aws_iam_policy_document" "cloudtrail_kms_policy" {
  statement {
    sid    = "EnableRootAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailUse"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = var.s3_bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.tags, {
    Name    = var.s3_bucket_name
    Purpose = "cloudtrail-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count  = var.s3_log_expiration_days == null ? 0 : 1
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "expire-cloudtrail-logs"
    status = "Enabled"
    expiration {
      days = var.s3_log_expiration_days
    }
    filter {}
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/${local.s3_logs_prefix}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudwatch_logging ? 1 : 0
  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.cloudwatch_log_group_retention_days

  tags = merge(var.tags, {
    Name    = "${var.trail_name}-logs"
    Purpose = "cloudtrail-audit-logs"
  })
}

data "aws_iam_policy_document" "cloudtrail_assume_role" {
  statement {
    sid     = "AllowCloudTrailAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail" {
  count              = var.enable_cloudwatch_logging ? 1 : 0
  name               = "${var.trail_name}-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "cloudtrail_logs_policy" {
  statement {
    sid     = "AllowCloudTrailWriteLogs"
    effect  = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = var.enable_cloudwatch_logging ? ["${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"] : []
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs_policy" {
  count  = var.enable_cloudwatch_logging ? 1 : 0
  name   = "${var.trail_name}-cloudtrail-logs"
  role   = aws_iam_role.cloudtrail[0].id
  policy = data.aws_iam_policy_document.cloudtrail_logs_policy.json
}

resource "aws_cloudtrail" "this" {
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  s3_key_prefix                 = local.s3_key_prefix != "" ? local.s3_key_prefix : null
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  enable_logging                = true
  enable_log_file_validation    = var.enable_log_file_validation
  is_multi_region_trail         = var.is_multi_region_trail
  include_global_service_events = var.include_global_service_events
  is_organization_trail         = var.is_organization_trail

  cloud_watch_logs_group_arn = var.enable_cloudwatch_logging ? "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*" : null
  cloud_watch_logs_role_arn  = var.enable_cloudwatch_logging ? aws_iam_role.cloudtrail[0].arn : null

  depends_on = [
    aws_s3_bucket_policy.cloudtrail
  ]

  tags = merge(var.tags, {
    Name    = var.trail_name
    Purpose = "cloudtrail"
  })
}
