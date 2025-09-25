locals {
  logging_bucket_name = var.logging_bucket_name
}

# KMS Key for S3 encryption
# COMPLIANCE CONTROL MAPPINGS:
# SOC 2 CC6.3: Data Transmission and Disposal - Encryption key management
# SOC 2 CC6.7: Data Transmission and Disposal - Key rotation
# PCI DSS 3.4: Render PAN unreadable - Encryption key management
# PCI DSS 3.6.1: Key management - Key rotation
# PCI DSS 3.6.2: Key management - Key lifecycle management
# ISO 27001 A.13.2.1: Information transfer policies - Encryption key management
# ISO 27001 A.13.2.3: Cryptographic controls - Key rotation
# NIST CSF PR.DS-1: Data-at-rest protection - Encryption key management
# NIST CSF PR.DS-2: Data-in-transit protection - Key management
resource "aws_kms_key" "s3" {
  description             = "KMS key for encrypting S3 objects at rest"
  deletion_window_in_days = var.kms_deletion_window_in_days  # SOC 2 CC6.3, PCI DSS 3.6.2, ISO 27001 A.13.2.1, NIST CSF PR.DS-1
  enable_key_rotation     = true  # SOC 2 CC6.7, PCI DSS 3.6.1, ISO 27001 A.13.2.3, NIST CSF PR.DS-1
  tags                    = merge(var.tags, { "Name" = "s3-kms" })
}

resource "aws_kms_alias" "s3" {
  name          = var.kms_key_alias
  target_key_id = aws_kms_key.s3.key_id
}

resource "aws_s3_bucket" "logs" {
  bucket        = local.logging_bucket_name
  force_destroy = var.force_destroy
  tags          = merge(var.tags, { "Name" = local.logging_bucket_name, "Purpose" = "access-logs" })
}

# S3 Bucket Public Access Block for Logs Bucket
# COMPLIANCE CONTROL MAPPINGS:
# SOC 2 CC6.1: Logical and Physical Access Controls - Public access prevention
# SOC 2 CC6.2: System Access Controls - Access restrictions
# PCI DSS 1.2.1: Restrict inbound and outbound traffic - Public access blocking
# PCI DSS 7.1: Restrict access to cardholder data - Public access prevention
# ISO 27001 A.13.1.1: Network controls - Public access restrictions
# ISO 27001 A.13.1.2: Network controls - Access control implementation
# NIST CSF PR.AC-3: Remote access management - Public access controls
# NIST CSF PR.AC-5: Network integrity - Access restrictions
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true  # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
  block_public_policy     = true  # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
  ignore_public_acls      = true  # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
  restrict_public_buckets = true  # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id
  acl    = "log-delivery-write"
  depends_on = [
    aws_s3_bucket_ownership_controls.logs,
    aws_s3_bucket_public_access_block.logs
  ]
}

resource "aws_s3_bucket" "this" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy
  tags          = merge(var.tags, { "Name" = var.bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    filter {}
  }

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_expiration_days
    }
    filter {}
  }
}

data "aws_iam_policy_document" "this" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyUnEncryptedObjectUploads"
    effect  = "Deny"
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:InitiateMultipartUpload"
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.this.arn}/*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.s3.arn]
    }
  }

  dynamic "statement" {
    for_each = length(var.restrict_to_vpc_endpoint_ids) > 0 ? [1] : []
    content {
      sid     = "DenyRequestsNotFromAllowedVPCEndpoints"
      effect  = "Deny"
      actions = ["s3:*"]
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      resources = [
        aws_s3_bucket.this.arn,
        "${aws_s3_bucket.this.arn}/*"
      ]
      condition {
        test     = "ForAnyValue:StringNotEquals"
        variable = "aws:sourceVpce"
        values   = var.restrict_to_vpc_endpoint_ids
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json
}
