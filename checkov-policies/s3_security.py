from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
import json


class S3BucketSSEKMS(BaseResourceCheck):
    def __init__(self):
        name = "S3 bucket must use SSE with aws:kms"
        id = "CKV_AWS_S3_SSE_KMS"
        supported_resources = ["aws_s3_bucket_server_side_encryption_configuration"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "rule" in conf:
            rules = conf["rule"]
            for rule in rules:
                if isinstance(rule, dict) and "apply_server_side_encryption_by_default" in rule:
                    sse_config = rule["apply_server_side_encryption_by_default"]
                    if isinstance(sse_config, list) and len(sse_config) > 0:
                        sse_algorithm = sse_config[0].get("sse_algorithm")
                        if sse_algorithm == "aws:kms":
                            return CheckResult.PASSED
        return CheckResult.FAILED


class S3BucketKeyEnabled(BaseResourceCheck):
    def __init__(self):
        name = "S3 bucket should enable Bucket Keys for SSE-KMS"
        id = "CKV_AWS_S3_BUCKET_KEY_ENABLED"
        supported_resources = ["aws_s3_bucket_server_side_encryption_configuration"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "rule" in conf:
            rules = conf["rule"]
            for rule in rules:
                if isinstance(rule, dict) and "bucket_key_enabled" in rule:
                    if rule["bucket_key_enabled"][0]:
                        return CheckResult.PASSED
        return CheckResult.FAILED


class S3PublicAccessBlockAcls(BaseResourceCheck):
    def __init__(self):
        name = "S3 public access block: block_public_acls must be true"
        id = "CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_ACLS"
        supported_resources = ["aws_s3_bucket_public_access_block"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "block_public_acls" in conf:
            if conf["block_public_acls"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class S3PublicAccessBlockPolicy(BaseResourceCheck):
    def __init__(self):
        name = "S3 public access block: block_public_policy must be true"
        id = "CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_POLICY"
        supported_resources = ["aws_s3_bucket_public_access_block"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "block_public_policy" in conf:
            if conf["block_public_policy"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class S3PublicAccessBlockIgnoreAcls(BaseResourceCheck):
    def __init__(self):
        name = "S3 public access block: ignore_public_acls must be true"
        id = "CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_IGNORE_ACLS"
        supported_resources = ["aws_s3_bucket_public_access_block"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "ignore_public_acls" in conf:
            if conf["ignore_public_acls"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class S3PublicAccessBlockRestrictBuckets(BaseResourceCheck):
    def __init__(self):
        name = "S3 public access block: restrict_public_buckets must be true"
        id = "CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_RESTRICT_BUCKETS"
        supported_resources = ["aws_s3_bucket_public_access_block"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "restrict_public_buckets" in conf:
            if conf["restrict_public_buckets"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class S3BucketOwnerEnforced(BaseResourceCheck):
    def __init__(self):
        name = "S3 bucket ownership must be BucketOwnerEnforced"
        id = "CKV_AWS_S3_BUCKET_OWNER_ENFORCED"
        supported_resources = ["aws_s3_bucket_ownership_controls"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "rule" in conf:
            rules = conf["rule"]
            for rule in rules:
                if isinstance(rule, dict) and "object_ownership" in rule:
                    ownership = rule["object_ownership"][0]
                    if ownership == "BucketOwnerEnforced":
                        return CheckResult.PASSED
        return CheckResult.FAILED


class S3BucketVersioningEnabled(BaseResourceCheck):
    def __init__(self):
        name = "S3 bucket versioning must be Enabled"
        id = "CKV_AWS_S3_BUCKET_VERSIONING_ENABLED"
        supported_resources = ["aws_s3_bucket_versioning"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "versioning_configuration" in conf:
            versioning_config = conf["versioning_configuration"]
            if isinstance(versioning_config, list) and len(versioning_config) > 0:
                status = versioning_config[0].get("status")
                if status == "Enabled":
                    return CheckResult.PASSED
        return CheckResult.FAILED


class S3BucketLoggingEnabled(BaseResourceCheck):
    def __init__(self):
        name = "S3 server access logging must target a logging bucket"
        id = "CKV_AWS_S3_BUCKET_LOGGING_ENABLED"
        supported_resources = ["aws_s3_bucket_logging"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "target_bucket" in conf:
            target_bucket = conf["target_bucket"][0]
            if target_bucket and target_bucket.strip():
                return CheckResult.PASSED
        return CheckResult.FAILED


class S3BucketPolicyDenyInsecureTransport(BaseResourceCheck):
    def __init__(self):
        name = "Bucket policy must deny insecure transport (TLS only)"
        id = "CKV_AWS_S3_BUCKET_POLICY_DENY_INSECURE_TRANSPORT"
        supported_resources = ["aws_s3_bucket_policy"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf:
            policy_json = conf["policy"][0]
            try:
                policy = json.loads(policy_json)
                statements = policy.get("Statement", [])
                for statement in statements:
                    if statement.get("Sid") == "DenyInsecureTransport":
                        return CheckResult.PASSED
            except (json.JSONDecodeError, TypeError):
                pass
        return CheckResult.FAILED


class S3BucketPolicyDenyUnencryptedUploads(BaseResourceCheck):
    def __init__(self):
        name = "Bucket policy must deny unencrypted uploads (aws:kms with CMK)"
        id = "CKV_AWS_S3_BUCKET_POLICY_DENY_UNENCRYPTED_UPLOADS"
        supported_resources = ["aws_s3_bucket_policy"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf:
            policy_json = conf["policy"][0]
            try:
                policy = json.loads(policy_json)
                statements = policy.get("Statement", [])
                for statement in statements:
                    if statement.get("Sid") == "DenyUnEncryptedObjectUploads":
                        return CheckResult.PASSED
            except (json.JSONDecodeError, TypeError):
                pass
        return CheckResult.FAILED


class S3BucketPolicyVPCEndpointRestriction(BaseResourceCheck):
    def __init__(self):
        name = "Bucket policy VPCE restriction present but not enforcing aws:sourceVpce"
        id = "CKV_AWS_S3_BUCKET_POLICY_VPCE_RESTRICTION"
        supported_resources = ["aws_s3_bucket_policy"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf:
            policy_json = conf["policy"][0]
            try:
                policy = json.loads(policy_json)
                statements = policy.get("Statement", [])
                for statement in statements:
                    if statement.get("Sid") == "DenyRequestsNotFromAllowedVPCEndpoints":
                        condition = statement.get("Condition", {})
                        for_any_value = condition.get("ForAnyValue", {})
                        string_not_equals = for_any_value.get("StringNotEquals", {})
                        if "aws:sourceVpce" in string_not_equals:
                            return CheckResult.PASSED
                        else:
                            return CheckResult.FAILED
            except (json.JSONDecodeError, TypeError):
                pass
        return CheckResult.PASSED
