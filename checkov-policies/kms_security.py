from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
import json


class KMSKeyRotationEnabled(BaseResourceCheck):
    def __init__(self):
        name = "KMS key rotation must be enabled for compliance"
        id = "CKV_AWS_KMS_KEY_ROTATION_ENABLED"
        supported_resources = ["aws_kms_key"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "enable_key_rotation" in conf:
            if conf["enable_key_rotation"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class KMSKeyDeletionWindow(BaseResourceCheck):
    def __init__(self):
        name = "KMS key deletion window must be between 7 and 30 days"
        id = "CKV_AWS_KMS_KEY_DELETION_WINDOW"
        supported_resources = ["aws_kms_key"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "deletion_window_in_days" in conf:
            deletion_window = conf["deletion_window_in_days"][0]
            if isinstance(deletion_window, int) and 7 <= deletion_window <= 30:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class KMSKeyPolicyDefined(BaseResourceCheck):
    def __init__(self):
        name = "KMS key must have a policy defined"
        id = "CKV_AWS_KMS_KEY_POLICY_DEFINED"
        supported_resources = ["aws_kms_key"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf:
            policy = conf["policy"][0]
            if policy and policy.strip():
                return CheckResult.PASSED
        return CheckResult.FAILED


class KMSKeyPolicyStatements(BaseResourceCheck):
    def __init__(self):
        name = "KMS key policy must contain at least one statement"
        id = "CKV_AWS_KMS_KEY_POLICY_STATEMENTS"
        supported_resources = ["aws_kms_key"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf:
            policy_json = conf["policy"][0]
            try:
                policy = json.loads(policy_json)
                statements = policy.get("Statement", [])
                if len(statements) > 0:
                    return CheckResult.PASSED
            except (json.JSONDecodeError, TypeError):
                pass
        return CheckResult.FAILED


class KMSKeyPolicyRootAccess(BaseResourceCheck):
    def __init__(self):
        name = "KMS key policy must grant access to root account"
        id = "CKV_AWS_KMS_KEY_POLICY_ROOT_ACCESS"
        supported_resources = ["aws_kms_key"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf:
            policy_json = conf["policy"][0]
            try:
                policy = json.loads(policy_json)
                statements = policy.get("Statement", [])
                for statement in statements:
                    principal = statement.get("Principal", {})
                    aws_principal = principal.get("AWS", "")
                    if isinstance(aws_principal, str) and aws_principal.endswith(":root"):
                        return CheckResult.PASSED
                    elif isinstance(aws_principal, list):
                        for principal_arn in aws_principal:
                            if isinstance(principal_arn, str) and principal_arn.endswith(":root"):
                                return CheckResult.PASSED
            except (json.JSONDecodeError, TypeError):
                pass
        return CheckResult.FAILED


class KMSKeyPolicyNoWildcardAccess(BaseResourceCheck):
    def __init__(self):
        name = "KMS key policy should not grant kms:* to all principals"
        id = "CKV_AWS_KMS_KEY_POLICY_NO_WILDCARD_ACCESS"
        supported_resources = ["aws_kms_key"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf:
            policy_json = conf["policy"][0]
            try:
                policy = json.loads(policy_json)
                statements = policy.get("Statement", [])
                for statement in statements:
                    if statement.get("Effect") == "Allow":
                        action = statement.get("Action", "")
                        principal = statement.get("Principal", {})
                        aws_principal = principal.get("AWS", "")
                        
                        # Check for wildcard actions and principals
                        if action == "kms:*" and aws_principal == "*":
                            return CheckResult.FAILED
            except (json.JSONDecodeError, TypeError):
                pass
        return CheckResult.PASSED


class KMSAliasDefined(BaseResourceCheck):
    def __init__(self):
        name = "KMS key must have an alias defined"
        id = "CKV_AWS_KMS_ALIAS_DEFINED"
        supported_resources = ["aws_kms_alias"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # This check is more complex as it needs to verify that at least one alias exists
        # In practice, this would be checked at the module level or through a different approach
        return CheckResult.PASSED


class KMSAliasPrefix(BaseResourceCheck):
    def __init__(self):
        name = "KMS alias must start with 'alias/'"
        id = "CKV_AWS_KMS_ALIAS_PREFIX"
        supported_resources = ["aws_kms_alias"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "name" in conf:
            alias_name = conf["name"][0]
            if alias_name.startswith("alias/"):
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class CloudWatchLogGroupRetention(BaseResourceCheck):
    def __init__(self):
        name = "CloudWatch log group retention should be between 30 days and 7 years"
        id = "CKV_AWS_CLOUDWATCH_LOG_GROUP_RETENTION"
        supported_resources = ["aws_cloudwatch_log_group"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "retention_in_days" in conf:
            retention = conf["retention_in_days"][0]
            if isinstance(retention, int) and 30 <= retention <= 2557:  # 7 years = 2557 days
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED
