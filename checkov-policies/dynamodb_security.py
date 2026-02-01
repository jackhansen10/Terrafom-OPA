from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class DynamoDBTableServerSideEncryption(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB table must have server-side encryption enabled"
        id = "CKV_AWS_DYNAMODB_SSE_ENABLED"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "server_side_encryption" in conf:
            sse_config = conf["server_side_encryption"]
            if isinstance(sse_config, list) and len(sse_config) > 0:
                sse_enabled = sse_config[0].get("enabled")
                if sse_enabled:
                    return CheckResult.PASSED
        return CheckResult.FAILED


class DynamoDBTablePointInTimeRecovery(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB table must have point-in-time recovery enabled"
        id = "CKV_AWS_DYNAMODB_PITR_ENABLED"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "point_in_time_recovery" in conf:
            pitr_config = conf["point_in_time_recovery"]
            if isinstance(pitr_config, list) and len(pitr_config) > 0:
                pitr_enabled = pitr_config[0].get("enabled")
                if pitr_enabled:
                    return CheckResult.PASSED
        return CheckResult.FAILED


class DynamoDBTableDeletionProtection(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB table should have deletion protection enabled"
        id = "CKV_AWS_DYNAMODB_DELETION_PROTECTION"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "deletion_protection" in conf:
            deletion_protection = conf["deletion_protection"]
            if isinstance(deletion_protection, list) and len(deletion_protection) > 0:
                protection_enabled = deletion_protection[0].get("enabled")
                if protection_enabled:
                    return CheckResult.PASSED
        return CheckResult.FAILED


class DynamoDBTableBackupEnabled(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB table should have backup enabled"
        id = "CKV_AWS_DYNAMODB_BACKUP_ENABLED"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "backup" in conf:
            backup_config = conf["backup"]
            if isinstance(backup_config, list) and len(backup_config) > 0:
                backup_enabled = backup_config[0].get("enabled")
                if backup_enabled:
                    return CheckResult.PASSED
        return CheckResult.FAILED


class DynamoDBBackupRetentionPeriod(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB backup retention must be between 1 and 35 days"
        id = "CKV_AWS_DYNAMODB_BACKUP_RETENTION_PERIOD"
        supported_resources = ["aws_dynamodb_table_backup"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "backup_retention_period" in conf:
            retention = conf["backup_retention_period"][0]
            if isinstance(retention, int) and 1 <= retention <= 35:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class DynamoDBTableHashKey(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB table must have a hash key defined"
        id = "CKV_AWS_DYNAMODB_HASH_KEY"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "hash_key" in conf:
            hash_key = conf["hash_key"][0]
            if hash_key and hash_key.strip():
                return CheckResult.PASSED
        return CheckResult.FAILED


class DynamoDBTableHashKeyAttribute(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB table must have attribute definition for hash key"
        id = "CKV_AWS_DYNAMODB_HASH_KEY_ATTRIBUTE"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "hash_key" in conf and "attribute" in conf:
            hash_key = conf["hash_key"][0]
            attributes = conf["attribute"]
            for attr in attributes:
                if isinstance(attr, dict) and attr.get("name") == hash_key:
                    return CheckResult.PASSED
        return CheckResult.FAILED


class DynamoDBTableRangeKeyAttribute(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB table must have attribute definition for range key"
        id = "CKV_AWS_DYNAMODB_RANGE_KEY_ATTRIBUTE"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "range_key" in conf and "attribute" in conf:
            range_key = conf["range_key"][0]
            if range_key:
                attributes = conf["attribute"]
                for attr in attributes:
                    if isinstance(attr, dict) and attr.get("name") == range_key:
                        return CheckResult.PASSED
        return CheckResult.PASSED  # No range key is acceptable


class DynamoDBGSIHashKeyAttribute(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB GSI hash key must have attribute definition"
        id = "CKV_AWS_DYNAMODB_GSI_HASH_KEY_ATTRIBUTE"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "global_secondary_index" in conf and "attribute" in conf:
            gsis = conf["global_secondary_index"]
            attributes = conf["attribute"]
            attribute_names = [attr.get("name") for attr in attributes if isinstance(attr, dict)]
            
            for gsi in gsis:
                if isinstance(gsi, dict) and "hash_key" in gsi:
                    gsi_hash_key = gsi["hash_key"]
                    if gsi_hash_key not in attribute_names:
                        return CheckResult.FAILED
        return CheckResult.PASSED


class DynamoDBLSIRangeKeyAttribute(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB LSI range key must have attribute definition"
        id = "CKV_AWS_DYNAMODB_LSI_RANGE_KEY_ATTRIBUTE"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "local_secondary_index" in conf and "attribute" in conf:
            lsis = conf["local_secondary_index"]
            attributes = conf["attribute"]
            attribute_names = [attr.get("name") for attr in attributes if isinstance(attr, dict)]
            
            for lsi in lsis:
                if isinstance(lsi, dict) and "range_key" in lsi:
                    lsi_range_key = lsi["range_key"]
                    if lsi_range_key not in attribute_names:
                        return CheckResult.FAILED
        return CheckResult.PASSED


class DynamoDBTTLAttributeName(BaseResourceCheck):
    def __init__(self):
        name = "DynamoDB TTL must specify attribute name when enabled"
        id = "CKV_AWS_DYNAMODB_TTL_ATTRIBUTE_NAME"
        supported_resources = ["aws_dynamodb_table"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "ttl" in conf:
            ttl_config = conf["ttl"]
            if isinstance(ttl_config, list) and len(ttl_config) > 0:
                ttl_enabled = ttl_config[0].get("enabled")
                if ttl_enabled:
                    attribute_name = ttl_config[0].get("attribute_name")
                    if attribute_name and attribute_name.strip():
                        return CheckResult.PASSED
                    else:
                        return CheckResult.FAILED
        return CheckResult.PASSED

