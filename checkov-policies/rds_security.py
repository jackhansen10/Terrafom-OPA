from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class RDSStorageEncryption(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance must have storage encryption enabled"
        id = "CKV_AWS_RDS_STORAGE_ENCRYPTION"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "storage_encrypted" in conf:
            if conf["storage_encrypted"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class RDSBackupRetention(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance backup retention should be at least 1 day"
        id = "CKV_AWS_RDS_BACKUP_RETENTION"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "backup_retention_period" in conf:
            retention = conf["backup_retention_period"][0]
            if isinstance(retention, int) and retention >= 1:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class RDSDeletionProtection(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance should have deletion protection enabled"
        id = "CKV_AWS_RDS_DELETION_PROTECTION"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "deletion_protection" in conf:
            if conf["deletion_protection"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class RDSSkipFinalSnapshot(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance should not skip final snapshot"
        id = "CKV_AWS_RDS_SKIP_FINAL_SNAPSHOT"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "skip_final_snapshot" in conf:
            if not conf["skip_final_snapshot"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.PASSED  # Default is False, which is good


class RDSAutoMinorVersionUpgrade(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance should have auto minor version upgrade enabled"
        id = "CKV_AWS_RDS_AUTO_MINOR_VERSION_UPGRADE"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "auto_minor_version_upgrade" in conf:
            if conf["auto_minor_version_upgrade"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class RDSPerformanceInsights(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance should have Performance Insights enabled"
        id = "CKV_AWS_RDS_PERFORMANCE_INSIGHTS"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "performance_insights_enabled" in conf:
            if conf["performance_insights_enabled"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class RDSEnhancedMonitoring(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance should have enhanced monitoring enabled"
        id = "CKV_AWS_RDS_ENHANCED_MONITORING"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "monitoring_interval" in conf:
            interval = conf["monitoring_interval"][0]
            if isinstance(interval, int) and interval > 0:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class RDSManageMasterUserPassword(BaseResourceCheck):
    def __init__(self):
        name = "RDS instance should use Secrets Manager for password management"
        id = "CKV_AWS_RDS_MANAGE_MASTER_USER_PASSWORD"
        supported_resources = ["aws_db_instance"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "manage_master_user_password" in conf:
            if conf["manage_master_user_password"][0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.FAILED


class RDSSecurityGroupNoPublicAccess(BaseResourceCheck):
    def __init__(self):
        name = "RDS security group should not allow access from 0.0.0.0/0"
        id = "CKV_AWS_RDS_SECURITY_GROUP_NO_PUBLIC_ACCESS"
        supported_resources = ["aws_security_group"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "ingress" in conf:
            ingress_rules = conf["ingress"]
            for rule in ingress_rules:
                if isinstance(rule, dict):
                    cidr_blocks = rule.get("cidr_blocks", [])
                    if "0.0.0.0/0" in cidr_blocks:
                        return CheckResult.FAILED
        return CheckResult.PASSED

