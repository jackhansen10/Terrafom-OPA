from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class EKSClusterEncryptionAtRest(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must have encryption at rest enabled"
        id = "CKV_AWS_EKS_CLUSTER_ENCRYPTION_AT_REST"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "encryption_config" in conf:
            encryption_config = conf["encryption_config"]
            if isinstance(encryption_config, list) and len(encryption_config) > 0:
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterPrivateEndpoint(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must have private endpoint access only"
        id = "CKV_AWS_EKS_CLUSTER_PRIVATE_ENDPOINT"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "vpc_config" in conf:
            vpc_config = conf["vpc_config"]
            if isinstance(vpc_config, list) and len(vpc_config) > 0:
                vpc = vpc_config[0]
                if isinstance(vpc, dict):
                    endpoint_public_access = vpc.get("endpoint_public_access")
                    if endpoint_public_access is False:
                        return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterNoPublicCIDRs(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must disable public access CIDRs"
        id = "CKV_AWS_EKS_CLUSTER_NO_PUBLIC_CIDRS"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "vpc_config" in conf:
            vpc_config = conf["vpc_config"]
            if isinstance(vpc_config, list) and len(vpc_config) > 0:
                vpc = vpc_config[0]
                if isinstance(vpc, dict):
                    public_access_cidrs = vpc.get("public_access_cidrs", [])
                    if len(public_access_cidrs) == 0:
                        return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterAuditLogging(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must enable audit logging"
        id = "CKV_AWS_EKS_CLUSTER_AUDIT_LOGGING"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "enabled_cluster_log_types" in conf:
            enabled_logs = conf["enabled_cluster_log_types"]
            if isinstance(enabled_logs, list) and "audit" in enabled_logs:
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterAPILogging(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must enable API server logging"
        id = "CKV_AWS_EKS_CLUSTER_API_LOGGING"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "enabled_cluster_log_types" in conf:
            enabled_logs = conf["enabled_cluster_log_types"]
            if isinstance(enabled_logs, list) and "api" in enabled_logs:
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterAuthenticatorLogging(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must enable authenticator logging"
        id = "CKV_AWS_EKS_CLUSTER_AUTHENTICATOR_LOGGING"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "enabled_cluster_log_types" in conf:
            enabled_logs = conf["enabled_cluster_log_types"]
            if isinstance(enabled_logs, list) and "authenticator" in enabled_logs:
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterControllerManagerLogging(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must enable controller manager logging"
        id = "CKV_AWS_EKS_CLUSTER_CONTROLLER_MANAGER_LOGGING"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "enabled_cluster_log_types" in conf:
            enabled_logs = conf["enabled_cluster_log_types"]
            if isinstance(enabled_logs, list) and "controllerManager" in enabled_logs:
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterSchedulerLogging(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must enable scheduler logging"
        id = "CKV_AWS_EKS_CLUSTER_SCHEDULER_LOGGING"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "enabled_cluster_log_types" in conf:
            enabled_logs = conf["enabled_cluster_log_types"]
            if isinstance(enabled_logs, list) and "scheduler" in enabled_logs:
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterSecurityGroup(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must have security group configured"
        id = "CKV_AWS_EKS_CLUSTER_SECURITY_GROUP"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "vpc_config" in conf:
            vpc_config = conf["vpc_config"]
            if isinstance(vpc_config, list) and len(vpc_config) > 0:
                vpc = vpc_config[0]
                if isinstance(vpc, dict):
                    security_group_ids = vpc.get("security_group_ids", [])
                    if len(security_group_ids) > 0:
                        return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterVersion(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must use latest supported version"
        id = "CKV_AWS_EKS_CLUSTER_VERSION"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "version" in conf:
            version = conf["version"][0]
            # Check if version is 1.25 or higher
            if version >= "1.25":
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSNodeGroupCapacityType(BaseResourceCheck):
    def __init__(self):
        name = "EKS node group must use ON_DEMAND capacity type"
        id = "CKV_AWS_EKS_NODE_GROUP_CAPACITY_TYPE"
        supported_resources = ["aws_eks_node_group"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "capacity_type" in conf:
            capacity_type = conf["capacity_type"][0]
            if capacity_type == "ON_DEMAND":
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSNodeGroupUpdateConfig(BaseResourceCheck):
    def __init__(self):
        name = "EKS node group must have update configuration"
        id = "CKV_AWS_EKS_NODE_GROUP_UPDATE_CONFIG"
        supported_resources = ["aws_eks_node_group"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "update_config" in conf:
            update_config = conf["update_config"]
            if isinstance(update_config, list) and len(update_config) > 0:
                return CheckResult.PASSED
        return CheckResult.FAILED


class EKSNodeGroupMaxUnavailablePercentage(BaseResourceCheck):
    def __init__(self):
        name = "EKS node group update config must limit unavailable percentage"
        id = "CKV_AWS_EKS_NODE_GROUP_MAX_UNAVAILABLE_PERCENTAGE"
        supported_resources = ["aws_eks_node_group"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "update_config" in conf:
            update_config = conf["update_config"]
            if isinstance(update_config, list) and len(update_config) > 0:
                config = update_config[0]
                if isinstance(config, dict):
                    max_unavailable_percentage = config.get("max_unavailable_percentage")
                    if max_unavailable_percentage is not None and max_unavailable_percentage <= 25:
                        return CheckResult.PASSED
        return CheckResult.FAILED


class EKSNodeGroupMinSize(BaseResourceCheck):
    def __init__(self):
        name = "EKS node group must have minimum 2 nodes"
        id = "CKV_AWS_EKS_NODE_GROUP_MIN_SIZE"
        supported_resources = ["aws_eks_node_group"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "scaling_config" in conf:
            scaling_config = conf["scaling_config"]
            if isinstance(scaling_config, list) and len(scaling_config) > 0:
                config = scaling_config[0]
                if isinstance(config, dict):
                    min_size = config.get("min_size")
                    if min_size is not None and min_size >= 2:
                        return CheckResult.PASSED
        return CheckResult.FAILED


class EKSNodeGroupMaxSize(BaseResourceCheck):
    def __init__(self):
        name = "EKS node group must have maximum node limit"
        id = "CKV_AWS_EKS_NODE_GROUP_MAX_SIZE"
        supported_resources = ["aws_eks_node_group"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "scaling_config" in conf:
            scaling_config = conf["scaling_config"]
            if isinstance(scaling_config, list) and len(scaling_config) > 0:
                config = scaling_config[0]
                if isinstance(config, dict):
                    max_size = config.get("max_size")
                    if max_size is not None and max_size <= 100:
                        return CheckResult.PASSED
        return CheckResult.FAILED


class EKSClusterSubnetCount(BaseResourceCheck):
    def __init__(self):
        name = "EKS cluster must have proper subnet configuration"
        id = "CKV_AWS_EKS_CLUSTER_SUBNET_COUNT"
        supported_resources = ["aws_eks_cluster"]
        categories = ["security"]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "vpc_config" in conf:
            vpc_config = conf["vpc_config"]
            if isinstance(vpc_config, list) and len(vpc_config) > 0:
                vpc = vpc_config[0]
                if isinstance(vpc, dict):
                    subnet_ids = vpc.get("subnet_ids", [])
                    if len(subnet_ids) >= 2:
                        return CheckResult.PASSED
        return CheckResult.FAILED
