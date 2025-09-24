# Checkov Policy Configuration
# This file defines custom policies that match the OPA policies in this repository

# RDS Security Policies
from checkov_policies.rds_security import (
    RDSStorageEncryption,
    RDSBackupRetention,
    RDSDeletionProtection,
    RDSSkipFinalSnapshot,
    RDSAutoMinorVersionUpgrade,
    RDSPerformanceInsights,
    RDSEnhancedMonitoring,
    RDSManageMasterUserPassword,
    RDSSecurityGroupNoPublicAccess
)

# S3 Security Policies
from checkov_policies.s3_security import (
    S3BucketSSEKMS,
    S3BucketKeyEnabled,
    S3PublicAccessBlockAcls,
    S3PublicAccessBlockPolicy,
    S3PublicAccessBlockIgnoreAcls,
    S3PublicAccessBlockRestrictBuckets,
    S3BucketOwnerEnforced,
    S3BucketVersioningEnabled,
    S3BucketLoggingEnabled,
    S3BucketPolicyDenyInsecureTransport,
    S3BucketPolicyDenyUnencryptedUploads,
    S3BucketPolicyVPCEndpointRestriction
)

# DynamoDB Security Policies
from checkov_policies.dynamodb_security import (
    DynamoDBTableServerSideEncryption,
    DynamoDBTablePointInTimeRecovery,
    DynamoDBTableDeletionProtection,
    DynamoDBTableBackupEnabled,
    DynamoDBBackupRetentionPeriod,
    DynamoDBTableHashKey,
    DynamoDBTableHashKeyAttribute,
    DynamoDBTableRangeKeyAttribute,
    DynamoDBGSIHashKeyAttribute,
    DynamoDBLSIRangeKeyAttribute,
    DynamoDBTTLAttributeName
)

# KMS Security Policies
from checkov_policies.kms_security import (
    KMSKeyRotationEnabled,
    KMSKeyDeletionWindow,
    KMSKeyPolicyDefined,
    KMSKeyPolicyStatements,
    KMSKeyPolicyRootAccess,
    KMSKeyPolicyNoWildcardAccess,
    KMSAliasDefined,
    KMSAliasPrefix,
    CloudWatchLogGroupRetention
)

# Register all policies
REGISTRY = [
    # RDS Policies
    RDSStorageEncryption(),
    RDSBackupRetention(),
    RDSDeletionProtection(),
    RDSSkipFinalSnapshot(),
    RDSAutoMinorVersionUpgrade(),
    RDSPerformanceInsights(),
    RDSEnhancedMonitoring(),
    RDSManageMasterUserPassword(),
    RDSSecurityGroupNoPublicAccess(),
    
    # S3 Policies
    S3BucketSSEKMS(),
    S3BucketKeyEnabled(),
    S3PublicAccessBlockAcls(),
    S3PublicAccessBlockPolicy(),
    S3PublicAccessBlockIgnoreAcls(),
    S3PublicAccessBlockRestrictBuckets(),
    S3BucketOwnerEnforced(),
    S3BucketVersioningEnabled(),
    S3BucketLoggingEnabled(),
    S3BucketPolicyDenyInsecureTransport(),
    S3BucketPolicyDenyUnencryptedUploads(),
    S3BucketPolicyVPCEndpointRestriction(),
    
    # DynamoDB Policies
    DynamoDBTableServerSideEncryption(),
    DynamoDBTablePointInTimeRecovery(),
    DynamoDBTableDeletionProtection(),
    DynamoDBTableBackupEnabled(),
    DynamoDBBackupRetentionPeriod(),
    DynamoDBTableHashKey(),
    DynamoDBTableHashKeyAttribute(),
    DynamoDBTableRangeKeyAttribute(),
    DynamoDBGSIHashKeyAttribute(),
    DynamoDBLSIRangeKeyAttribute(),
    DynamoDBTTLAttributeName(),
    
    # KMS Policies
    KMSKeyRotationEnabled(),
    KMSKeyDeletionWindow(),
    KMSKeyPolicyDefined(),
    KMSKeyPolicyStatements(),
    KMSKeyPolicyRootAccess(),
    KMSKeyPolicyNoWildcardAccess(),
    KMSAliasDefined(),
    KMSAliasPrefix(),
    CloudWatchLogGroupRetention()
]
