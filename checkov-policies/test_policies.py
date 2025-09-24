#!/usr/bin/env python3
"""
Test script for Checkov policies
This script validates that the custom Checkov policies are properly structured and can be imported.
"""

import sys
import os

# Add the checkov-policies directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'checkov-policies'))

def test_policy_imports():
    """Test that all policy modules can be imported successfully."""
    try:
        # Import the registry directly
        import __init__
        registry = __init__.REGISTRY
        print(f"✓ Successfully imported {len(registry)} policies")
        
        # Test individual policy imports
        from rds_security import RDSStorageEncryption
        from s3_security import S3BucketSSEKMS
        from dynamodb_security import DynamoDBTableServerSideEncryption
        from kms_security import KMSKeyRotationEnabled
        
        print("✓ All policy modules imported successfully")
        
        # Test policy instantiation
        rds_policy = RDSStorageEncryption()
        s3_policy = S3BucketSSEKMS()
        dynamodb_policy = DynamoDBTableServerSideEncryption()
        kms_policy = KMSKeyRotationEnabled()
        
        print("✓ All policies instantiated successfully")
        
        # Print policy summary
        print("\nPolicy Summary:")
        print(f"RDS Policies: {len([p for p in registry if 'RDS' in p.id])}")
        print(f"S3 Policies: {len([p for p in registry if 'S3' in p.id])}")
        print(f"DynamoDB Policies: {len([p for p in registry if 'DYNAMODB' in p.id])}")
        print(f"KMS Policies: {len([p for p in registry if 'KMS' in p.id])}")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_policy_structure():
    """Test that policies have the required structure."""
    try:
        import __init__
        registry = __init__.REGISTRY
        
        for policy in registry:
            # Check required attributes
            assert hasattr(policy, 'name'), f"Policy {policy.__class__.__name__} missing 'name'"
            assert hasattr(policy, 'id'), f"Policy {policy.__class__.__name__} missing 'id'"
            assert hasattr(policy, 'supported_resources'), f"Policy {policy.__class__.__name__} missing 'supported_resources'"
            assert hasattr(policy, 'scan_resource_conf'), f"Policy {policy.__class__.__name__} missing 'scan_resource_conf'"
            
            # Check ID format
            assert policy.id.startswith('CKV_AWS_'), f"Policy {policy.id} doesn't follow naming convention"
            
        print("✓ All policies have correct structure")
        return True
        
    except AssertionError as e:
        print(f"✗ Structure error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    print("Testing Checkov Policies...")
    print("=" * 50)
    
    success = True
    success &= test_policy_imports()
    success &= test_policy_structure()
    
    print("=" * 50)
    if success:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print("✗ Some tests failed!")
        sys.exit(1)
