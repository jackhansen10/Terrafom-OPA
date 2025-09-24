#!/usr/bin/env python3
"""
Simple validation script for Checkov policies
This script validates the structure and syntax of the policy files without requiring Checkov to be installed.
"""

import ast
import os
import sys

def validate_python_syntax(file_path):
    """Validate that a Python file has correct syntax."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        ast.parse(content)
        return True, None
    except SyntaxError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def validate_policy_structure(file_path):
    """Validate that a policy file has the expected structure."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for required imports
        if 'from checkov.common.models.enums import CheckResult' not in content:
            return False, "Missing CheckResult import"
        
        if 'from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck' not in content:
            return False, "Missing BaseResourceCheck import"
        
        # Check for class definitions
        if 'class ' not in content:
            return False, "No class definitions found"
        
        # Check for required methods
        if 'def scan_resource_conf(self, conf):' not in content:
            return False, "Missing scan_resource_conf method"
        
        return True, None
        
    except Exception as e:
        return False, str(e)

def main():
    """Main validation function."""
    policy_files = [
        'rds_security.py',
        's3_security.py', 
        'dynamodb_security.py',
        'kms_security.py',
        '__init__.py'
    ]
    
    print("Validating Checkov Policy Files...")
    print("=" * 50)
    
    all_valid = True
    
    for policy_file in policy_files:
        if not os.path.exists(policy_file):
            print(f"✗ {policy_file}: File not found")
            all_valid = False
            continue
            
        # Validate syntax
        syntax_valid, syntax_error = validate_python_syntax(policy_file)
        if not syntax_valid:
            print(f"✗ {policy_file}: Syntax error - {syntax_error}")
            all_valid = False
            continue
        
        # Validate structure (skip __init__.py)
        if policy_file != '__init__.py':
            structure_valid, structure_error = validate_policy_structure(policy_file)
            if not structure_valid:
                print(f"✗ {policy_file}: Structure error - {structure_error}")
                all_valid = False
                continue
        
        print(f"✓ {policy_file}: Valid")
    
    print("=" * 50)
    if all_valid:
        print("✓ All policy files are valid!")
        
        # Count policies
        total_policies = 0
        for policy_file in policy_files:
            if policy_file != '__init__.py' and os.path.exists(policy_file):
                with open(policy_file, 'r') as f:
                    content = f.read()
                    # Count class definitions that inherit from BaseResourceCheck
                    class_count = content.count('class ') - content.count('class BaseResourceCheck')
                    total_policies += class_count
        
        print(f"Total policies created: {total_policies}")
        print("\nPolicy files are ready for use with Checkov!")
        print("To use these policies:")
        print("1. Install Checkov: pip install checkov")
        print("2. Run: checkov -d . --framework terraform --external-checks-dir checkov-policies/")
        
    else:
        print("✗ Some policy files have issues that need to be fixed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
