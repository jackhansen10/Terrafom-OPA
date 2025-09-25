#!/bin/bash
# Example script showing how to use Checkov policies with the existing examples

echo "Running Checkov policies on Terraform examples..."
echo "================================================"

# Install Checkov if not already installed
if ! command -v checkov &> /dev/null; then
    echo "Installing Checkov..."
    pip install checkov
fi

echo ""
echo "Testing RDS example..."
cd examples/secure-rds
checkov -d . --framework terraform --external-checks-dir ../../checkov-policies/ --check CKV_AWS_RDS_ --output cli
echo ""

echo "Testing S3 example..."
cd ../secure-s3-bucket
checkov -d . --framework terraform --external-checks-dir ../../checkov-policies/ --check CKV_AWS_S3_ --output cli
echo ""

echo "Testing DynamoDB example..."
cd ../secure-dynamodb
checkov -d . --framework terraform --external-checks-dir ../../checkov-policies/ --check CKV_AWS_DYNAMODB_ --output cli
echo ""

echo "Testing KMS example..."
cd ../secure-kms-key
checkov -d . --framework terraform --external-checks-dir ../../checkov-policies/ --check CKV_AWS_KMS_ --output cli
echo ""

echo "Testing secure EKS example..."
cd ../secure-eks
checkov -d . --framework terraform --external-checks-dir ../../checkov-policies/ --download-external-modules true --check CKV_AWS_EKS_ --output cli
echo ""

echo "Testing insecure EKS example..."
cd ../insecure-eks
checkov -d . --framework terraform --external-checks-dir ../../checkov-policies/ --download-external-modules true --check CKV_AWS_EKS_ --output cli
echo ""

echo "All examples tested!"
