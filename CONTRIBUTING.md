# Contributing to Terraform Secure S3 Bucket Templates

Thank you for your interest in contributing to this project! This document provides guidelines for contributing to the Terraform Secure S3 Bucket Templates repository.

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct. Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Issues

- Use the GitHub issue tracker to report bugs or request features
- Provide clear descriptions, steps to reproduce, and expected vs actual behavior
- Include relevant environment details (Terraform version, AWS region, etc.)

### Submitting Changes

1. **Fork the repository** and create a feature branch
2. **Make your changes** following the existing code style and patterns
3. **Test your changes** thoroughly:
   - Run `terraform plan` and `terraform apply` in examples
   - Validate with OPA policies: `conftest test tfplan.json --policy ../policy`
   - Ensure compliance features remain intact
4. **Update documentation** as needed (README, module docs, etc.)
5. **Commit with clear messages** following conventional commit format
6. **Submit a pull request** with a detailed description

### Development Guidelines

- Follow Terraform best practices and style guidelines
- Maintain backward compatibility when possible
- Add appropriate variable descriptions and validation
- Include comprehensive documentation for new features
- Ensure all examples work with the changes
- Update OPA policies if security controls change

### Security Considerations

- All changes must maintain or improve security posture
- New features should align with SOC 2, PCI DSS, ISO 27001, and NIST CSF requirements
- Changes to encryption, access controls, or logging require careful review
- OPA policy validation must pass for all changes

### Review Process

- All pull requests require review before merging
- Security-related changes require additional scrutiny
- Maintainers will review for compliance, functionality, and documentation
- CI/CD checks must pass (if implemented)

## Attribution

When contributing, you agree that your contributions will be licensed under the same MIT License that covers the project. You retain copyright to your contributions but grant the project the right to use them.

## Questions?

Feel free to open an issue for questions about contributing or the project in general.
