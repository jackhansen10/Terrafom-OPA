# Compliance Control Mappings

This document explains how compliance controls from major frameworks are mapped to specific lines of code in our Terraform modules. This mapping helps compliance personnel quickly identify which code implements each control requirement during audits and certifications.

## Supported Compliance Frameworks

- **SOC 2**: Service Organization Control 2 (Type II)
- **PCI DSS**: Payment Card Industry Data Security Standard
- **ISO 27001**: Information Security Management System
- **NIST CSF**: National Institute of Standards and Technology Cybersecurity Framework

## Control Mapping Format

Each Terraform resource includes:

1. **Header Comment Block**: Lists all applicable controls for the resource
2. **Inline Comments**: Specific controls mapped to individual configuration lines
3. **Control Reference**: Framework abbreviation + control number + description

### Example Format:
```hcl
# Resource Name
# COMPLIANCE CONTROL MAPPINGS:
# SOC 2 CC6.1: Logical and Physical Access Controls - Description
# PCI DSS 1.2.1: Restrict inbound and outbound traffic - Description
# ISO 27001 A.13.1.1: Network controls - Description
# NIST CSF PR.AC-3: Remote access management - Description
resource "aws_resource" "example" {
  setting1 = "value"  # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
  setting2 = "value"  # SOC 2 CC6.2, PCI DSS 1.2.2, ISO 27001 A.13.1.2, NIST CSF PR.AC-4
}
```

## Control Categories by Service

### EKS (Elastic Kubernetes Service)

**Access Controls:**
- SOC 2 CC6.1: Logical and Physical Access Controls
- SOC 2 CC6.2: System Access Controls
- PCI DSS 1.2.1: Restrict inbound and outbound traffic
- ISO 27001 A.13.1.1: Network controls
- NIST CSF PR.AC-3: Remote access management

**Data Protection:**
- SOC 2 CC6.3: Data Transmission and Disposal
- PCI DSS 3.4: Render PAN unreadable
- ISO 27001 A.13.2.1: Information transfer policies
- NIST CSF PR.DS-1: Data-at-rest protection

**Monitoring & Logging:**
- SOC 2 CC7.1: System Monitoring
- PCI DSS 10.1: Implement audit trails
- ISO 27001 A.12.4.1: Event logging
- NIST CSF DE.AE-1: Baseline network operations

### S3 (Simple Storage Service)

**Access Controls:**
- SOC 2 CC6.1: Logical and Physical Access Controls
- PCI DSS 1.2.1: Restrict inbound and outbound traffic
- PCI DSS 7.1: Restrict access to cardholder data
- ISO 27001 A.13.1.1: Network controls
- NIST CSF PR.AC-3: Remote access management

**Data Protection:**
- SOC 2 CC6.3: Data Transmission and Disposal
- PCI DSS 3.4: Render PAN unreadable
- ISO 27001 A.13.2.1: Information transfer policies
- NIST CSF PR.DS-1: Data-at-rest protection

**Key Management:**
- SOC 2 CC6.7: Data Transmission and Disposal
- PCI DSS 3.6.1: Key management
- PCI DSS 3.6.2: Key lifecycle management
- ISO 27001 A.13.2.3: Cryptographic controls

### KMS (Key Management Service)

**Key Management:**
- SOC 2 CC6.3: Data Transmission and Disposal
- SOC 2 CC6.7: Data Transmission and Disposal
- PCI DSS 3.6.1: Key management
- PCI DSS 3.6.2: Key lifecycle management
- ISO 27001 A.13.2.1: Information transfer policies
- ISO 27001 A.13.2.3: Cryptographic controls
- NIST CSF PR.DS-1: Data-at-rest protection
- NIST CSF PR.DS-2: Data-in-transit protection

### DynamoDB

**Data Protection:**
- SOC 2 CC6.3: Data Transmission and Disposal
- PCI DSS 3.4: Render PAN unreadable
- ISO 27001 A.13.2.1: Information transfer policies
- NIST CSF PR.DS-1: Data-at-rest protection

**Backup & Recovery:**
- SOC 2 CC7.3: System Monitoring
- PCI DSS 12.10: Implement incident response procedures
- ISO 27001 A.12.3.1: Information backup
- NIST CSF RS.RP-1: Response planning

### RDS (Relational Database Service)

**Data Protection:**
- SOC 2 CC6.3: Data Transmission and Disposal
- PCI DSS 3.4: Render PAN unreadable
- ISO 27001 A.13.2.1: Information transfer policies
- NIST CSF PR.DS-1: Data-at-rest protection

**Monitoring & Logging:**
- SOC 2 CC7.1: System Monitoring
- PCI DSS 10.1: Implement audit trails
- ISO 27001 A.12.4.1: Event logging
- NIST CSF DE.AE-1: Baseline network operations

### CloudTrail

**Monitoring & Logging:**
- SOC 2 CC7.1: System Monitoring
- SOC 2 CC7.2: Change detection
- PCI DSS 10.1: Implement audit trails
- PCI DSS 10.3: Record audit trail entries
- ISO 27001 A.12.4.1: Event logging
- ISO 27001 A.16.1.7: Evidence collection
- NIST CSF DE.AE-1: Baseline network operations
- NIST CSF DE.CM-1: Continuous monitoring

## Using Control Mappings for Audits

### For Compliance Personnel:

1. **Identify Control Requirements**: Reference the specific control from your framework
2. **Locate Implementation**: Search for the control reference in Terraform files
3. **Verify Configuration**: Check that the mapped line implements the control correctly
4. **Document Evidence**: Reference specific file names and line numbers in audit reports

### For Developers:

1. **Understand Requirements**: Review control mappings when modifying code
2. **Maintain Compliance**: Ensure changes don't break control implementations
3. **Add New Controls**: Follow the established format when adding new compliance features

## Search Examples

To find implementations of specific controls:

```bash
# Find SOC 2 CC6.1 implementations
grep -r "SOC 2 CC6.1" modules/

# Find PCI DSS 3.4 implementations
grep -r "PCI DSS 3.4" modules/

# Find ISO 27001 A.13.1.1 implementations
grep -r "ISO 27001 A.13.1.1" modules/

# Find NIST CSF PR.AC-3 implementations
grep -r "NIST CSF PR.AC-3" modules/
```

## Control Mapping Status

| Service | SOC 2 | PCI DSS | ISO 27001 | NIST CSF | Status |
|---------|-------|---------|-----------|----------|--------|
| EKS     | ✅    | ✅      | ✅        | ✅       | Complete |
| S3      | ✅    | ✅      | ✅        | ✅       | Complete |
| KMS     | ✅    | ✅      | ✅        | ✅       | Complete |
| DynamoDB| ✅    | ✅      | ✅        | ✅       | Complete |
| RDS     | ✅    | ✅      | ✅        | ✅       | Complete |
| CloudTrail | ✅ | ✅      | ✅        | ✅       | Complete |

## Contributing

When adding new compliance controls:

1. Follow the established comment format
2. Include all applicable frameworks
3. Map controls to specific configuration lines
4. Update this documentation
5. Test control implementations

## References

- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/document_library/)
- [ISO 27001 Controls](https://www.iso.org/isoiec-27001-information-security.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

