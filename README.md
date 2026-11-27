
# 🛡️ CloudGuard X

### AWS Cloud Security & Compliance Automation Lab

![AWS](https://img.shields.io/badge/AWS-Cloud-FF9900?style=for-the-badge&logo=amazonwebservices&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-IaC-844FBA?style=for-the-badge&logo=terraform&logoColor=white)
![Python](https://img.shields.io/badge/Python-Automation-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Focus-Cloud%20Security-00BFA5?style=for-the-badge)

## Project Overview

CloudGuard X is a hands-on cloud security and
compliance automation project that demonstrates
secure AWS infrastructure deployment, automated
security assessments, misconfiguration detection,
remediation, and evidence-based reporting.

The project uses Terraform for Infrastructure as
Code, Python and Boto3 for automated AWS security
checks, and an interactive HTML dashboard for
visualizing security findings.

The assessment is inspired by selected SOC 2
technical security controls.

## Key Results

| Metric | Result |
|---|---:|
| Evaluated security checks | 12 |
| Passed checks in final assessment | 12 |
| Failed checks in final assessment | 0 |
| Final recorded pass rate | 100% |
| Verified security remediations | 2 |
| CloudTrail log delivery | Verified |
| Lab infrastructure cleanup | Completed |

These results represent a historical assessment
of selected security controls before infrastructure
cleanup.

## Architecture

The AWS infrastructure was deployed in the
Mumbai region (ap-south-1).

[View Architecture Diagram](docs/architecture.md)

## Technology Stack

| Technology | Purpose |
|---|---|
| AWS | Cloud infrastructure |
| Terraform | Infrastructure as Code |
| Python | Security automation |
| Boto3 | AWS API integration |
| AWS CLI | Verification and remediation |
| IAM Identity Center | Secure authentication |
| HTML, CSS, JavaScript | Interactive reporting |
| Git and GitHub | Version control |

## AWS Infrastructure

- Custom VPC with CIDR 10.0.0.0/16
- Private subnet with CIDR 10.0.1.0/24
- Restricted security group
- Amazon EC2 t3.micro
- Amazon Linux 2023
- IMDSv2 enforcement
- Encrypted 8 GiB gp3 EBS storage
- Secure Amazon S3 bucket
- Multi-region AWS CloudTrail
- Separate audit and deployment permission sets

Resources were deployed and tested in stages.
The EC2 instance was terminated before the S3
and CloudTrail deployment phase.

## Automated Security Checks

The Python scanner evaluates the following
security configurations:

| Security Domain | Control |
|---|---|
| Identity Security | Root account MFA |
| Identity Security | Root access key detection |
| IAM Permissions | Direct AdministratorAccess attachments |
| Data Protection | S3 public access block |
| Data Protection | S3 default encryption |
| Network Security | Selected public security group exposure |
| Storage Security | EBS volume encryption |
| Storage Security | Regional EBS default encryption |
| Audit Logging | CloudTrail logging status |
| Audit Logging | Multi-region trail configuration |
| Audit Logging | Log file validation |

## Security Findings and Remediation

### AWS-EBS-001 — EBS Default Encryption Disabled

**Finding:** Regional EBS default encryption
was disabled.

**Risk:** Future EBS volumes could be created
without encryption unless explicitly configured.

**Remediation:** Enabled EBS encryption by
default in the Mumbai region using AWS CLI.

**Retest:** PASS

### AWS-NET-001 — Unrestricted SSH Ingress

**Finding:** A temporary inbound TCP port 22 rule
allowed access from 0.0.0.0/0.

**Testing environment:** An isolated lab security
group with no attached network interfaces.

**Remediation:** Revoked the temporary public
SSH ingress rule.

**Retest:** PASS

This was a controlled misconfiguration test
performed to validate the scanner's detection
and remediation verification capabilities.

## Security Testing Methodology

1. Provision infrastructure using Terraform.
2. Perform automated security assessments.
3. Record baseline audit evidence.
4. Identify insecure configurations.
5. Apply targeted remediation.
6. Repeat the security assessment.
7. Compare before-and-after results.
8. Generate a compliance-inspired dashboard.
9. Remove temporary AWS infrastructure.

## CloudGuard X Dashboard

The HTML dashboard provides:

- Security posture visualization
- Animated security indicators
- Historical assessment analytics
- Interactive audit explorer
- Security domain filtering
- Searchable audit findings
- Remediation tracking
- Infrastructure topology
- Browser-based PDF export

The dashboard uses recorded audit evidence
rather than fabricated security results.

It runs locally without requiring active AWS
infrastructure.

## Repository Structure

    aws-cloud-security-lab/
    ├── terraform/
    │   ├── main.tf
    │   └── .terraform.lock.hcl
    ├── docs/
    │   └── architecture.md
    ├── scanner.py
    ├── generate_report.py
    ├── requirements.txt
    ├── .gitignore
    └── README.md

Private reports, Terraform state files,
credentials, and raw CloudTrail logs are
excluded from the public repository.

## Local Setup

### Prerequisites

- Python
- Terraform
- AWS CLI
- AWS account
- AWS IAM Identity Center access

### Install Python Dependencies

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### AWS Authentication

Configure separate AWS SSO profiles:

- cloud-security-audit
- cloud-security-deploy

```bash
aws configure sso
aws sso login --profile cloud-security-audit
```

### Run Security Scanner

```bash
python scanner.py
```

### Review Terraform Configuration

```bash
cd terraform
terraform init
terraform validate
terraform plan
```

Review the required permissions, account settings,
resource configurations, and estimated AWS
charges before deploying infrastructure.

The EC2 resource is disabled by default in
the final Terraform configuration.

### Generate HTML Dashboard

The report generator requires locally available
audit evidence files in the reports directory.

These files are excluded from the public
repository for security and privacy reasons.

Once the required evidence is available:

```bash
python generate_report.py
```

Open the generated compliance-dashboard.html
file in a browser.

## Cost Management

- No NAT Gateway was deployed.
- No public IPv4 address was assigned to EC2.
- EC2 was terminated after security testing.
- EBS volume deletion was verified.
- CloudTrail logging was removed.
- S3 audit logs and temporary storage were removed.
- Remaining Terraform-managed resources were destroyed.
- AWS budget monitoring was configured.

Final billing is subject to AWS billing updates.

## Security and Compliance Limitations

This is a personal cybersecurity learning project.

The scanner evaluates selected technical security
configurations and does not provide comprehensive
AWS security coverage.

The IAM check detects direct AdministratorAccess
policy attachments rather than all possible
effective administrative permissions.

The dashboard represents historical audit results
and is not a live monitoring platform.

A 100% recorded pass rate does not establish
complete cloud security or SOC 2 compliance.

This project is not a SOC 2 certification.

## Skills Demonstrated

- AWS Cloud Security
- Infrastructure as Code
- IAM and Access Management
- Python Security Automation
- Cloud Misconfiguration Detection
- Security Remediation
- Encryption and Data Protection
- Cloud Audit Logging
- Security Assessment Reporting
- Cloud Infrastructure Lifecycle Management

---

**CloudGuard X**

A hands-on cybersecurity portfolio project
focused on cloud security, automation,
and compliance-inspired assessments.
