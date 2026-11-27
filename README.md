
# CloudGuard X

### AWS Cloud Security & Compliance Automation Lab

![Python](https://img.shields.io/badge/Python-Security_Automation-blue)
![AWS](https://img.shields.io/badge/AWS-Cloud_Security-orange)
![Terraform](https://img.shields.io/badge/Terraform-Infrastructure_as_Code-purple)
![Architecture](https://img.shields.io/badge/Architecture-Client_Side-teal)
![Security Tests](https://img.shields.io/badge/Security_Tests-5_Passed-green)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
## Overview

CloudGuard X is an AWS cloud security assessment and compliance automation project designed to identify selected cloud misconfigurations, evaluate security controls, and visualize security findings.

The project combines Infrastructure as Code, read-only AWS security assessments, verified remediation exercises, structured JSON reporting, and an interactive browser-based dashboard.

## Key Features

- Configurable AWS profile and region
- Read-only AWS security assessments using Python and Boto3
- Automated JSON report generation
- Interactive historical security dashboard
- Personal Audit Mode with JSON report import
- Dynamic security pass rate calculation
- Security domain analytics
- Rule-based remediation recommendations
- Searchable and filterable security findings
- Printable PDF assessment reports
- Browser-only report processing
- Beginner-friendly installation guide

## Security Assessment Coverage

| Domain | Assessment |
|---|---|
| Identity & Access | Root MFA, root access keys, direct AdministratorAccess attachments |
| Data Protection | S3 public access blocking and default encryption |
| Audit Logging | CloudTrail logging, multi-region configuration and log validation |
| Network Security | Selected unrestricted security group ingress rules |
| Encryption | EBS default encryption and volume encryption |

## Verified Lab Results

The historical assessment was recorded before the lab infrastructure was destroyed.

| Metric | Result |
|---|---|
| Passed evaluations | 12 |
| Failed evaluations | 0 |
| Warnings | 0 |
| Verified remediations | 2 |
| Final evaluated pass rate | 100% |

### Remediation Exercises

1. Detected and remediated disabled EBS default encryption.
2. Detected and removed a controlled unrestricted SSH ingress rule.

Both improvements were verified through subsequent security assessments.

## Application Security Testing

| Test | Result |
|---|---|
| Malformed JSON rejection | PASS |
| Invalid report schema rejection | PASS |
| Controlled XSS input test | PASS |
| Oversized file rejection | PASS |
| Manipulated score recalculation | PASS |

These results represent selected manual security tests, not a comprehensive penetration test.

## Technology Stack

- AWS
- Terraform
- Python
- Boto3
- AWS CLI
- AWS IAM Identity Center
- HTML5
- CSS3
- JavaScript
- GitHub

## Architecture

See [Architecture Documentation](docs/architecture.md).

The scanner runs locally using authorized AWS credentials. Generated JSON reports are imported into the browser-based dashboard without requiring a report-processing backend.

## Getting Started

### Prerequisites

- Python 3
- AWS CLI v2
- Git
- Authorized AWS account
- Appropriate read-only AWS permissions

### Installation

```bash
git clone https://github.com/omsoniii/CloudGuard-X.git
cd CloudGuard-X

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -r requirements.txt
```

### AWS Authentication

Configure an authorized read-only AWS profile.

```bash
aws configure sso --profile cloudguard-audit
aws sso login --profile cloudguard-audit
```

IAM Identity Center access must be provisioned by the AWS account administrator.

### Run a Security Assessment

```bash
python scanner.py \
  --profile cloudguard-audit \
  --region ap-south-1 \
  --output reports/cloudguard-report.json
```

For available options:

```bash
python scanner.py --help
```

### Launch Dashboard Locally

```bash
python -m http.server 8000 --bind 127.0.0.1 --directory docs
```

Open:

http://127.0.0.1:8000/

Select Personal Audit and import the generated JSON report.

Terraform deployment is not required to use the scanner.

## Project Structure

```text
CloudGuard-X/
├── docs/
│   ├── index.html
│   ├── personal-audit.html
│   ├── get-started.html
│   ├── audit.css
│   ├── audit.js
│   └── architecture.md
├── terraform/
│   ├── main.tf
│   └── .terraform.lock.hcl
├── scanner.py
├── generate_report.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Security & Privacy

- The scanner uses read-only AWS API operations.
- The website does not collect AWS credentials.
- Imported reports are processed in the browser.
- Private audit reports and Terraform state files are excluded from the repository.
- Security recommendations do not automatically modify AWS resources.
- Generated reports may contain sensitive resource names and should be kept private.

## Infrastructure Lifecycle

The AWS lab infrastructure was deployed, assessed, and destroyed after testing to minimize ongoing costs.

The historical dashboard represents recorded assessments, not live AWS monitoring.

The historical report generator requires private audit evidence that is not distributed with this repository. The published historical dashboard can be viewed independently.

## Limitations

- Selected security checks only.
- Regional assessments are limited to the selected region.
- Missing AWS permissions may interrupt an assessment.
- Imported report authenticity is not independently verified.
- Pass rates do not represent overall AWS account security.
- Cross-account and cross-platform compatibility testing is limited.
- SOC 2-inspired, not SOC 2 certified.

## Project Purpose

CloudGuard X is an educational cloud security engineering project demonstrating practical experience in AWS security, Infrastructure as Code, security automation, misconfiguration detection, remediation validation, and secure client-side application development.

## License

CloudGuard X is released under the MIT License.
See the [LICENSE](LICENSE) file for details.