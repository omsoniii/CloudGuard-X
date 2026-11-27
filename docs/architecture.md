
# CloudGuard X — AWS Architecture

## Infrastructure Overview

```mermaid
flowchart TD
    IAM["IAM Identity Center<br/>SSO + MFA"]

    IAM --> Deploy["Terraform Deployment Role"]
    IAM --> Audit["Read-only Security Audit Role"]

    subgraph AWS["AWS Cloud - Mumbai Region"]
        subgraph VPC["VPC - 10.0.0.0/16"]
            subgraph Subnet["Private Subnet - 10.0.1.0/24"]
                SG["Restricted Security Group"]
                EC2["EC2 - t3.micro<br/>Amazon Linux 2023"]
                EBS["Encrypted EBS - 8 GiB gp3"]

                SG -. Protects .-> EC2
                EC2 --- EBS
            end
        end

        CT["Multi-region CloudTrail"]
        S3["Secure S3 Bucket<br/>AES-256 Encryption<br/>Public Access Block"]

        CT -->|Audit Logs| S3
    end

    Deploy -->|Provision and Cleanup| VPC
    Deploy --> S3
    Deploy --> CT

    Audit --> Scanner["Python and Boto3 Scanner"]

    Scanner -->|Read-only API Checks| AWS
    Scanner --> Evidence["Historical Audit Evidence"]

    Evidence --> Generator["Python Report Generator"]
    Generator --> Dashboard["CloudGuard X Dashboard"]

    classDef identity fill:#182b43,stroke:#60a5fa,color:#fff
    classDef terraform fill:#28213f,stroke:#a78bfa,color:#fff
    classDef secure fill:#12352f,stroke:#2dd4bf,color:#fff
    classDef compute fill:#382a20,stroke:#fb923c,color:#fff

    class IAM,Audit,Scanner identity
    class Deploy terraform
    class SG,EBS,S3,Dashboard secure
    class EC2 compute
```

## Security Architecture

- Separate deployment and read-only audit roles.
- Private subnet without public IP assignment.
- Restricted security group.
- IMDSv2 enforced on the EC2 instance.
- Encrypted EBS storage.
- S3 public access protection and server-side encryption.
- Multi-region CloudTrail management event logging.
- Automated security checks using Python and Boto3.
- Historical audit reporting and remediation verification.

## Infrastructure Lifecycle

Resources were provisioned and tested in stages.
The EC2 instance was terminated before the S3 and
CloudTrail testing phase.

Lab infrastructure was destroyed after testing
to minimize AWS costs.

This architecture represents the historical lab,
not currently running infrastructure.

## Compliance Scope

This project demonstrates selected SOC 2-inspired
technical security controls. It does not constitute
SOC 2 certification or a comprehensive compliance audit.
