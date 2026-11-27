
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = "ap-south-1"
  profile = "cloud-security-deploy"
}

# Create custom VPC
resource "aws_vpc" "lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "cloud-security-lab-vpc"
    Project = "CloudSecurityLab"
  }
}

# Create private subnet
resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name    = "cloud-security-private-subnet"
    Project = "CloudSecurityLab"
  }
}

# Secure Security Group
resource "aws_security_group" "lab_sg" {

  name        = "cloud-security-lab-sg"
  description = "Restricted security group for security lab"
  vpc_id      = aws_vpc.lab_vpc.id

  ingress = []
  egress  = []

  tags = {
    Name    = "cloud-security-lab-sg"
    Project = "CloudSecurityLab"
  }
}

# Find Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-6.18-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Secure EC2 Instance
resource "aws_instance" "lab_ec2" {
  count                       = 0
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_subnet.id
  vpc_security_group_ids      = [aws_security_group.lab_sg.id]
  associate_public_ip_address = false
  monitoring                  = false

  # Avoid surplus CPU credit charges
  credit_specification {
    cpu_credits = "standard"
  }

  # Enforce IMDSv2
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Encrypted storage
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name    = "cloud-security-lab-ec2"
    Project = "CloudSecurityLab"
  }
}

# S3 Bucket
resource "aws_s3_bucket" "lab_bucket" {
  bucket_prefix = "cloud-security-lab-"
  force_destroy = false

  tags = {
    Name    = "cloud-security-lab-bucket"
    Project = "CloudSecurityLab"
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "lab_bucket" {
  bucket = aws_s3_bucket.lab_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "lab_bucket" {
  bucket = aws_s3_bucket.lab_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enforce bucket ownership
resource "aws_s3_bucket_ownership_controls" "lab_bucket" {
  bucket = aws_s3_bucket.lab_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Enforce HTTPS connections

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "lab_bucket" {
  bucket = aws_s3_bucket.lab_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.lab_bucket.arn,
          "${aws_s3_bucket.lab_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport"       = "false"
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.lab_bucket.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:ap-south-1:${data.aws_caller_identity.current.account_id}:trail/cloud-security-lab-trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.lab_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:ap-south-1:${data.aws_caller_identity.current.account_id}:trail/cloud-security-lab-trail"
          }
        }
      }
    ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.lab_bucket
  ]
}



# CloudTrail Audit Logging
resource "aws_cloudtrail" "lab_trail" {
  name                          = "cloud-security-lab-trail"
  s3_bucket_name                = aws_s3_bucket.lab_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  is_organization_trail         = false

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name    = "cloud-security-lab-trail"
    Project = "CloudSecurityLab"
  }

  depends_on = [
    aws_s3_bucket_policy.lab_bucket,
    aws_s3_bucket_ownership_controls.lab_bucket,
    aws_s3_bucket_server_side_encryption_configuration.lab_bucket
  ]
}
