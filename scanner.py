
import boto3

session = boto3.Session(
    profile_name="cloud-security-audit",
    region_name="ap-south-1"
)

iam = session.client("iam")

summary = iam.get_account_summary()["SummaryMap"]

print("AWS CLOUD SECURITY SCANNER")
print("=" * 40)

# Check 1: Root MFA
if summary["AccountMFAEnabled"] == 1:
    print("[PASS] Root MFA is enabled")
else:
    print("[FAIL] Root MFA is disabled")

# Check 2: Root access keys
if summary["AccountAccessKeysPresent"] == 0:
    print("[PASS] No root access keys found")
else:
    print("[FAIL] Root access keys exist")

# S3 Security Audit
print("\nS3 SECURITY AUDIT")
print("=" * 40)

s3 = session.client("s3")
buckets = s3.list_buckets()["Buckets"]

print(f"Total S3 buckets: {len(buckets)}")

if not buckets:
    print("[INFO] No S3 buckets found")

for bucket in buckets:
    name = bucket["Name"]
    print(f"\nBucket: {name}")

    # Check Public Access Block
    try:
        config = s3.get_public_access_block(
            Bucket=name
        )["PublicAccessBlockConfiguration"]

        if all(config.values()):
            print("[PASS] Public access block enabled")
        else:
            print("[WARN] Public access block incomplete")

    except s3.exceptions.ClientError as error:
        print("[WARN] Unable to verify public access block")
        print(error.response["Error"]["Code"])

    # Check Encryption
    try:
        s3.get_bucket_encryption(Bucket=name)
        print("[PASS] Default encryption configured")

    except s3.exceptions.ClientError as error:
        print("[WARN] Unable to verify encryption")
        print(error.response["Error"]["Code"])

# CloudTrail Security Audit
print("\nCLOUDTRAIL SECURITY AUDIT")
print("=" * 40)

cloudtrail = session.client("cloudtrail")

trails = cloudtrail.describe_trails(
    includeShadowTrails=False
)["trailList"]

if not trails:
    print("[WARN] No dedicated CloudTrail trail found")

for trail in trails:
    print(f"\nTrail: {trail['Name']}")

    status = cloudtrail.get_trail_status(
        Name=trail["TrailARN"]
    )

    if status["IsLogging"]:
        print("[PASS] CloudTrail logging enabled")
    else:
        print("[FAIL] CloudTrail logging disabled")

    if trail.get("IsMultiRegionTrail"):
        print("[PASS] Multi-region trail enabled")
    else:
        print("[WARN] Multi-region trail disabled")

    if trail.get("LogFileValidationEnabled"):
        print("[PASS] Log file validation enabled")
    else:
        print("[WARN] Log file validation disabled")

# EC2 Security Group Audit
print("\nEC2 SECURITY GROUP AUDIT")
print("=" * 40)

ec2 = session.client("ec2")

groups = []

paginator = ec2.get_paginator("describe_security_groups")

for page in paginator.paginate():
    groups.extend(page["SecurityGroups"])

print(f"Total security groups: {len(groups)}")

for group in groups:
    print(f"\nSecurity Group: {group['GroupName']}")

    risky = False

    for rule in group["IpPermissions"]:
        public_ipv4 = any(
            ip.get("CidrIp") == "0.0.0.0/0"
            for ip in rule.get("IpRanges", [])
        )

        public_ipv6 = any(
            ip.get("CidrIpv6") == "::/0"
            for ip in rule.get("Ipv6Ranges", [])
        )

        if not (public_ipv4 or public_ipv6):
            continue

        protocol = rule["IpProtocol"]

        if protocol == "-1":
            print("[FAIL] All traffic open to internet")
            risky = True

        elif protocol in ("tcp", "6"):
            start = rule.get("FromPort", 0)
            end = rule.get("ToPort", 65535)

            if start <= 22 <= end:
                print("[FAIL] SSH open to internet")
                risky = True

            if start <= 3389 <= end:
                print("[FAIL] RDP open to internet")
                risky = True

    if not risky:
        print("[PASS] No targeted public exposure found")

# EBS Encryption Security Audit
print("\nEBS ENCRYPTION AUDIT")
print("=" * 40)

# Check default encryption
encryption = ec2.get_ebs_encryption_by_default()

if encryption["EbsEncryptionByDefault"]:
    print("[PASS] EBS default encryption enabled")
else:
    print("[FAIL] EBS default encryption disabled")

# Check existing EBS volumes
volumes = []

paginator = ec2.get_paginator("describe_volumes")

for page in paginator.paginate():
    volumes.extend(page["Volumes"])

print(f"Total EBS volumes: {len(volumes)}")

if not volumes:
    print("[INFO] No EBS volumes found")

for volume in volumes:
    print(f"\nVolume: {volume['VolumeId']}")

    if volume["Encrypted"]:
        print("[PASS] EBS volume encrypted")
    else:
        print("[FAIL] EBS volume not encrypted")

# IAM Permissions Audit
print("\nIAM PERMISSIONS AUDIT")
print("=" * 40)

admin_policy = "arn:aws:iam::aws:policy/AdministratorAccess"

paginator = iam.get_paginator("list_entities_for_policy")

users = []
roles = []
groups = []

for page in paginator.paginate(PolicyArn=admin_policy):
    users.extend(page["PolicyUsers"])
    roles.extend(page["PolicyRoles"])
    groups.extend(page["PolicyGroups"])

print(f"Administrator users: {len(users)}")
print(f"Administrator roles: {len(roles)}")
print(f"Administrator groups: {len(groups)}")

if not (users or roles or groups):
    print("[PASS] No direct AdministratorAccess attachments found")
else:
    print("[WARN] Administrator permissions require review")

    for user in users:
        print(f"Admin User: {user['UserName']}")

    for role in roles:
        print(f"Admin Role: {role['RoleName']}")

    for group in groups:
        print(f"Admin Group: {group['GroupName']}")

