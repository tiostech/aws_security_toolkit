#!/usr/bin/env python3
"""
AWS Security Auditor — tioscapital
Checks: IAM, EC2, S3, RDS, Athena, ElastiCache
Usage: python aws_audit.py [--profile PROFILE] [--region REGION] [--output report.txt]

READ-ONLY GUARANTEE — every AWS API call in this script is a read-only operation:
  describe_*, list_*, get_*  — no Put, Create, Delete, Modify, or Update calls are made.
  For extra safety, attach the AWS managed policy "ReadOnlyAccess" to the IAM user or
  role whose credentials you use to run this script. That policy will block any accidental
  write at the AWS level regardless of what code runs.
"""

import boto3
import json
import argparse
import sys
import time
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from colorama import Fore, Style, init

init(autoreset=True)

# ── Severity helpers ────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.GREEN,
}

findings = []


def finding(severity, service, resource, issue, recommendation):
    findings.append({
        "severity":       severity,
        "service":        service,
        "resource":       resource,
        "issue":          issue,
        "recommendation": recommendation,
    })
    color = SEVERITY_COLOR.get(severity, "")
    print(f"{color}[{severity}]{Style.RESET_ALL} [{service}] {resource}")
    print(f"         Issue: {issue}")
    print(f"         Fix  : {recommendation}\n")


def warn(msg):
    print(f"  {Fore.YELLOW}[SKIP]{Style.RESET_ALL} {msg}")


def section(title):
    print(f"\n{Fore.WHITE + Style.BRIGHT}{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")


# ── IAM ─────────────────────────────────────────────────────────────────────

def audit_iam(session):
    section("IAM")
    iam = session.client("iam")

    # Root account MFA
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        finding("CRITICAL", "IAM", "root account",
                "Root account does not have MFA enabled",
                "Enable MFA on the root account immediately via IAM console")

    # Password policy
    try:
        pw = iam.get_account_password_policy()["PasswordPolicy"]
        if pw.get("MinimumPasswordLength", 0) < 14:
            finding("MEDIUM", "IAM", "password policy",
                    f"Minimum password length is {pw.get('MinimumPasswordLength')} (recommended 14+)",
                    "Set MinimumPasswordLength to 14 or higher")
        if not pw.get("RequireMFAToChangePassword", False):
            finding("MEDIUM", "IAM", "password policy",
                    "Password policy does not require MFA",
                    "Enable RequireMFAToChangePassword in the account password policy")
    except iam.exceptions.NoSuchEntityException:
        finding("HIGH", "IAM", "password policy",
                "No account password policy is set",
                "Configure a strong password policy in IAM")

    # Users: MFA, unused, old keys
    users = iam.list_users()["Users"]
    for user in users:
        time.sleep(0.05)
        name = user["UserName"]

        # Determine if this is a human user (has console password) or CLI-only user
        has_console = False
        try:
            iam.get_login_profile(UserName=name)
            has_console = True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        # MFA only matters for users with console access
        if has_console:
            mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
            if not mfa:
                finding("HIGH", "IAM", f"user/{name}",
                        "Human IAM user with console access has no MFA device attached",
                        "Enforce MFA for all users with console access")

        # Access key age
        keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age_days > 90:
                    finding("HIGH", "IAM", f"user/{name} key/{key['AccessKeyId'][:8]}…",
                            f"Active access key is {age_days} days old (>90)",
                            "Rotate access keys every 90 days; delete unused keys")

        # Inline + managed policies — flag AdministratorAccess
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        for policy in attached:
            if policy["PolicyName"] == "AdministratorAccess":
                finding("HIGH", "IAM", f"user/{name}",
                        "User has AdministratorAccess policy attached directly",
                        "Use IAM roles with least-privilege instead of AdministratorAccess")

    # Roles: check for wildcard * actions in inline policies
    roles = iam.list_roles()["Roles"]
    for role in roles:
        rname = role["RoleName"]
        inline = iam.list_role_policies(RoleName=rname)["PolicyNames"]
        for pname in inline:
            doc = iam.get_role_policy(RoleName=rname, PolicyName=pname)["PolicyDocument"]
            for stmt in doc.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if stmt.get("Effect") == "Allow" and "*" in actions:
                    finding("HIGH", "IAM", f"role/{rname} policy/{pname}",
                            "Inline policy grants Allow on Action: '*'",
                            "Replace wildcard actions with specific required permissions")

    print(f"{Fore.GREEN}IAM audit complete. {len(users)} users checked.{Style.RESET_ALL}")


# ── EC2 ─────────────────────────────────────────────────────────────────────

def audit_ec2(session, region):
    section("EC2")
    ec2 = session.client("ec2", region_name=region)

    # Security groups open to world
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            for cidr in rule.get("IpRanges", []):
                if cidr.get("CidrIp") == "0.0.0.0/0":
                    port = rule.get("FromPort", "ALL")
                    proto = rule.get("IpProtocol", "all")
                    sev = "CRITICAL" if port in [22, 3389, 3306, 5432, 6379, 11211] else "HIGH"
                    finding(sev, "EC2", f"sg/{sg['GroupId']} ({sg['GroupName']})",
                            f"Inbound rule allows {proto}:{port} from 0.0.0.0/0",
                            "Restrict source to known IPs or use a bastion/VPN")
            for cidr6 in rule.get("Ipv6Ranges", []):
                if cidr6.get("CidrIpv6") == "::/0":
                    port = rule.get("FromPort", "ALL")
                    finding("HIGH", "EC2", f"sg/{sg['GroupId']}",
                            f"Inbound rule allows port {port} from ::/0 (all IPv6)",
                            "Restrict IPv6 source CIDRs")

    # Instances
    reservations = ec2.describe_instances()["Reservations"]
    for res in reservations:
        for inst in res["Instances"]:
            iid = inst["InstanceId"]
            state = inst["State"]["Name"]
            if state != "running":
                continue

            # IMDSv2
            meta = inst.get("MetadataOptions", {})
            if meta.get("HttpTokens") != "required":
                finding("HIGH", "EC2", f"instance/{iid}",
                        "IMDSv2 is not enforced (HttpTokens != required); SSRF can steal credentials",
                        "Set HttpTokens=required: aws ec2 modify-instance-metadata-options --instance-id "
                        + iid + " --http-tokens required")

            # Public IP with no Elastic IP note
            if inst.get("PublicIpAddress"):
                finding("LOW", "EC2", f"instance/{iid}",
                        f"Instance has a public IP: {inst['PublicIpAddress']}",
                        "Confirm this instance should be publicly reachable; use ALB/NLB instead where possible")

    # Unencrypted EBS volumes
    volumes = ec2.describe_volumes()["Volumes"]
    for vol in volumes:
        if not vol.get("Encrypted", False):
            finding("MEDIUM", "EC2", f"volume/{vol['VolumeId']}",
                    "EBS volume is not encrypted",
                    "Enable EBS encryption by default in account settings; re-create unencrypted volumes")

    # Public snapshots
    snapshots = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
    for snap in snapshots:
        time.sleep(0.05)
        perms = ec2.describe_snapshot_attribute(
            SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission"
        )
        for p in perms.get("CreateVolumePermissions", []):
            if p.get("Group") == "all":
                finding("CRITICAL", "EC2", f"snapshot/{snap['SnapshotId']}",
                        "EBS snapshot is publicly accessible",
                        "Remove public permission: aws ec2 modify-snapshot-attribute --snapshot-id "
                        + snap["SnapshotId"] + " --attribute createVolumePermission --operation-type remove --group-names all")

    # Unused security groups
    # Collect every SG ID that is attached to a network interface
    attached_sg_ids = set()
    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        for eni in page["NetworkInterfaces"]:
            for sg in eni.get("Groups", []):
                attached_sg_ids.add(sg["GroupId"])

    for sg in sgs:
        sgid = sg["GroupId"]
        sgname = sg["GroupName"]
        # Skip the default SG — AWS won't let you delete it
        if sgname == "default":
            continue
        if sgid not in attached_sg_ids:
            finding("LOW", "EC2", f"sg/{sgid} ({sgname})",
                    "Security group is not attached to any network interface",
                    "Delete unused security groups to reduce attack surface and avoid accidental use")

    print(f"{Fore.GREEN}EC2 audit complete.{Style.RESET_ALL}")


# ── Security Group Map ───────────────────────────────────────────────────────

def audit_sg_map(session, region):
    section("SECURITY GROUP MAP")
    ec2 = session.client("ec2", region_name=region)

    # ── Collect all SGs ──────────────────────────────────────────────────────
    sgs      = ec2.describe_security_groups()["SecurityGroups"]
    sg_index = {sg["GroupId"]: sg["GroupName"] for sg in sgs}

    # ── Build resource map from ENIs ─────────────────────────────────────────
    # ENIs cover EC2, RDS, ElastiCache, ALB, Lambda — everything
    sg_resources = {sg["GroupId"]: [] for sg in sgs}
    attached_ids = set()

    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        for eni in page["NetworkInterfaces"]:
            # Identify what this ENI belongs to
            desc        = eni.get("Description", "")
            itype       = eni.get("InterfaceType", "")
            instance_id = eni.get("Attachment", {}).get("InstanceId")
            owner_label = None

            if instance_id:
                owner_label = f"EC2 {instance_id}"
            elif "RDSNetworkInterface" in desc or "rds" in desc.lower():
                owner_label = f"RDS ({desc[:40]})"
            elif "ElastiCache" in desc:
                owner_label = f"ElastiCache ({desc[:40]})"
            elif "ELB" in desc or "load balancer" in desc.lower():
                owner_label = f"ALB/ELB ({desc[:40]})"
            elif "Lambda" in desc:
                owner_label = f"Lambda ({desc[:40]})"
            elif desc:
                owner_label = desc[:50]
            else:
                owner_label = f"ENI {eni['NetworkInterfaceId']}"

            for grp in eni.get("Groups", []):
                gid = grp["GroupId"]
                attached_ids.add(gid)
                if gid in sg_resources:
                    if owner_label not in sg_resources[gid]:
                        sg_resources[gid].append(owner_label)

    # ── Print usage table ─────────────────────────────────────────────────────
    print(f"  {Fore.WHITE + Style.BRIGHT}{'Security Group':<40} {'ID':<22} {'Attached To'}{Style.RESET_ALL}")
    print(f"  {'-'*40} {'-'*22} {'-'*40}")

    for sg in sorted(sgs, key=lambda x: x["GroupName"]):
        sgid    = sg["GroupId"]
        sgname  = sg["GroupName"]
        res     = sg_resources.get(sgid, [])

        if not res:
            color   = Fore.YELLOW
            res_str = "NOT USED"
        else:
            color   = Fore.GREEN
            res_str = ", ".join(res[:3])
            if len(res) > 3:
                res_str += f" (+{len(res)-3} more)"

        print(f"  {color}{sgname:<40}{Style.RESET_ALL} {sgid:<22} {res_str}")

    # ── SG-to-SG relationship map ─────────────────────────────────────────────
    print(f"\n\n  {Fore.WHITE + Style.BRIGHT}SECURITY GROUP RELATIONSHIPS (SG-to-SG rules){Style.RESET_ALL}")
    print(f"  {'Source SG (allowed in)':<35} {'Arrow':<7} {'Destination SG (receives traffic)':<35} {'Port/Protocol'}")
    print(f"  {'-'*35} {'-'*7} {'-'*35} {'-'*20}")

    relationships_found = False
    for sg in sgs:
        dst_id   = sg["GroupId"]
        dst_name = sg["GroupName"]
        for rule in sg.get("IpPermissions", []):
            proto    = rule.get("IpProtocol", "all")
            port_from = rule.get("FromPort", "*")
            port_to   = rule.get("ToPort",   "*")
            port_str  = (f"{port_from}" if port_from == port_to
                         else f"{port_from}-{port_to}" if port_from != "*" else "ALL")
            if proto == "-1":
                port_str = "ALL TRAFFIC"

            for pair in rule.get("UserIdGroupPairs", []):
                src_id   = pair.get("GroupId", "unknown")
                src_name = sg_index.get(src_id, f"DELETED/EXTERNAL ({src_id})")
                relationships_found = True

                # Flag if source SG no longer exists
                if src_id not in sg_index:
                    finding("MEDIUM", "EC2", f"sg/{dst_id} ({dst_name})",
                            f"References deleted/external SG {src_id} in inbound rules",
                            "Remove stale SG references to keep rules clean")

                # Flag ALL TRAFFIC between SGs
                if proto == "-1":
                    finding("MEDIUM", "EC2", f"sg/{dst_id} ({dst_name})",
                            f"Allows ALL traffic from sg/{src_id} ({src_name})",
                            "Restrict to specific ports needed — avoid all-traffic rules between SGs")

                print(f"  {src_name:<35} {'──→':<7} {dst_name:<35} {port_str} ({proto})")

    if not relationships_found:
        print(f"  {Fore.YELLOW}No SG-to-SG rules found — all rules use IP CIDRs{Style.RESET_ALL}")

    # ── Findings: unused SGs ──────────────────────────────────────────────────
    print()
    unused = [sg for sg in sgs
              if sg["GroupId"] not in attached_ids and sg["GroupName"] != "default"]
    if unused:
        print(f"  {Fore.YELLOW + Style.BRIGHT}UNUSED SECURITY GROUPS ({len(unused)}){Style.RESET_ALL}")
        for sg in unused:
            print(f"  {Fore.YELLOW}[UNUSED]{Style.RESET_ALL} {sg['GroupName']:<40} {sg['GroupId']}")
            finding("LOW", "EC2", f"sg/{sg['GroupId']} ({sg['GroupName']})",
                    "Security group is not attached to any resource",
                    "Delete unused security groups to reduce attack surface")
    else:
        print(f"  {Fore.GREEN}All security groups are in use.{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}Security group map complete. {len(sgs)} groups analysed.{Style.RESET_ALL}")


# ── S3 ──────────────────────────────────────────────────────────────────────

def audit_s3(session):
    section("S3")
    s3 = session.client("s3")
    buckets = s3.list_buckets()["Buckets"]

    for bucket in buckets:
        time.sleep(0.05)
        name = bucket["Name"]

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all([
                pab.get("BlockPublicAcls"),
                pab.get("IgnorePublicAcls"),
                pab.get("BlockPublicPolicy"),
                pab.get("RestrictPublicBuckets"),
            ]):
                finding("CRITICAL", "S3", f"bucket/{name}",
                        "Public Access Block is not fully enabled",
                        "Enable all four PublicAccessBlock settings unless intentionally public")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                finding("CRITICAL", "S3", f"bucket/{name}",
                        "No Public Access Block configuration found",
                        "Apply aws s3api put-public-access-block with all four settings enabled")
            elif code != "AccessDenied":
                warn(f"S3 public access block check failed for {name}: {code}")

        # Encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            for rule in rules:
                algo = rule["ApplyServerSideEncryptionByDefault"].get("SSEAlgorithm")
                if algo not in ("aws:kms", "AES256"):
                    finding("HIGH", "S3", f"bucket/{name}",
                            f"Unexpected encryption algorithm: {algo}",
                            "Use AES256 or aws:kms encryption")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                finding("HIGH", "S3", f"bucket/{name}",
                        "Default encryption is not configured",
                        "Enable default bucket encryption with AES256 or KMS")
            elif code != "AccessDenied":
                warn(f"S3 encryption check skipped for {name}: {code}")

        # Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                finding("MEDIUM", "S3", f"bucket/{name}",
                        "Versioning is not enabled",
                        "Enable versioning to protect against accidental deletion or ransomware")
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                warn(f"S3 versioning check skipped for {name}: {e.response['Error']['Code']}")

        # Logging
        try:
            logging_cfg = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_cfg:
                finding("LOW", "S3", f"bucket/{name}",
                        "Access logging is not enabled",
                        "Enable S3 server access logging for audit trail")
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                warn(f"S3 logging check skipped for {name}: {e.response['Error']['Code']}")

        # Bucket policy — check for public Allow
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal", "")
                    if principal == "*" or principal == {"AWS": "*"}:
                        finding("CRITICAL", "S3", f"bucket/{name}",
                                "Bucket policy grants public Allow to Principal: '*'",
                                "Remove or restrict the public Allow statement in the bucket policy")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("NoSuchBucketPolicy", "AccessDenied"):
                warn(f"S3 bucket policy check failed for {name}: {code}")

    print(f"{Fore.GREEN}S3 audit complete. {len(buckets)} buckets checked.{Style.RESET_ALL}")


# ── RDS ─────────────────────────────────────────────────────────────────────

def audit_rds(session, region):
    section("RDS")
    rds = session.client("rds", region_name=region)
    instances = rds.describe_db_instances()["DBInstances"]

    for db in instances:
        did = db["DBInstanceIdentifier"]

        if db.get("PubliclyAccessible"):
            finding("CRITICAL", "RDS", f"db/{did}",
                    "RDS instance is publicly accessible",
                    "Set PubliclyAccessible=false and place in private subnet")

        if not db.get("StorageEncrypted", False):
            finding("HIGH", "RDS", f"db/{did}",
                    "RDS storage is not encrypted at rest",
                    "Enable encryption — requires snapshot restore to new encrypted instance")

        if db.get("BackupRetentionPeriod", 0) == 0:
            finding("HIGH", "RDS", f"db/{did}",
                    "Automated backups are disabled (retention = 0)",
                    "Set BackupRetentionPeriod to at least 7 days")

        if not db.get("DeletionProtection", False):
            finding("MEDIUM", "RDS", f"db/{did}",
                    "Deletion protection is disabled",
                    "Enable DeletionProtection to prevent accidental data loss")

        if not db.get("MultiAZ", False):
            finding("LOW", "RDS", f"db/{did}",
                    "Multi-AZ is not enabled",
                    "Enable Multi-AZ for production databases to ensure high availability")

        # Check for default master username
        if db.get("MasterUsername") in ("admin", "root", "postgres", "master"):
            finding("MEDIUM", "RDS", f"db/{did}",
                    f"Default master username '{db['MasterUsername']}' in use",
                    "Use a non-default master username to reduce brute-force risk")

    print(f"{Fore.GREEN}RDS audit complete. {len(instances)} instances checked.{Style.RESET_ALL}")


# ── ElastiCache ─────────────────────────────────────────────────────────────

def audit_elasticache(session, region):
    section("ElastiCache")
    ec = session.client("elasticache", region_name=region)

    # Redis replication groups
    try:
        groups = ec.describe_replication_groups()["ReplicationGroups"]
        for grp in groups:
            gid = grp["ReplicationGroupId"]

            if not grp.get("TransitEncryptionEnabled", False):
                finding("HIGH", "ElastiCache", f"replication-group/{gid}",
                        "Transit encryption (TLS) is not enabled",
                        "Enable transit encryption — requires cluster recreation")

            if not grp.get("AtRestEncryptionEnabled", False):
                finding("HIGH", "ElastiCache", f"replication-group/{gid}",
                        "At-rest encryption is not enabled",
                        "Enable at-rest encryption — requires cluster recreation")

            if not grp.get("AuthTokenEnabled", False):
                finding("HIGH", "ElastiCache", f"replication-group/{gid}",
                        "Redis AUTH token is not enabled",
                        "Enable AUTH token to require password authentication")
    except Exception as e:
        print(f"{Fore.YELLOW}  ElastiCache replication groups: {e}{Style.RESET_ALL}")

    # Memcached clusters
    try:
        clusters = ec.describe_cache_clusters()["CacheClusters"]
        for cluster in clusters:
            cid = cluster["CacheClusterId"]
            if cluster.get("Engine") == "memcached":
                if cluster.get("CacheSubnetGroupName") is None:
                    finding("HIGH", "ElastiCache", f"cluster/{cid}",
                            "Memcached cluster may not be inside a VPC",
                            "Ensure all ElastiCache clusters are in a private VPC subnet")
    except Exception as e:
        print(f"{Fore.YELLOW}  ElastiCache clusters: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}ElastiCache audit complete.{Style.RESET_ALL}")


# ── Athena ───────────────────────────────────────────────────────────────────

def audit_athena(session, region):
    section("Athena")
    athena = session.client("athena", region_name=region)

    try:
        workgroups = athena.list_work_groups()["WorkGroups"]
        for wg in workgroups:
            wname = wg["Name"]
            detail = athena.get_work_group(WorkGroup=wname)["WorkGroup"]
            config = detail.get("Configuration", {})
            result_config = config.get("ResultConfiguration", {})
            enc = result_config.get("EncryptionConfiguration", {})

            if not enc:
                finding("HIGH", "Athena", f"workgroup/{wname}",
                        "Query results are not encrypted",
                        "Configure EncryptionConfiguration on the workgroup result location")

            if not config.get("EnforceWorkGroupConfiguration", False):
                finding("MEDIUM", "Athena", f"workgroup/{wname}",
                        "EnforceWorkGroupConfiguration is disabled — clients can override encryption",
                        "Enable EnforceWorkGroupConfiguration so encryption cannot be bypassed by clients")

    except Exception as e:
        print(f"{Fore.YELLOW}  Athena: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}Athena audit complete.{Style.RESET_ALL}")


# ── IAM Privilege Escalation ─────────────────────────────────────────────────

# Permissions that alone allow privilege escalation
SINGLE_ESCALATION_PERMS = {
    "iam:CreatePolicyVersion":    "Can create a new admin policy version on any managed policy",
    "iam:SetDefaultPolicyVersion":"Can activate an older permissive policy version",
    "iam:AttachUserPolicy":       "Can attach any policy (including AdministratorAccess) to any user",
    "iam:AttachGroupPolicy":      "Can attach any policy to any group",
    "iam:AttachRolePolicy":       "Can attach any policy to any role",
    "iam:PutUserPolicy":          "Can create/overwrite inline policy on any user",
    "iam:PutGroupPolicy":         "Can create/overwrite inline policy on any group",
    "iam:PutRolePolicy":          "Can create/overwrite inline policy on any role",
    "iam:AddUserToGroup":         "Can add any user (including self) to any group",
    "iam:UpdateAssumeRolePolicy": "Can modify trust policy of any role to allow self-assumption",
    "iam:CreateAccessKey":        "Can create access keys for other users including admins",
    "iam:UpdateLoginProfile":     "Can reset console password for other users including admins",
    "iam:CreateLoginProfile":     "Can create console password for users that don't have one",
}

# Combinations that together allow escalation
COMBO_ESCALATION_PERMS = [
    {
        "perms": {"iam:PassRole", "ec2:RunInstances"},
        "desc":  "Can launch EC2 instance with an admin IAM role attached",
    },
    {
        "perms": {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
        "desc":  "Can create and invoke a Lambda function with an admin role",
    },
    {
        "perms": {"iam:PassRole", "glue:CreateDevEndpoint"},
        "desc":  "Can create a Glue dev endpoint with an admin role",
    },
    {
        "perms": {"iam:PassRole", "cloudformation:CreateStack"},
        "desc":  "Can create a CloudFormation stack using an admin role",
    },
    {
        "perms": {"iam:PassRole", "sagemaker:CreateNotebookInstance"},
        "desc":  "Can create a SageMaker notebook with an admin role",
    },
]


def expand_policy_actions(policy_doc):
    """Return a flat set of allowed actions from a policy document."""
    allowed = set()
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            allowed.add(action.lower())
    return allowed


def actions_match(allowed_actions, target):
    """Check if target permission is covered (handles wildcards like iam:* or *)."""
    target = target.lower()
    if "*" in allowed_actions or target in allowed_actions:
        return True
    service = target.split(":")[0]
    if f"{service}:*" in allowed_actions:
        return True
    return False


def get_principal_actions(iam, principal_type, principal_name):
    """Collect all allowed actions for a user or role from all policy sources."""
    all_actions = set()

    # Attached managed policies
    try:
        if principal_type == "user":
            attached = iam.list_attached_user_policies(UserName=principal_name)["AttachedPolicies"]
        else:
            attached = iam.list_attached_role_policies(RoleName=principal_name)["AttachedPolicies"]

        for policy in attached:
            time.sleep(0.05)
            try:
                versions = iam.list_policy_versions(PolicyArn=policy["PolicyArn"])["Versions"]
                default  = next(v for v in versions if v["IsDefaultVersion"])
                doc = iam.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=default["VersionId"]
                )["PolicyVersion"]["Document"]
                all_actions |= expand_policy_actions(doc)
            except Exception:
                pass
    except Exception:
        pass

    # Inline policies
    try:
        if principal_type == "user":
            inline_names = iam.list_user_policies(UserName=principal_name)["PolicyNames"]
            for pname in inline_names:
                doc = iam.get_user_policy(UserName=principal_name, PolicyName=pname)["PolicyDocument"]
                all_actions |= expand_policy_actions(doc)
        else:
            inline_names = iam.list_role_policies(RoleName=principal_name)["PolicyNames"]
            for pname in inline_names:
                doc = iam.get_role_policy(RoleName=principal_name, PolicyName=pname)["PolicyDocument"]
                all_actions |= expand_policy_actions(doc)
    except Exception:
        pass

    # For users — also check group policies
    if principal_type == "user":
        try:
            groups = iam.list_groups_for_user(UserName=principal_name)["Groups"]
            for group in groups:
                gname = group["GroupName"]
                # Group attached managed policies
                for policy in iam.list_attached_group_policies(GroupName=gname)["AttachedPolicies"]:
                    time.sleep(0.05)
                    try:
                        versions = iam.list_policy_versions(PolicyArn=policy["PolicyArn"])["Versions"]
                        default  = next(v for v in versions if v["IsDefaultVersion"])
                        doc = iam.get_policy_version(
                            PolicyArn=policy["PolicyArn"],
                            VersionId=default["VersionId"]
                        )["PolicyVersion"]["Document"]
                        all_actions |= expand_policy_actions(doc)
                    except Exception:
                        pass
                # Group inline policies
                for pname in iam.list_group_policies(GroupName=gname)["PolicyNames"]:
                    doc = iam.get_group_policy(GroupName=gname, PolicyName=pname)["PolicyDocument"]
                    all_actions |= expand_policy_actions(doc)
        except Exception:
            pass

    return all_actions


def audit_iam_escalation(session):
    section("IAM PRIVILEGE ESCALATION PATHS")
    iam = session.client("iam")

    principals = []

    # Collect users
    try:
        for user in iam.list_users()["Users"]:
            principals.append(("user", user["UserName"]))
    except Exception:
        pass

    # Collect roles (skip AWS service roles — they can't be assumed by humans)
    try:
        for role in iam.list_roles()["Roles"]:
            trust = role.get("AssumeRolePolicyDocument", {})
            stmts = trust.get("Statement", [])
            # Only include roles assumable by IAM users/roles (not pure service roles)
            for stmt in stmts:
                principal = stmt.get("Principal", {})
                if "AWS" in principal or principal == "*":
                    principals.append(("role", role["RoleName"]))
                    break
    except Exception:
        pass

    escalation_found = False

    for ptype, pname in principals:
        time.sleep(0.05)
        try:
            actions = get_principal_actions(iam, ptype, pname)
        except Exception:
            continue

        if not actions:
            continue

        label = f"{ptype}/{pname}"

        # Check single-permission escalations
        for perm, desc in SINGLE_ESCALATION_PERMS.items():
            if actions_match(actions, perm):
                escalation_found = True
                finding("HIGH", "IAM-Escalation", label,
                        f"Has {perm} — {desc}",
                        f"Remove {perm} unless this principal explicitly requires it; scope resource to specific ARNs")

        # Check combination escalations
        for combo in COMBO_ESCALATION_PERMS:
            if all(actions_match(actions, p) for p in combo["perms"]):
                escalation_found = True
                finding("HIGH", "IAM-Escalation", label,
                        f"Has combination {' + '.join(combo['perms'])} — {combo['desc']}",
                        "Remove unused permissions from this combination or restrict resource ARNs")

    if not escalation_found:
        print(f"  {Fore.GREEN}No privilege escalation paths detected.{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}IAM escalation audit complete. {len(principals)} principals checked.{Style.RESET_ALL}")


# ── HTML Report ───────────────────────────────────────────────────────────────

def generate_html_report(output_path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    sev_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM":   "#d97706", "LOW":  "#2563eb", "INFO": "#16a34a",
    }

    rows = ""
    for f in findings:
        color = sev_colors.get(f["severity"], "#6b7280")
        rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
            <td>{f['service']}</td>
            <td style="font-family:monospace;font-size:0.85em">{f['resource']}</td>
            <td>{f['issue']}</td>
            <td style="color:#374151">{f['recommendation']}</td>
        </tr>"""

    summary_cards = ""
    for sev, count in counts.items():
        if count == 0:
            continue
        color = sev_colors.get(sev, "#6b7280")
        summary_cards += f"""
        <div class="card" style="border-top:4px solid {color}">
            <div class="card-count" style="color:{color}">{count}</div>
            <div class="card-label">{sev}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Security Audit — tioscapital</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #f3f4f6; color: #111827; }}
  .header {{ background: #111827; color: white; padding: 24px 32px; }}
  .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
  .header p  {{ color: #9ca3af; font-size: 0.875rem; margin-top: 4px; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px 32px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 16px 24px;
           min-width: 120px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  .card-count {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.75rem; font-weight: 600; color: #6b7280;
                 text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }}
  .total-card {{ background: #111827; color: white; }}
  .total-card .card-count {{ color: white; }}
  .total-card .card-label {{ color: #9ca3af; }}
  .filters {{ margin-bottom: 16px; display: flex; gap: 12px; flex-wrap: wrap; }}
  .filters select {{ padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px;
                     background: white; font-size: 0.875rem; cursor: pointer; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 8px; overflow: hidden;
           box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  th {{ background: #111827; color: #f9fafb; text-align: left;
        padding: 12px 16px; font-size: 0.75rem; text-transform: uppercase;
        letter-spacing: .05em; font-weight: 600; }}
  td {{ padding: 12px 16px; font-size: 0.875rem; border-bottom: 1px solid #f3f4f6;
        vertical-align: top; }}
  tr:hover td {{ background: #f9fafb; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 9999px;
            color: white; font-size: 0.75rem; font-weight: 600; }}
  input[type=text] {{ padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px;
                      font-size: 0.875rem; width: 280px; }}
</style>
</head>
<body>
<div class="header">
  <h1>AWS Security Audit Report — tioscapital</h1>
  <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; Region: us-east-1</p>
</div>
<div class="container">
  <div class="summary">
    <div class="card total-card">
      <div class="card-count">{len(findings)}</div>
      <div class="card-label">Total Findings</div>
    </div>
    {summary_cards}
  </div>

  <div class="filters">
    <input type="text" id="search" onkeyup="filterTable()" placeholder="Search findings...">
    <select id="sevFilter" onchange="filterTable()">
      <option value="">All Severities</option>
      <option>CRITICAL</option><option>HIGH</option>
      <option>MEDIUM</option><option>LOW</option>
    </select>
    <select id="svcFilter" onchange="filterTable()">
      <option value="">All Services</option>
      {''.join(f'<option>{s}</option>' for s in sorted(set(f["service"] for f in findings)))}
    </select>
  </div>

  <table id="findingsTable">
    <thead>
      <tr>
        <th>Severity</th><th>Service</th><th>Resource</th>
        <th>Issue</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<script>
function filterTable() {{
  const search = document.getElementById('search').value.toLowerCase();
  const sev    = document.getElementById('sevFilter').value;
  const svc    = document.getElementById('svcFilter').value;
  const rows   = document.querySelectorAll('#findingsTable tbody tr');
  rows.forEach(row => {{
    const text    = row.textContent.toLowerCase();
    const rowSev  = row.cells[0].textContent.trim();
    const rowSvc  = row.cells[1].textContent.trim();
    const visible = (!search || text.includes(search))
                 && (!sev || rowSev === sev)
                 && (!svc || rowSvc === svc);
    row.style.display = visible ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w") as fh:
        fh.write(html)
    print(f"\n{Fore.GREEN}HTML report saved to {output_path}{Style.RESET_ALL}")


# ── Amazon MQ ────────────────────────────────────────────────────────────────

def audit_mq(session, region):
    section("Amazon MQ")
    mq = session.client("mq", region_name=region)
    try:
        brokers = mq.list_brokers()["BrokerSummaries"]
    except ClientError as e:
        warn(f"MQ: {e.response['Error']['Code']} — skipping")
        return
    if not brokers:
        print("  No MQ brokers found.")
        return
    for b in brokers:
        time.sleep(0.05)
        name = b["BrokerName"]
        try:
            d = mq.describe_broker(BrokerId=b["BrokerId"])
        except ClientError:
            continue
        if d.get("PubliclyAccessible", False):
            finding("CRITICAL", "MQ", f"broker/{name}",
                    "Broker is publicly accessible — message queue reachable from the internet",
                    "Set PubliclyAccessible=false and place broker in private subnets")
        if not d.get("AutoMinorVersionUpgrade", False):
            finding("MEDIUM", "MQ", f"broker/{name}",
                    "Auto minor version upgrade is disabled — security patches not applied automatically",
                    "Enable AutoMinorVersionUpgrade on the broker")
        logs = d.get("Logs", {})
        if not logs.get("General") and not logs.get("Audit"):
            finding("MEDIUM", "MQ", f"broker/{name}",
                    "Broker audit and general logging are both disabled",
                    "Enable audit and general logging to CloudWatch for visibility")
    print(f"{Fore.GREEN}MQ audit complete. {len(brokers)} broker(s) checked.{Style.RESET_ALL}")


# ── Route 53 ──────────────────────────────────────────────────────────────────

def audit_route53(session):
    section("Route 53")
    r53 = session.client("route53")
    try:
        zones = r53.list_hosted_zones()["HostedZones"]
    except ClientError as e:
        warn(f"Route53: {e.response['Error']['Code']} — skipping")
        return
    if not zones:
        print("  No hosted zones found.")
        return
    for zone in zones:
        zone_id  = zone["Id"].split("/")[-1]
        name     = zone["Name"]
        private  = zone["Config"]["PrivateZone"]
        if private:
            continue  # Private zones are internal DNS — lower risk
        # DNSSEC
        try:
            status = r53.get_dnssec(HostedZoneId=zone_id)["Status"]["ServeSignature"]
            if status != "SIGNING":
                finding("MEDIUM", "Route53", f"zone/{name}",
                        "DNSSEC is not enabled — DNS responses can be spoofed (cache poisoning)",
                        "Enable DNSSEC signing on the hosted zone")
        except ClientError:
            pass
        # Query logging
        try:
            configs = r53.list_query_logging_configs(HostedZoneId=zone_id)["QueryLoggingConfigs"]
            if not configs:
                finding("LOW", "Route53", f"zone/{name}",
                        "DNS query logging is not enabled — no visibility into DNS lookups",
                        "Enable query logging to CloudWatch Logs for audit trail")
        except ClientError:
            pass
        # Wildcard records
        try:
            paginator = r53.get_paginator("list_resource_record_sets")
            for page in paginator.paginate(HostedZoneId=zone_id):
                for rec in page["ResourceRecordSets"]:
                    if rec["Name"].startswith("*."):
                        finding("LOW", "Route53", f"zone/{name} record/{rec['Name']}",
                                f"Wildcard DNS record {rec['Name']} may resolve unintended subdomains",
                                "Review wildcard records and remove if not specifically required")
        except ClientError:
            pass
    public = [z for z in zones if not z["Config"]["PrivateZone"]]
    print(f"{Fore.GREEN}Route53 audit complete. {len(public)} public zone(s) checked.{Style.RESET_ALL}")


# ── VPC ───────────────────────────────────────────────────────────────────────

def audit_vpc(session, region):
    section("VPC")
    ec2 = session.client("ec2", region_name=region)

    # Default VPC + flow logs
    vpcs = ec2.describe_vpcs()["Vpcs"]
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        if vpc.get("IsDefault", False):
            finding("MEDIUM", "VPC", f"vpc/{vpc_id}",
                    "Default VPC exists — production resources should never run in the default VPC",
                    "Delete the default VPC if unused; use custom VPCs with explicit CIDR ranges")
        flow_logs = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )["FlowLogs"]
        if not flow_logs:
            finding("MEDIUM", "VPC", f"vpc/{vpc_id}",
                    "VPC flow logs are not enabled — no network traffic audit trail",
                    "Enable VPC flow logs to S3 or CloudWatch Logs")

    # Subnets auto-assigning public IPs
    subnets = ec2.describe_subnets()["Subnets"]
    for sn in subnets:
        if sn.get("MapPublicIpOnLaunch", False):
            finding("LOW", "VPC", f"subnet/{sn['SubnetId']}",
                    "Subnet auto-assigns public IPs — every instance launched here gets a public IP",
                    "Disable MapPublicIpOnLaunch unless this is an intentional public subnet")

    # Default security group should have no rules
    default_sgs = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    for sg in default_sgs:
        if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
            finding("MEDIUM", "VPC", f"vpc/{sg['VpcId']} default-sg/{sg['GroupId']}",
                    "Default security group has inbound or outbound rules — resources using it are exposed",
                    "Remove all rules from the default SG; use dedicated custom security groups")

    # NACLs with allow-all rules
    nacls = ec2.describe_network_acls()["NetworkAcls"]
    for nacl in nacls:
        if nacl.get("IsDefault", False):
            continue
        for entry in nacl.get("Entries", []):
            if (entry.get("CidrBlock") == "0.0.0.0/0"
                    and entry.get("RuleAction") == "allow"
                    and entry.get("Protocol") == "-1"):
                finding("MEDIUM", "VPC", f"nacl/{nacl['NetworkAclId']}",
                        "Network ACL has an allow-all rule for 0.0.0.0/0 — provides no traffic filtering",
                        "Replace allow-all NACL rules with specific rules for required traffic only")
                break

    print(f"{Fore.GREEN}VPC audit complete. {len(vpcs)} VPC(s) checked.{Style.RESET_ALL}")


# ── CloudFront ────────────────────────────────────────────────────────────────

def audit_cloudfront(session):
    section("CloudFront")
    cf = session.client("cloudfront")
    try:
        dist_list = cf.list_distributions().get("DistributionList", {})
        distributions = dist_list.get("Items", [])
    except ClientError as e:
        warn(f"CloudFront: {e.response['Error']['Code']} — skipping")
        return
    if not distributions:
        print("  No CloudFront distributions found.")
        return
    for dist in distributions:
        dist_id = dist["Id"]
        domain  = dist.get("DomainName", dist_id)
        behavior = dist.get("DefaultCacheBehavior", {})

        # HTTP not forced to HTTPS
        viewer_proto = behavior.get("ViewerProtocolPolicy", "")
        if viewer_proto == "allow-all":
            finding("HIGH", "CloudFront", f"distribution/{dist_id} ({domain})",
                    "Distribution allows plain HTTP — traffic can be intercepted in cleartext",
                    "Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only'")

        # Weak minimum TLS version
        cert = dist.get("ViewerCertificate", {})
        min_tls = cert.get("MinimumProtocolVersion", "")
        if min_tls in ("SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"):
            finding("HIGH", "CloudFront", f"distribution/{dist_id}",
                    f"Minimum TLS version is {min_tls} — weak protocols accepted by viewers",
                    "Set MinimumProtocolVersion to TLSv1.2_2021")

        # No WAF
        if not dist.get("WebACLId"):
            finding("MEDIUM", "CloudFront", f"distribution/{dist_id} ({domain})",
                    "No AWS WAF Web ACL is associated — no protection against common web attacks",
                    "Associate a WAF Web ACL with rate limiting and managed rule groups")

        # Access logging disabled
        if not dist.get("Logging", {}).get("Enabled", False):
            finding("LOW", "CloudFront", f"distribution/{dist_id}",
                    "CloudFront access logging is disabled — no request audit trail",
                    "Enable access logging to an S3 bucket")

        # Origin using HTTP
        for origin in dist.get("Origins", {}).get("Items", []):
            proto = origin.get("CustomOriginConfig", {}).get("OriginProtocolPolicy", "")
            if proto == "http-only":
                finding("HIGH", "CloudFront", f"distribution/{dist_id} origin/{origin.get('Id')}",
                        "Origin connection is HTTP only — traffic between CloudFront and origin is unencrypted",
                        "Set OriginProtocolPolicy to 'https-only'")

    print(f"{Fore.GREEN}CloudFront audit complete. {len(distributions)} distribution(s) checked.{Style.RESET_ALL}")


# ── ACM (Certificate Manager) ─────────────────────────────────────────────────

def audit_acm(session, region):
    section("Certificate Manager (ACM)")
    acm = session.client("acm", region_name=region)
    try:
        paginator = acm.get_paginator("list_certificates")
        certs = []
        for page in paginator.paginate():
            certs.extend(page["CertificateSummaryList"])
    except ClientError as e:
        warn(f"ACM: {e.response['Error']['Code']} — skipping")
        return
    if not certs:
        print("  No ACM certificates found.")
        return
    for summary in certs:
        arn    = summary["CertificateArn"]
        domain = summary.get("DomainName", arn)
        time.sleep(0.05)
        try:
            cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        except ClientError:
            continue
        status = cert.get("Status", "")
        if status == "EXPIRED":
            finding("CRITICAL", "ACM", f"certificate/{domain}",
                    "Certificate is EXPIRED — services using it will show SSL errors to users",
                    "Renew or replace the certificate immediately")
        elif status == "FAILED":
            finding("HIGH", "ACM", f"certificate/{domain}",
                    "Certificate issuance FAILED — the certificate is not active",
                    "Check the certificate and re-request if needed")
        elif status == "PENDING_VALIDATION":
            finding("MEDIUM", "ACM", f"certificate/{domain}",
                    "Certificate is pending validation — not yet in use",
                    "Complete DNS or email validation to activate the certificate")
        elif status == "ISSUED":
            not_after = cert.get("NotAfter")
            if not_after:
                days_left = (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                if days_left < 0:
                    finding("CRITICAL", "ACM", f"certificate/{domain}",
                            f"Certificate expired {abs(days_left)} days ago",
                            "Renew immediately — services using this cert are broken")
                elif days_left < 30:
                    finding("HIGH", "ACM", f"certificate/{domain}",
                            f"Certificate expires in {days_left} days",
                            "Renew now to avoid service disruption")
            if not cert.get("InUseBy"):
                finding("LOW", "ACM", f"certificate/{domain}",
                        "Certificate is issued but not attached to any AWS resource",
                        "Attach to a load balancer or CloudFront distribution, or delete if unused")
    print(f"{Fore.GREEN}ACM audit complete. {len(certs)} certificate(s) checked.{Style.RESET_ALL}")


# ── Secrets Manager ───────────────────────────────────────────────────────────

def audit_secrets_manager(session, region):
    section("Secrets Manager")
    sm = session.client("secretsmanager", region_name=region)
    try:
        paginator = sm.get_paginator("list_secrets")
        secrets = []
        for page in paginator.paginate():
            secrets.extend(page["SecretList"])
    except ClientError as e:
        warn(f"Secrets Manager: {e.response['Error']['Code']} — skipping")
        return
    if not secrets:
        print("  No secrets found.")
        return
    for secret in secrets:
        name = secret.get("Name", secret.get("ARN", "unknown"))
        time.sleep(0.05)
        # Rotation not enabled
        if not secret.get("RotationEnabled", False):
            finding("MEDIUM", "SecretsManager", f"secret/{name}",
                    "Automatic rotation is not enabled — credentials are never auto-rotated",
                    "Enable automatic rotation with a Lambda rotation function")
        else:
            last_rotated  = secret.get("LastRotatedDate")
            rotation_days = secret.get("RotationRules", {}).get("AutomaticallyAfterDays", 0)
            if last_rotated and rotation_days:
                days_since = (datetime.now(timezone.utc) - last_rotated.replace(tzinfo=timezone.utc)).days
                if days_since > rotation_days + 7:
                    finding("HIGH", "SecretsManager", f"secret/{name}",
                            f"Rotation is overdue — last rotated {days_since} days ago (policy: every {rotation_days} days)",
                            "Check if the rotation Lambda is functioning; trigger a manual rotation")
        # Default AWS managed key
        kms = secret.get("KmsKeyId", "")
        if not kms or "aws/secretsmanager" in kms:
            finding("LOW", "SecretsManager", f"secret/{name}",
                    "Secret uses the default AWS managed KMS key — no customer control over key lifecycle",
                    "Use a customer-managed KMS key for full control over encryption and key rotation")
        # Not accessed in 90+ days
        last_accessed = secret.get("LastAccessedDate")
        if last_accessed:
            days_idle = (datetime.now(timezone.utc) - last_accessed.replace(tzinfo=timezone.utc)).days
            if days_idle > 90:
                finding("LOW", "SecretsManager", f"secret/{name}",
                        f"Secret not accessed in {days_idle} days — may be stale or unused",
                        "Review whether this secret is still needed; delete unused secrets")
    print(f"{Fore.GREEN}Secrets Manager audit complete. {len(secrets)} secret(s) checked.{Style.RESET_ALL}")


# ── Report ───────────────────────────────────────────────────────────────────

def print_summary(output_file=None):
    section("SUMMARY")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  Total findings: {len(findings)}")
    for sev, count in counts.items():
        color = SEVERITY_COLOR.get(sev, "")
        print(f"  {color}{sev:<10}{Style.RESET_ALL}: {count}")

    if output_file:
        with open(output_file, "w") as fh:
            fh.write(f"AWS Security Audit Report\n")
            fh.write(f"Generated: {datetime.now().isoformat()}\n")
            fh.write("=" * 60 + "\n\n")
            for f in findings:
                fh.write(f"[{f['severity']}] [{f['service']}] {f['resource']}\n")
                fh.write(f"  Issue: {f['issue']}\n")
                fh.write(f"  Fix  : {f['recommendation']}\n\n")
            fh.write(f"\nTotal: {len(findings)} findings\n")
            for sev, count in counts.items():
                fh.write(f"  {sev}: {count}\n")
        print(f"\n{Fore.GREEN}Report saved to {output_file}{Style.RESET_ALL}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AWS Security Auditor — tioscapital")
    parser.add_argument("--output",   default=None, help="Save text report to file (e.g. report.txt)")
    parser.add_argument("--html",     default=None, help="Save HTML report to file (e.g. report.html)")
    parser.add_argument("--services", default="all",
                        help="Comma-separated: iam,ec2,sgmap,s3,rds,elasticache,athena,escalation,"
                             "mq,route53,vpc,cloudfront,acm,secretsmanager (default: all)")
    args = parser.parse_args()

    profile = "security-scanner"
    region  = "us-east-1"

    print(f"\n{Fore.WHITE + Style.BRIGHT}AWS Security Auditor — tioscapital")
    print(f"Region : {region}")
    print(f"Profile: {profile}")
    print(f"Time   : {datetime.now().isoformat()}{Style.RESET_ALL}\n")

    session = boto3.Session(profile_name=profile, region_name=region)

    all_services = [
        "iam", "escalation", "ec2", "sgmap", "vpc",
        "s3", "rds", "elasticache", "athena",
        "mq", "route53", "cloudfront", "acm", "secretsmanager",
    ]
    services = [s.strip().lower() for s in args.services.split(",")] if args.services != "all" \
        else all_services

    try:
        if "iam"            in services: audit_iam(session)
        if "escalation"     in services: audit_iam_escalation(session)
        if "ec2"            in services: audit_ec2(session, region)
        if "sgmap"          in services: audit_sg_map(session, region)
        if "vpc"            in services: audit_vpc(session, region)
        if "s3"             in services: audit_s3(session)
        if "rds"            in services: audit_rds(session, region)
        if "elasticache"    in services: audit_elasticache(session, region)
        if "athena"         in services: audit_athena(session, region)
        if "mq"             in services: audit_mq(session, region)
        if "route53"        in services: audit_route53(session)
        if "cloudfront"     in services: audit_cloudfront(session)
        if "acm"            in services: audit_acm(session, region)
        if "secretsmanager" in services: audit_secrets_manager(session, region)
    except Exception as e:
        print(f"{Fore.RED}Error during audit: {e}{Style.RESET_ALL}")
        sys.exit(1)

    print_summary(args.output)

    if args.html:
        generate_html_report(args.html)


if __name__ == "__main__":
    main()
