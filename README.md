# AWS Security Toolkit — tioscapital

A read-only security auditing toolkit for AWS infrastructure and servers. It never modifies anything — every API call is a `Describe*`, `List*`, or `Get*` operation.

---

## What's in the Toolkit

| File | What it does |
|---|---|
| `aws_audit.py` | Audits your AWS account — IAM, EC2, S3, RDS, ElastiCache, Athena, security group relationships, and IAM privilege escalation paths |
| `server_scan.py` | Scans an individual server for open ports, weak configurations, and exposed services |
| `lynis_scan.py` | SSHs into your EC2 instances, runs a deep Lynis security audit on each one, and saves a report |
| `requirements.txt` | Python dependencies |

---

## One-Time Setup

### 1. Python environment

```bash
cd ~/aws_security_toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. AWS credentials

You need an IAM user called `security-scanner` with the `SecurityScannerReadOnly` policy attached.

**Create the IAM user:**
1. Go to AWS Console → IAM → Users → Create user
2. Name: `security-scanner`
3. Access type: programmatic only (no console access)
4. Attach the `SecurityScannerReadOnly` policy (see policy JSON below)
5. Download the access key

**Add the profile to your Mac:**
```bash
aws configure --profile security-scanner
# Enter: Access Key ID, Secret Access Key, region: us-east-1, output: json
```

**SecurityScannerReadOnly policy JSON** (paste this in IAM → Policies → Create policy → JSON):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:ListAttachedUserPolicies",
                "iam:ListUserPolicies",
                "iam:GetUserPolicy",
                "iam:ListGroupsForUser",
                "iam:ListAttachedGroupPolicies",
                "iam:GetGroupPolicy",
                "iam:ListGroupPolicies",
                "iam:ListRoles",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:GetPolicyVersion",
                "iam:ListPolicyVersions",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots",
                "ec2:DescribeSnapshotAttribute",
                "ec2:DescribeNetworkInterfaces",
                "s3:ListAllMyBuckets",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketVersioning",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketLogging",
                "s3:GetBucketPolicy",
                "s3:GetBucketAcl",
                "rds:DescribeDBInstances",
                "elasticache:DescribeReplicationGroups",
                "elasticache:DescribeCacheClusters",
                "athena:ListWorkGroups",
                "athena:GetWorkGroup"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Script 1 — aws_audit.py (AWS Cloud Audit)

Scans your entire AWS account and reports security misconfigurations.

### What it checks

**IAM**
- Root account MFA not enabled
- Weak password policy (length, complexity, rotation)
- Users without MFA
- Access keys older than 90 days
- Users/roles with wildcard (`*`) policies or AdministratorAccess

**IAM Privilege Escalation**
- 13 single-permission escalation paths (e.g. `iam:CreatePolicyVersion` alone can grant full admin)
- 5 combination escalation paths (e.g. `iam:PassRole` + `ec2:RunInstances`)
- Checks every IAM user and role

**EC2**
- Security groups open to the entire internet (0.0.0.0/0)
- IMDSv2 not enforced on instances (metadata service exposure)
- Unencrypted EBS volumes
- Public snapshots

**Security Group Map**
- Table showing what each security group is attached to (EC2, RDS, ALB, Lambda, etc.)
- Which security groups allow traffic between each other
- Unused security groups (not attached to anything)
- Deleted SG references and ALL TRAFFIC rules between groups

**S3**
- Public access block not enabled
- Default encryption not configured
- Versioning disabled
- Access logging disabled
- Bucket policy granting public access

**RDS**
- Publicly accessible instances
- Unencrypted storage
- Backup retention under 7 days
- Deletion protection disabled
- Multi-AZ not enabled
- Default username (admin/root)

**ElastiCache**
- Transit encryption (TLS) disabled
- At-rest encryption disabled
- Redis missing AUTH token
- Memcached not in a VPC

**Athena**
- Workgroup results not encrypted
- EnforceWorkGroupConfiguration disabled

### How to run

```bash
cd ~/aws_security_toolkit
source venv/bin/activate

# Full audit, print to terminal
python aws_audit.py

# Save text report
python aws_audit.py --output report.txt

# Save HTML report (opens in any browser, has search + filters)
python aws_audit.py --html report.html

# Both text and HTML
python aws_audit.py --output report.txt --html report.html

# Audit only specific services
python aws_audit.py --services iam,s3,ec2

# Audit without escalation check (faster)
python aws_audit.py --services iam,ec2,sgmap,s3,rds,elasticache,athena
```

### Severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Fix immediately — active risk of full account compromise |
| HIGH | Fix soon — significant exposure |
| MEDIUM | Should be addressed — best practice violation |
| LOW | Minor hardening opportunity |
| INFO | Informational only |

### HTML report

The `--html` flag generates a self-contained HTML file you can open in any browser. It includes:
- Colour-coded severity badges
- Search box (searches across all fields)
- Filter by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Filter by service (IAM / EC2 / S3 / etc.)

---

## Script 2 — server_scan.py (External Server Scanner)

Scans a server from the outside — like an attacker would. Give it an IP or hostname and it checks for open ports, weak services, and exposed information.

> Only run this against servers you own or have written authorisation to test.

### What it checks

- **Port scan** — 56 common ports by default, or full 1–65535 scan
- **Banner grabbing** — detects software version disclosure
- **SSH** — SSHv1 enabled, outdated OpenSSH version, password authentication enabled
- **HTTP/HTTPS** — missing security headers (HSTS, CSP, X-Frame-Options, etc.), server version disclosure, directory listing
- **SSL/TLS** — weak protocol versions (TLS 1.0 / 1.1), weak ciphers (RC4, DES, NULL), certificate expiry
- **FTP** — anonymous login allowed
- **Unauthenticated services** — Redis, Memcached, MongoDB, Elasticsearch open without authentication
- **Dangerous protocols** — Telnet, RDP, SMB, VNC, Docker API (port 2375) exposed

### How to run

```bash
cd ~/aws_security_toolkit
source venv/bin/activate

# Basic scan
python server_scan.py --target 1.2.3.4

# Scan a hostname
python server_scan.py --target myserver.example.com

# Full port scan (slow — scans all 65535 ports)
python server_scan.py --target 1.2.3.4 --ports full

# Save results to JSON
python server_scan.py --target 1.2.3.4 --output scan_results.json

# Adjust timeout (default 3 seconds)
python server_scan.py --target 1.2.3.4 --timeout 5
```

---

## Script 3 — lynis_scan.py (Deep Server Audit via SSH)

SSHs into your EC2 instances and runs Lynis — a comprehensive Linux security auditing tool. Produces a hardening score and a list of warnings and suggestions for each server.

### What it does

1. Looks up your EC2 instances in AWS
2. Asks you which instance to scan (or you can provide an IP directly)
3. SSHs in using your key
4. Installs Lynis v3.1.4 from source (always the latest version)
5. Runs a full Lynis audit in the background
6. Polls every 60 seconds until complete
7. Pulls the report and saves it locally

### What Lynis checks (500+ tests)

- OS and package updates
- Users, groups, authentication, PAM
- SSH configuration
- File permissions and SUID/SGID files
- Kernel hardening (sysctl)
- Firewall configuration
- Logging and auditd
- Malware scanners installed
- Running processes and services
- Cron jobs and scheduled tasks
- Network configuration

### Requirements

- Your EC2 instances must be reachable via SSH
- If instances are on private subnets: **connect to Tailscale VPN first**
- The script reminds you to do this at startup

### How to run

```bash
cd ~/aws_security_toolkit
source venv/bin/activate

# Connect to Tailscale first if scanning private subnet instances
python lynis_scan.py
```

The script will ask you:
1. Path to your SSH private key (e.g. `~/.ssh/my-key.pem`)
2. SSH username (e.g. `ubuntu` or `ec2-user`)
3. Instance ID (e.g. `i-0abc123`) or IP address directly

### Output files

All saved to `./lynis_output/` (created automatically):

| File | Contents |
|---|---|
| `<instance-id>.dat` | Raw Lynis report |
| `<instance-id>.json` | Parsed findings: hardening score, warnings, suggestions |
| `<instance-id>.csv` | Findings as a spreadsheet |
| `lynis_summary.csv` | One row per instance — score + finding counts |
| `lynis_summary.json` | Same data in JSON |

### Hardening score

Lynis gives each server a score out of 100. Typical ranges:

| Score | Meaning |
|---|---|
| 0–44 | Poor — significant hardening needed |
| 45–64 | Fair — common issues present |
| 65–79 | Good — well configured |
| 80–100 | Excellent — hardened system |

---

## Folder Structure

```
aws_security_toolkit/
├── README.md           ← this file
├── CLAUDE.md           ← development changelog
├── requirements.txt    ← Python dependencies
├── aws_audit.py        ← AWS cloud security auditor
├── server_scan.py      ← External server vulnerability scanner
├── lynis_scan.py       ← Deep server audit via SSH + Lynis
└── lynis_output/       ← Created automatically when lynis_scan.py runs
```

---

## Quick Reference

```bash
# Setup (once)
cd ~/aws_security_toolkit && python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Full AWS audit with HTML report
python aws_audit.py --html report.html

# Scan a specific server
python server_scan.py --target <ip-or-hostname>

# Deep audit an EC2 instance (connect Tailscale first for private subnets)
python lynis_scan.py
```
