# AWS Security Toolkit — tioscapital

A read-only security auditing and penetration testing toolkit for AWS infrastructure and servers. It never modifies anything — every AWS API call is a `Describe*`, `List*`, or `Get*` operation.

---

## What's in the Toolkit

| File | What it does |
|---|---|
| `aws_audit.py` | Audits your entire AWS account across 14 services — IAM, EC2, S3, RDS, ElastiCache, Athena, MQ, Route53, VPC, CloudFront, ACM, Secrets Manager, security group map, and IAM privilege escalation |
| `server_scan.py` | Full penetration test simulation against a server — CVE matching, SSH audit, SSL/TLS deep audit including Heartbleed, web vulnerability scanning, SNMP enumeration, default credentials, service checks |
| `lynis_scan.py` | SSHs into EC2 instances, installs Lynis, runs a 500+ test deep OS security audit, and saves reports |
| `requirements.txt` | Python dependencies |

---

## One-Time Setup

### 1. Python environment

```bash
cd ~/dev/aws_security_toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt --index-url https://pypi.org/simple/
```

### 2. AWS credentials

You need an IAM user called `security-scanner` with the `SecurityScannerReadOnly` policy attached.

**Create the IAM user:**
1. Go to AWS Console → IAM → Users → Create user
2. Name: `security-scanner`
3. Access type: programmatic only (no console access)
4. Attach the `SecurityScannerReadOnly` policy (JSON below)
5. Download the access key

**Add the profile to your Mac:**
```bash
aws configure --profile security-scanner
# Access Key ID, Secret Access Key, region: us-east-1, output: json
```

**SecurityScannerReadOnly policy** — paste in IAM → Policies → Create policy → JSON:

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
                "iam:GetLoginProfile",
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
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots",
                "ec2:DescribeSnapshotAttribute",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeNetworkAcls",
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
                "athena:GetWorkGroup",
                "mq:ListBrokers",
                "mq:DescribeBroker",
                "route53:ListHostedZones",
                "route53:GetDNSSEC",
                "route53:ListQueryLoggingConfigs",
                "route53:ListResourceRecordSets",
                "cloudfront:ListDistributions",
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "secretsmanager:ListSecrets",
                "secretsmanager:DescribeSecret"
            ],
            "Resource": "*"
        }
    ]
}
```

> Every action in this policy is read-only (`Get*`, `List*`, `Describe*`). AWS will block any accidental write at the API level regardless of what code runs.

---

## Script 1 — aws_audit.py (AWS Cloud Audit)

Scans your entire AWS account and reports security misconfigurations across 14 services.

### What it checks

**IAM**
- Root account MFA not enabled
- Weak password policy (length, complexity, rotation)
- Human users (console access) without MFA — CLI-only users are skipped
- Access keys older than 90 days
- Users/roles with AdministratorAccess or wildcard (`*`) policies

**IAM Privilege Escalation**
- 13 single-permission escalation paths (e.g. `iam:CreatePolicyVersion` alone can grant full admin)
- 5 combination paths (e.g. `iam:PassRole` + `ec2:RunInstances`)
- Checks every IAM user and role against all paths

**EC2**
- Security groups open to the internet (0.0.0.0/0)
- IMDSv2 not enforced (metadata service exposure)
- Unencrypted EBS volumes
- Public snapshots

**Security Group Map**
- What each security group is attached to (EC2, RDS, ALB, Lambda, etc.)
- Security group to security group traffic rules
- Unused security groups
- Deleted SG references and ALL TRAFFIC rules between groups

**VPC**
- Default VPC still exists
- VPC flow logs not enabled
- Subnets auto-assigning public IPs
- Default security group has rules
- Network ACLs with allow-all rules

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

**Amazon MQ**
- Broker publicly accessible
- Auto minor version upgrade disabled
- Audit and general logging disabled

**Route 53**
- DNSSEC not enabled on public hosted zones
- Query logging disabled
- Wildcard DNS records

**CloudFront**
- HTTP not redirected to HTTPS
- Weak minimum TLS version (TLS 1.0 / 1.1)
- No WAF Web ACL associated
- Access logging disabled
- Origin using HTTP instead of HTTPS

**ACM (Certificate Manager)**
- Expired certificates
- Certificates expiring within 30 days
- Failed or pending validation certificates
- Issued certificates not attached to any resource

**Secrets Manager**
- Automatic rotation not enabled
- Rotation overdue (missed schedule)
- Using default AWS managed KMS key
- Secrets not accessed in 90+ days

### How to run

```bash
cd ~/dev/aws_security_toolkit
source venv/bin/activate

# Full audit — all 14 services
python aws_audit.py

# Save text report
python aws_audit.py --output report.txt

# Save HTML report (opens in any browser, has search + filters)
python aws_audit.py --html report.html

# Both text and HTML
python aws_audit.py --output report.txt --html report.html

# Audit specific services only
python aws_audit.py --services iam,ec2,s3,vpc

# Skip the escalation check (faster)
python aws_audit.py --services iam,ec2,sgmap,vpc,s3,rds,elasticache,athena,mq,route53,cloudfront,acm,secretsmanager
```

**Available service names:**
`iam`, `escalation`, `ec2`, `sgmap`, `vpc`, `s3`, `rds`, `elasticache`, `athena`, `mq`, `route53`, `cloudfront`, `acm`, `secretsmanager`

### Severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Fix immediately — active risk of full account compromise |
| HIGH | Fix soon — significant exposure |
| MEDIUM | Should be addressed — best practice violation |
| LOW | Minor hardening opportunity |

### HTML report

The `--html` flag generates a self-contained file you can open in any browser:
- Colour-coded severity badges
- Search box across all fields
- Filter by severity
- Filter by service

---

## Script 2 — server_scan.py (Penetration Test Scanner)

Simulates what an attacker would do against a server — from the outside. Runs 8 phases of checks.

> Only run against servers you own or have written authorisation to test.

### Scan phases

| Phase | What it does |
|---|---|
| 1 — Port scan | TCP connect scan across 56 common ports (or full 1–65535) |
| 2 — Banner + CVE | Grabs service banners, matches versions against 25+ known CVEs across OpenSSH, Apache, nginx, vsftpd, PHP, OpenSSL, IIS, Exim |
| 3 — SSH deep audit | Password/keyboard-interactive auth probe, SSHv1 detection, weak algorithm detection |
| 4 — SSL/TLS | Weak protocol versions (TLS 1.0/1.1), weak ciphers, certificate expiry, Heartbleed (CVE-2014-0160) |
| 5 — Web scanner | 60+ sensitive paths (.env, .git, admin panels, backups, debug endpoints), CORS misconfiguration, HTTP methods (PUT/DELETE/TRACE), SQL injection probes, security header audit, insecure cookies, default credentials on admin panels |
| 6 — FTP | Anonymous login, default credential testing |
| 7 — Services | Redis (unauthenticated + CONFIG RCE check), Memcached, MongoDB, Elasticsearch (lists visible indices), Docker API |
| 8 — SNMP | UDP community string enumeration (public, private, manager, etc.) |

### How to run

```bash
cd ~/dev/aws_security_toolkit
source venv/bin/activate

# Basic scan — terminal output only
python server_scan.py --target 10.1.157.226

# Save HTML report (default format)
python server_scan.py --target 10.1.157.226 --output report

# Save CSV only
python server_scan.py --target 10.1.157.226 --output report --format csv

# Save JSON only
python server_scan.py --target 10.1.157.226 --output report --format json

# Save all three formats at once
python server_scan.py --target 10.1.157.226 --output report --format html,csv,json
# Creates: report.html, report.csv, report.json

# Full port scan (slow — all 65535 ports)
python server_scan.py --target 10.1.157.226 --ports full

# Specific ports only
python server_scan.py --target 10.1.157.226 --ports 22,80,443,3306

# Adjust timeout
python server_scan.py --target 10.1.157.226 --timeout 5
```

**`--format` options:** `html`, `csv`, `json` — comma-separated, default is `html`

**`--output`** is the base filename without extension. The script appends `.html`, `.csv`, `.json` automatically.

### Notes for your setup

- Connect to **Tailscale** before scanning private subnet instances — the scanner reaches past security groups and tests the OS-level exposure
- The web scanner (phase 5) skips automatically if no HTTP/HTTPS port is open
- JSON report includes all findings structured for programmatic use

---

## Script 3 — lynis_scan.py (Deep OS Audit via SSH)

SSHs into EC2 instances and runs Lynis — a 500+ test Linux security auditing tool. Produces a hardening score and full findings list per server.

### What it does

1. Discovers running EC2 instances via AWS API
2. Asks which instance to scan (or accepts an IP directly)
3. SSHs in using your key
4. Installs Lynis v3.1.4 from source (always latest — skips reinstall if already current)
5. Runs a full audit in the background (non-blocking)
6. Polls every 60 seconds until complete
7. Pulls the report and saves it locally

### What Lynis checks

- OS and package updates / vulnerable packages
- User accounts, groups, PAM authentication
- SSH configuration hardening
- File permissions, SUID/SGID binaries
- Kernel hardening parameters (sysctl)
- Firewall rules (ufw/iptables)
- Logging, auditd, sysstat
- Malware scanners and file integrity tools
- Running processes and services
- Cron jobs and scheduled tasks

### Requirements

- EC2 instances must be reachable via SSH
- For private subnet instances: **connect to Tailscale first**
- The script shows a VPN reminder at startup

### How to run

```bash
cd ~/dev/aws_security_toolkit
source venv/bin/activate

python lynis_scan.py
```

The script will ask:
1. Path to your SSH private key (e.g. `~/.ssh/my-key.pem`)
2. SSH username (e.g. `ubuntu`)
3. Instance ID (e.g. `i-0abc123`) or IP address

### Output files

All saved to `./lynis_reports/` (created automatically):

| File | Contents |
|---|---|
| `<id>_<ts>_lynis_raw.dat` | Raw Lynis report file |
| `<id>_<ts>_summary.json` | Parsed findings: hardening score, warnings, suggestions |
| `<id>_<ts>_findings.csv` | Findings as a spreadsheet |
| `combined_<ts>.csv` | All instances and all findings in one CSV |
| `combined_<ts>.json` | Same data in JSON |
| `combined_<ts>.html` | Interactive HTML report — always generated automatically |

### HTML report

Generated automatically every run. Opens in any browser:
- Instance summary table with colour-coded hardening score bars
- Full findings table with search box
- Filter by instance
- Filter by type (WARNING / SUGGESTION)

### Hardening score

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
├── README.md            ← this file
├── CLAUDE.md            ← development changelog
├── requirements.txt     ← Python dependencies
├── aws_audit.py         ← AWS cloud security auditor (14 services)
├── server_scan.py       ← Server penetration test scanner
├── lynis_scan.py        ← Deep OS audit via SSH + Lynis
└── lynis_reports/       ← Created automatically when lynis_scan.py runs
```

---

## Quick Reference

```bash
# Setup (once)
cd ~/dev/aws_security_toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt --index-url https://pypi.org/simple/

# Full AWS audit with HTML report
python aws_audit.py --html report.html

# Pentest a server
python server_scan.py --target <ip> --output scan

# Deep OS audit (connect Tailscale first for private subnets)
python lynis_scan.py
```
