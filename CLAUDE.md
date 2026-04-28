# AWS Security Toolkit — Project Log

## Overview
Authorized security auditing toolkit for AWS infrastructure and server penetration testing.
Owner: smashal@tioscapital.com

## AWS Services in Scope
- EC2, S3, RDS, Athena, IAM, ElastiCache

## Project Structure
```
aws_security_toolkit/
├── CLAUDE.md           # This file — project log for Claude
├── requirements.txt    # Python dependencies
├── aws_audit.py        # AWS cloud security auditor (Boto3)
└── server_scan.py      # Server vulnerability / pentest scanner
```

## Changelog

### 2026-04-24 — v0.1 Initial Build
- Created project structure
- `aws_audit.py`: IAM, EC2, S3, RDS, ElastiCache, Athena checks with CRITICAL/HIGH/MEDIUM/LOW severity
- `server_scan.py`: Port scan, banner grab, SSH/HTTP/FTP/SSL checks, exposed service detection
- `requirements.txt`: boto3, requests, colorama, paramiko

### 2026-04-28 — v0.1.5 HTML Report, IAM Escalation Checker, S3 Fixes
- `aws_audit.py`: Added `audit_iam_escalation()` — checks all IAM users and roles for 13 single-permission escalation paths and 5 combination escalation paths; reports CRITICAL/HIGH per principal
- `aws_audit.py`: Added `generate_html_report()` — self-contained HTML with severity colour coding, search box, severity/service filter dropdowns; triggered via `--html report.html`
- `aws_audit.py`: Fixed S3 crash on buckets with explicit deny policies — wrapped `get_bucket_versioning` and `get_bucket_encryption` in `ClientError` handlers; distinguishes AccessDenied from genuine missing config
- `aws_audit.py`: `main()` wired up: `escalation` added to default services list; `--html` flag added; `audit_iam_escalation()` runs after `audit_iam()`; `generate_html_report()` called at end if `--html` set
- IAM policy `SecurityScannerReadOnly` needs new permissions: `iam:GetPolicyVersion`, `iam:ListPolicyVersions`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListGroupsForUser`, `iam:ListAttachedGroupPolicies`, `iam:GetGroupPolicy`, `iam:ListGroupPolicies`, `iam:ListAttachedRolePolicies`

### 2026-04-28 — v0.1.4 Security Group Map
- `aws_audit.py`: Added `audit_sg_map()` — usage table, SG-to-SG relationship map, unused SGs
- Detects what each SG is attached to via ENIs (covers EC2, RDS, ElastiCache, ALB, Lambda)
- Flags deleted SG references and ALL TRAFFIC rules between SGs
- Fixed `args.region` bug in main(); added `sgmap` to default services

### 2026-04-24 — v0.1.3 Unused Security Groups
- `aws_audit.py`: Added unused security group check — queries all ENIs via paginator, reports any SG not attached to any network interface (skips `default` SG which AWS won't allow deleting)
- IAM policy `SecurityScannerReadOnly` needs `ec2:DescribeNetworkInterfaces` added

### 2026-04-24 — v0.1.2 S3 Exception Fix
- `aws_audit.py`: Replaced invalid `s3.exceptions.NoSuchPublicAccessBlockConfiguration` and `s3.exceptions.NoSuchBucketPolicy` with `ClientError` + error code check — boto3 S3 client does not expose those as typed exceptions
- `aws_audit.py`: Added `botocore.exceptions.ClientError` import
- `aws_audit.py`: Added `warn()` helper for non-fatal skipped checks

### 2026-04-24 — v0.1.1 Read-Only Hardening
- **server_scan.py**: Replaced `auth_password()` with `auth_none()` for SSH check — zero credentials sent, server returns supported auth methods list
- **server_scan.py**: Replaced broken MongoDB hex bytes with correct OP_MSG `hello` command built via `struct` — verified read-only wire protocol query
- **server_scan.py**: Removed unused `import subprocess` and `import time` — subprocess removed to prevent any risk of local command execution
- **server_scan.py**: Added `import struct` for proper binary protocol construction
- **aws_audit.py**: Added explicit read-only guarantee in docstring; recommends attaching AWS `ReadOnlyAccess` managed policy
- Both files: Added READ-ONLY GUARANTEE block in docstrings listing exactly what the script never does

### 2026-04-27 — v0.2.1 Lynis Auto-Update
- `lynis_scan.py`: Always installs latest Lynis from source (v3.1.4) instead of relying on apt package (which ships v2.6.2)
- Checks installed version first — skips reinstall if already on latest, upgrades if outdated
- `LYNIS_VERSION` constant at top of file — update it when new Lynis releases come out

### 2026-04-27 — v0.2.0 Lynis Remote Scanner
- Created `lynis_scan.py`: discovers EC2 instances via boto3, SSHs in with paramiko, installs Lynis, runs full audit, pulls report, generates combined summary
- Supports Ubuntu (apt), Amazon Linux / RHEL / CentOS (yum), Fedora (dnf)
- Falls back to installing Lynis from source tarball if package manager fails
- Parses lynis-report.dat: hardening index, warnings, suggestions
- Saves raw .dat + parsed .json per instance + combined JSON summary
- IAM needs only ec2:DescribeInstances (already in policy)
- CLI args: --key, --user, --region, --profile, --instance, --output, --private-ip

## File Details

### aws_audit.py
- IAM: root MFA, password policy, user MFA, access key age (90d), wildcard policies, AdministratorAccess
- EC2: security groups open to 0.0.0.0/0, IMDSv2 not enforced, unencrypted EBS, public snapshots
- S3: public access block, default encryption, versioning, access logging, public bucket policy
- RDS: publicly accessible, storage encryption, backup retention, deletion protection, Multi-AZ, default usernames
- ElastiCache: transit + at-rest encryption, Redis AUTH token, Memcached VPC placement
- Athena: workgroup result encryption, EnforceWorkGroupConfiguration
- CLI args: --profile, --region, --output, --services

### server_scan.py
- Port scanner: concurrent socket scan, 56 top ports by default, full 1-65535 mode available
- Banner grabbing with version disclosure detection
- SSH: SSHv1, outdated OpenSSH, password auth enabled (via paramiko)
- HTTP/HTTPS: 6 security headers, Server/X-Powered-By disclosure, directory listing
- SSL/TLS: weak versions (TLS1.0/1.1), weak ciphers (RC4/DES/NULL), cert expiry
- FTP: anonymous login check
- Unauthenticated services: Redis PING, Memcached stats, MongoDB wire, Elasticsearch
- Flagged protocols: Telnet, RDP, SMB, VNC, Docker 2375
- CLI args: --target, --ports, --output, --timeout

## Known Limitations / TODOs
- server_scan.py uses pure socket (no nmap dependency required)
- RDS check does not yet cover Aurora clusters — to be added
- No GuardDuty / CloudTrail audit yet — planned for v0.2
- No HTML report export yet — planned for v0.2
- Athena check may hit permissions errors if caller lacks athena:ListWorkGroups

## Usage Notes
- Run `aws configure` or set env vars before running aws_audit.py
- server_scan.py must only target servers you own or have written authorization to test
