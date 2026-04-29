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

### 2026-04-28 — v0.2.0 aws_audit.py Six New Service Checks
- Added `audit_mq()` — public broker exposure, auto minor upgrade disabled, audit/general logging disabled
- Added `audit_route53()` — DNSSEC not enabled on public zones, query logging disabled, wildcard records
- Added `audit_vpc()` — default VPC exists, flow logs disabled, subnets auto-assigning public IPs, default SG has rules, NACLs with allow-all
- Added `audit_cloudfront()` — HTTP not redirected to HTTPS, weak min TLS version, no WAF, logging disabled, origin using HTTP
- Added `audit_acm()` — expired/failed/pending certs, expiring < 30 days, issued but not in use
- Added `audit_secrets_manager()` — rotation not enabled, rotation overdue, default KMS key, not accessed in 90+ days
- `main()`: all 6 wired into default services list; IAM MFA check now skips CLI users (no login profile)
- New IAM permissions needed: `mq:ListBrokers`, `mq:DescribeBroker`, `route53:ListHostedZones`, `route53:GetDNSSEC`, `route53:ListQueryLoggingConfigs`, `route53:ListResourceRecordSets`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeFlowLogs`, `ec2:DescribeNetworkAcls`, `cloudfront:ListDistributions`, `acm:ListCertificates`, `acm:DescribeCertificate`, `secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret`, `iam:GetLoginProfile`

### 2026-04-28 — v0.3.0 server_scan.py Full Pentest Rebuild
- Rebuilt `server_scan.py` from a port scanner into a full penetration testing simulator
- Added CVE database — 25+ entries across OpenSSH, Apache, nginx, vsftpd, ProFTPD, Exim, PHP, OpenSSL, IIS; matches detected service versions to known CVEs
- Added Heartbleed check (CVE-2014-0160) — raw TLS heartbeat probe; detects memory leak without crashing server
- Added SSL/TLS deep audit — weak protocol version acceptance (TLS 1.0/1.1), weak cipher negotiation, certificate expiry
- Added SSH deep audit — password/keyboard-interactive auth probe (auth_none), SSHv1 detection, weak algorithm flags
- Added web vulnerability scanner — sensitive path discovery (60+ paths: .env, .git, admin panels, backups, debug endpoints), CORS misconfiguration, HTTP method testing (PUT/DELETE/TRACE), SQL injection probes, security header analysis, insecure cookie detection, HTTP→HTTPS redirect check, default credential testing on admin panels
- Added SNMP community string enumeration — raw UDP probe for public/private/community/manager strings
- Added FTP default credential testing — anonymous, ftp, admin, root
- Enhanced Redis check — detects unauthenticated CONFIG command access (RCE vector)
- Enhanced Elasticsearch check — lists visible index names when unauthenticated
- JSON report output (`--output report.json`) replaces plaintext
- 8-phase scan flow: port scan → banner+CVE → SSH → SSL → web → FTP → services → SNMP

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

### 2026-04-29 — v0.6.0 Removed OpenVAS
- Deleted `openvas_scan.py` and `config/openvas.txt` — GVM data feeds were not synced on the server (no port lists, no scan configs), and the python-gvm API has breaking changes between versions that made the integration unreliable
- Removed `python-gvm` from `requirements.txt`
- README updated: Script 4 section removed, folder structure and quick reference cleaned up
- Toolkit is now 3 scripts: `aws_audit.py`, `server_scan.py`, `lynis_scan.py`

### 2026-04-28 — v0.5.1 OpenVAS SSH Tunnel Connection
- Replaced `TLSConnection` with a custom `_GmpSSHConnection` class — gvmd only listens on Unix socket by default, not TCP 9390; SSH tunnel via `nc -U` is the correct remote access method
- `connect_gmp()` signature changed: takes `ssh_user`, `ssh_key`, `socket_path` instead of `port`
- `config/openvas.txt` extended: `ssh_user`, `ssh_key`, `socket` fields added; `port` removed
- Requirement: ubuntu user must be in `_gvm` group on server (`sudo usermod -aG _gvm ubuntu`)
- README updated with one-time server setup instructions and new config format

### 2026-04-28 — v0.5.0 Replaced Nessus with OpenVAS
- Removed `nessus_scan.py` and `config/nessus.txt` — Nessus Essentials license blocks all REST API write operations (POST /scans, POST /scans/{id}/launch) returning 412 regardless of auth method; no workaround exists
- Created `openvas_scan.py`: connects via GMP (Greenbone Management Protocol) on port 9390, full write access, free/open source, 100k+ NVTs with real CVE IDs
- Added `config/openvas.txt` for credentials (host, port, user, password)
- Added `python-gvm` to `requirements.txt`
- README updated: Script 4 is now openvas_scan.py; nessus removed from file table, folder structure, and quick reference
- OpenVAS install on Ubuntu: `sudo apt install openvas && sudo gvm-setup && sudo gvm-start`

### 2026-04-28 — v0.4.0 Nessus Scanner
- Created `nessus_scan.py`: connects to a running Nessus instance via REST API, creates and launches a scan, polls until complete, extracts findings with CVE IDs, generates HTML/CSV/JSON reports
- Default Nessus URL: `https://nessus.tioscapital.com`
- Auth via `--username`/`--password` or `NESSUS_USER`/`NESSUS_PASS` env vars
- Auto-selects "Basic Network Scan" template (falls back to first available)
- Severity mapping: Nessus 0–4 integers → INFO/LOW/MEDIUM/HIGH/CRITICAL
- Extracts CVE IDs from plugin attributes and ref_information
- `--keep` flag to preserve scan in Nessus history after pulling results (default: delete)
- No new dependencies — uses `requests` already in requirements.txt
- CLI args: `--target`, `--url`, `--username`, `--password`, `--output`, `--format`, `--timeout`, `--keep`

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
