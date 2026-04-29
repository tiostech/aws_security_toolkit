#!/usr/bin/env python3
"""
Server Penetration Testing Scanner — tioscapital
Simulates real attacker techniques: reconnaissance, CVE detection,
default credential probing, web vulnerability discovery, and service exploitation probes.

AUTHORIZED USE ONLY — only run against servers you own or have explicit
written permission to test.

READ-ONLY GUARANTEE — this script never:
  - Uploads, creates, or modifies files on the target
  - Executes OS commands on the target
  - Modifies any service configuration
  - Causes crashes, DoS, or data loss
  All checks are observe-only probes that replicate attacker discovery
  techniques without causing damage.

Usage:
  python server_scan.py --target 1.2.3.4
  python server_scan.py --target myserver.com --ports full --output report.json
  python server_scan.py --target 1.2.3.4 --ports 22,80,443 --timeout 5
"""

import socket
import ssl
import struct
import json
import re
import time
import argparse
import sys
import concurrent.futures
from datetime import datetime, timezone
from colorama import Fore, Style, init

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

init(autoreset=True)

# ── Output helpers ────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.GREEN,
}

findings = []


def finding(severity, category, detail, recommendation):
    findings.append({
        "severity":       severity,
        "category":       category,
        "detail":         detail,
        "recommendation": recommendation,
    })
    color = SEVERITY_COLOR.get(severity, "")
    print(f"  {color}[{severity}]{Style.RESET_ALL} {category}")
    print(f"           {detail}")
    print(f"           Fix: {recommendation}\n")


def section(title):
    print(f"\n{Fore.WHITE + Style.BRIGHT}{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")


def info(msg):
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warn(msg):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


# ── CVE Database ──────────────────────────────────────────────────────────────
# Format: {service: [(max_version_tuple, [CVE IDs], description, severity), ...]}
# A finding is raised if detected version <= max_version_tuple

CVE_DB = {
    "OpenSSH": [
        ((9, 1),    ["CVE-2023-38408"], "ssh-agent RCE via malicious PKCS#11 provider", "CRITICAL"),
        ((8, 7),    ["CVE-2021-41617"], "Privilege escalation when AuthorizedKeysCommand is configured", "HIGH"),
        ((7, 6),    ["CVE-2018-15473"], "Username enumeration via observable timing difference", "MEDIUM"),
        ((7, 1),    ["CVE-2016-0777"],  "Roaming feature leaks client memory — private keys exposed", "HIGH"),
        ((6, 8),    ["CVE-2015-5600"],  "MaxAuthTries bypass via keyboard-interactive authentication", "MEDIUM"),
        ((5, 9),    ["CVE-2012-0814"],  "Timing attack to enumerate users", "MEDIUM"),
    ],
    "Apache": [
        ((2, 4, 51), ["CVE-2021-41773", "CVE-2021-42013"], "Path traversal + RCE via mod_cgi", "CRITICAL"),
        ((2, 4, 52), ["CVE-2022-22720"],  "HTTP request smuggling via incomplete request body", "HIGH"),
        ((2, 4, 55), ["CVE-2023-25690"],  "HTTP request smuggling via mod_proxy", "HIGH"),
        ((2, 4, 57), ["CVE-2023-31122"],  "mod_macro buffer over-read", "MEDIUM"),
    ],
    "nginx": [
        ((1, 17, 6), ["CVE-2019-20372"], "HTTP request smuggling via error_page", "MEDIUM"),
        ((1, 13, 2), ["CVE-2017-7529"],  "Integer overflow — memory disclosure via Range header", "MEDIUM"),
    ],
    "vsftpd": [
        ((2, 3, 4),  ["CVE-2011-2523"],  "BACKDOOR — opens a shell on port 6200", "CRITICAL"),
    ],
    "ProFTPD": [
        ((1, 3, 5),  ["CVE-2015-3306"],  "Unauthenticated arbitrary file read/write via mod_copy", "CRITICAL"),
    ],
    "Exim": [
        ((4, 94, 1), ["CVE-2021-27928"], "Remote code execution via MAIL FROM", "CRITICAL"),
        ((4, 91),    ["CVE-2019-10149"], "Remote code execution — 21Nails vulnerability chain", "CRITICAL"),
    ],
    "PHP": [
        ((7, 4, 20), ["CVE-2019-11043"], "RCE via nginx + php-fpm URL processing bug", "CRITICAL"),
        ((8, 0, 6),  ["CVE-2021-21703"], "Local privilege escalation in PHP-FPM", "HIGH"),
    ],
    "OpenSSL": [
        ((1, 0, 1),  ["CVE-2014-0160"], "Heartbleed — reads server memory, exposes private keys", "CRITICAL"),
        ((1, 0, 2),  ["CVE-2016-0800"], "DROWN — cross-protocol decryption attack via SSLv2", "CRITICAL"),
        ((1, 1, 1),  ["CVE-2022-0778"], "Infinite loop in BN_mod_sqrt() — denial of service", "HIGH"),
    ],
    "IIS": [
        ((10, 0),    ["CVE-2022-21907"], "HTTP Protocol Stack RCE — pre-auth, wormable", "CRITICAL"),
        ((7, 5),     ["CVE-2017-7269"],  "WebDAV buffer overflow — RCE", "CRITICAL"),
    ],
}

VERSION_PATTERNS = {
    "OpenSSH":  r"OpenSSH[_/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    "Apache":   r"Apache[/ ]([0-9]+\.[0-9]+\.[0-9]+)",
    "nginx":    r"nginx[/ ]([0-9]+\.[0-9]+\.[0-9]+)",
    "vsftpd":   r"vsftpd ([0-9]+\.[0-9]+\.[0-9]+)",
    "ProFTPD":  r"ProFTPD ([0-9]+\.[0-9]+\.[0-9]+)",
    "Exim":     r"Exim ([0-9]+\.[0-9]+)",
    "PHP":      r"PHP[/ ]([0-9]+\.[0-9]+\.[0-9]+)",
    "OpenSSL":  r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+)",
    "IIS":      r"Microsoft-IIS[/ ]([0-9]+\.[0-9]+)",
}

# ── Port lists ────────────────────────────────────────────────────────────────

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 2181, 2375, 2376, 3000, 3306, 3389, 4369,
    5432, 5601, 5672, 5900, 6379, 6443, 7001, 7443, 8000, 8080, 8443,
    8888, 9000, 9042, 9090, 9092, 9200, 9300, 11211, 15672, 27017, 27018,
    28017, 50070, 50075,
]

DANGEROUS_PORTS = {
    23:    ("Telnet",                "CRITICAL"),
    2375:  ("Docker API (no TLS)",   "CRITICAL"),
    6379:  ("Redis",                 "CRITICAL"),
    9200:  ("Elasticsearch",         "CRITICAL"),
    9300:  ("Elasticsearch Cluster", "CRITICAL"),
    11211: ("Memcached",             "CRITICAL"),
    27017: ("MongoDB",               "CRITICAL"),
    27018: ("MongoDB",               "CRITICAL"),
    28017: ("MongoDB HTTP",          "CRITICAL"),
    50070: ("Hadoop NameNode",       "HIGH"),
    50075: ("Hadoop DataNode",       "HIGH"),
    7001:  ("WebLogic",              "HIGH"),
    2181:  ("ZooKeeper",             "HIGH"),
    4369:  ("RabbitMQ/Erlang",       "HIGH"),
    15672: ("RabbitMQ Management",   "HIGH"),
    9092:  ("Kafka",                 "HIGH"),
    5601:  ("Kibana",                "HIGH"),
    21:    ("FTP",                   "HIGH"),
    5900:  ("VNC",                   "HIGH"),
    3389:  ("RDP",                   "HIGH"),
    445:   ("SMB",                   "HIGH"),
}

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}

HTTP_PORTS  = {80, 8080, 8000, 3000, 8888}
HTTPS_PORTS = {443, 8443, 7443, 4443}

# ── Sensitive paths to probe ──────────────────────────────────────────────────

SENSITIVE_PATHS = [
    # Environment / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.env.old", "/.env.example", "/.env.save",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/configuration.php", "/settings.py", "/settings.php",
    "/database.yml", "/database.php",
    "/wp-config.php", "/wp-config.php.bak",
    "/config/database.yml", "/config/secrets.yml",
    "/app/config/parameters.yml",
    # Git / VCS exposure
    "/.git/HEAD", "/.git/config", "/.git/index",
    "/.gitignore", "/.svn/entries", "/.hg/hgrc",
    # Admin panels
    "/admin", "/admin/", "/admin.php", "/admin/login",
    "/administrator/", "/wp-admin/", "/wp-login.php",
    "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/adminer.php",
    "/manager/html",        # Tomcat
    "/console",             # JBoss / WildFly
    "/_ah/admin",           # Google App Engine
    # Spring Boot actuator (common in Java apps)
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/dump", "/actuator/trace", "/actuator/mappings",
    "/heapdump", "/threaddump",
    # Debug / info
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info",  # Apache
    "/nginx_status",
    "/_profiler",           # Symfony
    # Backup files
    "/backup", "/backup/", "/backup.zip", "/backup.tar.gz",
    "/backup.sql", "/db.sql", "/database.sql", "/dump.sql",
    "/index.php.bak", "/web.tar.gz", "/site.tar.gz",
    # API / docs
    "/swagger-ui.html", "/swagger-ui/", "/swagger/",
    "/api-docs", "/openapi.json", "/openapi.yaml",
    "/graphiql", "/graphql",
    "/redoc", "/api/", "/api/v1/", "/api/v2/",
    # Credential files
    "/.htpasswd", "/.htaccess",
    # WordPress-specific
    "/wp-json/wp/v2/users",
    "/xmlrpc.php",
    # Docker / infra files
    "/Dockerfile", "/docker-compose.yml",
    "/requirements.txt", "/package.json", "/composer.json",
    # Discovery helpers
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    # AWS metadata proxy (if app proxies internal metadata)
    "/latest/meta-data/iam/security-credentials/",
]

# ── SQL injection error signatures ───────────────────────────────────────────

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1 AND 1=2--"]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "mysql_fetch", "mysqli_",
    "ora-01756", "oracle error",
    "sqlite_", "sqlite3",
    "pg_query", "pgsql",
    "sqlstate", "unclosed quotation mark",
    "syntax error", "unterminated string",
    "microsoft ole db", "odbc microsoft access",
    "invalid column name", "invalid object name",
    "division by zero", "supplied argument is not a valid mysql",
]

# ── Default credentials ───────────────────────────────────────────────────────

DEFAULT_WEB_CREDS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         ""),
    ("admin",         "admin123"),
    ("admin",         "123456"),
    ("administrator", "administrator"),
    ("root",          "root"),
    ("root",          "password"),
    ("test",          "test"),
    ("guest",         "guest"),
]

FTP_CREDS = [
    ("anonymous", "anonymous@example.com"),
    ("anonymous", ""),
    ("ftp",       "ftp"),
    ("admin",     "admin"),
    ("root",      "root"),
]

SNMP_COMMUNITIES = ["public", "private", "community", "manager", "admin", "default", "snmp"]

# ── Weak SSH algorithm signatures ─────────────────────────────────────────────

WEAK_SSH_KEX = {
    "diffie-hellman-group1-sha1":  "1024-bit DH — Logjam attack (CVE-2015-4000)",
    "diffie-hellman-group14-sha1": "SHA-1 based key exchange, deprecated by RFC 8270",
    "gss-group1-sha1-":            "GSSAPI with weak 1024-bit DH group",
}

WEAK_SSH_CIPHERS = {
    "arcfour":     "RC4 — cryptographically broken",
    "arcfour128":  "RC4 — cryptographically broken",
    "arcfour256":  "RC4 — cryptographically broken",
    "3des-cbc":    "3DES — SWEET32 birthday attack (CVE-2016-2183)",
    "blowfish-cbc": "Blowfish — 64-bit block, SWEET32 vulnerable",
    "cast128-cbc": "CAST-128 — deprecated",
    "aes128-cbc":  "AES-CBC — Lucky13 padding oracle possible",
    "aes192-cbc":  "AES-CBC — Lucky13 padding oracle possible",
    "aes256-cbc":  "AES-CBC — Lucky13 padding oracle possible",
}

WEAK_SSH_MACS = {
    "hmac-md5":            "MD5 — cryptographically broken",
    "hmac-md5-96":         "MD5 — cryptographically broken",
    "hmac-sha1":           "SHA-1 — deprecated",
    "hmac-sha1-96":        "SHA-1 — deprecated",
    "umac-64@openssh.com": "64-bit tag — too short, birthday attack risk",
}


# ── Port Scanner ──────────────────────────────────────────────────────────────

def scan_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False


def run_port_scan(host, ports, timeout):
    section(f"PORT SCAN — {host}")
    open_ports = []

    print(f"  Scanning {len(ports)} ports...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=150) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = PORT_SERVICES.get(port, "unknown")
                open_ports.append(port)
                info(f"Port {port:>5}/tcp  OPEN  ({service})")
                if port in DANGEROUS_PORTS:
                    svc, sev = DANGEROUS_PORTS[port]
                    finding(sev, f"Dangerous port open: {svc} ({port})",
                            f"Port {port} ({svc}) is accessible — commonly targeted by attackers",
                            f"Firewall port {port} to trusted IPs only, or disable the service if unused")

    return sorted(open_ports)


# ── Banner Grabbing + CVE Matching ────────────────────────────────────────────

def grab_banner(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if port in (80, 8080, 8000, 3000):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            try:
                return s.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""


def parse_version(banner, pattern):
    match = re.search(pattern, banner, re.IGNORECASE)
    if not match:
        return None
    try:
        return tuple(int(x) for x in match.group(1).split(".")[:3])
    except Exception:
        return None


def check_cve_versions(banner, port):
    for service, pattern in VERSION_PATTERNS.items():
        version = parse_version(banner, pattern)
        if version is None or service not in CVE_DB:
            continue
        ver_str = ".".join(str(v) for v in version)
        for max_ver, cves, desc, severity in CVE_DB[service]:
            if version <= max_ver:
                cve_str = ", ".join(cves[:2])
                finding(severity, f"CVE match: {service} {ver_str}",
                        f"{desc} ({cve_str})",
                        f"Upgrade {service} — version {ver_str} is vulnerable")


def run_banner_scan(host, open_ports, timeout):
    section("BANNER GRABBING & CVE MATCHING")
    banners = {}

    for port in open_ports:
        banner = grab_banner(host, port, timeout)
        if not banner:
            continue
        first_line = banner.split("\n")[0][:120].replace("\r", "")
        info(f"Port {port:>5}: {first_line}")
        banners[port] = banner

        # Version disclosure
        for svc, pattern in VERSION_PATTERNS.items():
            if re.search(pattern, banner, re.IGNORECASE):
                finding("LOW", f"Version disclosure on port {port}",
                        f"{svc} version is visible in the service banner",
                        "Suppress version info in server config (ServerTokens Prod / server_tokens off)")
                break

        check_cve_versions(banner, port)

    return banners


# ── SSH Deep Audit ────────────────────────────────────────────────────────────

def check_ssh_deep(host, port, timeout):
    section(f"SSH DEEP AUDIT — port {port}")

    # Get raw banner for CVE check
    banner = grab_banner(host, port, timeout)
    if banner:
        info(f"Banner: {banner.split(chr(10))[0].strip()}")
        check_cve_versions(banner, port)

    if not HAS_PARAMIKO:
        warn("paramiko not installed — skipping auth method and algorithm checks")
        return

    # ── Auth methods probe (sends zero credentials) ──
    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)
        try:
            transport.auth_none("__security_probe__")
        except paramiko.BadAuthenticationType as e:
            methods = e.allowed_types
            info(f"Supported auth methods: {', '.join(methods)}")
            if "password" in methods:
                finding("HIGH", "SSH password authentication enabled",
                        "SSH accepts password auth — vulnerable to brute force and credential stuffing",
                        "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config — use key-based auth only")
            if "keyboard-interactive" in methods:
                finding("MEDIUM", "SSH keyboard-interactive auth enabled",
                        "keyboard-interactive can allow password login via PAM",
                        "Set 'ChallengeResponseAuthentication no' in /etc/ssh/sshd_config")
        except Exception:
            pass

        # ── Algorithm audit ──
        if hasattr(transport, "_agreed_kex_algo") and transport._agreed_kex_algo:
            kex = transport._agreed_kex_algo
            for weak, reason in WEAK_SSH_KEX.items():
                if weak in kex:
                    finding("HIGH", f"Weak SSH key exchange: {kex}",
                            reason,
                            f"Remove '{kex}' from KexAlgorithms in /etc/ssh/sshd_config")

        # Check remote server's kex init for offered algorithms
        if hasattr(transport, "remote_version") and transport.remote_version:
            info(f"Remote version: {transport.remote_version}")

        transport.close()

    except paramiko.ssh_exception.SSHException:
        pass
    except Exception as e:
        warn(f"SSH probe error: {e}")

    # ── Check SSHv1 support ──
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner_raw = s.recv(256).decode("utf-8", errors="ignore")
            if "SSH-1" in banner_raw and "SSH-2" not in banner_raw:
                finding("CRITICAL", "SSHv1 supported",
                        "Server advertises SSH protocol version 1 — has known cryptographic weaknesses",
                        "Set 'Protocol 2' in /etc/ssh/sshd_config")
    except Exception:
        pass


# ── SSL / TLS Deep Audit ──────────────────────────────────────────────────────

def check_heartbleed(host, port, timeout):
    """CVE-2014-0160 — send a malformed TLS heartbeat and check for memory leak."""
    # ClientHello with heartbeat extension (TLS 1.1, 220 bytes)
    hello = bytes([
        0x16, 0x03, 0x01, 0x00, 0xdc,
        0x01, 0x00, 0x00, 0xd8,
        0x03, 0x02,
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
        0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
        0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
        0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
        0x00,
        0x00, 0x66,
        0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
        0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
        0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
        0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
        0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
        0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
        0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
        0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
        0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
        0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
        0x00, 0x05, 0x00, 0x04, 0x00, 0xff,
        0x01, 0x00,
        0x00, 0x4f,
        0xff, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00,
        0x0a, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
        0x73, 0x74,
        0x00, 0x23, 0x00, 0x00,
        0x00, 0x0f, 0x00, 0x01, 0x01,  # heartbeat extension
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
        0x05, 0x01, 0x05, 0x02, 0x05, 0x03,
        0x04, 0x01, 0x04, 0x02, 0x04, 0x03,
        0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ])
    # Heartbeat request — claims 65535 bytes payload, sends 0
    heartbeat = bytes([0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0xff, 0xff])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(hello)

        # Drain ServerHello
        data = b""
        deadline = time.time() + 4
        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\x0e" in data[5:]:  # ServerHelloDone message type
                    break
            except socket.timeout:
                break

        if not data:
            sock.close()
            return False

        sock.sendall(heartbeat)

        response = b""
        try:
            sock.settimeout(3)
            while len(response) < 100:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        sock.close()
        # A heartbeat response (type 0x18) with substantial data = vulnerable
        return len(response) > 7 and response[0] == 0x18

    except Exception:
        return False


def check_ssl_deep(host, open_ports, timeout):
    ssl_ports = [p for p in open_ports if p in HTTPS_PORTS or p in (465, 587, 993, 995)]
    if not ssl_ports:
        return

    section("SSL/TLS DEEP AUDIT")

    for port in ssl_ports:
        info(f"\n  Checking port {port}...")

        # ── Weak protocol versions ──
        for proto_name, proto_const in [
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = proto_const
                ctx.maximum_version = proto_const
                with socket.create_connection((host, port), timeout=timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        finding("HIGH", f"Weak TLS version accepted: {proto_name}",
                                f"Port {port} accepts {proto_name} — vulnerable to POODLE/BEAST attacks",
                                f"Disable {proto_name} in server config; enforce TLS 1.2 minimum")
            except Exception:
                pass

        # ── Certificate + negotiated cipher ──
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert   = ss.getpeercert()
                    cipher = ss.cipher()
                    proto  = ss.version()

            info(f"  Protocol: {proto}  Cipher: {cipher[0] if cipher else '?'}")

            if cipher and any(w in cipher[0].upper() for w in ["RC4", "DES", "NULL", "EXPORT", "MD5", "3DES"]):
                finding("HIGH", f"Weak cipher negotiated: {cipher[0]}",
                        f"Port {port} agreed on a weak cipher suite",
                        "Update cipher suite config to use ECDHE+AES-GCM or ChaCha20-Poly1305")

            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry    = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    info(f"  Cert expires: {not_after} ({days_left} days)")
                    if days_left < 0:
                        finding("CRITICAL", "SSL certificate expired",
                                f"Certificate on port {port} expired {abs(days_left)} days ago",
                                "Renew the SSL certificate immediately")
                    elif days_left < 30:
                        finding("HIGH", "SSL certificate expiring soon",
                                f"Certificate on port {port} expires in {days_left} days",
                                "Renew the SSL certificate now")

        except Exception as e:
            warn(f"  SSL connect failed on port {port}: {e}")

        # ── Heartbleed ──
        info(f"  Testing Heartbleed (CVE-2014-0160)...")
        if check_heartbleed(host, port, timeout):
            finding("CRITICAL", f"HEARTBLEED VULNERABLE (CVE-2014-0160) on port {port}",
                    "Server leaks memory on malformed heartbeat — private keys and session data exposed",
                    "Upgrade OpenSSL immediately and rotate all private keys and certificates")
        else:
            info(f"  Port {port}: Not vulnerable to Heartbleed")


# ── Web Vulnerability Scanner ─────────────────────────────────────────────────

def _web_session():
    s = requests.Session()
    s.verify  = False
    s.headers.update({"User-Agent": "Mozilla/5.0 (Security-Scanner/2.0)"})
    s.timeout = 6
    return s


def check_security_headers(resp, base_url):
    headers = {k.lower(): v for k, v in resp.headers.items()}

    REQUIRED = {
        "strict-transport-security": ("HIGH",   "HSTS missing — browser will connect over HTTP",
                                                 "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        "x-content-type-options":    ("MEDIUM",  "MIME sniffing enabled — can be used for XSS",
                                                 "Add: X-Content-Type-Options: nosniff"),
        "x-frame-options":           ("MEDIUM",  "Clickjacking possible — no framing protection",
                                                 "Add: X-Frame-Options: DENY"),
        "content-security-policy":   ("MEDIUM",  "No CSP — XSS attacks have no browser-level mitigation",
                                                 "Add a Content-Security-Policy header"),
        "referrer-policy":           ("LOW",     "Referrer-Policy missing — URLs may leak to third parties",
                                                 "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    }

    for header, (sev, issue, fix) in REQUIRED.items():
        if header not in headers:
            finding(sev, f"Missing security header: {header}", f"{issue} on {base_url}", fix)

    if "server" in headers:
        server = headers["server"]
        if any(v in server for v in ["Apache/", "nginx/", "IIS/", "PHP/", "OpenSSL"]):
            finding("LOW", "Server version disclosure",
                    f"Server header reveals version: {server}",
                    "Remove or obfuscate the Server header in your web server config")

    if "x-powered-by" in headers:
        finding("LOW", "Technology stack disclosure",
                f"X-Powered-By: {headers['x-powered-by']}",
                "Remove X-Powered-By from your app/server config")

    # Cookie flags
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if "httponly" not in str(cookie._rest).lower() and not getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if "samesite" not in str(cookie._rest).lower():
            issues.append("missing SameSite")
        if issues:
            finding("MEDIUM", f"Insecure cookie: {cookie.name}",
                    f"Cookie '{cookie.name}' has: {', '.join(issues)}",
                    "Set Secure; HttpOnly; SameSite=Strict on all session cookies")


def check_cors(session, base_url):
    try:
        r = session.get(base_url, headers={"Origin": "https://evil-attacker.com"}, allow_redirects=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            finding("MEDIUM", "CORS: wildcard origin allowed",
                    f"{base_url} sets Access-Control-Allow-Origin: * — any site can read responses",
                    "Restrict CORS to specific trusted domains; never use * with credentials")
        elif "evil-attacker.com" in acao:
            if acac == "true":
                finding("HIGH", "CORS: reflected origin with credentials allowed",
                        f"{base_url} reflects attacker origin and allows credentials — session theft possible",
                        "Validate Origin against a strict allowlist; never reflect arbitrary origins")
            else:
                finding("MEDIUM", "CORS: untrusted origin reflected",
                        f"{base_url} reflects arbitrary Origin header",
                        "Validate Origin against a strict allowlist instead of reflecting it")
    except Exception:
        pass


def check_http_methods(session, base_url):
    try:
        r = session.options(base_url, allow_redirects=False)
        allow = (r.headers.get("Allow", "") + " " + r.headers.get("Public", "")).upper()
        dangerous = [m for m in ["PUT", "DELETE", "TRACE"] if m in allow]
        if dangerous:
            finding("MEDIUM", f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                    f"{base_url} OPTIONS response advertises: {', '.join(dangerous)}",
                    "Disable PUT, DELETE, TRACE in web server config")
    except Exception:
        pass

    # Direct TRACE check
    try:
        r = session.request("TRACE", base_url)
        if r.status_code == 200 and "TRACE" in r.text.upper():
            finding("MEDIUM", "HTTP TRACE method enabled (XST)",
                    f"{base_url} reflects TRACE requests — Cross-Site Tracing can steal cookies",
                    "Set TraceEnable Off in Apache / add deny for TRACE in nginx")
    except Exception:
        pass


def check_sqli_probes(session, base_url):
    """Probe common parameters for SQL error messages."""
    params = ["id", "page", "cat", "q", "search", "user", "name", "product", "item"]
    found = []

    for param in params[:6]:
        for payload in SQLI_PAYLOADS[:2]:
            try:
                r = session.get(base_url, params={param: payload}, allow_redirects=False)
                body = r.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        found.append((param, payload, err))
                        break
            except Exception:
                pass

    for param, payload, err in found[:3]:
        finding("CRITICAL", "SQL injection fingerprint detected",
                f"Parameter '{param}' with payload {repr(payload)} triggers SQL error: '{err}'",
                "Use parameterised queries — never concatenate user input into SQL strings")


def check_sensitive_paths(session, base_url):
    section(f"SENSITIVE PATH DISCOVERY — {base_url}")
    found_paths = []

    def probe(path):
        try:
            r = session.get(base_url.rstrip("/") + path, allow_redirects=False)
            return path, r.status_code, len(r.content), r.headers.get("Content-Type", "")
        except Exception:
            return path, 0, 0, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for path, status, size, ctype in executor.map(probe, SENSITIVE_PATHS):
            if status in (200, 301, 302, 403) and size > 0:
                info(f"  HTTP {status}  {path}  ({size} bytes)  [{ctype[:40]}]")
                if status in (200, 403):
                    found_paths.append((path, status, size))

    for path, status, size in found_paths:
        if any(k in path for k in [".env", ".git", "config", "secret", "key", "pass", "id_rsa"]):
            sev = "CRITICAL"
        elif any(k in path for k in ["admin", "phpmyadmin", "backup", "phpinfo", "actuator", "dump"]):
            sev = "HIGH"
        else:
            sev = "MEDIUM"
        finding(sev, f"Sensitive path accessible: {path}",
                f"HTTP {status} returned for {base_url}{path} ({size} bytes)",
                f"Block or remove {path} — ensure it is not accessible in production")


def check_default_creds_web(session, base_url):
    """Try default credentials against HTTP Basic Auth on common admin paths."""
    admin_paths = ["/admin", "/manager/html", "/phpmyadmin/", "/adminer.php"]

    for path in admin_paths:
        try:
            url = base_url.rstrip("/") + path
            r = session.get(url, allow_redirects=False)
            if r.status_code != 401:
                continue
            for user, passwd in DEFAULT_WEB_CREDS[:6]:
                try:
                    r2 = requests.get(url, auth=(user, passwd), verify=False, timeout=5)
                    if r2.status_code == 200:
                        finding("CRITICAL", f"Default credentials accepted on {path}",
                                f"HTTP Basic Auth bypassed with '{user}:{passwd}' on {url}",
                                "Change default credentials immediately and enforce strong passwords")
                        break
                except Exception:
                    pass
        except Exception:
            pass


def check_http_redirect(session, host, open_ports):
    """Check if HTTP redirects to HTTPS."""
    if 80 in open_ports and (443 in open_ports or any(p in open_ports for p in HTTPS_PORTS)):
        try:
            r = session.get(f"http://{host}", allow_redirects=False)
            if r.status_code not in (301, 302, 307, 308) or "https" not in r.headers.get("Location", ""):
                finding("MEDIUM", "HTTP does not redirect to HTTPS",
                        f"Port 80 is open but does not redirect to HTTPS — traffic may be sent unencrypted",
                        "Add a redirect from HTTP to HTTPS in your web server config")
        except Exception:
            pass


def run_web_scan(host, open_ports, timeout):
    if not HAS_REQUESTS:
        warn("requests not installed — skipping web vulnerability scan")
        return

    web_targets = []
    for port in open_ports:
        if port in HTTP_PORTS:
            web_targets.append((f"http://{host}" + (f":{port}" if port != 80 else ""), port))
        elif port in HTTPS_PORTS:
            web_targets.append((f"https://{host}" + (f":{port}" if port != 443 else ""), port))

    if not web_targets:
        return

    session = _web_session()
    check_http_redirect(session, host, open_ports)

    for base_url, port in web_targets:
        section(f"WEB VULNERABILITY SCAN — {base_url}")
        try:
            r = session.get(base_url + "/", allow_redirects=True)
            info(f"HTTP {r.status_code} — {len(r.content)} bytes")

            if any(p in r.text.lower() for p in ["index of /", "directory listing for", "parent directory"]):
                finding("HIGH", "Directory listing enabled",
                        f"{base_url}/ exposes directory listing to browsers",
                        "Disable Options -Indexes in Apache or autoindex off in nginx")

            check_security_headers(r, base_url)
            check_cors(session, base_url)
            check_http_methods(session, base_url)
            check_sqli_probes(session, base_url)

        except Exception as e:
            warn(f"Could not connect to {base_url}: {e}")
            continue

        check_sensitive_paths(session, base_url)
        check_default_creds_web(session, base_url)


# ── FTP ───────────────────────────────────────────────────────────────────────

def check_ftp(host, port, timeout):
    section(f"FTP AUDIT — port {port}")
    for user, passwd in FTP_CREDS:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                info(f"Banner: {banner[:100]}")
                check_cve_versions(banner, port)

                s.send(f"USER {user}\r\n".encode())
                resp = s.recv(256).decode("utf-8", errors="ignore")

                if "331" in resp:
                    s.send(f"PASS {passwd}\r\n".encode())
                    resp2 = s.recv(256).decode("utf-8", errors="ignore")
                    if "230" in resp2:
                        sev = "HIGH" if user == "anonymous" else "CRITICAL"
                        finding(sev, f"FTP login succeeded: {user}:{passwd}",
                                f"FTP server accepted credentials '{user}:{passwd}'",
                                "Disable anonymous FTP; replace FTP with SFTP; restrict access to trusted IPs")
                        return
                elif "230" in resp:
                    finding("CRITICAL", f"FTP login without password: {user}",
                            f"FTP accepted user '{user}' without requiring a password",
                            "Require passwords for all FTP accounts; replace FTP with SFTP")
                    return
        except Exception:
            pass


# ── SNMP Enumeration ──────────────────────────────────────────────────────────

def check_snmp(host, timeout):
    section("SNMP ENUMERATION (UDP 161)")

    def build_snmp_get(community):
        cb = community.encode()
        # OID 1.3.6.1.2.1.1.1.0 (sysDescr)
        oid     = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        null_v  = bytes([0x05, 0x00])
        varbind = bytes([0x30, len(oid) + len(null_v)]) + oid + null_v
        vblist  = bytes([0x30, len(varbind)]) + varbind
        req_id  = bytes([0x02, 0x01, 0x01])
        err_st  = bytes([0x02, 0x01, 0x00])
        err_idx = bytes([0x02, 0x01, 0x00])
        pdu_d   = req_id + err_st + err_idx + vblist
        pdu     = bytes([0xa0, len(pdu_d)]) + pdu_d
        comm    = bytes([0x04, len(cb)]) + cb
        ver     = bytes([0x02, 0x01, 0x00])
        msg_d   = ver + comm + pdu
        return  bytes([0x30, len(msg_d)]) + msg_d

    open_communities = []
    for community in SNMP_COMMUNITIES:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(build_snmp_get(community), (host, 161))
            data, _ = sock.recvfrom(4096)
            sock.close()
            if data and len(data) > 5:
                open_communities.append(community)
                info(f"Community '{community}' responded ({len(data)} bytes)")
        except Exception:
            pass

    for community in open_communities:
        finding("HIGH", f"SNMP open with community string: '{community}'",
                f"SNMP responds to community '{community}' — exposes network topology, device info, running services",
                "Disable SNMP if unused; if needed, migrate to SNMPv3 with auth and encryption")

    if not open_communities:
        info("No SNMP community strings responded")


# ── Service-Specific Checks ───────────────────────────────────────────────────

def check_redis(host, timeout):
    try:
        with socket.create_connection((host, 6379), timeout=timeout) as s:
            s.send(b"*1\r\n$4\r\nPING\r\n")
            if "+PONG" in s.recv(64).decode("utf-8", errors="ignore"):
                finding("CRITICAL", "Redis: no authentication required",
                        "Redis responds to commands without auth — all data readable/writable",
                        "Set 'requirepass' in redis.conf and bind to 127.0.0.1 only")

                # Check if CONFIG is accessible — can be used for RCE
                s.send(b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$4\r\ndir\r\n")
                cfg = s.recv(256).decode("utf-8", errors="ignore")
                if "*2" in cfg or "$" in cfg:
                    finding("CRITICAL", "Redis: CONFIG command accessible without auth",
                            "Attacker can use CONFIG SET to write SSH keys or cron jobs — full server compromise",
                            "Set requirepass AND disable CONFIG with: rename-command CONFIG ''")
    except Exception:
        pass


def check_memcached(host, timeout):
    try:
        with socket.create_connection((host, 11211), timeout=timeout) as s:
            s.send(b"stats\r\n")
            if "STAT" in s.recv(256).decode("utf-8", errors="ignore"):
                finding("CRITICAL", "Memcached: unauthenticated access",
                        "Memcached responds to stats without auth — cached application data exposed",
                        "Bind Memcached to 127.0.0.1 and block port 11211 in firewall")
    except Exception:
        pass


def check_mongodb(host, timeout):
    try:
        bson_hello = b'\x0f\x00\x00\x00\x10hello\x00\x01\x00\x00\x00\x00'
        body       = b'\x00\x00\x00\x00' + b'\x00' + bson_hello
        header     = struct.pack('<iiii', 16 + len(body), 1, 0, 2013)
        with socket.create_connection((host, 27017), timeout=timeout) as s:
            s.send(header + body)
            resp = s.recv(512)
            if len(resp) > 16:
                finding("CRITICAL", "MongoDB: accessible without authentication",
                        "MongoDB wire protocol accepts queries without credentials",
                        "Enable auth in mongod.conf (security.authorization: enabled) and restrict port 27017")
    except Exception:
        pass


def check_elasticsearch(host, timeout):
    if not HAS_REQUESTS:
        return
    for port in [9200, 9300]:
        try:
            r = requests.get(f"http://{host}:{port}/", timeout=timeout, verify=False)
            if r.status_code == 200 and ("cluster_name" in r.text or "tagline" in r.text):
                finding("CRITICAL", f"Elasticsearch: unauthenticated on port {port}",
                        "Full cluster access without credentials — all indexed data readable",
                        "Enable X-Pack security (xpack.security.enabled: true) and restrict port")
                try:
                    r2 = requests.get(f"http://{host}:{port}/_cat/indices?v", timeout=timeout, verify=False)
                    if r2.status_code == 200:
                        indices = [l.split()[-1] for l in r2.text.strip().split("\n")[1:] if l][:5]
                        if indices:
                            info(f"  Visible indices: {', '.join(indices)}")
                except Exception:
                    pass
        except Exception:
            pass


def check_docker_api(host, timeout):
    if not HAS_REQUESTS:
        return
    try:
        r = requests.get(f"http://{host}:2375/version", timeout=timeout)
        if r.status_code == 200 and "ApiVersion" in r.text:
            finding("CRITICAL", "Docker API exposed without TLS on port 2375",
                    "Unauthenticated Docker daemon — attacker can mount host filesystem and achieve full root",
                    "Remove -H tcp:// from Docker daemon, or enforce TLS mutual auth on port 2376")
    except Exception:
        pass


def run_service_checks(host, open_ports, timeout):
    section("SERVICE-SPECIFIC CHECKS")
    if 6379  in open_ports: check_redis(host, timeout)
    if 11211 in open_ports: check_memcached(host, timeout)
    if 27017 in open_ports: check_mongodb(host, timeout)
    if any(p in open_ports for p in [9200, 9300]): check_elasticsearch(host, timeout)
    if 2375  in open_ports: check_docker_api(host, timeout)

    if 23  in open_ports:
        finding("CRITICAL", "Telnet exposed",
                "Port 23 (Telnet) is open — all traffic is plaintext including passwords",
                "Disable Telnet immediately; use SSH")
    if 445 in open_ports:
        finding("HIGH", "SMB exposed",
                "Port 445 (SMB) is accessible — EternalBlue/WannaCry targets this port",
                "Block SMB from the network; SMB should never be accessible externally")
    if 5900 in open_ports:
        finding("HIGH", "VNC exposed",
                "Port 5900 (VNC) is accessible — often weak auth or no auth",
                "Disable VNC or tunnel through SSH; never expose VNC directly")


# ── Summary ───────────────────────────────────────────────────────────────────

def generate_html_report(host, open_ports, output_path):
    scan_time = datetime.now().isoformat()
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    SEV_COLOR = {"CRITICAL": "#c0392b", "HIGH": "#e74c3c", "MEDIUM": "#e67e22", "LOW": "#3498db"}

    badge = lambda s: (f'<span style="background:{SEV_COLOR.get(s,"#888")};color:#fff;'
                       f'padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{s}</span>')

    rows = ""
    for f in findings:
        rows += (f"<tr>"
                 f"<td>{badge(f['severity'])}</td>"
                 f"<td>{f['category']}</td>"
                 f"<td>{f['detail']}</td>"
                 f"<td>{f['recommendation']}</td>"
                 f"</tr>")

    summary_pills = "".join(
        f'<span style="background:{SEV_COLOR.get(s,"#888")};color:#fff;padding:4px 12px;'
        f'border-radius:12px;margin:4px;font-weight:bold">{s}: {counts.get(s,0)}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if counts.get(s, 0)
    )

    sev_options = "".join(f'<option value="{s}">{s}</option>'
                          for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Server Scan — {host}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#0f1117;color:#e0e0e0}}
  .header{{background:#1a1d27;padding:24px 32px;border-bottom:1px solid #2a2d3a}}
  .header h1{{margin:0;font-size:1.4em;color:#fff}}
  .header p{{margin:4px 0;color:#888;font-size:0.9em}}
  .meta{{display:flex;gap:24px;margin-top:12px;flex-wrap:wrap}}
  .meta-item{{background:#0f1117;border:1px solid #2a2d3a;border-radius:6px;padding:8px 16px}}
  .meta-item span{{display:block;font-size:0.75em;color:#888;margin-bottom:2px}}
  .meta-item strong{{color:#fff}}
  .pills{{margin:8px 0}}
  .controls{{padding:16px 32px;background:#13151f;border-bottom:1px solid #2a2d3a;display:flex;gap:12px;flex-wrap:wrap}}
  input,select{{background:#1a1d27;border:1px solid #2a2d3a;color:#e0e0e0;padding:8px 12px;border-radius:6px;font-size:0.9em}}
  input{{width:280px}} input:focus,select:focus{{outline:none;border-color:#4a90d9}}
  table{{width:100%;border-collapse:collapse;font-size:0.88em}}
  th{{background:#1a1d27;color:#888;text-align:left;padding:10px 16px;font-weight:600;font-size:0.8em;text-transform:uppercase;letter-spacing:.05em;position:sticky;top:0}}
  td{{padding:10px 16px;border-bottom:1px solid #1a1d27;vertical-align:top}}
  tr:hover td{{background:#1a1d27}}
  .container{{padding:0 0 40px 0}}
  ::-webkit-scrollbar{{width:6px}} ::-webkit-scrollbar-track{{background:#0f1117}} ::-webkit-scrollbar-thumb{{background:#2a2d3a;border-radius:3px}}
</style>
</head>
<body>
<div class="header">
  <h1>Server Penetration Test — {host}</h1>
  <div class="meta">
    <div class="meta-item"><span>Target</span><strong>{host}</strong></div>
    <div class="meta-item"><span>Open Ports</span><strong>{', '.join(str(p) for p in open_ports)}</strong></div>
    <div class="meta-item"><span>Findings</span><strong>{len(findings)}</strong></div>
    <div class="meta-item"><span>Scan Time</span><strong>{scan_time}</strong></div>
  </div>
  <div class="pills" style="margin-top:12px">{summary_pills}</div>
</div>
<div class="controls">
  <input type="text" id="search" placeholder="Search findings..." oninput="filterTable()">
  <select id="sevFilter" onchange="filterTable()">
    <option value="">All severities</option>{sev_options}
  </select>
</div>
<div class="container">
<table id="findingsTable">
  <thead><tr><th>Severity</th><th>Category</th><th>Detail</th><th>Fix</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>
<script>
function filterTable(){{
  const search = document.getElementById('search').value.toLowerCase();
  const sev    = document.getElementById('sevFilter').value;
  document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
    const text   = row.textContent.toLowerCase();
    const rowSev = row.cells[0].textContent.trim();
    row.style.display = (!search || text.includes(search)) && (!sev || rowSev === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w") as fh:
        fh.write(html)
    print(f"\n{Fore.GREEN}HTML report saved to {output_path}{Style.RESET_ALL}")


def generate_csv_report(host, open_ports, output_path):
    import csv
    with open(output_path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Severity", "Category", "Detail", "Fix"])
        for f in findings:
            writer.writerow([f["severity"], f["category"], f["detail"], f["recommendation"]])
    print(f"\n{Fore.GREEN}CSV report saved to {output_path}{Style.RESET_ALL}")


def generate_json_report(host, open_ports, output_path):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    report = {
        "target":     host,
        "scan_time":  datetime.now().isoformat(),
        "open_ports": open_ports,
        "summary":    counts,
        "findings":   findings,
    }
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n{Fore.GREEN}JSON report saved to {output_path}{Style.RESET_ALL}")


def print_summary(host, open_ports):
    section("SUMMARY")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  Target        : {host}")
    print(f"  Open ports    : {open_ports}")
    print(f"  Total findings: {len(findings)}\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = counts.get(sev, 0)
        if c:
            color = SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{Style.RESET_ALL}: {c}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Server Penetration Testing Scanner — tioscapital\n"
                    "AUTHORIZED USE ONLY — only scan servers you own or have written permission to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",  required=True, help="Target IP or hostname")
    parser.add_argument("--ports",   default="top",
                        help="'top' (56 common ports), 'full' (1–65535), or 'PORT,PORT,...'")
    parser.add_argument("--output",  default=None,
                        help="Base filename for reports, no extension (e.g. 'report' or './reports/scan')")
    parser.add_argument("--format",  default="html",
                        help="Comma-separated report formats: html,csv,json (default: html)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout in seconds (default 3)")
    args = parser.parse_args()

    print(f"\n{Fore.RED + Style.BRIGHT}  AUTHORIZED USE ONLY — only scan servers you own or have written permission to test{Style.RESET_ALL}")
    print(f"\n{Fore.WHITE + Style.BRIGHT}  Server Penetration Testing Scanner — tioscapital")
    print(f"  Target : {args.target}")
    print(f"  Time   : {datetime.now().isoformat()}{Style.RESET_ALL}\n")

    try:
        ip = socket.gethostbyname(args.target)
        if ip != args.target:
            info(f"Resolved {args.target} → {ip}")
    except socket.gaierror:
        print(f"{Fore.RED}Cannot resolve: {args.target}{Style.RESET_ALL}")
        sys.exit(1)

    if args.ports == "top":
        ports = TOP_PORTS
    elif args.ports == "full":
        ports = list(range(1, 65536))
        warn("Full scan — 65535 ports — this will take a few minutes")
    else:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(f"{Fore.RED}Invalid --ports value{Style.RESET_ALL}")
            sys.exit(1)

    # Phase 1: Discovery
    open_ports = run_port_scan(ip, ports, args.timeout)
    if not open_ports:
        print(f"\n{Fore.YELLOW}No open ports found.{Style.RESET_ALL}")
        sys.exit(0)

    # Phase 2: Banner + CVE matching
    run_banner_scan(ip, open_ports, args.timeout)

    # Phase 3: SSH
    if 22 in open_ports:
        check_ssh_deep(ip, 22, args.timeout)

    # Phase 4: SSL/TLS
    check_ssl_deep(ip, open_ports, args.timeout)

    # Phase 5: Web
    run_web_scan(ip, open_ports, args.timeout)

    # Phase 6: FTP
    if 21 in open_ports:
        check_ftp(ip, 21, args.timeout)

    # Phase 7: Services
    run_service_checks(ip, open_ports, args.timeout)

    # Phase 8: SNMP (UDP — always probe)
    check_snmp(ip, args.timeout)

    print_summary(args.target, open_ports)

    if args.output:
        formats = [f.strip().lower() for f in args.format.split(",")]
        base    = args.output.rstrip(".")
        if "html" in formats: generate_html_report(args.target, open_ports, f"{base}.html")
        if "csv"  in formats: generate_csv_report(args.target, open_ports, f"{base}.csv")
        if "json" in formats: generate_json_report(args.target, open_ports, f"{base}.json")
    elif args.format != "html":
        print(f"\n{Fore.YELLOW}Tip: add --output <base> to save reports (e.g. --output report){Style.RESET_ALL}")


if __name__ == "__main__":
    main()
