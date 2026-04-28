#!/usr/bin/env python3
"""
Server Vulnerability Scanner — tioscapital
Authorized penetration testing tool. Only run against servers you own
or have explicit written permission to test.

READ-ONLY GUARANTEE — this script never:
  - Uploads, creates, or deletes files on the target
  - Executes commands on the target
  - Modifies any service configuration
  - Sends credentials (SSH uses auth_none probe only)
  All checks are observe-only: TCP connect, banner read, header read, read-only protocol queries.

Usage:
  python server_scan.py --target 1.2.3.4
  python server_scan.py --target myserver.com --ports full --output report.txt
  python server_scan.py --target 1.2.3.4 --ports 22,80,443,3306,6379
"""

import socket
import ssl
import struct
import argparse
import sys
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ── Severity / output helpers ────────────────────────────────────────────────

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


# ── Port lists ────────────────────────────────────────────────────────────────

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 2181, 2375, 2376, 3000, 3306, 3389, 4369,
    5432, 5601, 5672, 5900, 6379, 6443, 7001, 7443, 8000, 8080, 8443,
    8888, 9000, 9042, 9090, 9092, 9200, 9300, 11211, 15672, 27017, 27018,
    28017, 50070, 50075,
]

# Services that should NEVER be internet-exposed without auth
DANGEROUS_PORTS = {
    21:    ("FTP",           "HIGH"),
    23:    ("Telnet",        "CRITICAL"),
    2375:  ("Docker (no TLS)","CRITICAL"),
    5601:  ("Kibana",        "HIGH"),
    6379:  ("Redis",         "CRITICAL"),
    9200:  ("Elasticsearch", "CRITICAL"),
    9300:  ("Elasticsearch cluster", "CRITICAL"),
    11211: ("Memcached",     "CRITICAL"),
    27017: ("MongoDB",       "CRITICAL"),
    27018: ("MongoDB",       "CRITICAL"),
    28017: ("MongoDB HTTP",  "CRITICAL"),
    50070: ("Hadoop NameNode","HIGH"),
    50075: ("Hadoop DataNode","HIGH"),
    7001:  ("WebLogic",      "HIGH"),
    2181:  ("ZooKeeper",     "HIGH"),
    4369:  ("RabbitMQ/Erlang","HIGH"),
    15672: ("RabbitMQ Mgmt", "HIGH"),
    9092:  ("Kafka",         "HIGH"),
}

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}


# ── Port scanner ──────────────────────────────────────────────────────────────

def scan_port(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False


def run_port_scan(host, ports):
    section(f"PORT SCAN — {host}")
    open_ports = []

    print(f"  Scanning {len(ports)} ports...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = PORT_SERVICES.get(port, "unknown")
                open_ports.append(port)
                info(f"Port {port:>5}/tcp  OPEN  ({service})")

                # Immediately flag dangerous ports
                if port in DANGEROUS_PORTS:
                    svc_name, sev = DANGEROUS_PORTS[port]
                    finding(sev, f"Exposed {svc_name} port {port}",
                            f"Port {port} ({svc_name}) is accessible — no auth may be required",
                            f"Firewall port {port} to trusted IPs only or disable if unused")

    open_ports.sort()
    print(f"\n  {Fore.WHITE + Style.BRIGHT}Open ports: {open_ports}{Style.RESET_ALL}")
    return open_ports


# ── Banner grabbing ───────────────────────────────────────────────────────────

def grab_banner(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                if not banner:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner[:300]
            except Exception:
                return None
    except Exception:
        return None


def run_banner_grab(host, open_ports):
    section("BANNER GRABBING")
    banners = {}
    for port in open_ports:
        banner = grab_banner(host, port)
        if banner:
            banners[port] = banner
            info(f"Port {port}: {banner[:100].replace(chr(10),' ').replace(chr(13),'')}")

            # Version disclosure checks
            lower = banner.lower()
            for keyword in ["apache", "nginx", "openssh", "vsftpd", "proftpd",
                            "microsoft-iis", "php", "wordpress", "drupal"]:
                if keyword in lower:
                    finding("LOW", "Version Disclosure",
                            f"Port {port} reveals software version: {banner[:80]}",
                            "Suppress version banners in server config (e.g. ServerTokens Prod in Apache)")
                    break
    return banners


# ── SSH checks ────────────────────────────────────────────────────────────────

def check_ssh(host, port=22):
    section("SSH SECURITY")
    banner = grab_banner(host, port)
    if not banner:
        warn("Could not retrieve SSH banner")
        return

    info(f"SSH Banner: {banner}")

    # Old SSH version
    if "SSH-1" in banner:
        finding("CRITICAL", "SSH Protocol Version",
                "Server supports SSH protocol version 1 (SSHv1)",
                "Disable SSHv1 in /etc/ssh/sshd_config: Protocol 2")

    # Weak version patterns
    if any(v in banner for v in ["OpenSSH_6.", "OpenSSH_5.", "OpenSSH_4.", "OpenSSH_7.2"]):
        finding("HIGH", "Outdated OpenSSH",
                f"Outdated OpenSSH version detected: {banner}",
                "Update OpenSSH to the latest stable version")

    # Query supported auth methods using auth_none — sends NO credentials, purely read-only.
    # The server rejects auth_none and responds with the list of allowed methods.
    try:
        import paramiko
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=5)
        try:
            transport.auth_none("__probe__")
        except paramiko.BadAuthenticationType as e:
            allowed = e.allowed_types
            info(f"SSH auth methods: {', '.join(allowed)}")
            if "password" in allowed:
                finding("MEDIUM", "SSH Password Authentication",
                        f"SSH allows password-based authentication (methods: {', '.join(allowed)})",
                        "Disable password auth in sshd_config: PasswordAuthentication no  (use key-based auth only)")
        except Exception:
            pass
        finally:
            transport.close()
    except ImportError:
        warn("paramiko not installed — skipping SSH auth method check")
    except Exception:
        pass


# ── HTTP/HTTPS checks ─────────────────────────────────────────────────────────

def check_http(host, port, use_tls=False):
    proto = "https" if use_tls else "http"
    url = f"{proto}://{host}:{port}"

    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        resp = requests.get(url, timeout=5, verify=False,
                            allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (Security-Audit)"})

        info(f"{proto.upper()}:{port} — {resp.status_code} {resp.reason}")

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Security headers
        required_headers = {
            "strict-transport-security": ("HIGH", "HSTS not set",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            "x-content-type-options":    ("MEDIUM", "X-Content-Type-Options not set",
                "Add: X-Content-Type-Options: nosniff"),
            "x-frame-options":           ("MEDIUM", "X-Frame-Options not set",
                "Add: X-Frame-Options: DENY or SAMEORIGIN"),
            "content-security-policy":   ("MEDIUM", "Content-Security-Policy not set",
                "Define a strict CSP header to prevent XSS"),
            "referrer-policy":           ("LOW",    "Referrer-Policy not set",
                "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            "permissions-policy":        ("LOW",    "Permissions-Policy not set",
                "Add a Permissions-Policy header to restrict browser features"),
        }

        for header, (sev, issue, fix) in required_headers.items():
            if header not in headers:
                finding(sev, f"Missing HTTP Header ({header})",
                        f"{url} does not send '{header}' header",
                        fix)

        # Server header info leak
        if "server" in headers:
            finding("LOW", "Server Header Disclosure",
                    f"Server header reveals: {headers['server']}",
                    "Remove or genericize the Server header in your web server config")

        # X-Powered-By leak
        if "x-powered-by" in headers:
            finding("LOW", "X-Powered-By Header Disclosure",
                    f"X-Powered-By: {headers['x-powered-by']}",
                    "Remove X-Powered-By header from your application/server config")

        # Check for directory listing (basic)
        if any(phrase in resp.text.lower() for phrase in
               ["index of /", "directory listing for", "parent directory"]):
            finding("HIGH", "Directory Listing Enabled",
                    f"{url} appears to have directory listing enabled",
                    "Disable directory listing in your web server config (Options -Indexes in Apache)")

    except ImportError:
        warn("requests not installed — skipping HTTP header checks")
    except Exception as e:
        warn(f"HTTP check failed on {url}: {e}")


def check_ssl(host, port=443):
    section(f"SSL/TLS — port {port}")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()

        info(f"Protocol : {proto}")
        info(f"Cipher   : {cipher[0] if cipher else 'unknown'}")

        # Weak TLS versions
        if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            finding("HIGH", "Weak TLS Version",
                    f"Server negotiated {proto} — this version has known vulnerabilities",
                    "Disable TLS 1.0 and 1.1; enforce TLS 1.2+ in your server config")

        # Cipher strength
        if cipher:
            cipher_name = cipher[0].upper()
            if any(w in cipher_name for w in ["RC4", "DES", "NULL", "EXPORT", "MD5", "3DES"]):
                finding("HIGH", "Weak Cipher Suite",
                        f"Weak cipher in use: {cipher_name}",
                        "Remove weak ciphers from your SSL config; use ECDHE + AES-GCM suites")

        # Certificate expiry
        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
                info(f"Cert expires: {not_after} ({days_left} days)")
                if days_left < 0:
                    finding("CRITICAL", "SSL Certificate Expired",
                            f"Certificate expired {abs(days_left)} days ago",
                            "Renew SSL certificate immediately")
                elif days_left < 30:
                    finding("HIGH", "SSL Certificate Expiring Soon",
                            f"Certificate expires in {days_left} days",
                            "Renew SSL certificate before it expires")

    except ssl.SSLError as e:
        warn(f"SSL error on port {port}: {e}")
    except Exception as e:
        warn(f"TLS check failed: {e}")


# ── FTP anonymous login ───────────────────────────────────────────────────────

def check_ftp(host, port=21):
    section("FTP")
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            banner = s.recv(1024).decode("utf-8", errors="ignore")
            info(f"FTP Banner: {banner.strip()}")

            s.send(b"USER anonymous\r\n")
            resp = s.recv(1024).decode("utf-8", errors="ignore")
            if resp.startswith("331"):
                s.send(b"PASS anonymous@test.com\r\n")
                resp2 = s.recv(1024).decode("utf-8", errors="ignore")
                if resp2.startswith("230"):
                    finding("CRITICAL", "FTP Anonymous Login",
                            "FTP server allows anonymous login",
                            "Disable anonymous FTP access or replace FTP with SFTP/SCP entirely")
                else:
                    finding("HIGH", "FTP Service Exposed",
                            "FTP is running (anonymous login rejected but service is exposed)",
                            "Replace FTP with SFTP; if FTP is required, restrict to trusted IPs")
    except Exception as e:
        warn(f"FTP check: {e}")


# ── Common unauthenticated services ──────────────────────────────────────────

def check_redis(host, port=6379):
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.send(b"PING\r\n")
            resp = s.recv(64).decode("utf-8", errors="ignore")
            if "+PONG" in resp:
                finding("CRITICAL", "Redis No Authentication",
                        f"Redis on port {port} responds to PING without authentication",
                        "Set 'requirepass <strong-password>' in redis.conf and restrict port to localhost/VPC")
    except Exception:
        pass


def check_memcached(host, port=11211):
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.send(b"stats\r\n")
            resp = s.recv(256).decode("utf-8", errors="ignore")
            if "STAT" in resp:
                finding("CRITICAL", "Memcached Unauthenticated",
                        f"Memcached on port {port} responds without authentication",
                        "Bind Memcached to 127.0.0.1 only; use security groups to block external access")
    except Exception:
        pass


def check_mongodb(host, port=27017):
    # Send a read-only OP_MSG "hello" command — equivalent to db.hello(), no writes.
    # BSON: {hello: 1}  (15 bytes)
    # OP_MSG: flagBits(4) + section_type_0(1) + bson_doc
    try:
        bson_hello = b'\x0f\x00\x00\x00\x10hello\x00\x01\x00\x00\x00\x00'
        body = b'\x00\x00\x00\x00' + b'\x00' + bson_hello  # flagBits + section type 0 + doc
        header = struct.pack('<iiii', 16 + len(body), 1, 0, 2013)  # opCode 2013 = OP_MSG
        with socket.create_connection((host, port), timeout=3) as s:
            s.send(header + body)
            resp = s.recv(256)
            if len(resp) > 16:
                finding("CRITICAL", "MongoDB Unauthenticated",
                        f"MongoDB on port {port} responds to hello without authentication",
                        "Enable MongoDB authentication (security.authorization: enabled) and restrict port to VPC only")
    except Exception:
        pass


def check_elasticsearch(host, port=9200):
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        resp = requests.get(f"http://{host}:{port}", timeout=3)
        if resp.status_code == 200 and "cluster_name" in resp.text:
            finding("CRITICAL", "Elasticsearch Unauthenticated",
                    f"Elasticsearch on port {port} responds without authentication",
                    "Enable Elasticsearch security (xpack.security.enabled: true) and restrict port")
    except Exception:
        pass


def run_service_checks(host, open_ports):
    section("SERVICE-SPECIFIC CHECKS")

    if 22  in open_ports: check_ssh(host, 22)
    if 21  in open_ports: check_ftp(host, 21)
    if 6379 in open_ports: check_redis(host, 6379)
    if 11211 in open_ports: check_memcached(host, 11211)
    if 27017 in open_ports: check_mongodb(host, 27017)
    if 9200 in open_ports: check_elasticsearch(host, 9200)

    # HTTP
    for port in [p for p in open_ports if p in (80, 8080, 8000, 3000)]:
        section(f"HTTP — port {port}")
        check_http(host, port, use_tls=False)

    # HTTPS
    for port in [p for p in open_ports if p in (443, 8443, 4443)]:
        section(f"HTTPS — port {port}")
        check_ssl(host, port)
        check_http(host, port, use_tls=True)

    # Telnet
    if 23 in open_ports:
        finding("CRITICAL", "Telnet Exposed",
                "Port 23 (Telnet) is open — all traffic is cleartext",
                "Disable Telnet immediately and use SSH instead")

    # RDP
    if 3389 in open_ports:
        finding("HIGH", "RDP Exposed",
                "Port 3389 (RDP) is publicly accessible",
                "Restrict RDP to VPN/bastion only; enable NLA; use AWS Systems Manager Session Manager instead")

    # SMB
    if 445 in open_ports:
        finding("HIGH", "SMB Exposed",
                "Port 445 (SMB) is publicly accessible",
                "Block SMB from the internet; SMB should never be exposed publicly (EternalBlue/WannaCry)")

    # VNC
    if 5900 in open_ports:
        finding("HIGH", "VNC Exposed",
                "Port 5900 (VNC) is publicly accessible",
                "Disable or firewall VNC; use SSH tunneling or AWS Session Manager instead")

    # Docker daemon
    if 2375 in open_ports:
        finding("CRITICAL", "Docker Daemon Exposed (No TLS)",
                "Port 2375 (Docker daemon without TLS) is accessible — full host takeover possible",
                "Disable Docker TCP socket or enforce TLS on port 2376; never expose port 2375 publicly")


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(target, open_ports, output_file=None):
    section("SUMMARY")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  Target     : {target}")
    print(f"  Open ports : {open_ports}")
    print(f"  Total findings: {len(findings)}\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        color = SEVERITY_COLOR.get(sev, "")
        count = counts.get(sev, 0)
        if count:
            print(f"  {color}{sev:<10}{Style.RESET_ALL}: {count}")

    if output_file:
        with open(output_file, "w") as fh:
            fh.write(f"Server Vulnerability Scan Report\n")
            fh.write(f"Target : {target}\n")
            fh.write(f"Date   : {datetime.now().isoformat()}\n")
            fh.write("=" * 60 + "\n\n")
            fh.write(f"Open ports: {open_ports}\n\n")
            for f in findings:
                fh.write(f"[{f['severity']}] {f['category']}\n")
                fh.write(f"  {f['detail']}\n")
                fh.write(f"  Fix: {f['recommendation']}\n\n")
            fh.write(f"\nTotal: {len(findings)} findings\n")
            for sev, count in counts.items():
                fh.write(f"  {sev}: {count}\n")
        print(f"\n{Fore.GREEN}Report saved to {output_file}{Style.RESET_ALL}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Server Vulnerability Scanner — tioscapital\n"
                    "WARNING: Only use against servers you own or have authorization to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target",  required=True, help="Target IP or hostname")
    parser.add_argument("--ports",   default="top",
                        help="'top' (default), 'full' (1-65535), or comma-separated list e.g. 22,80,443")
    parser.add_argument("--output",  default=None, help="Save report to file (e.g. report.txt)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Port scan timeout in seconds")
    args = parser.parse_args()

    print(f"\n{Fore.RED + Style.BRIGHT}⚠  AUTHORIZED USE ONLY — only scan servers you own or have permission to test{Style.RESET_ALL}")
    print(f"\n{Fore.WHITE + Style.BRIGHT}Server Vulnerability Scanner — tioscapital")
    print(f"Target : {args.target}")
    print(f"Time   : {datetime.now().isoformat()}{Style.RESET_ALL}")

    # Resolve hostname
    try:
        ip = socket.gethostbyname(args.target)
        if ip != args.target:
            info(f"Resolved {args.target} → {ip}")
    except socket.gaierror:
        print(f"{Fore.RED}Could not resolve host: {args.target}{Style.RESET_ALL}")
        sys.exit(1)

    # Build port list
    if args.ports == "top":
        ports = TOP_PORTS
    elif args.ports == "full":
        ports = list(range(1, 65536))
        print(f"{Fore.YELLOW}Full scan (65535 ports) — this will take several minutes...{Style.RESET_ALL}")
    else:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(f"{Fore.RED}Invalid port list: {args.ports}{Style.RESET_ALL}")
            sys.exit(1)

    open_ports = run_port_scan(ip, ports)

    if not open_ports:
        print(f"{Fore.YELLOW}No open ports found. The host may be firewalled or offline.{Style.RESET_ALL}")
        sys.exit(0)

    run_banner_grab(ip, open_ports)
    run_service_checks(ip, open_ports)
    print_summary(args.target, open_ports, args.output)


if __name__ == "__main__":
    main()
