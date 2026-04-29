#!/usr/bin/env python3
"""
Lynis Remote Scanner — tioscapital
Discovers all running EC2 instances, installs Lynis, runs a full audit,
pulls the results back to your Mac, and generates a combined report.

READ-ONLY on AWS: only ec2:DescribeInstances is called.
Lynis itself is read-only on the server — it audits but never changes anything.

Usage:
  python3 lynis_scan.py --key ~/.ssh/mykey.pem
  python3 lynis_scan.py --key ~/.ssh/mykey.pem --user ubuntu --region us-east-1
  python3 lynis_scan.py --key ~/.ssh/mykey.pem --instance i-1234567890abc
  python3 lynis_scan.py --key ~/.ssh/mykey.pem --output ./lynis_reports
"""

import boto3
import paramiko
import argparse
import sys
import os
import json
import csv
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ── Helpers ──────────────────────────────────────────────────────────────────

def info(msg):  print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):  print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def error(msg): print(f"  {Fore.RED}[✗]{Style.RESET_ALL} {msg}")
def step(msg):  print(f"\n  {Fore.WHITE + Style.BRIGHT}→ {msg}{Style.RESET_ALL}")


def section(title):
    print(f"\n{Fore.WHITE + Style.BRIGHT}{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")


# ── EC2 discovery ─────────────────────────────────────────────────────────────

def discover_instances(session, region, instance_id_filter=None, use_private_ip=False):
    ec2 = session.client("ec2", region_name=region)
    filters = [{"Name": "instance-state-name", "Values": ["running"]}]
    if instance_id_filter:
        filters.append({"Name": "instance-id", "Values": [instance_id_filter]})

    reservations = ec2.describe_instances(Filters=filters)["Reservations"]
    instances = []

    for res in reservations:
        for inst in res["Instances"]:
            iid = inst["InstanceId"]
            ip = inst.get("PrivateIpAddress") if use_private_ip else inst.get("PublicIpAddress")

            if not ip:
                warn(f"{iid}: no {'private' if use_private_ip else 'public'} IP — skipping "
                     f"(use --private-ip if instance is in a private subnet)")
                continue

            # Get Name tag if present
            name = iid
            for tag in inst.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
                    break

            platform = inst.get("Platform", "linux")  # 'windows' or absent (linux)
            if platform == "windows":
                warn(f"{iid} ({name}): Windows instance — Lynis is Linux only, skipping")
                continue

            instances.append({
                "id":     iid,
                "name":   name,
                "ip":     ip,
                "type":   inst.get("InstanceType"),
                "az":     inst["Placement"]["AvailabilityZone"],
            })
            info(f"Found: {iid} ({name})  {ip}  {inst.get('InstanceType')}")

    return instances


# ── SSH connection ────────────────────────────────────────────────────────────

def ssh_connect(ip, user, key_path, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key_file(key_path)
    client.connect(ip, username=user, pkey=key, timeout=timeout,
                   banner_timeout=30, auth_timeout=30)
    # Send keepalive every 30s so long-running commands (Lynis) don't drop the connection
    client.get_transport().set_keepalive(30)
    return client


def ssh_run(client, command, timeout=900):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    rc  = stdout.channel.recv_exit_status()
    return rc, out, err


# ── OS detection ──────────────────────────────────────────────────────────────

def detect_os(client):
    rc, out, _ = ssh_run(client, "cat /etc/os-release 2>/dev/null || cat /etc/system-release 2>/dev/null")
    out_lower = out.lower()

    if "ubuntu" in out_lower:
        return "ubuntu", "apt"
    if "debian" in out_lower:
        return "debian", "apt"
    if "amazon linux" in out_lower:
        return "amzn", "yum"
    if "centos" in out_lower:
        return "centos", "yum"
    if "rhel" in out_lower or "red hat" in out_lower:
        return "rhel", "yum"
    if "fedora" in out_lower:
        return "fedora", "dnf"
    return "unknown", "yum"


# ── Lynis install + run ───────────────────────────────────────────────────────

LYNIS_VERSION = "3.1.4"  # latest stable — update this when a new version is released


def get_installed_lynis_version(client):
    rc, out, _ = ssh_run(client, "lynis --version 2>/dev/null | head -1")
    if rc == 0 and out.strip():
        # output is like "3.0.9" or "Lynis 3.0.9"
        for part in out.strip().split():
            if part[0].isdigit():
                return part.strip()
    return None


def install_lynis_latest(client):
    step(f"Installing Lynis {LYNIS_VERSION} from source (always latest)...")
    cmds = [
        "sudo apt-get install -y curl 2>/dev/null || sudo yum install -y curl 2>/dev/null || true",
        "cd /tmp && sudo rm -rf lynis lynis-*.tar.gz",
        f"cd /tmp && curl -sO https://downloads.cisofy.com/lynis/lynis-{LYNIS_VERSION}.tar.gz",
        f"cd /tmp && sudo tar -xzf lynis-{LYNIS_VERSION}.tar.gz",
        "sudo rm -rf /usr/local/lynis",
        "sudo mv /tmp/lynis /usr/local/lynis",
        "sudo ln -sf /usr/local/lynis/lynis /usr/local/bin/lynis",
        "sudo chmod +x /usr/local/lynis/lynis",
    ]
    for cmd in cmds:
        rc, out, err = ssh_run(client, cmd, timeout=60)
        if rc != 0:
            error(f"Install step failed: {cmd}\n  {err[:150]}")
            return False
    rc, _, _ = ssh_run(client, "which lynis")
    return rc == 0


def install_lynis(client, pkg_manager):
    installed = get_installed_lynis_version(client)

    if installed:
        info(f"Lynis installed: v{installed}")
        if installed == LYNIS_VERSION:
            info(f"Already on latest version ({LYNIS_VERSION}) — skipping update")
            return True
        warn(f"Lynis v{installed} is outdated — upgrading to v{LYNIS_VERSION}...")
    else:
        step("Lynis not found — installing...")

    return install_lynis_latest(client)


REPORT_FILE = "/var/log/lynis-report.dat"


def run_lynis_background(client):
    step("Starting Lynis audit in background...")

    # Remove old report and any leftover launcher
    ssh_run(client, f"sudo rm -f {REPORT_FILE} /tmp/lynis_launcher.sh /tmp/lynis_run.log", timeout=10)

    # Write a launcher script — more reliable than inline bash with nohup
    script = (
        "#!/bin/bash\n"
        "/usr/local/lynis/lynis audit system "
        "--cronjob --no-colors --auditor tioscapital-scanner "
        "> /tmp/lynis_run.log 2>&1\n"
    )
    # Write script via tee
    ssh_run(client, f"echo '{script}' | sudo tee /tmp/lynis_launcher.sh > /dev/null", timeout=10)
    ssh_run(client, "sudo chmod +x /tmp/lynis_launcher.sh", timeout=5)

    # Launch detached via nohup, capture PID
    rc, out, _ = ssh_run(client, "sudo nohup /tmp/lynis_launcher.sh > /dev/null 2>&1 & echo $!", timeout=15)
    pid = out.strip()
    if pid.isdigit():
        info(f"Lynis started (PID {pid}) — scan takes ~10 minutes, polling every 60s...")
    else:
        warn(f"Unexpected PID output: '{pid}' — will poll by process name")
        pid = None
    return pid


def show_lynis_log(client):
    rc, out, _ = ssh_run(client, "sudo tail -30 /tmp/lynis_run.log 2>/dev/null", timeout=10)
    if out.strip():
        print(f"\n  {Fore.YELLOW}Lynis log (last 30 lines):{Style.RESET_ALL}")
        for line in out.strip().splitlines():
            print(f"    {line}")
    else:
        warn("No Lynis log found at /tmp/lynis_run.log")


def wait_for_lynis(ip, user, key_path, pid=None, poll_interval=60, max_wait=900):
    # Wait 2 minutes before first check — scan takes ~10 minutes
    info("Waiting 2 minutes before first check...")
    time.sleep(120)

    # Reconnect every poll_interval seconds and check if Lynis is still running
    elapsed = 120
    while elapsed < max_wait:
        time.sleep(poll_interval)
        elapsed += poll_interval
        try:
            client = ssh_connect(ip, user, key_path)

            # Check both by PID and by process name
            rc, out, _ = ssh_run(client,
                "pgrep -f 'lynis_launcher\\|lynis audit' > /dev/null 2>&1 && echo running || echo done",
                timeout=10)
            still_running = "running" in out

            if still_running:
                info(f"Lynis still running... ({elapsed}s elapsed)")
                client.close()
            else:
                info(f"Lynis finished after {elapsed}s")
                return client  # return open connection ready to pull report

        except Exception as e:
            warn(f"Poll attempt failed ({elapsed}s): {e} — retrying...")

    return None  # timed out


def pull_report(client):
    # Try our controlled report path first, then fall back to default locations
    report_paths = [
        REPORT_FILE,
        "/var/log/lynis-report.dat",
        "/var/log/lynis/lynis-report.dat",
    ]
    for path in report_paths:
        rc, out, _ = ssh_run(client, f"sudo cat {path} 2>/dev/null", timeout=30)
        if rc == 0 and out.strip() and "hardening_index" in out:
            return out
    return None


# ── Report parsing ────────────────────────────────────────────────────────────

def parse_report(raw):
    result = {
        "hardening_index": None,
        "lynis_version":   None,
        "os":              None,
        "kernel":          None,
        "warnings":        [],
        "suggestions":     [],
        "tests_performed": None,
    }

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("hardening_index="):
            result["hardening_index"] = line.split("=", 1)[1]
        elif line.startswith("lynis_version="):
            result["lynis_version"] = line.split("=", 1)[1]
        elif line.startswith("os="):
            result["os"] = line.split("=", 1)[1]
        elif line.startswith("linux_kernel_version="):
            result["kernel"] = line.split("=", 1)[1]
        elif line.startswith("tests_executed="):
            result["tests_performed"] = line.split("=", 1)[1]
        elif line.startswith("warning[]="):
            parts = line.split("=", 1)[1].split("|")
            result["warnings"].append({
                "id":   parts[0] if len(parts) > 0 else "",
                "desc": parts[1] if len(parts) > 1 else "",
                "fix":  parts[2] if len(parts) > 2 else "",
            })
        elif line.startswith("suggestion[]="):
            parts = line.split("=", 1)[1].split("|")
            result["suggestions"].append({
                "id":   parts[0] if len(parts) > 0 else "",
                "desc": parts[1] if len(parts) > 1 else "",
                "fix":  parts[2] if len(parts) > 2 else "",
            })

    return result


def hardening_color(index):
    try:
        score = int(index)
        if score >= 80: return Fore.GREEN
        if score >= 60: return Fore.YELLOW
        return Fore.RED
    except Exception:
        return Fore.WHITE


def print_instance_report(instance, parsed):
    section(f"RESULTS — {instance['name']} ({instance['id']})  {instance['ip']}")

    score = parsed.get("hardening_index", "?")
    color = hardening_color(score)
    print(f"  {color}Hardening Score : {score}/100{Style.RESET_ALL}")
    print(f"  OS              : {parsed.get('os', 'unknown')}")
    print(f"  Kernel          : {parsed.get('kernel', 'unknown')}")
    print(f"  Lynis version   : {parsed.get('lynis_version', 'unknown')}")
    print(f"  Tests performed : {parsed.get('tests_performed', 'unknown')}")
    print(f"  Warnings        : {Fore.RED}{len(parsed['warnings'])}{Style.RESET_ALL}")
    print(f"  Suggestions     : {Fore.YELLOW}{len(parsed['suggestions'])}{Style.RESET_ALL}\n")

    if parsed["warnings"]:
        print(f"  {Fore.RED + Style.BRIGHT}WARNINGS{Style.RESET_ALL}")
        for w in parsed["warnings"]:
            print(f"  {Fore.RED}[WARN]{Style.RESET_ALL} {w['id']}: {w['desc']}")
            if w["fix"]:
                print(f"         Fix: {w['fix']}")
        print()

    if parsed["suggestions"]:
        print(f"  {Fore.YELLOW + Style.BRIGHT}SUGGESTIONS (top 20){Style.RESET_ALL}")
        for s in parsed["suggestions"][:20]:
            print(f"  {Fore.YELLOW}[SUGG]{Style.RESET_ALL} {s['id']}: {s['desc']}")
        if len(parsed["suggestions"]) > 20:
            print(f"  ... and {len(parsed['suggestions']) - 20} more (see full report file)")


# ── Save reports ──────────────────────────────────────────────────────────────

def save_reports(output_dir, instance, raw_report, parsed):
    os.makedirs(output_dir, exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    iid = instance["id"]

    # Raw Lynis report
    raw_path = os.path.join(output_dir, f"{iid}_{ts}_lynis_raw.dat")
    with open(raw_path, "w") as f:
        f.write(raw_report)

    # Parsed JSON summary
    json_path = os.path.join(output_dir, f"{iid}_{ts}_summary.json")
    with open(json_path, "w") as f:
        json.dump({"instance": instance, "report": parsed}, f, indent=2)

    # CSV — one row per finding (warnings + suggestions)
    csv_path = os.path.join(output_dir, f"{iid}_{ts}_findings.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Instance ID", "Instance Name", "IP", "Hardening Score",
                         "OS", "Kernel", "Lynis Version",
                         "Type", "ID", "Description", "Fix"])
        score   = parsed.get("hardening_index", "")
        os_name = parsed.get("os", "")
        kernel  = parsed.get("kernel", "")
        lver    = parsed.get("lynis_version", "")
        for w in parsed["warnings"]:
            writer.writerow([iid, instance["name"], instance["ip"], score,
                             os_name, kernel, lver,
                             "WARNING", w["id"], w["desc"], w["fix"]])
        for s in parsed["suggestions"]:
            writer.writerow([iid, instance["name"], instance["ip"], score,
                             os_name, kernel, lver,
                             "SUGGESTION", s["id"], s["desc"], s["fix"]])

    info(f"CSV saved : {csv_path}")
    return raw_path, json_path, csv_path


# ── HTML Report ──────────────────────────────────────────────────────────────

def generate_html_report(all_results, output_path):
    scan_time = datetime.now().isoformat()

    def score_color(score):
        try:
            s = int(score)
            if s >= 80: return "#27ae60"
            if s >= 65: return "#f39c12"
            return "#e74c3c"
        except Exception:
            return "#888"

    def score_bar(score):
        try:
            pct = min(int(score), 100)
        except Exception:
            pct = 0
        color = score_color(score)
        return (f'<div style="background:#2a2d3a;border-radius:4px;height:8px;width:100px;display:inline-block;vertical-align:middle">'
                f'<div style="background:{color};width:{pct}%;height:8px;border-radius:4px"></div></div>'
                f'&nbsp;<strong style="color:{color}">{score}/100</strong>')

    # Summary table rows
    summary_rows = ""
    for r in all_results:
        inst   = r["instance"]
        parsed = r["parsed"]
        score  = parsed.get("hardening_index", "?")
        warns  = len(parsed["warnings"])
        suggs  = len(parsed["suggestions"])
        summary_rows += (f"<tr>"
                         f"<td>{inst['id']}</td>"
                         f"<td>{inst['name']}</td>"
                         f"<td>{inst['ip']}</td>"
                         f"<td>{score_bar(score)}</td>"
                         f"<td style='color:#e74c3c;font-weight:bold'>{warns}</td>"
                         f"<td style='color:#f39c12'>{suggs}</td>"
                         f"<td>{parsed.get('os','?')}</td>"
                         f"</tr>")

    # Findings rows
    finding_rows = ""
    for r in all_results:
        inst   = r["instance"]
        parsed = r["parsed"]
        iid    = inst["id"]
        iip    = inst["ip"]
        score  = parsed.get("hardening_index", "?")

        for w in parsed["warnings"]:
            finding_rows += (f"<tr data-instance='{iid}' data-type='WARNING'>"
                             f"<td>{iid}</td><td>{iip}</td>"
                             f"<td><span style='background:#e74c3c;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em'>WARNING</span></td>"
                             f"<td>{w['id']}</td><td>{w['desc']}</td><td>{w.get('fix','-')}</td>"
                             f"</tr>")
        for s in parsed["suggestions"]:
            finding_rows += (f"<tr data-instance='{iid}' data-type='SUGGESTION'>"
                             f"<td>{iid}</td><td>{iip}</td>"
                             f"<td><span style='background:#f39c12;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em'>SUGGESTION</span></td>"
                             f"<td>{s['id']}</td><td>{s['desc']}</td><td>{s.get('fix','-')}</td>"
                             f"</tr>")

    scores = [int(r["parsed"]["hardening_index"])
              for r in all_results
              if str(r["parsed"].get("hardening_index","")).isdigit()]
    avg_score = sum(scores) // len(scores) if scores else 0

    instance_options = "".join(
        f'<option value="{r["instance"]["id"]}">{r["instance"]["id"]} ({r["instance"]["ip"]})</option>'
        for r in all_results
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Lynis Security Report — tioscapital</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#0f1117;color:#e0e0e0}}
  .header{{background:#1a1d27;padding:24px 32px;border-bottom:1px solid #2a2d3a}}
  .header h1{{margin:0;font-size:1.4em;color:#fff}}
  .meta{{display:flex;gap:16px;margin-top:12px;flex-wrap:wrap}}
  .meta-item{{background:#0f1117;border:1px solid #2a2d3a;border-radius:6px;padding:8px 16px}}
  .meta-item span{{display:block;font-size:0.75em;color:#888;margin-bottom:2px}}
  .meta-item strong{{color:#fff}}
  h2{{color:#aaa;font-size:0.9em;text-transform:uppercase;letter-spacing:.08em;padding:20px 32px 8px;margin:0;border-top:1px solid #2a2d3a}}
  .controls{{padding:12px 32px;background:#13151f;border-bottom:1px solid #2a2d3a;display:flex;gap:12px;flex-wrap:wrap}}
  input,select{{background:#1a1d27;border:1px solid #2a2d3a;color:#e0e0e0;padding:8px 12px;border-radius:6px;font-size:0.9em}}
  input{{width:260px}} input:focus,select:focus{{outline:none;border-color:#4a90d9}}
  table{{width:100%;border-collapse:collapse;font-size:0.87em}}
  th{{background:#1a1d27;color:#888;text-align:left;padding:10px 16px;font-weight:600;font-size:0.78em;text-transform:uppercase;letter-spacing:.05em;position:sticky;top:0}}
  td{{padding:9px 16px;border-bottom:1px solid #1a1d27;vertical-align:top}}
  tr:hover td{{background:#1a1d27}}
  ::-webkit-scrollbar{{width:6px}} ::-webkit-scrollbar-track{{background:#0f1117}} ::-webkit-scrollbar-thumb{{background:#2a2d3a;border-radius:3px}}
</style>
</head>
<body>
<div class="header">
  <h1>Lynis Security Audit — tioscapital</h1>
  <div class="meta">
    <div class="meta-item"><span>Instances Scanned</span><strong>{len(all_results)}</strong></div>
    <div class="meta-item"><span>Average Hardening Score</span><strong style="color:{score_color(avg_score)}">{avg_score}/100</strong></div>
    <div class="meta-item"><span>Scan Time</span><strong>{scan_time}</strong></div>
  </div>
</div>

<h2>Instance Summary</h2>
<table>
  <thead><tr><th>Instance ID</th><th>Name</th><th>IP</th><th>Hardening Score</th><th>Warnings</th><th>Suggestions</th><th>OS</th></tr></thead>
  <tbody>{summary_rows}</tbody>
</table>

<h2>All Findings</h2>
<div class="controls">
  <input type="text" id="search" placeholder="Search findings..." oninput="filterFindings()">
  <select id="instanceFilter" onchange="filterFindings()">
    <option value="">All instances</option>{instance_options}
  </select>
  <select id="typeFilter" onchange="filterFindings()">
    <option value="">All types</option>
    <option value="WARNING">Warnings only</option>
    <option value="SUGGESTION">Suggestions only</option>
  </select>
</div>
<table id="findingsTable">
  <thead><tr><th>Instance</th><th>IP</th><th>Type</th><th>Check ID</th><th>Finding</th><th>Fix</th></tr></thead>
  <tbody>{finding_rows}</tbody>
</table>

<script>
function filterFindings(){{
  const search = document.getElementById('search').value.toLowerCase();
  const inst   = document.getElementById('instanceFilter').value;
  const type   = document.getElementById('typeFilter').value;
  document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
    const text    = row.textContent.toLowerCase();
    const rowInst = row.dataset.instance || '';
    const rowType = row.dataset.type || '';
    row.style.display =
      (!search || text.includes(search)) &&
      (!inst   || rowInst === inst) &&
      (!type   || rowType === type) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w") as fh:
        fh.write(html)
    print(f"\n  {Fore.GREEN}HTML report : {output_path}{Style.RESET_ALL}")


# ── Combined summary ──────────────────────────────────────────────────────────

def print_combined_summary(all_results):
    section("COMBINED SUMMARY — ALL INSTANCES")

    if not all_results:
        warn("No results to summarize.")
        return

    print(f"  {'Instance':<30} {'IP':<16} {'Score':>6}  {'Warnings':>8}  {'Suggestions':>11}")
    print(f"  {'-'*30} {'-'*16} {'-'*6}  {'-'*8}  {'-'*11}")

    for r in all_results:
        inst    = r["instance"]
        parsed  = r["parsed"]
        score   = parsed.get("hardening_index") or "?"
        color   = hardening_color(score)
        warns   = len(parsed["warnings"])
        suggs   = len(parsed["suggestions"])
        name    = f"{inst['name'][:28]}"
        print(f"  {name:<30} {inst['ip']:<16} {color}{str(score):>6}{Style.RESET_ALL}  "
              f"{Fore.RED}{warns:>8}{Style.RESET_ALL}  {Fore.YELLOW}{suggs:>11}{Style.RESET_ALL}")

    scores = [int(r["parsed"]["hardening_index"])
              for r in all_results if r["parsed"].get("hardening_index") and str(r["parsed"]["hardening_index"]).isdigit()]
    if scores:
        avg = sum(scores) // len(scores)
        color = hardening_color(avg)
        print(f"\n  {color}Average hardening score: {avg}/100{Style.RESET_ALL}")
        if avg < 60:
            print(f"  {Fore.RED}Your infrastructure needs significant hardening work.{Style.RESET_ALL}")
        elif avg < 80:
            print(f"  {Fore.YELLOW}Good start — address the warnings to improve your score.{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}Well hardened — keep reviewing suggestions periodically.{Style.RESET_ALL}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Lynis Remote Scanner — tioscapital\n"
                    "Connects to EC2 instances via SSH, runs Lynis, pulls results.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--output", default="./lynis_reports",
                        help="Directory to save reports (default: ./lynis_reports)")
    parser.add_argument("--format", default="html,csv,json",
                        help="Comma-separated report formats: html,csv,json (default: all three)")
    args = parser.parse_args()
    formats = [f.strip().lower() for f in args.format.split(",")]

    # Hardcoded for tioscapital infrastructure
    profile        = "security-scanner"
    region         = "us-east-1"
    use_private_ip = True  # all instances are in private subnets — requires VPN connection

    print(f"\n{Fore.WHITE + Style.BRIGHT}Lynis Remote Scanner — tioscapital{Style.RESET_ALL}\n")
    print(f"  {Fore.YELLOW}Make sure you are connected to the VPN before continuing.{Style.RESET_ALL}\n")

    # Prompt for SSH key
    while True:
        raw = input(f"  {Fore.CYAN}SSH key path (.pem){Style.RESET_ALL} [e.g. ~/.ssh/mykey.pem]: ").strip()
        key_path = os.path.expanduser(raw)
        if os.path.exists(key_path):
            break
        print(f"  {Fore.RED}File not found: {key_path} — try again{Style.RESET_ALL}")

    # Prompt for SSH username
    raw = input(f"  {Fore.CYAN}SSH username{Style.RESET_ALL} [default: ubuntu]: ").strip()
    ssh_user = raw if raw else "ubuntu"

    # Prompt for instance ID or IP
    raw = input(f"  {Fore.CYAN}Instance ID or private IP{Style.RESET_ALL} [e.g. i-0abc123 or 10.0.1.55]: ").strip()
    instance_input = raw if raw else None

    print(f"\n  Profile : {profile}")
    print(f"  Region  : {region}")
    print(f"  SSH User: {ssh_user}")
    print(f"  Key     : {key_path}")
    print(f"  Target  : {instance_input or 'all running instances'}")
    print(f"  Output  : {args.output}")
    print(f"  Time    : {datetime.now().isoformat()}")

    # If user entered a raw IP, build the instance list directly without AWS lookup
    session = boto3.Session(profile_name=profile, region_name=region)

    if instance_input and instance_input[0].isdigit():
        # Looks like an IP address — use it directly
        instances = [{"id": "unknown", "name": instance_input, "ip": instance_input,
                      "type": "unknown", "az": "unknown"}]
        info(f"Using IP directly: {instance_input}")
    else:
        # Instance ID or None — discover via AWS
        section("DISCOVERING EC2 INSTANCES")
        instance_id_filter = instance_input if instance_input and instance_input.startswith("i-") else None
        instances = discover_instances(session, region, instance_id_filter, use_private_ip)

    if not instances:
        print(f"{Fore.YELLOW}No running instances found.{Style.RESET_ALL}")
        sys.exit(0)

    print(f"\n  Found {len(instances)} instance(s) to scan.")

    # Scan each instance
    all_results = []

    for inst in instances:
        section(f"SCANNING — {inst['name']} ({inst['id']})  {inst['ip']}")

        try:
            step(f"Connecting via SSH ({ssh_user}@{inst['ip']})...")
            client = ssh_connect(inst["ip"], ssh_user, key_path)
            info("SSH connected")

            os_name, pkg_manager = detect_os(client)
            info(f"OS detected: {os_name} (package manager: {pkg_manager})")

            if not install_lynis(client, pkg_manager):
                error(f"Could not install Lynis on {inst['id']} — skipping")
                client.close()
                continue

            info("Lynis installed")

            # Start Lynis in background then close SSH — avoids timeout on long scans
            pid = run_lynis_background(client)
            client.close()

            # Reconnect every 30s to check if Lynis finished
            client = wait_for_lynis(inst["ip"], ssh_user, key_path, pid, max_wait=1200)
            if not client:
                error(f"Lynis timed out on {inst['id']} after 20 minutes")
                continue

            step("Pulling report...")
            raw_report = pull_report(client)

            if not raw_report:
                error(f"Could not retrieve Lynis report from {inst['id']}")
                show_lynis_log(client)
                client.close()
                continue

            client.close()

            parsed = parse_report(raw_report)
            print_instance_report(inst, parsed)
            save_reports(args.output, inst, raw_report, parsed)

            all_results.append({"instance": inst, "parsed": parsed})

        except paramiko.AuthenticationException:
            error(f"{inst['ip']}: SSH authentication failed — check --user and --key")
        except paramiko.SSHException as e:
            error(f"{inst['ip']}: SSH error — {e}")
        except TimeoutError:
            error(f"{inst['ip']}: Connection timed out — instance may not be reachable")
        except Exception as e:
            error(f"{inst['ip']}: Unexpected error — {e}")

    print_combined_summary(all_results)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(args.output, exist_ok=True)
    saved = []

    if "json" in formats:
        combined_json = os.path.join(args.output, f"combined_{ts}.json")
        with open(combined_json, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        saved.append(("JSON ", combined_json))

    if "csv" in formats:
        combined_csv = os.path.join(args.output, f"combined_{ts}.csv")
        with open(combined_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Instance ID", "Instance Name", "IP", "Hardening Score",
                             "OS", "Kernel", "Lynis Version",
                             "Type", "ID", "Description", "Fix"])
            for r in all_results:
                inst   = r["instance"]
                parsed = r["parsed"]
                score  = parsed.get("hardening_index", "")
                for w in parsed["warnings"]:
                    writer.writerow([inst["id"], inst["name"], inst["ip"], score,
                                     parsed.get("os",""), parsed.get("kernel",""), parsed.get("lynis_version",""),
                                     "WARNING", w["id"], w["desc"], w["fix"]])
                for s in parsed["suggestions"]:
                    writer.writerow([inst["id"], inst["name"], inst["ip"], score,
                                     parsed.get("os",""), parsed.get("kernel",""), parsed.get("lynis_version",""),
                                     "SUGGESTION", s["id"], s["desc"], s["fix"]])
        saved.append(("CSV  ", combined_csv))

    if "html" in formats:
        combined_html = os.path.join(args.output, f"combined_{ts}.html")
        generate_html_report(all_results, combined_html)
        saved.append(("HTML ", combined_html))

    print()
    for label, path in saved:
        print(f"  {Fore.GREEN}{label}: {path}{Style.RESET_ALL}")
    print()


if __name__ == "__main__":
    main()
