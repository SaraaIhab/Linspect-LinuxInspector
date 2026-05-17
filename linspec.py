#!/usr/bin/env python3
"""
privesc_enum.py — Privilege Escalation Enumeration Tool
A manual alternative / benchmark companion to LinPEAS.
Author: Your Name | For educational use in controlled lab environments only.
"""

import os
import subprocess
import platform
import stat
import pwd
import grp
import re
import json
import sys
from datetime import datetime
from pathlib import Path

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

CRITICAL = f"{RED}{BOLD}"
WARNING  = f"{YELLOW}{BOLD}"
INFO     = f"{CYAN}"
OK       = f"{GREEN}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{CYAN}{BOLD}
╔═══════════════════════════════════════════════════════════╗
║           privesc_enum.py  —  PrivEsc Hunter              ║
║      Educational Tool | Controlled Lab Use Only           ║
╚═══════════════════════════════════════════════════════════╝
{RESET}""")

def section(title):
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  ▶  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}\n")

def finding(severity, label, detail):
    """severity: CRITICAL | WARNING | INFO | OK"""
    icons = {"CRITICAL": "💀", "WARNING": "⚠️ ", "INFO": "ℹ️ ", "OK": "✅"}
    colors = {"CRITICAL": CRITICAL, "WARNING": WARNING, "INFO": INFO, "OK": OK}
    icon  = icons.get(severity, "•")
    color = colors.get(severity, RESET)
    print(f"  {icon}  {color}[{severity}]{RESET}  {BOLD}{label}{RESET}")
    if detail:
        for line in detail.strip().split("\n"):
            print(f"       {DIM}{line}{RESET}")

def run(cmd, shell=True, timeout=10):
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""

# ─── Results store (for JSON export) ─────────────────────────────────────────
results = {
    "scan_time": datetime.now().isoformat(),
    "hostname": platform.node(),
    "findings": []
}

def record(severity, category, label, detail):
    finding(severity, label, detail)
    results["findings"].append({
        "severity": severity,
        "category": category,
        "label": label,
        "detail": detail
    })

# ─── 1. SYSTEM INFO ───────────────────────────────────────────────────────────

def check_system_info():
    section("1. System Information")

    hostname = platform.node()
    kernel   = platform.release()
    arch     = platform.machine()
    os_info  = run("cat /etc/os-release | grep PRETTY_NAME")
    user     = run("whoami")
    uid      = os.getuid()
    groups   = run("id")

    print(f"  {INFO}Hostname  :{RESET} {hostname}")
    print(f"  {INFO}OS        :{RESET} {os_info.replace('PRETTY_NAME=','').strip('\"')}")
    print(f"  {INFO}Kernel    :{RESET} {kernel}  ({arch})")
    print(f"  {INFO}Current User:{RESET} {user}  (UID={uid})")
    print(f"  {INFO}Groups    :{RESET} {groups}\n")

    # Flag if running as root already
    if uid == 0:
        record("WARNING", "system", "Already running as root", "No privesc needed — but check for persistence vectors.")

    results["system"] = {
        "hostname": hostname, "kernel": kernel,
        "arch": arch, "user": user, "uid": uid, "groups": groups
    }

# ─── 2. KERNEL VERSION CHECK ─────────────────────────────────────────────────

KNOWN_KERNEL_VULNS = {
    "4.4.0":  "CVE-2016-5195 (DirtyCow) — Local privilege escalation via race condition in copy-on-write",
    "5.8.0":  "CVE-2021-3156 (Sudo Baron Samedit) — Heap overflow in sudo, affects sudo < 1.9.5p2",
    "5.13.0": "CVE-2021-4034 (PwnKit) — Polkit pkexec local privilege escalation",
    "4.15.0": "CVE-2018-18955 — User namespace privilege escalation",
}

def check_kernel():
    section("2. Kernel Version & Known Vulnerabilities")

    kernel_full = run("uname -r")
    print(f"  Full kernel string: {BOLD}{kernel_full}{RESET}\n")

    matched = False
    for k, cve in KNOWN_KERNEL_VULNS.items():
        if kernel_full.startswith(k):
            record("CRITICAL", "kernel", f"Kernel {kernel_full} matches known vulnerability pattern",
                   f"{cve}\n  Kernel prefix matched: {k}")
            matched = True

    if not matched:
        record("INFO", "kernel",
               f"Kernel {kernel_full} — no automatic match found",
               "Cross-reference manually at: https://www.linuxkernelcves.com/cves")

    # Also check sudo version
    sudo_ver = run("sudo --version 2>/dev/null | head -1")
    if sudo_ver:
        print(f"  Sudo: {sudo_ver}")
        record("INFO", "kernel", "Sudo version detected", sudo_ver)

# ─── 3. SUID / SGID BINARIES ─────────────────────────────────────────────────

GTFOBIN_SUID = [
    "bash","sh","python","python3","perl","ruby","find","nmap",
    "vim","vi","less","more","nano","awk","nawk","gawk","tar","zip",
    "cp","mv","env","tee","wget","curl","php","lua","node","gcc",
    "dd","xxd","base64","openssl","strace","gdb","socat","netcat","nc"
]

def check_suid():
    section("3. SUID / SGID Binaries")

    output = run("find / -perm -4000 -type f 2>/dev/null")
    sgid   = run("find / -perm -2000 -type f 2>/dev/null")

    suid_bins = [l.strip() for l in output.splitlines() if l.strip()]
    sgid_bins = [l.strip() for l in sgid.splitlines() if l.strip()]

    print(f"  Found {BOLD}{len(suid_bins)}{RESET} SUID binaries, {BOLD}{len(sgid_bins)}{RESET} SGID binaries.\n")

    dangerous = []
    for path in suid_bins:
        name = os.path.basename(path).lower()
        if name in GTFOBIN_SUID:
            dangerous.append(path)

    if dangerous:
        for d in dangerous:
            record("CRITICAL", "suid",
                   f"SUID binary exploitable via GTFOBins: {d}",
                   f"Check https://gtfobins.github.io/gtfobins/{os.path.basename(d).lower()}/#suid")
    else:
        record("OK", "suid", "No obvious GTFOBins SUID matches found", "\n".join(suid_bins[:10]))

    # Print all SUID bins regardless
    print(f"\n  {DIM}All SUID binaries:{RESET}")
    for b in suid_bins:
        print(f"    {DIM}{b}{RESET}")

# ─── 4. WORLD-WRITABLE FILES & DIRECTORIES ────────────────────────────────────

SENSITIVE_PATHS = ["/etc", "/usr/local/bin", "/opt", "/var/www", "/tmp"]

def check_world_writable():
    section("4. World-Writable Files & Directories")

    # World-writable files NOT in /proc /sys /dev
    output = run(
        "find / -writable -type f 2>/dev/null "
        "| grep -v '^/proc' | grep -v '^/sys' | grep -v '^/dev'"
    )
    files = [l.strip() for l in output.splitlines() if l.strip()]

    print(f"  Found {BOLD}{len(files)}{RESET} world-writable files (excl. /proc /sys /dev)\n")

    flagged = []
    for f in files:
        for sp in SENSITIVE_PATHS:
            if f.startswith(sp):
                flagged.append(f)
                break

    if flagged:
        for f in flagged:
            record("CRITICAL", "writable",
                   f"World-writable file in sensitive path: {f}",
                   "A root-owned cron job or service referencing this file is a privesc vector.")
    else:
        record("INFO", "writable",
               f"{len(files)} world-writable files found — none in critical paths",
               "\n".join(files[:5]) if files else "None found")

    # World-writable directories
    dirs_out = run(
        "find / -writable -type d 2>/dev/null "
        "| grep -v '^/proc' | grep -v '^/sys' | grep -v '^/dev' | grep -v '^/run'"
    )
    dirs = [l.strip() for l in dirs_out.splitlines() if l.strip()]
    print(f"\n  {DIM}World-writable directories: {len(dirs)}{RESET}")
    for d in dirs[:10]:
        print(f"    {DIM}{d}{RESET}")

# ─── 5. CRON JOBS ─────────────────────────────────────────────────────────────

def check_cron():
    section("5. Cron Jobs")

    crontab_files = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
    ]

    for cf in crontab_files:
        if os.path.exists(cf):
            content = run(f"cat {cf} 2>/dev/null") if os.path.isfile(cf) else run(f"ls -la {cf}/")
            print(f"  {INFO}{cf}:{RESET}\n{DIM}{content}{RESET}\n")

            # Check if scripts referenced in crontab are writable
            if os.path.isfile(cf):
                for line in content.splitlines():
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.split()
                    for part in parts:
                        if part.startswith("/") and os.path.isfile(part):
                            try:
                                mode = os.stat(part).st_mode
                                if mode & stat.S_IWOTH:
                                    record("CRITICAL", "cron",
                                           f"Cron script is world-writable: {part}",
                                           f"Line: {line}\nThis script runs as root — append commands to escalate.")
                            except Exception:
                                pass

    # User crontab
    user_cron = run("crontab -l 2>/dev/null")
    if user_cron:
        print(f"  {INFO}Current user's crontab:{RESET}\n{DIM}{user_cron}{RESET}")

# ─── 6. SUDO CONFIGURATION ────────────────────────────────────────────────────

def check_sudo():
    section("6. Sudo Configuration")

    sudo_l = run("sudo -l 2>/dev/null")
    if not sudo_l:
        record("OK", "sudo", "Cannot run sudo -l (no sudo access or requires password)", "")
        return

    print(f"  {DIM}{sudo_l}{RESET}\n")

    if "NOPASSWD" in sudo_l:
        record("CRITICAL", "sudo",
               "NOPASSWD entry found in sudo rules",
               f"{sudo_l}\nCheck GTFOBins for allowed binaries.")
    elif "(ALL" in sudo_l:
        record("WARNING", "sudo",
               "Broad sudo permissions detected",
               sudo_l)
    else:
        record("INFO", "sudo", "Sudo rules found — review manually", sudo_l)

# ─── 7. SERVICES & PROCESSES ──────────────────────────────────────────────────

def check_services():
    section("7. Running Services & Processes (Root-owned)")

    # Processes running as root
    ps_out = run("ps aux 2>/dev/null | grep '^root' | grep -v grep")
    print(f"  {INFO}Root-owned processes:{RESET}\n")
    for line in ps_out.splitlines()[:15]:
        print(f"  {DIM}{line}{RESET}")

    # Writable service unit files
    unit_out = run(
        "find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' "
        "-writable 2>/dev/null"
    )
    if unit_out:
        record("CRITICAL", "services",
               "Writable systemd service file(s) found",
               unit_out + "\nModify ExecStart to execute a payload as root.")
    else:
        record("OK", "services", "No writable systemd service files detected", "")

# ─── 8. PATH HIJACKING CHECK ──────────────────────────────────────────────────

def check_path():
    section("8. PATH Hijacking Opportunities")

    path_val = os.environ.get("PATH", "")
    print(f"  Current PATH: {BOLD}{path_val}{RESET}\n")

    writable_in_path = []
    for directory in path_val.split(":"):
        if not directory:
            continue
        try:
            if os.access(directory, os.W_OK):
                writable_in_path.append(directory)
        except Exception:
            pass

    if writable_in_path:
        record("CRITICAL", "path",
               "Writable directories found in PATH",
               "\n".join(writable_in_path) +
               "\nPlant a malicious binary with a common name (e.g. 'id', 'ls') to hijack execution.")
    else:
        record("OK", "path", "No writable directories in PATH", path_val)

    # Check if PATH contains current directory (.) — dangerous
    if "." in path_val.split(":") or "" in path_val.split(":"):
        record("WARNING", "path",
               "Current directory (.) is in PATH",
               "Commands run from a writable CWD may be hijacked.")

# ─── 9. INTERESTING FILES ─────────────────────────────────────────────────────

def check_interesting_files():
    section("9. Interesting Files (Credentials, Keys, History)")

    checks = {
        "Bash history":         run("cat ~/.bash_history 2>/dev/null | head -30"),
        "SSH private keys":     run("find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null | head -10"),
        "Config files w/ pass": run("grep -rli 'password' /etc /opt /var/www 2>/dev/null | head -10"),
        ".env files":           run("find / -name '.env' 2>/dev/null | grep -v proc | head -10"),
        "Readable /etc/shadow": run("cat /etc/shadow 2>/dev/null | head -5"),
        "MySQL credentials":    run("find / -name '.my.cnf' 2>/dev/null"),
    }

    for label, output in checks.items():
        if output:
            severity = "CRITICAL" if label in ["Readable /etc/shadow", "SSH private keys"] else "WARNING"
            record(severity, "files", label, output)
        else:
            print(f"  {OK}✅ {label}: nothing found{RESET}")

# ─── 10. NETWORK EXPOSURE ─────────────────────────────────────────────────────

def check_network():
    section("10. Network — Locally Listening Services")

    netstat = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    print(f"  {DIM}{netstat}{RESET}\n")

    # Internal-only services (127.0.0.1) not exposed externally
    internal = [l for l in netstat.splitlines() if "127.0.0.1" in l]
    if internal:
        record("INFO", "network",
               f"{len(internal)} service(s) listening only on localhost",
               "\n".join(internal) + "\nThese may be exploitable via local port forwarding.")

# ─── REPORT ───────────────────────────────────────────────────────────────────

def print_summary():
    section("SUMMARY")

    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "OK": 0}
    for f in results["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  {CRITICAL}💀 CRITICAL : {counts['CRITICAL']}{RESET}")
    print(f"  {WARNING}⚠️  WARNING  : {counts['WARNING']}{RESET}")
    print(f"  {INFO}ℹ️  INFO     : {counts['INFO']}{RESET}")
    print(f"  {OK}✅ OK       : {counts['OK']}{RESET}")

    # JSON export
    outfile = f"/tmp/privesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(outfile, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n  {INFO}Full JSON report saved to: {BOLD}{outfile}{RESET}")
    except Exception as e:
        print(f"\n  {WARNING}Could not save JSON report: {e}{RESET}")

    print(f"\n  {DIM}Compare these findings against LinPEAS output to benchmark accuracy.{RESET}\n")

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    banner()
    print(f"  {WARNING}⚠  For use in authorised lab environments only.{RESET}\n")

    checks = [
        check_system_info,
        check_kernel,
        check_suid,
        check_world_writable,
        check_cron,
        check_sudo,
        check_services,
        check_path,
        check_interesting_files,
        check_network,
    ]

    for check in checks:
        try:
            check()
        except Exception as e:
            print(f"  {WARNING}Check failed: {check.__name__} — {e}{RESET}")

    print_summary()

if __name__ == "__main__":
    if platform.system() != "Linux":
        print(f"{WARNING}Warning: This script is designed for Linux systems.{RESET}")
    main()
