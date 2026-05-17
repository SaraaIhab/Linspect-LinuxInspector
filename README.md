# privesc_enum.py — Linux Privilege Escalation Enumeration Tool

> **For educational use in authorised, controlled lab environments only.**  
> Do not run this tool on systems you do not own or have explicit permission to test.

---

## Overview

`privesc_enum.py` is a manual Linux privilege escalation enumeration tool and a benchmark companion to [LinPEAS](https://github.com/carlospolop/PEASS-ng). It systematically audits a Linux system for common misconfigurations and vulnerabilities that could allow a low-privilege user to escalate to root.

The tool is written entirely in Python 3 using the standard library — no external dependencies required.

---

## How It Works

Key imports include subprocess, which can run shell commands from within the python script, os, which may engage with the OS and platform,  which can get the system’s information such as the hostname. Constants in the beginning such as GREEN   = "\033[92m"  and CYAN    = "\033[96m" are ANSI escape codes, their purpose is to make the resulting output more human friendly and readable at a glance.

There are four main helper functions. First, `run()`, which acts as the gateway between the Python code and the outer shell it has a timeout of 10 seconds so as not to be delayed by a slow command. Second, `section()`, which prints headers to allow the end user to see which section of the scan is currently running. It is a purely decorative function. Third, `finding()`, which prints findings using the ANSI escape codes defined at the start. Lastly, `record()`, which stores all findings in a dictionary ready for JSON export.

---

##  The 10 Check Modules

### 1. `check_system_info()` — System Information
Collects context about the machine by running `whoami` and `os.getuid()` to identify the current user, and `id` to list all group memberships. If the UID is zero, the user is already root, in which case the tool notifies that privilege escalation is unnecessary and that persistence vectors are more relevant.

### 2. `check_kernel()` — Kernel Vulnerability Matching
Four of the most well-known kernel vulnerabilities are stored in a dictionary. The tool runs `uname -r` to get the full kernel string and checks if it matches any of the four vulnerability prefixes. If a match is found, it flags a critical warning. Otherwise, it alerts the user that no automatic match was found. This function also checks and displays the installed `sudo` version.

### 3. `check_suid()` — SUID / SGID Binaries
Runs `find / -perm -4000` and `find / -perm -2000` to find files where the SUID or SGID bit is set. The SUID bit allows a binary to run with the privileges of its owner (often root). While legitimate for commands like `/bin/passwd`, it is dangerous for utilities like `find`, which can spawn a privileged shell. Found binaries are cross-referenced against a curated `GTFOBIN_SUID` list — any matches are flagged as CRITICAL.

### 4. `check_world_writable()` — World-Writable Files & Directories
Runs `find / -writable -type f` (excluding virtual filesystems like `/proc`, `/sys`, and `/dev`) to find files anyone can write to. Results are cross-referenced against a list of sensitive paths (`/etc`, `/opt`, `/var/www`, etc.) — any matches are flagged as CRITICAL, as a root-owned process reading a world-writable config file is a direct escalation vector.

### 5. `check_cron()` — Cron Job Analysis
Cron jobs are time-based schedulers that run predefined tasks at set intervals. The tool checks three sources:
- `/etc/crontab` which checks system-wide cron jobs
- `/etc/cron.d/` which is a drop-in cron directory
- `/var/spool/cron/crontabs` which checks per-user cron jobs

If any script referenced by a cron job is world-writable, any user can inject commands that will be executed as root.

### 6. `check_sudo()` — Sudo Configuration
Runs `sudo -l` and checks for two dangerous patterns:
- **NOPASSWD** : the user can run something as root without a password
- **ALL** : broad permissions suggesting the user can run any command as root

### 7. `check_services()` — Services & Processes
Runs `ps aux | grep '^root'` to list all root-owned processes, then searches for writable systemd service files. If a `.service` file can be modified, its `ExecStart` directive can be changed to execute any payload as root on the next service restart or system reboot.

### 8. `check_path()` — PATH Hijacking
Checks if any directory in the current user's `$PATH` environment variable is writable. If so, an attacker can plant a malicious binary with a common name (e.g. `ls`, `id`) that gets executed in place of the real one when called by a privileged process. Also flags if `.` (the current directory) is in `$PATH`.

### 9. `check_interesting_files()` — Credentials & Keys
Searches for high-value targets including:
- `~/.bash_history` : command history, often containing plaintext passwords
- `id_rsa` / `id_ed25519` : SSH private keys enabling lateral movement
- `/etc/shadow` : hashed passwords (readable only by root under normal conditions)
- `.env` files : API keys and database credentials
- `.my.cnf` : MySQL credentials often stored in plaintext
- Config files containing the word `password`

### 10. `check_network()` — Network Exposure
Lists all listening TCP services using `ss -tlnp`. Flags services bound to `127.0.0.1` (loopback) — these are not exposed to the network but are reachable by a local attacker and may be exploitable via port forwarding.

---

##  Output & Reporting

After all checks complete, the tool prints a summary of findings by severity:

| Severity | Meaning |
|----------|---------|
| 💀 CRITICAL | Directly exploitable misconfiguration |
| ⚠️ WARNING | Potentially dangerous — review manually |
| ℹ️ INFO | Informational — worth noting |
| ✅ OK | No issue detected |

A full JSON report is saved to `/tmp/privesc_report_<timestamp>.json` for offline review or comparison against LinPEAS output.

---

## Usage

```bash
# Clone the repo
git clone https://github.com/SaraaIhab/privesc_enum.git
cd privesc_enum

# Run the tool (Python 3, no dependencies needed)
python3 privesc_enum.py
```

> **Note:** Some checks (e.g. `sudo -l`, reading `/etc/shadow`) may require specific permissions. Run as a low-privilege user to simulate a real escalation scenario.

---

##  Project Structure

```
privesc_enum/
├── privesc_enum.py       # Main enumeration script
├── README.md             # This file
├── LICENSE               # MIT License
└── sample_output/
    └── example_report.json   # Example JSON output
```

---

##  Disclaimer

This tool is intended **solely for educational purposes** in authorised environments such as:
- Personal home labs
- CTF (Capture The Flag) challenges
- Penetration testing engagements with written permission

Unauthorised use against systems you do not own is **illegal** and unethical. The authors accept no responsibility for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
