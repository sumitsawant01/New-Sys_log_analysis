#!/usr/init/env python3
"""
===================================================================
Project Title : System Log Security Analyzer (Static & Real-Time)
Target OS     : Kali Linux / Debian-based Linux
Language      : Python 3
Description   : Parses authentication logs, detects SSH brute-force 
                attacks, flags invalid user attempts, logs privilege 
                escalations (sudo), and tracks successful login activities 
                either statically or in real-time via journalctl.
===================================================================
"""

import sys
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime

# ANSI Color Codes for Kali Terminal UI
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

SAMPLE_LOGS = """May 10 10:14:22 kali sshd[1234]: Failed password for root from 192.168.1.105 port 54321 ssh2
May 10 10:14:25 kali sshd[1235]: Failed password for root from 192.168.1.105 port 54322 ssh2
May 10 10:14:28 kali sshd[1236]: Failed password for root from 192.168.1.105 port 54323 ssh2
May 10 10:14:31 kali sshd[1237]: Failed password for root from 192.168.1.105 port 54324 ssh2
May 10 10:14:35 kali sshd[1238]: Failed password for root from 192.168.1.105 port 54325 ssh2
May 10 10:14:40 kali sshd[1239]: Failed password for invalid user admin from 10.0.0.50 port 44321 ssh2
May 10 10:14:42 kali sshd[1240]: Failed password for invalid user guest from 10.0.0.50 port 44322 ssh2
May 10 10:15:02 kali sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
May 10 10:16:10 kali sshd[1241]: Accepted password for kali from 192.168.1.50 port 51111 ssh2
"""

class LogParser:
    """Extracts structured fields from syslog/journalctl lines."""
    
    LOG_PATTERN = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w-]+)\s+'
        r'(?P<process>[\w\(\)\[\]/-]+):\s+'
        r'(?P<message>.*)$'
    )

    @classmethod
    def parse_line(cls, line):
        match = cls.LOG_PATTERN.match(line.strip())
        return match.groupdict() if match else None


class ThreatDetector:
    """Analyzes parsed log entries for security threats."""
    
    def __init__(self, brute_force_threshold=3):
        self.threshold = brute_force_threshold
        self.failed_attempts = defaultdict(int)
        self.invalid_users = []
        self.sudo_events = []
        self.successful_logins = []

    def process_entry(self, entry, live_mode=False):
        msg = entry.get('message', '')
        ts = entry.get('timestamp', 'N/A')

        # 1. SSH Failed Passwords & Brute Force Tracking
        if 'Failed password' in msg:
            ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', msg)
            user_match = re.search(r'for (?:invalid user )?(\w+)', msg)
            
            ip = ip_match.group(1) if ip_match else 'Unknown'
            user = user_match.group(1) if user_match else 'Unknown'
            
            self.failed_attempts[ip] += 1
            
            if 'invalid user' in msg:
                self.invalid_users.append({'timestamp': ts, 'user': user, 'ip': ip})
                if live_mode:
                    print(f"{Colors.YELLOW}  [-] INVALID USER: '{user}' from IP {ip} at {ts}{Colors.RESET}")

            if self.failed_attempts[ip] == self.threshold and live_mode:
                print(f"{Colors.RED}  [ALERT] Brute-force threshold breached by IP: {ip} ({self.failed_attempts[ip]} attempts){Colors.RESET}")

        # 2. Privilege Escalation (Sudo Usage)
        elif 'sudo:' in msg or 'COMMAND=' in msg:
            self.sudo_events.append({'timestamp': ts, 'details': msg})
            if live_mode:
                print(f"{Colors.BLUE}  [*] SUDO EVENT: {ts} | {msg}{Colors.RESET}")

        # 3. Successful Logins
        elif 'Accepted password' in msg or 'session opened' in msg:
            user_match = re.search(r'for (\w+)', msg)
            user = user_match.group(1) if user_match else 'Unknown'
            self.successful_logins.append({'timestamp': ts, 'user': user})
            if live_mode:
                print(f"{Colors.GREEN}  [+] SUCCESSFUL LOGIN: User '{user}' at {ts}{Colors.RESET}")

    def get_results(self):
        brute_force_ips = {ip: cnt for ip, cnt in self.failed_attempts.items() if cnt >= self.threshold}
        return {
            'brute_force': brute_force_ips,
            'invalid_users': self.invalid_users,
            'sudo_events': self.sudo_events,
            'successful_logins': self.successful_logins
        }


def print_and_save_report(results, total_lines, target_source):
    """Prints formatted output to terminal and exports a text report."""
    report_lines = []
    
    def output(text, color=""):
        clean_text = re.sub(r'\033\[[0-9;]*m', '', text)
        report_lines.append(clean_text)
        print(f"{color}{text}{Colors.RESET if color else ''}")

    output("=" * 65, Colors.BOLD)
    output("         KALI LINUX SYSTEM LOG ANALYZER REPORT         ", Colors.BOLD)
    output("=" * 65, Colors.BOLD)
    output(f"Analysis Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output(f"Log Source    : {target_source}")
    output(f"Total Lines   : {total_lines}")
    output("-" * 65)

    # Brute Force Section
    output("\n[!] BRUTE-FORCE DETECTIONS (THRESHOLD >= 3 FAILED ATTEMPTS):", Colors.BOLD)
    if results['brute_force']:
        for ip, count in results['brute_force'].items():
            output(f"  [ALERT] High Risk IP: {ip:<15} | Failed Attempts: {count}", Colors.RED)
    else:
        output("  [+] No brute-force thresholds breached.", Colors.GREEN)

    # Invalid Users Section
    output("\n[!] INVALID USER LOGIN ATTEMPTS:", Colors.BOLD)
    if results['invalid_users']:
        for item in results['invalid_users']:
            output(f"  [-] Time: {item['timestamp']} | Target User: '{item['user']}' | Source IP: {item['ip']}", Colors.YELLOW)
    else:
        output("  [+] No unauthorized username attempts found.", Colors.GREEN)

    # Privilege Escalation Section
    output("\n[!] PRIVILEGE ESCALATION MONITORING (SUDO ACTIVITIES):", Colors.BOLD)
    if results['sudo_events']:
        for item in results['sudo_events']:
            output(f"  [*] Time: {item['timestamp']} | Event: {item['details']}", Colors.BLUE)
    else:
        output("  [+] No privilege escalation events detected.", Colors.GREEN)

    # Successful Logins Section
    output("\n[+] SUCCESSFUL LOGIN ACTIVITIES:", Colors.BOLD)
    if results['successful_logins']:
        for item in results['successful_logins']:
            output(f"  [+] Time: {item['timestamp']} | User: '{item['user']}' successfully logged in", Colors.GREEN)
    else:
        output("  [-] No successful login sessions recorded in this dataset.", Colors.YELLOW)

    output("\n" + "=" * 65, Colors.BOLD)

    report_filename = "system_security_report.txt"
    with open(report_filename, "w") as f:
        f.write("\n".join(report_lines))
    
    output(f"\n[+] Analysis complete! Text report saved to: {os.path.abspath(report_filename)}", Colors.GREEN)


def stream_realtime_journal(detector):
    """Streams system logs live using journalctl via subprocess."""
    print(f"{Colors.BOLD}[*] Streaming live system logs via journalctl (-f)...{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Listening for events... Press Ctrl+C to exit and generate report.\n{Colors.RESET}")
    
    cmd = ['journalctl', '-f', '-o', 'syslog']
    total_lines = 0
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout:
            total_lines += 1
            parsed = LogParser.parse_line(line)
            if parsed:
                detector.process_entry(parsed, live_mode=True)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Real-time monitoring stopped by user. Generating summary report...{Colors.RESET}")
        if 'process' in locals():
            process.terminate()
    return total_lines


def main():
    detector = ThreatDetector(brute_force_threshold=3)
    total_lines = 0

    # Command line argument handling
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--live" or arg == "-l":
            # Real-time mode via journalctl
            if os.geteuid() != 0:
                print(f"{Colors.RED}[-] Error: Real-time journal monitoring requires root privileges.{Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Run with: sudo python3 {sys.argv[0]} --live{Colors.RESET}")
                sys.exit(1)
            target_source = "Live systemd-journald (journalctl)"
            total_lines = stream_realtime_journal(detector)
        else:
            # Static file mode
            log_file = arg
            if not os.path.exists(log_file):
                print(f"{Colors.RED}[-] Error: File '{log_file}' not found.{Colors.RESET}")
                sys.exit(1)
            target_source = log_file
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            for line in lines:
                total_lines += 1
                parsed = LogParser.parse_line(line)
                if parsed:
                    detector.process_entry(parsed, live_mode=False)
    else:
        # Default behavior: Try live journalctl if root, otherwise fallback to sample logs
        if os.geteuid() == 0:
            print(f"{Colors.BLUE}[*] No arguments provided. Defaulting to live journal monitoring (run with a file path for static mode).{Colors.RESET}")
            target_source = "Live systemd-journald (journalctl)"
            total_lines = stream_realtime_journal(detector)
        else:
            print(f"{Colors.YELLOW}[*] Not running as root. Falling back to built-in sample logs (use 'sudo python3 ... --live' for live mode).{Colors.RESET}")
            target_source = "Embedded Test Sample Logs"
            lines = SAMPLE_LOGS.strip().split('\n')
            for line in lines:
                total_lines += 1
                parsed = LogParser.parse_line(line)
                if parsed:
                    detector.process_entry(parsed, live_mode=False)

    # Generate final output report
    results = detector.get_results()
    print_and_save_report(results, total_lines, target_source)


if __name__ == "__main__":
    main()
