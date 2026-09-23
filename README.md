# 🛡️ System Log Security Analyzer (Static & Real-Time)

A lightweight, robust Python-based security auditing tool developed for Kali Linux / Debian-based systems. It parses authentication logs to detect critical security threats such as SSH brute-force attacks, unauthorized username attempts, privilege escalations (sudo), and successful user logins—supporting both embedded sample testing and real-time live journal monitoring in a single script.

---

## 🚀 Key Features

* Dual-Mode Operation in a Single Script:
  * Sample Mode: Instantly runs against built-in test logs for quick demonstrations and testing.
  * Live Mode: Streams system authentication logs in real-time using journalctl.
* Security Threat Detection:
  * Brute-Force Detection: Flags high-risk IP addresses exceeding configured failed login thresholds (default >= 3 attempts).
  * Invalid User Tracking: Captures login attempts targeting non-existent or unauthorized usernames.
  * Privilege Escalation Monitoring: Tracks all sudo and root command execution activities.
  * Successful Login Tracking: Records legitimate user sessions with exact timestamps.
* Professional Reporting: Outputs a color-coded CLI interface and automatically exports a clean summary report to system_security_report.txt.

---

## ⚙️ Prerequisites

* Python 3.x installed on your system.
* Kali Linux or any systemd-based Linux distribution (required for live journal monitoring via journalctl).

---

## 📥 Installation & Usage

1. Clone the repository:
   git clone https://github.com/YOUR_USERNAME/system-log-analyzer.git
   cd system-log-analyzer

2. Make the script executable:
   chmod +x log_analysis.py

3. Run the Tool:

   * Option A: Run Built-in Sample Analysis (No Root Required)
     python3 log_analysis.py

   * Option B: Run Real-Time Live Monitoring (Requires Root/Sudo)
     Streams live system logs. Perform actions (like sudo ls or SSH) in another terminal, then press Ctrl + C to stop and generate the final report.
     sudo python3 log_analysis.py --live

   * Option C: Analyze an External Log File
     python3 log_analysis.py /var/log/auth.log

---

## 📊 Sample Output Report (system_security_report.txt)

=================================================================
         KALI LINUX SYSTEM LOG ANALYZER REPORT         
=================================================================
Analysis Time : 2026-09-24 03:20:00
Log Source    : Live systemd-journald (journalctl)
Total Lines   : 120
-----------------------------------------------------------------

[!] BRUTE-FORCE DETECTIONS (THRESHOLD >= 3 FAILED ATTEMPTS):
  [ALERT] High Risk IP: 192.168.1.105   | Failed Attempts: 5

[!] INVALID USER LOGIN ATTEMPTS:
  [-] Time: May 10 10:14:40 | Target User: 'admin' | Source IP: 10.0.0.50

[!] PRIVILEGE ESCALATION MONITORING (SUDO ACTIVITIES):
  [*] Time: May 10 10:15:02 | Event: sudo: user1 : TTY=pts/0 ...

[+] SUCCESSFUL LOGIN ACTIVITIES:
  [+] Time: May 10 10:16:10 | User: 'kali' successfully logged in

=================================================================
[+] Analysis complete! Text report saved to: /home/kali/system_security_report.txt

---

## 👨‍💻 Author
Developed as a Cybersecurity Mini-Project for System Auditing, Log Management, and Threat Analysis.
