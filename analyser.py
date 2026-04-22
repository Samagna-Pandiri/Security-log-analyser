#!/usr/bin/env python3
"""
=============================================================
  SECURITY LOG ANALYSER & THREAT DETECTOR
  Author: [Your Name]
  Description: Analyses authentication logs to detect
               suspicious activity like brute force attacks,
               privilege escalation, and unknown IP logins.
=============================================================
"""

import re
import json
import os
from collections import defaultdict
from datetime import datetime


# ─────────────────────────────────────────────
#  CONFIGURATION — tweak these thresholds
# ─────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5   # failed logins from same IP = brute force
KNOWN_SAFE_IPS = {           # IPs you trust (e.g. office network)
    "192.168.1.0/24",
    "10.0.0.0/8"
}


# ─────────────────────────────────────────────
#  COLOUR OUTPUT (makes terminal look cool)
# ─────────────────────────────────────────────
class Colour:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is from a private/internal network."""
    private_prefixes = ("192.168.", "10.", "172.16.", "172.17.",
                        "172.18.", "172.19.", "172.2", "127.")
    return ip.startswith(private_prefixes)


# ─────────────────────────────────────────────
#  STEP 1: PARSE THE LOG FILE
# ─────────────────────────────────────────────
def parse_log(filepath: str) -> list[dict]:
    """
    Read each line of the log file and extract:
    - timestamp, event type (success/fail), username, IP address
    Returns a list of event dictionaries.
    """
    events = []

    # Regex patterns to match log lines
    # We look for "Failed password" or "Accepted password" lines
    failed_pattern  = re.compile(
        r"(\w+ \d+ \d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\S+)"
    )
    success_pattern = re.compile(
        r"(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\S+) from (\S+)"
    )
    sudo_pattern    = re.compile(
        r"(\w+ \d+ \d+:\d+:\d+).*sudo.*USER=(\S+).*COMMAND=(.+)"
    )

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            match = failed_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group(1),
                    "type":      "FAILED_LOGIN",
                    "user":      match.group(2),
                    "ip":        match.group(3),
                    "raw":       line
                })
                continue

            match = success_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group(1),
                    "type":      "SUCCESS_LOGIN",
                    "user":      match.group(2),
                    "ip":        match.group(3),
                    "raw":       line
                })
                continue

            match = sudo_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group(1),
                    "type":      "PRIVILEGE_ESCALATION",
                    "user":      "system",
                    "ip":        "localhost",
                    "command":   match.group(3).strip(),
                    "raw":       line
                })

    return events


# ─────────────────────────────────────────────
#  STEP 2: DETECT THREATS
# ─────────────────────────────────────────────
def detect_threats(events: list[dict]) -> list[dict]:
    """
    Analyse parsed events and flag suspicious activity.
    Detects:
      1. Brute Force Attacks  — many failed logins from same IP
      2. Suspicious Logins    — logins from external/unknown IPs
      3. Privilege Escalation — sudo commands run as root
    """
    alerts = []

    # --- Count failed logins per IP ---
    failed_by_ip = defaultdict(list)
    for event in events:
        if event["type"] == "FAILED_LOGIN":
            failed_by_ip[event["ip"]].append(event)

    # --- THREAT 1: Brute Force Detection ---
    for ip, failures in failed_by_ip.items():
        if len(failures) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "severity":    "HIGH",
                "threat_type": "BRUTE FORCE ATTACK",
                "ip":          ip,
                "detail":      f"{len(failures)} failed login attempts detected from {ip}",
                "users_targeted": list(set(e["user"] for e in failures)),
                "first_seen":  failures[0]["timestamp"],
                "last_seen":   failures[-1]["timestamp"]
            })

    # --- THREAT 2: Suspicious Successful Login from External IP ---
    for event in events:
        if event["type"] == "SUCCESS_LOGIN":
            ip = event["ip"]
            if not is_private_ip(ip):
                alerts.append({
                    "severity":    "MEDIUM",
                    "threat_type": "EXTERNAL IP LOGIN",
                    "ip":          ip,
                    "detail":      f"Successful login by '{event['user']}' from external IP {ip}",
                    "user":        event["user"],
                    "timestamp":   event["timestamp"]
                })

    # --- THREAT 3: Privilege Escalation (sudo to root) ---
    for event in events:
        if event["type"] == "PRIVILEGE_ESCALATION":
            alerts.append({
                "severity":    "MEDIUM",
                "threat_type": "PRIVILEGE ESCALATION",
                "ip":          "localhost",
                "detail":      f"Sudo command executed: {event.get('command', 'unknown')}",
                "timestamp":   event["timestamp"]
            })

    return alerts


# ─────────────────────────────────────────────
#  STEP 3: GENERATE A SUMMARY REPORT
# ─────────────────────────────────────────────
def generate_report(events: list[dict], alerts: list[dict], log_file: str) -> str:
    """Build a readable text report of findings."""

    total      = len(events)
    successes  = sum(1 for e in events if e["type"] == "SUCCESS_LOGIN")
    failures   = sum(1 for e in events if e["type"] == "FAILED_LOGIN")
    escalations= sum(1 for e in events if e["type"] == "PRIVILEGE_ESCALATION")
    high_alerts= sum(1 for a in alerts if a["severity"] == "HIGH")
    med_alerts = sum(1 for a in alerts if a["severity"] == "MEDIUM")

    lines = []
    lines.append("=" * 60)
    lines.append("       SECURITY LOG ANALYSIS REPORT")
    lines.append(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"       Log File:  {log_file}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("[ SUMMARY ]")
    lines.append(f"  Total Events Parsed     : {total}")
    lines.append(f"  Successful Logins       : {successes}")
    lines.append(f"  Failed Login Attempts   : {failures}")
    lines.append(f"  Privilege Escalations   : {escalations}")
    lines.append(f"  HIGH Severity Alerts    : {high_alerts}")
    lines.append(f"  MEDIUM Severity Alerts  : {med_alerts}")
    lines.append("")
    lines.append("[ ALERTS ]")

    if not alerts:
        lines.append("  No threats detected. System looks clean.")
    else:
        for i, alert in enumerate(alerts, 1):
            lines.append(f"\n  [{i}] {alert['severity']} — {alert['threat_type']}")
            lines.append(f"      IP      : {alert['ip']}")
            lines.append(f"      Detail  : {alert['detail']}")
            if "users_targeted" in alert:
                lines.append(f"      Targets : {', '.join(alert['users_targeted'])}")
            if "first_seen" in alert:
                lines.append(f"      Window  : {alert['first_seen']} → {alert['last_seen']}")
            if "timestamp" in alert:
                lines.append(f"      Time    : {alert['timestamp']}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("  END OF REPORT")
    lines.append("=" * 60)
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  STEP 4: SAVE JSON REPORT (machine-readable)
# ─────────────────────────────────────────────
def save_json_report(alerts: list[dict], output_path: str):
    """Save alerts as JSON — useful for feeding into a SIEM or dashboard."""
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)


# ─────────────────────────────────────────────
#  MAIN — ties everything together
# ─────────────────────────────────────────────
def main():
    LOG_FILE         = "logs/sample_auth.log"
    TEXT_REPORT_PATH = "reports/threat_report.txt"
    JSON_REPORT_PATH = "reports/alerts.json"

    os.makedirs("reports", exist_ok=True)  # create reports folder if it doesn't exist

    print(f"\n{Colour.CYAN}{Colour.BOLD}  🔍 Security Log Analyser Starting...{Colour.RESET}\n")

    # Step 1 — Parse
    print(f"{Colour.CYAN}  [1/4] Parsing log file: {LOG_FILE}{Colour.RESET}")
    events = parse_log(LOG_FILE)
    print(f"        → {len(events)} events found\n")

    # Step 2 — Detect
    print(f"{Colour.CYAN}  [2/4] Running threat detection...{Colour.RESET}")
    alerts = detect_threats(events)
    print(f"        → {len(alerts)} alerts generated\n")

    # Step 3 — Text Report
    print(f"{Colour.CYAN}  [3/4] Generating text report...{Colour.RESET}")
    report_text = generate_report(events, alerts, LOG_FILE)
    with open(TEXT_REPORT_PATH, "w") as f:
        f.write(report_text)
    print(f"        → Saved to {TEXT_REPORT_PATH}\n")

    # Step 4 — JSON Report
    print(f"{Colour.CYAN}  [4/4] Saving JSON alert data...{Colour.RESET}")
    save_json_report(alerts, JSON_REPORT_PATH)
    print(f"        → Saved to {JSON_REPORT_PATH}\n")

    # Print report to terminal too
    print(report_text)

    # Final alert summary in colour
    high_count = sum(1 for a in alerts if a["severity"] == "HIGH")
    if high_count > 0:
        print(f"\n{Colour.RED}{Colour.BOLD}  ⚠️  {high_count} HIGH severity threat(s) detected! Immediate investigation recommended.{Colour.RESET}\n")
    else:
        print(f"\n{Colour.GREEN}  ✅ No critical threats found.{Colour.RESET}\n")


if __name__ == "__main__":
    main()
