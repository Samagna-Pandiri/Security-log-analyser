# 🔍 Security Log Analyser & Threat Detector

A Python tool that simulates real Security Analyst work — parsing authentication logs and automatically detecting cyber threats.

---

## What It Does

Analyses Linux authentication logs (`auth.log`) and detects:

| Threat | Severity | Description |
|--------|----------|-------------|
| Brute Force Attack | 🔴 HIGH | Multiple failed logins from same IP |
| External IP Login | 🟡 MEDIUM | Successful login from unknown external IP |
| Privilege Escalation | 🟡 MEDIUM | Sudo commands run as root |

---

## Project Structure

```
log_analyser/
├── analyser.py          # Main script
├── logs/
│   └── sample_auth.log  # Sample Linux auth log
├── reports/
│   ├── threat_report.txt  # Human-readable report (auto-generated)
│   └── alerts.json        # Machine-readable JSON output (auto-generated)
└── README.md
```

---

## How to Run

```bash
# Clone or download the project
cd log_analyser

# Run the analyser
python3 analyser.py
```

No external libraries needed — uses Python standard library only.

---

## Sample Output

```
🔍 Security Log Analyser Starting...

[1/4] Parsing log file: logs/sample_auth.log
      → 30 events found

[2/4] Running threat detection...
      → 5 alerts generated

[ SUMMARY ]
  Total Events Parsed     : 30
  Successful Logins       : 6
  Failed Login Attempts   : 23
  HIGH Severity Alerts    : 3
  MEDIUM Severity Alerts  : 2

[1] HIGH — BRUTE FORCE ATTACK
    IP     : 203.0.113.42
    Detail : 6 failed login attempts detected
    Window : Jan 10 08:03:45 → Jan 10 08:03:50
```

---

## How It Works (Technical)

1. **Parsing** — Uses regex to extract IP addresses, usernames, timestamps, and event types from raw log lines
2. **Detection** — Groups failed logins by IP, flags IPs exceeding the threshold (default: 5 attempts)
3. **Alerting** — Categorises threats by severity (HIGH/MEDIUM) with full context
4. **Reporting** — Outputs both a human-readable `.txt` report and a machine-readable `.json` file

---

## Extending This Project

- Add email alerts when HIGH threats are detected
- Build a web dashboard (Flask + Chart.js) to visualise alerts
- Integrate with a real SIEM tool (Splunk, ELK Stack)
- Add GeoIP lookup to map attacker locations
- Schedule it to run automatically with a cron job

---

## Skills Demonstrated

- Python scripting & regex
- Log analysis & parsing
- Threat detection logic
- Security operations (SOC analyst mindset)
- JSON/structured data output
