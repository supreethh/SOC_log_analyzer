# SOC Log Analyzer

A Python-based log analysis tool designed for security and SOC-style workflows. It ingests structured JSON log files, normalizes log entries, supports filtering by timestamp, severity, and message content, and detects brute-force authentication attempts.

This project demonstrates practical log processing, event correlation, and basic security analytics in a lightweight CLI tool.

---

## Features

- Parses JSON-formatted log files  
- Normalizes timestamps into comparable datetime objects  
- Flattens extra log fields into readable messages  
- Filters logs by:
  - time range  
  - log level  
  - message content  
- Detects brute-force login attempts  
- Generates summarized output for quick inspection  

---

## Project Structure

```
SOC_log_analyzer/
│
├── log_analyzer.py   # Core log parsing, filtering, and detection logic
├── logger.py        # Log generator used to simulate realistic log data
├── app              # Sample application log
├── test             # Large test dataset for analysis
├── README.md
└── .gitignore
```

---

## Log Format

Logs are stored as JSON objects, one per line. Example:

```json
{
  "time": "2026-01-11 14:05:32",
  "level": "ERROR",
  "msg": "Failed login attempt",
  "user": "admin",
  "ip": "192.168.1.12"
}
```

Any additional fields (such as `user`, `ip`, or `service`) are automatically appended to the message during parsing.

---

## Getting the Code

Clone the repository:

```bash
git clone https://github.com/supreethh/SOC_log_analyzer.git
```

Move into the project directory:

```bash
cd SOC_log_analyzer
```

---

## How to Run

Run the analyzer by passing a log file:

```bash
python log_analyzer.py test
```

Depending on your implementation, you can also filter by time ranges, log level, or message content.

---

## Why this project matters

This tool mirrors the type of scripting used in SOC environments for:

- Log triage  
- Alert investigation  
- Incident reconstruction  
- Detection prototyping  

It is designed to demonstrate security-focused Python skills rather than generic scripting.

