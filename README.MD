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
├── analyzer.py   # Core log parsing, filtering, and detection logic
├── logger.py        # Log generator used to simulate realistic log data
├── app              # Sample application log
├── test             # Large test dataset for analysis
├── README.md
└── .gitignore
```

---

## Log Format

Logs are stored as JSON objects. Example:

```json
{
  "time": "2026-01-11 14:05:32","level": "ERROR","msg": "Failed login attempt","user": "admin","ip": "192.168.1.12"
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
python analyzer.py test.log
```

This will parse the logs, apply detection logic, and output a summary along with any detected brute-force activity.

## Log Filtering Examples

The analyzer supports basic filtering to help narrow down relevant events during SOC-style investigations.

### Filter by Log Level

The analyzer supports basic filtering to help narrow down relevant events during SOC-style investigations.

Analyze only warning-level events:

```
python analyzer.py test.log WARNING
```
## Filter by Message Content

Search for authentication-related activity, such as failed logins:

```
python analyzer.py test.log "failed login"
```
## Filter by Time Range

Analyze logs within a specific time window:

```
python analyzer.py test.log "2026-01-11 12:00:00" "2026-01-11 13:00:00"
```


---

## Why this project matters

This tool mirrors the type of scripting used in SOC environments for:

- Log triage  
- Alert investigation  
- Incident reconstruction  
- Detection prototyping  

It is designed to demonstrate security-focused Python skills rather than generic scripting.






