# Simulated SOC Incident Report: Multi-Vector Authentication Threat Detection

## Executive Summary

This document presents a simulated Security Operations Center (SOC) investigation based on application logs analyzed using a custom Python-based log analyzer. During routine log analysis, three distinct threat patterns were detected across authentication logs: brute-force login attempts, off-hours successful login activity, and account enumeration from a single source IP.

Each detection was correlated from structured JSON log data, mapped to MITRE ATT&CK techniques, and assessed for potential impact. This report demonstrates SOC-style investigative thinking, multi-vector detection logic, and structured incident reporting suitable for an entry-level Security Analyst role.

This report is **purely a simulation for learning and portfolio purposes**. No systems were compromised, and no real users or production environments were affected.

---

## Incident Overview

| Field | Details |
|---|---|
| Incident Type | Multi-vector authentication threat (simulated) |
| Detection Types | Brute-force, Off-hours login, Account enumeration |
| Log Source | JSON application logs |
| Total Logs Analyzed | 526 |
| Total Warnings | 17 (includes 2 non-security HTTP request logs) |
| Total Errors | 8 |
| Timestamp Format | ISO 8601 with timezone |
| MITRE ATT&CK Mapping | T1110 — Brute Force, T1078 — Valid Accounts |

---

## Detection 1: Brute-Force Login Attempt

### What Happened
Six failed login attempts were observed for the `admin` account originating from IP `192.168.1.45` across two separate time windows — three on 2026-01-11 and three on 2026-03-03. The repeated targeting of a privileged account across multiple sessions triggered the brute-force detection rule.

### Detection Logic
Events were grouped by user and source IP. A counter was incremented for each failed authentication attempt per group. Once the count reached the configurable threshold of 3, the analyzer flagged the activity and generated an alert.

**MITRE ATT&CK:** TA0006 — Credential Access | T1110 — Brute Force

### Timeline of Events

| Time (Normalized) | Level | User | Source IP | Event |
|---|---|---|---|---|
| 2026-01-11 12:31:28 | WARNING | admin | 192.168.1.45 | Failed login attempt |
| 2026-01-11 12:31:28 | WARNING | admin | 192.168.1.45 | Failed login attempt |
| 2026-01-11 12:31:28 | WARNING | admin | 192.168.1.45 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | admin | 192.168.1.45 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | admin | 192.168.1.45 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | admin | 192.168.1.45 | Failed login attempt |

> Note: Multiple events share identical timestamps due to second-level timestamp precision in application logging. The detection logic correctly correlates across the full dataset regardless of timestamp granularity.

### Risk Assessment
**Low to Moderate.** Six total attempts across two sessions, no successful authentication observed, single source IP. However, persistent targeting of a privileged `admin` account across multiple sessions suggests intentional and repeated activity rather than a one-off misconfiguration.

---

## Detection 2: Off-Hours Login Activity

### What Happened
Three successful login events were detected outside normal business hours between 10pm and 6am. Two involved the `admin` account from different source IPs, and one involved the `root` account — indicating either legitimate privileged access or potential unauthorized use of compromised credentials.

### Detection Logic
The analyzer checked the hour component of each successful login timestamp. Any successful authentication occurring between 22:00 and 06:00 was flagged as off-hours activity regardless of source IP or user.

**MITRE ATT&CK:** TA0001 — Initial Access | T1078 — Valid Accounts

### Timeline of Events

| Time (Normalized) | Level | User | Source IP | Event |
|---|---|---|---|---|
| 2026-03-03 23:14:00 | INFO | admin | 192.168.1.45 | Successful login — off-hours |
| 2026-03-03 02:33:00 | INFO | root | 10.0.0.22 | Successful login — off-hours |
| 2026-03-03 04:51:00 | INFO | admin | 203.0.113.5 | Successful login — off-hours |

### Risk Assessment
**Moderate.** Successful logins outside business hours from privileged accounts warrant immediate investigation. Notably, the 02:33am `root` login originates from a different IP than the brute-force source, suggesting either a separate threat actor or a second compromised access point. The `admin` login at 04:51am from `203.0.113.5` also differs from the brute-force IP, warranting verification against known trusted IP ranges.

---

## Detection 3: Account Enumeration

### What Happened
Seven different usernames were attempted from a single source IP `45.33.32.156` within the same timestamp window. This pattern is consistent with account enumeration — an attacker systematically probing the authentication system to identify valid usernames before launching targeted credential attacks.

### Detection Logic
Failed login events were grouped by source IP. The set of unique usernames attempted per IP was tracked. Once the count of distinct usernames from a single IP reached the threshold of 3, the analyzer flagged the activity as potential enumeration.

**MITRE ATT&CK:** TA0006 — Credential Access | T1110 — Brute Force (Password Spraying variant)

### Timeline of Events

| Time (Normalized) | Level | Username Attempted | Source IP | Event |
|---|---|---|---|---|
| 2026-03-03 12:28:26 | WARNING | admin | 45.33.32.156 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | root | 45.33.32.156 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | administrator | 45.33.32.156 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | user | 45.33.32.156 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | test | 45.33.32.156 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | guest | 45.33.32.156 | Failed login attempt |
| 2026-03-03 12:28:26 | WARNING | operator | 45.33.32.156 | Failed login attempt |

### Risk Assessment
**Moderate to High.** Systematic probing of seven common privileged and default usernames from a single IP within the same second suggests automated tooling. This activity commonly precedes targeted brute-force or password spraying campaigns. The source IP `45.33.32.156` is distinct from the brute-force IP, indicating a separate threat actor or tool.

---

## Analyzer Output
```text
SOC Log Summary:
  Total Logs : 526
  Errors     : 8
  Warnings   : 17
  Info       : 501

[ALERT] Brute-force detected:
  admin from 192.168.1.45 -> 6 failed login attempts

[ALERT] Off-hours login activity detected:
  admin from 192.168.1.45 at 2026-03-03 23:14:00
  root from 10.0.0.22 at 2026-03-03 02:33:00
  admin from 203.0.113.5 at 2026-03-03 04:51:00

[ALERT] Account enumeration detected:
  IP 45.33.32.156 attempted 7 different usernames: root, administrator, test, user, admin, operator, guest
```

---

## Technical Analysis

### Log Parsing and Normalization
The analyzer ingests logs in JSON format with fields including `time`, `level`, `msg`, `user`, `ip`, `env`, and `version`. Timestamps are normalized to ensure consistent comparison across entries, accounting for timezones. This step is critical in real-world SOC workflows where logs originate from distributed systems in different regions.

Not all WARNING level logs represent security events. Two WARNING entries in this dataset are HTTP request completion logs from a URL shortener middleware component — these are correctly ignored by the detection logic since they do not match authentication-related message patterns.

### Detection Methodology Summary

| Detection | Logic | Threshold | MITRE Technique |
|---|---|---|---|
| Brute Force | Failed logins grouped by user + IP | 3+ attempts | T1110 |
| Off-Hours Login | Successful logins outside 22:00-06:00 | Any occurrence | T1078 |
| Account Enumeration | Failed logins grouped by IP across unique usernames | 3+ usernames | T1110 |

---

## Response and Mitigation Recommendations

### Brute Force
- Enforce account lockout after 5 failed attempts with progressive delay
- Implement IP-based rate limiting on authentication endpoints
- Lower detection threshold for privileged accounts like `admin` and `root`
- Investigate whether `192.168.1.45` is an internal or external address

### Off-Hours Login
- Implement alerts for all privileged account logins outside business hours
- Require step-up authentication for off-hours access to privileged accounts
- Verify `10.0.0.22` and `203.0.113.5` against known trusted internal IP ranges
- Investigate whether off-hours logins from `192.168.1.45` are connected to the earlier brute-force activity from the same IP

### Account Enumeration
- Block or rate-limit `45.33.32.156` immediately
- Return generic error messages on authentication failure to prevent username confirmation
- Cross-reference `45.33.32.156` against threat intelligence feeds such as AbuseIPDB or VirusTotal
- Monitor for follow-up brute-force activity targeting the enumerated usernames

---

## Lessons Learned

- **Multi-vector visibility matters:** Analyzing logs for multiple threat patterns simultaneously provides a more complete picture than single-rule detection. The same IP appearing in both brute-force and off-hours detections is a correlation that single-rule systems would miss.
- **Privileged account activity requires closer scrutiny:** All three detections involved `admin` or `root` accounts, which should always be treated as high-priority targets.
- **Enumeration precedes exploitation:** The account enumeration from a distinct IP suggests a separate attacker or automated tool, highlighting the importance of correlating detections across source IPs.
- **Not all warnings are threats:** Two of the 17 WARNING entries were non-security HTTP logs. Accurate detection requires message-pattern matching, not just log level filtering.

---

## Planned Improvements

- Time-window-based correlation for brute force — flag X attempts within Y minutes rather than across the entire dataset
- Severity scoring system to classify alerts as Low, Medium, or High based on volume and account type
- Export alerts in JSON or CSV format for SIEM ingestion
- Cross-reference source IPs against threat intelligence APIs at detection time
- Extend detection to HTTP-based log sources for web application threat coverage

---

## Conclusion

This report demonstrates a realistic entry-level SOC investigation workflow using a custom-built Python log analyzer capable of detecting three distinct authentication threat patterns across 526 log entries. Each detection is grounded in real SOC methodology, mapped to MITRE ATT&CK, and assessed for potential impact and recommended response.

The correlation between the brute-force source IP and the subsequent off-hours login from the same address is a notable finding that illustrates the value of multi-vector detection over isolated single-rule alerting.

---

*Disclaimer: This report is based on a simulated dataset created for educational and portfolio purposes only.*
