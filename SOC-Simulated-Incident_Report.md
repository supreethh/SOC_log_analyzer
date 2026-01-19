# Simulated SOC Incident Report: Brute-Force Login Attempt Detection

## Executive Summary

This document presents a simulated Security Operations Center (SOC) investigation based on application logs analyzed using a custom Python-based log analyzer. During routine log analysis, multiple failed login attempts were detected targeting the `admin` user account from a single source IP address (`192.168.1.45`). The analyzer correlated log events by user and IP address and identified a pattern consistent with low-volume brute-force credential access behavior.

This report is **purely a simulation for learning and portfolio purposes**. No systems were compromised, and no real users or production environments were affected. The objective is to demonstrate SOC-style investigative thinking, detection logic, and structured reporting suitable for an entry-level Security Analyst role.

---

## Incident Overview

**Incident Type:** Suspected brute-force login attempt (simulated)  
**User Targeted:** `admin`  
**Source IP Address:** `192.168.1.45`  
**Total Failed Attempts:** 3  
**Detection Threshold:** 3 failed login attempts (user + IP correlation)  
**Environment:** Application logs (JSON format)  
**Log Source:** Custom application logging output  
**Timestamp Format:** ISO 8601 with timezone  

### What Happened

During analysis of application authentication logs, three consecutive failed login attempts were observed for the `admin` account originating from the same IP address. While the volume was low, the repetition and targeting of a privileged account triggered the brute-force detection logic implemented in the analyzer.

### When It Happened

The events occurred within a short, defined time window (as extracted from normalized timestamps in the log data). Exact timestamps are referenced in the Timeline of Events section.

---

## Detection Methodology

Detection was performed using a **custom Python-based log analyzer** designed to process structured JSON application logs. The analyzer performs the following core functions:

- Parses raw JSON log entries
- Normalizes timestamps into a consistent format
- Filters events based on severity, keywords, and time range
- Correlates authentication failures by **user and source IP**
- Applies a configurable threshold to identify suspicious patterns

For this scenario, the detection rule flagged any user + IP combination with **three or more failed login attempts** within the observed dataset.

This approach mirrors common SOC detection logic used in SIEM platforms, albeit implemented at a smaller scale for learning and demonstration purposes.

---

## Timeline of Events

| Time (Normalized) | Level  | User  | Source IP      | Event Description |
|------------------|--------|-------|----------------|------------------|
| T1               | WARNING | admin | 192.168.1.45   | Failed login attempt |
| T2               | WARNING | admin | 192.168.1.45   | Failed login attempt |
| T3               | WARNING | admin | 192.168.1.45   | Failed login attempt |

> Note: Timestamps were normalized from ISO 8601 format during parsing. No successful login events were observed following these attempts.

---

## Technical Analysis

### Log Parsing and Normalization

The analyzer ingests logs in JSON format with fields including:

- `time`
- `level`
- `msg`
- `user`
- `ip`
- `env`
- `version`

Timestamps were normalized to ensure consistent comparison across entries, accounting for time zones. This step is critical in real-world SOC workflows, where logs often originate from distributed systems operating in different regions.

### Filtering Logic

Events were filtered based on:
- Log level (`WARNING` and above)
- Presence of authentication-related keywords (e.g., “failed login”)
- Optional time window constraints

This ensured that only relevant authentication failure events were considered for correlation.

### Correlation and Thresholding

The core detection logic grouped events by:
- `user`
- `ip`

A counter was incremented for each failed authentication attempt per group. Once the count reached the predefined threshold of **3**, the analyzer flagged the activity as suspicious and generated an alert.

This methodology is intentionally simple but effective for demonstrating:
- Event correlation
- Stateful detection
- Pattern-based alerting

---

## Impact & Risk Assessment

Because this is a **simulated scenario**, there is no actual operational impact. However, in a real production environment, the observed pattern could indicate:

- An attempt to guess credentials for a privileged account
- Early-stage reconnaissance or low-volume brute-force activity
- Misconfigured application behavior or automated process errors

The risk level in this case would be considered **low to moderate**, given:
- The small number of attempts
- Lack of evidence of successful authentication
- Single source IP involved

Nevertheless, targeting an `admin` account increases the potential risk if such activity were to continue unchecked.

---

## Response & Mitigation Recommendations

In a real SOC environment, the following actions would be recommended:

1. **Account Review**
   - Verify whether the `admin` account is actively used and required.
   - Enforce strong, unique credentials and multi-factor authentication (MFA).

2. **Source IP Validation**
   - Determine whether `192.168.1.45` is an internal, trusted address or an external source.
   - Investigate for potential misconfigured services or scripts.

3. **Rate Limiting and Lockout Policies**
   - Implement account lockout or progressive delays after repeated failures.
   - Enforce IP-based rate limiting for authentication endpoints.

4. **Monitoring Enhancements**
   - Lower detection thresholds for privileged accounts.
   - Add alerting for repeated failures across multiple users from the same IP.

5. **Log Enrichment**
   - Include additional context such as user-agent strings or request IDs to aid future investigations.

---

## Lessons Learned and Future Improvements

This simulated investigation highlights several key learning points:

- **Correlation is critical:** Single failed logins are common; patterns emerge only when events are grouped and analyzed collectively.
- **Threshold tuning matters:** Detection thresholds should be adaptive, especially for high-privilege accounts.
- **Structured logs simplify analysis:** JSON-formatted logs significantly reduce parsing complexity and improve detection accuracy.

Planned improvements to the analyzer include:
- Time-window-based correlation (e.g., X attempts within Y minutes)
- Severity scoring rather than static thresholds
- Exporting alerts in SIEM-compatible formats
- Basic visualization of authentication trends

---

## Conclusion

This report demonstrates a realistic, entry-level SOC investigation workflow using a custom-built Python log analyzer. While the incident is simulated and low-impact, it effectively showcases foundational detection techniques such as log parsing, normalization, correlation, and alerting.

The project serves as a practical example of how Security Analysts can extract actionable insights from application logs and apply structured thinking to identify and assess potential security events.

---

*Disclaimer: This report is based on a simulated dataset created for educational and portfolio purposes only.*
