import json
import sys
from datetime import datetime
from collections import defaultdict


class LogAnalyzer:
    def __init__(self, logfile):
        self.logfile = logfile
        self.logs = self.parse_logs()

    # ================= PARSING =================

    def parse_logs(self):
        parsed = []

        with open(self.logfile, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                log = json.loads(line)

                message = log["msg"]
                for key in log:
                    if key not in ("time", "level", "msg"):
                        message += f" | {key}: {log[key]}"

                parsed.append({
                    "raw_time": log["time"],
                    "timestamp": self.format_time(log["time"]),
                    "level": log["level"],
                    "message": message,
                    "user": log.get("user"),
                    "ip": log.get("ip")
                })

        return parsed

    @staticmethod
    def format_time(timestr):
        dt = datetime.fromisoformat(timestr)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def parse_iso(timestr):
        return datetime.fromisoformat(timestr)

    @staticmethod
    def make_naive(dt_obj):
        return dt_obj.replace(tzinfo=None)

    # ================= FILTERS =================

    def filter_by_level(self, level):
        return [log for log in self.logs if log["level"] == level]

    def filter_by_keyword(self, keyword):
        keyword = keyword.lower()
        return [log for log in self.logs if keyword in log["message"].lower()]

    def filter_by_time_range(self, start, end):
        start_dt = self.make_naive(self.parse_iso(start))
        end_dt = self.make_naive(self.parse_iso(end))

        return [
            log for log in self.logs
            if start_dt <= self.make_naive(self.parse_iso(log["raw_time"])) <= end_dt
        ]

    # ================= DETECTION =================

    def detect_bruteforce(self, threshold=3):
        attempts = defaultdict(int)

        for log in self.logs:
            if "failed login attempt" in log["message"].lower():
                key = (log["user"], log["ip"])
                attempts[key] += 1

        alerts = []
        for (user, ip), count in attempts.items():
            if count >= threshold:
                alerts.append((user, ip, count))

        return alerts

    def detect_offhours_login(self, start_hour=22, end_hour=6):
        alerts = []

        for log in self.logs:
            if "login successful" in log["message"].lower():
                dt = self.make_naive(self.parse_iso(log["raw_time"]))
                hour = dt.hour

                if hour >= start_hour or hour < end_hour:
                    alerts.append({
                        "user": log["user"],
                        "ip": log["ip"],
                        "time": log["timestamp"]
                    })

        return alerts

    def detect_enumeration(self, threshold=3):
        ip_users = defaultdict(set)

        for log in self.logs:
            if "failed login attempt" in log["message"].lower():
                ip = log["ip"]
                user = log["user"]
                if ip and user:
                    ip_users[ip].add(user)

        alerts = []
        for ip, users in ip_users.items():
            if len(users) >= threshold:
                alerts.append((ip, list(users), len(users)))

        return alerts

    # ================= SUMMARY =================

    def get_summary(self):
        return {
            "Total Logs": len(self.logs),
            "Errors": len(self.filter_by_level("ERROR")),
            "Warnings": len(self.filter_by_level("WARNING")),
            "Info": len(self.filter_by_level("INFO"))
        }


# ======================= CLI =======================

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python analyzer.py <logfile>")
        print("  python analyzer.py <logfile> ERROR|WARNING|INFO|<keyword>")
        print("  python analyzer.py <logfile> <start_time> <end_time>")
        sys.exit(1)

    analyzer = LogAnalyzer(sys.argv[1])

    # Time-range query
    if len(sys.argv) == 4:
        start = sys.argv[2]
        end = sys.argv[3]

        print("\nLogs in Time Range:\n")
        logs = analyzer.filter_by_time_range(start, end)

        for log in logs:
            print(f"{log['timestamp']} | {log['level']} | {log['message']}")
        return

    # Keyword or severity query
    if len(sys.argv) == 3:
        arg = sys.argv[2]

        print("\nFiltered Logs:\n")

        if arg.upper() in ("ERROR", "INFO", "WARNING"):
            logs = analyzer.filter_by_level(arg.upper())
        else:
            logs = analyzer.filter_by_keyword(arg)

        for log in logs:
            print(f"{log['timestamp']} | {log['level']} | {log['message']}")

        alerts = analyzer.detect_bruteforce()
        if alerts:
            print("\n[ALERT] Brute-force detected:")
            for user, ip, count in alerts:
                print(f"  {user} from {ip} -> {count} failed login attempts")

        offhours = analyzer.detect_offhours_login()
        if offhours:
            print("\n[ALERT] Off-hours login activity detected:")
            for alert in offhours:
                print(f"  {alert['user']} from {alert['ip']} at {alert['time']}")

        enumeration = analyzer.detect_enumeration()
        if enumeration:
            print("\n[ALERT] Account enumeration detected:")
            for ip, users, count in enumeration:
                print(f"  IP {ip} attempted {count} different usernames: {', '.join(users)}")

        return

    # SOC dashboard
    summary = analyzer.get_summary()

    print("\nSOC Log Summary:")
    print(f"  Total Logs : {summary['Total Logs']}")
    print(f"  Errors     : {summary['Errors']}")
    print(f"  Warnings   : {summary['Warnings']}")
    print(f"  Info       : {summary['Info']}")

    alerts = analyzer.detect_bruteforce()
    if alerts:
        print("\n[ALERT] Brute-force detected:")
        for user, ip, count in alerts:
            print(f"  {user} from {ip} -> {count} failed login attempts")
    else:
        print("\nNo brute-force activity detected.")

    offhours = analyzer.detect_offhours_login()
    if offhours:
        print("\n[ALERT] Off-hours login activity detected:")
        for alert in offhours:
            print(f"  {alert['user']} from {alert['ip']} at {alert['time']}")
    else:
        print("\nNo off-hours login activity detected.")

    enumeration = analyzer.detect_enumeration()
    if enumeration:
        print("\n[ALERT] Account enumeration detected:")
        for ip, users, count in enumeration:
            print(f"  IP {ip} attempted {count} different usernames: {', '.join(users)}")
    else:
        print("\nNo account enumeration activity detected.")


if __name__ == "__main__":
    main()
