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
                log = json.loads(line)

                # Build enriched message
                message = log["msg"]
                for key in log:
                    if key not in ("time", "level", "msg"):
                        message += f" | {key}: {log[key]}"

                parsed.append({
                    "raw_time": log["time"],                          # ISO time with timezone
                    "timestamp": self.format_time(log["time"]),      # Human readable
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
        print(" python test-2.py <logfile>")
        print(" python test-2.py <logfile> ERROR|keyword")
        print(" python test-2.py <logfile> <start_time> <end_time>")
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
                print(f"{user} from {ip} → {count} failed login attempts")
        return

    # SOC dashboard
    summary = analyzer.get_summary()

    print("\nSOC Log Summary:")
    print(f"Total Logs: {summary['Total Logs']}")
    print(f"Errors: {summary['Errors']}")
    print(f"Warnings: {summary['Warnings']}")
    print(f"Info: {summary['Info']}")

    alerts = analyzer.detect_bruteforce()
    if alerts:
        print("\n[ALERT] Brute-force detected:")
        for user, ip, count in alerts:
            print(f"{user} from {ip} → {count} failed login attempts\n")
    else:
        print("\nNo brute-force activity detected.")


if __name__ == "__main__":
    main()
