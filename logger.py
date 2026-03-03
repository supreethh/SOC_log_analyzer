import logging
import json
from datetime import datetime, timezone, timedelta


# ================= FORMATTERS =================

class JSONFormatter(logging.Formatter):
    def __init__(self, env="prod", version="123"):
        super().__init__()
        self.env = env
        self.version = version

    def format(self, record):
        now = datetime.now().astimezone()
        log_record = {
            "time": now.isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
            "env": self.env,
            "version": self.version,
        }
        for attr in ("ip", "user", "service"):
            if hasattr(record, attr):
                log_record[attr] = getattr(record, attr)
        return json.dumps(log_record, ensure_ascii=False)


class TimedJSONFormatter(JSONFormatter):
    def __init__(self, fixed_time, env="prod", version="123"):
        super().__init__(env, version)
        self.fixed_time = fixed_time

    def format(self, record):
        log_record = {
            "time": self.fixed_time,
            "level": record.levelname,
            "msg": record.getMessage(),
            "env": self.env,
            "version": self.version,
        }
        for attr in ("ip", "user", "service"):
            if hasattr(record, attr):
                log_record[attr] = getattr(record, attr)
        return json.dumps(log_record, ensure_ascii=False)


# ================= HELPERS =================

def make_timed_logger(name, fixed_time):
    handler = logging.FileHandler("test.log", mode="a", encoding="utf-8")
    handler.setFormatter(TimedJSONFormatter(fixed_time=fixed_time))
    timed_logger = logging.getLogger(name)
    timed_logger.setLevel(logging.INFO)
    timed_logger.addHandler(handler)
    return timed_logger


# ================= MAIN LOGGER SETUP =================

logger = logging.getLogger("jsonLogger")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("test.log", mode="a", encoding="utf-8")
file_handler.setFormatter(JSONFormatter(env="prod", version="123"))
logger.addHandler(file_handler)


# ================= NORMAL APPLICATION LOGS =================

logger.info("starting url-shortener")
logger.info("server started")
logger.warning("low memory warning")
logger.error("something went wrong")


# ================= BRUTE FORCE SIMULATION =================

for _ in range(3):
    logger.warning(
        "failed login attempt",
        extra={"user": "admin", "ip": "192.168.1.45", "service": "ssh"}
    )


# ================= OFF-HOURS LOGIN SIMULATION =================

IST = timezone(timedelta(hours=5, minutes=30))

offhours_scenarios = [
    {"hour": 23, "minute": 14, "user": "admin",  "ip": "192.168.1.45"},
    {"hour": 2,  "minute": 33, "user": "root",   "ip": "10.0.0.22"},
    {"hour": 4,  "minute": 51, "user": "admin",  "ip": "203.0.113.5"},
]

for i, scenario in enumerate(offhours_scenarios):
    fixed_time = datetime.now(IST).replace(
        hour=scenario["hour"],
        minute=scenario["minute"],
        second=0,
        microsecond=0
    ).isoformat()

    timed_logger = make_timed_logger(f"offhoursLogger_{i}", fixed_time)
    timed_logger.info(
        "login successful",
        extra={"user": scenario["user"], "ip": scenario["ip"], "service": "ssh"}
    )


# ================= ACCOUNT ENUMERATION SIMULATION =================

enumeration_ip = "45.33.32.156"
usernames = ["admin", "root", "administrator", "user", "test", "guest", "operator"]

for username in usernames:
    logger.warning(
        "failed login attempt",
        extra={"user": username, "ip": enumeration_ip, "service": "ssh"}
    )
