import logging
import json
from datetime import datetime

# Custom JSON formatter
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

        # Capture extra fields like ip, user, service
        for attr in ("ip", "user", "service"):
            if hasattr(record, attr):
                log_record[attr] = getattr(record, attr)

        return json.dumps(log_record, ensure_ascii=False)


# Logger setup
logger = logging.getLogger("jsonLogger")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("test.log", mode="a", encoding="utf-8")
file_handler.setFormatter(JSONFormatter(env="prod", version="123"))

logger.addHandler(file_handler)


# Normal application logs
logger.info("starting url-shortener")
logger.info("server started")
logger.warning("low memory warning")
logger.error("something went wrong")


# Simulated failed login attempts (brute force)
logger.warning(
    "failed login attempt",
    extra={"user": "admin", "ip": "192.168.1.45", "service": "ssh"}
)
logger.warning(
    "failed login attempt",
    extra={"user": "admin", "ip": "192.168.1.45", "service": "ssh"}
)
logger.warning(
    "failed login attempt",
    extra={"user": "admin", "ip": "192.168.1.45", "service": "ssh"}
)
