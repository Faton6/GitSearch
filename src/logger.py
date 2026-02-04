import logging
import os
import time
import json
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

"""
    Logging configuration module.

    Supports configurable log levels via LOG_LEVEL environment variable.
    Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL
    Default: INFO

    JSON logging can be enabled via LOG_JSON_FORMAT=true environment variable.
"""

CLR = {
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "RED": "\033[31m",
    "VERYRED": "\033[91m",
    "bold_red": "\x1b[31;1m",
    "blue": "\x1b[1;34m",
    "light_blue": "\x1b[1;36m",
    "RESET": "\033[0m",
    "purple": "\x1b[1;35m",
    "BOLD": "\033[1m",
}

# Get log level from environment variable
LOG_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}
LOG_LEVEL_STR = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_LEVEL = LOG_LEVEL_MAP.get(LOG_LEVEL_STR, logging.INFO)

# Console log level can be different from file log level
CONSOLE_LOG_LEVEL_STR = os.getenv("CONSOLE_LOG_LEVEL", LOG_LEVEL_STR).upper()
CONSOLE_LOG_LEVEL = LOG_LEVEL_MAP.get(CONSOLE_LOG_LEVEL_STR, LOG_LEVEL)

# JSON format for file logs (for ELK/Grafana integration)
LOG_JSON_FORMAT = os.getenv("LOG_JSON_FORMAT", "false").lower() in ("true", "1", "yes")


class JsonLogFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Outputs logs in JSON format for easy parsing by log aggregation systems
    like ELK Stack, Grafana Loki, CloudWatch, etc.
    """

    # Standard logging fields to exclude from extra
    STANDARD_FIELDS = {
        "name",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "lineno",
        "funcName",
        "created",
        "thread",
        "threadName",
        "process",
        "message",
        "exc_info",
        "exc_text",
        "stack_info",
        "msg",
        "args",
        "msecs",
        "relativeCreated",
        "processName",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcfromtimestamp(record.created).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.threadName,
            "process": record.process,
        }

        # Add extra fields (from record.__dict__ that aren't standard)
        extra = {}
        for key, value in record.__dict__.items():
            if key not in self.STANDARD_FIELDS and not key.startswith("_"):
                try:
                    # Ensure JSON serializable
                    json.dumps(value)
                    extra[key] = value
                except (TypeError, ValueError):
                    extra[key] = str(value)

        if extra:
            log_entry["extra"] = extra

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False, default=str)


logger = logging.getLogger("my_logger")
logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all, handlers will filter

# Console formatter - simpler for readability
console_formatter = logging.Formatter("%(message)s")

# File formatter - JSON or text based on config
if LOG_JSON_FORMAT:
    file_formatter = JsonLogFormatter()
else:
    file_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s in %(filename)s, %(lineno)d line")

# Console handler with configurable level
console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
console_handler.setLevel(CONSOLE_LOG_LEVEL)

timestamp = time.strftime("%Y_%m_%d")

# Ensure logs directory exists
logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir, exist_ok=True)

# File extension based on format
log_extension = ".json.log" if LOG_JSON_FORMAT else ".log"

file_handler = TimedRotatingFileHandler(
    filename=os.path.join(logs_dir, f"log_{timestamp}{log_extension}"),
    when="midnight",  # Rotation time
    interval=1,  # Rotation interval (1 day)
    backupCount=7,  # Keep 7 backups (7 days)
    encoding="utf-8",
    delay=False,
    utc=False,
)
file_handler.setFormatter(file_formatter)
file_handler.setLevel(LOG_LEVEL)

logger.addHandler(console_handler)
logger.addHandler(file_handler)


# Helper function for structured logging

# Log the configured level on startup (only in debug mode)
if LOG_LEVEL == logging.DEBUG:
    logger.debug(
        f"Logger initialized with level: {LOG_LEVEL_STR}, console level: {CONSOLE_LOG_LEVEL_STR}, json_format: {LOG_JSON_FORMAT}"
    )
