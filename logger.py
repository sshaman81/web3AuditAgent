from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

try:
    from pythonjsonlogger import jsonlogger
except ImportError:  # pragma: no cover - fallback for minimal environments
    jsonlogger = None


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = logging.Formatter().formatException(record.exc_info)
        if hasattr(record, "context") and isinstance(record.context, dict):
            payload.update(record.context)
        return json.dumps(payload, ensure_ascii=True)


def setup_logging(level: str = "INFO", json_logs: bool = True) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler()
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        )
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
