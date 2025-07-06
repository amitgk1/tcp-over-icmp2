import logging
import sys
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_format: str = "%(asctime)s:%(name)s:%(levelname)s:%(message)s",
    log_file: Optional[str] = None,
):
    formatter = logging.Formatter(log_format)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    console_handler.setFormatter(formatter)
    handlers = [console_handler]

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    logging.basicConfig(
        level=getattr(logging, level), format=log_format, handlers=handlers
    )
