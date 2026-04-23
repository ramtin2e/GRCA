"""
Logger utility — consistent logging across the project.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

_configured = False


def configure_logging(level: str = "INFO", log_to_file: bool = False, log_file: Optional[str] = None) -> None:
    """Configure the root logger."""
    global _configured
    if _configured:
        return

    log_level = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))

    root_logger = logging.getLogger("src")
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)

    if log_to_file and log_file:
        from pathlib import Path
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
        root_logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a module."""
    return logging.getLogger(name)
