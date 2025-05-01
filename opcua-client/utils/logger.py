#!/usr/bin/env python3
"""
Logging utilities for OPC UA Client
"""
import os
import logging
import logging.handlers
from pathlib import Path
from typing import Union, Optional


def setup_logger(log_file: Optional[Union[str, Path]] = None, 
                console_level: str = "INFO", 
                file_level: str = "DEBUG",
                max_file_size: int = 10*1024*1024,  # 10MB
                backup_count: int = 5) -> None:
    """Set up logger with console and file handlers
    
    Args:
        log_file: Path to log file (optional)
        console_level: Logging level for console
        file_level: Logging level for file
        max_file_size: Maximum log file size in bytes
        backup_count: Number of backup files to keep
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, console_level))
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Create file handler if log_file provided
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        file_handler.setLevel(getattr(logging, file_level))
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Set library loggers to WARNING level
    for lib_logger in ['asyncio', 'asyncua']:
        logging.getLogger(lib_logger).setLevel(logging.WARNING)
    
    logging.getLogger('__main__').info(f"Logging initialized. Console: {console_level}, File: {file_level}")


class QLogHandler(logging.Handler):
    """Logging handler that emits to a Qt signal"""
    
    def __init__(self, signal):
        """Initialize handler
        
        Args:
            signal: PyQt signal to emit log messages to
        """
        super().__init__()
        self.signal = signal
        
    def emit(self, record):
        """Emit a log record
        
        Args:
            record: Log record to emit
        """
        try:
            msg = self.format(record)
            self.signal.emit(record.levelname, msg)
        except Exception:
            self.handleError(record)