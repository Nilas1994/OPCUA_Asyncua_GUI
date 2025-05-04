import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional, Tuple
from enum import Enum
from pathlib import Path
import json
from typing import Optional, Tuple
from datetime import datetime

# Constants for log file
LOG_DIR = os.path.join(Path.home(), ".opcua-client", "logs")
LOG_FILE = os.path.join(LOG_DIR, "opcua_client.log")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

class LogLevel(Enum):
    """Enum for log levels"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

def setup_logging(level: LogLevel = LogLevel.INFO) -> logging.Logger:
    """
    Set up logging with console and file handlers
    
    Args:
        level: Logging level
        
    Returns:
        Logger for the application
    """
    # Create logger
    logger = logging.getLogger("opcua_client")
    logger.setLevel(level.value)
    
    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level.value)
    console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)
    
    # Create file handler
    file_handler = RotatingFileHandler(
        LOG_FILE, 
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)  # File logs at DEBUG level
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger with the specified name
    
    Args:
        name: Logger name (defaults to root logger)
        
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f"opcua_client.{name}")
    return logging.getLogger("opcua_client")

class ConnectionStatus(Enum):
    """Connection status enum"""
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    RECONNECTING = "Reconnecting"
    ERROR = "Error"

def get_app_dir(app_name: str = "opcua-client") -> str:
    """
    Get the application directory for storing configurations, certificates, etc.
    
    Args:
        app_name: Application name
        
    Returns:
        Application directory path
    """
    app_dir = os.path.join(Path.home(), f".{app_name}")
    os.makedirs(app_dir, exist_ok=True)
    return app_dir

def get_config_dir() -> str:
    """
    Get the configuration directory
    
    Returns:
        Configuration directory path
    """
    config_dir = os.path.join(get_app_dir(), "config")
    os.makedirs(config_dir, exist_ok=True)
    return config_dir

def get_certificates_dir() -> str:
    """
    Get the certificates directory
    
    Returns:
        Certificates directory path
    """
    cert_dir = os.path.join(get_app_dir(), "certificates")
    os.makedirs(cert_dir, exist_ok=True)
    return cert_dir

def get_output_dir() -> str:
    """
    Get the output directory for JSON files, etc.
    
    Returns:
        Output directory path
    """
    output_dir = os.path.join(get_app_dir(), "output")
    os.makedirs(output_dir, exist_ok=True)
    
    # Create subdirectories for new file structure
    os.makedirs(os.path.join(output_dir, "subscriptions"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "registered_nodes"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "registered_nodes", "custom"), exist_ok=True)
    
    return output_dir

def ensure_json_output_files(output_dir: str) -> Tuple[str, str]:
    """
    Ensure JSON output files exist
    
    Args:
        output_dir: Output directory
        
    Returns:
        Tuple of (subscriptions_file, registered_nodes_file) paths
    """
    subscriptions_file = os.path.join(output_dir, "opcua_subscriptions.json")
    registered_nodes_file = os.path.join(output_dir, "opcua_registered_nodes.json")
    
    # Create empty files if they don't exist
    for filepath in [subscriptions_file, registered_nodes_file]:
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump({
                    "metadata": {
                        "file_type": os.path.basename(filepath).replace('.json', ''),
                        "generated_at": datetime.now().isoformat(),
                        "version": "1.0",
                        "node_count": 0
                    },
                    "structure": {},
                    "data": {},
                    "flat_data": {}
                }, f, indent=2)
    
    return subscriptions_file, registered_nodes_file