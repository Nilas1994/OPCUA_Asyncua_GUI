#!/usr/bin/env python3
"""
OPC UA Client Application Entry Point
"""
import sys
import os
import asyncio
import logging
import signal
import platform
from pathlib import Path

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
import qasync

from gui.main_window import MainWindow
from utils.logger import setup_logger
from config_handler import ConfigHandler


def main():
    # Set up application directories
    app_dir = Path.home() / ".opcua_client"
    app_dir.mkdir(exist_ok=True)
    
    config_dir = app_dir / "config"
    config_dir.mkdir(exist_ok=True)
    
    logs_dir = app_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    
    nodes_dir = app_dir / "nodes"
    nodes_dir.mkdir(exist_ok=True)
    
    certs_dir = app_dir / "certs"
    certs_dir.mkdir(exist_ok=True)
    
    # Set up logging
    log_file = logs_dir / "app.log"
    setup_logger(log_file)
    logger = logging.getLogger(__name__)
    logger.info("Starting OPC UA Client application")
    
    # Initialize configuration
    config_handler = ConfigHandler(config_dir)
    
    # Create Qt Application
    app = QApplication(sys.argv)
    app.setApplicationName("OPC UA Client")
    app.setApplicationVersion("1.0.0")
    
    # Apply dark mode style
    app.setStyle("Fusion")
    
    # Create event loop
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    
    # Create main window
    window = MainWindow(config_handler)
    window.show()
    
    # Handle graceful shutdown
    def signal_handler(*args):
        logger.info("Received termination signal, shutting down...")
        window.close()
        app.quit()
    
    # Register signal handlers - only on systems that support it
    if platform.system() != "Windows":
        # On Unix-like systems, we can use loop.add_signal_handler
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
    else:
        # On Windows, we don't use signal handlers with the event loop
        # Instead, we can use the built-in signal handlers if needed
        logger.info("Running on Windows - signal handlers not supported with asyncio")
    
    # Start the event loop
    with loop:
        sys.exit(loop.run_forever())


if __name__ == "__main__":
    main()