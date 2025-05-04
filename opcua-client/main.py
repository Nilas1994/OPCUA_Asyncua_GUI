import sys
import logging
from typing import Optional
from PyQt5.QtWidgets import QApplication

from gui_app import OpcUaClientApplication
from utils import setup_logging

def main():
    """Main entry point for the OPC UA Client application"""
    # Set up logging
    logger = setup_logging()
    logger.info("Starting OPC UA Client application")
    
    # Create and start the Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("OPC UA Client")
    app.setOrganizationName("OPC UA Tools")
    app.setOrganizationDomain("opcuatools.org")
    
    # Initialize and show the main window
    main_window = OpcUaClientApplication()
    main_window.show()
    
    # Run the application
    exit_code = app.exec_()
    
    logger.info(f"Application exited with code {exit_code}")
    return exit_code

if __name__ == "__main__":
    sys.exit(main())