#!/usr/bin/env python
"""
Script to set up the improved OPC UA client application structure.
This creates the directory structure and initializes all Python files with basic content.
"""

import os
import sys
import shutil
from pathlib import Path

# Base content for __init__.py files
INIT_CONTENT = '''"""
{module_name} module for the OPC UA client application
"""
'''

# Main package structure
PACKAGE_STRUCTURE = {
    'opcua_client': [
        '__init__.py',
        'core/__init__.py',
        'core/client.py',
        'core/connection.py',
        'core/subscriptions.py',
        'core/node_operations.py',
        'core/xml_export.py',
        'security/__init__.py',
        'security/certificate_manager.py',
        'security/security_policies.py',
        'utils/__init__.py',
        'utils/logging.py',
        'utils/async_helpers.py',
        'utils/constants.py',
        'gui/__init__.py',
        'gui/main_window.py',
        'gui/connection_widget.py',
        'gui/browser_widget.py',
        'gui/subscription_widget.py',
        'config/__init__.py',
        'config/config_manager.py',
        'models/__init__.py',
        'models/data_models.py',
        'controllers/__init__.py',
        'controllers/main_controller.py',
        'tests/__init__.py',
        'tests/test_client.py',
        'tests/test_connection.py',
    ]
}

# File contents
FILE_CONTENTS = {
    'opcua_client/__init__.py': '''"""
OPC UA Client Application Package
"""

__version__ = '0.1.0'
''',

    'opcua_client/core/__init__.py': '''"""
Core OPC UA client functionality
"""

from .client import OpcUaClient
''',

    'opcua_client/core/client.py': '''"""
OPC UA Client main class
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Tuple, Union

from asyncua import Client, Node, ua
from ..utils.constants import ConnectionStatus

logger = logging.getLogger(__name__)

class OpcUaClient:
    """Core OPC UA Client implementation using asyncua library"""
    
    def __init__(self, config):
        """
        Initialize OPC UA Client
        
        Args:
            config: Client configuration
        """
        self.config = config
        self.client = None
        self.connected = False
        self.subscription = None
        
        # Internal state
        self._connection_manager = None
        self._subscription_manager = None
        self._node_manager = None
        
    async def connect(self):
        """
        Connect to OPC UA server
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        # Implementation to be added
        pass
        
    async def disconnect(self):
        """
        Disconnect from OPC UA server
        """
        # Implementation to be added
        pass
''',

    'opcua_client/core/connection.py': '''"""
OPC UA Connection management
"""

import asyncio
import logging
from typing import Dict, Any, Optional

from asyncua import Client, ua
from ..utils.constants import ConnectionStatus
from ..security.security_policies import get_security_policy

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Manager for OPC UA connections"""
    
    def __init__(self, client):
        """
        Initialize connection manager
        
        Args:
            client: Parent OPC UA client instance
        """
        self.client = client
        self.config = client.config
        self.connection_status = ConnectionStatus.DISCONNECTED
        
    async def connect(self):
        """
        Connect to OPC UA server
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        # Implementation to be added
        pass
        
    async def disconnect(self):
        """
        Disconnect from OPC UA server
        """
        # Implementation to be added
        pass
        
    async def check_connection(self):
        """
        Check if connection is still active
        
        Returns:
            bool: True if connection is active, False otherwise
        """
        # Implementation to be added
        pass
''',

    'opcua_client/core/subscriptions.py': '''"""
OPC UA Subscription handling
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List

from asyncua import Client, Node, ua
from ..utils.constants import ConnectionStatus

logger = logging.getLogger(__name__)

class SubscriptionManager:
    """Manager for OPC UA subscriptions"""
    
    def __init__(self, client):
        """
        Initialize subscription manager
        
        Args:
            client: Parent OPC UA client instance
        """
        self.client = client
        self.subscription = None
        self.subscription_handles = {}
        
    async def create_subscription(self, publishing_interval=500):
        """
        Create a subscription
        
        Args:
            publishing_interval: Publishing interval in milliseconds
            
        Returns:
            Subscription: The created subscription
        """
        # Implementation to be added
        pass
        
    async def subscribe_to_node(self, node_id, display_name):
        """
        Subscribe to data changes for a node
        
        Args:
            node_id: Node ID
            display_name: Display name
            
        Returns:
            SubscriptionResult: Result of subscription operation
        """
        # Implementation to be added
        pass
        
    async def unsubscribe_from_node(self, node_id):
        """
        Unsubscribe from data changes for a node
        
        Args:
            node_id: Node ID
            
        Returns:
            bool: True if unsubscription successful, False otherwise
        """
        # Implementation to be added
        pass
''',

    'opcua_client/core/node_operations.py': '''"""
OPC UA Node browsing and operations
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List

from asyncua import Client, Node, ua
from ..utils.constants import ConnectionStatus

logger = logging.getLogger(__name__)

class NodeOperationsManager:
    """Manager for OPC UA node operations"""
    
    def __init__(self, client):
        """
        Initialize node operations manager
        
        Args:
            client: Parent OPC UA client instance
        """
        self.client = client
        
    async def browse_nodes(self, parent_node_id=None):
        """
        Browse nodes from the specified parent node
        
        Args:
            parent_node_id: Parent node ID (None for root)
            
        Returns:
            List[Dict]: List of nodes
        """
        # Implementation to be added
        pass
        
    async def get_node_details(self, node_id):
        """
        Get detailed information about a node
        
        Args:
            node_id: Node ID
            
        Returns:
            Dict: Node details
        """
        # Implementation to be added
        pass
        
    async def write_value(self, node_id, value, save_value=True):
        """
        Write a value to a node
        
        Args:
            node_id: Node ID
            value: Value to write
            save_value: Whether to save the value for reconnection
            
        Returns:
            tuple: (success, message)
        """
        # Implementation to be added
        pass
        
    async def call_method(self, parent_id, method_id, *args):
        """
        Call a method on the server
        
        Args:
            parent_id: Parent node ID
            method_id: Method node ID
            *args: Method arguments
            
        Returns:
            tuple: (success, result)
        """
        # Implementation to be added
        pass
''',

    'opcua_client/core/xml_export.py': '''"""
OPC UA XML export functionality
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class XmlExportManager:
    """Manager for XML exports"""
    
    def __init__(self, client):
        """
        Initialize XML export manager
        
        Args:
            client: Parent OPC UA client instance
        """
        self.client = client
        self.config = client.config
        self.xml_root = None
        self.init_xml()
        
    def init_xml(self):
        """Initialize XML structure for data output"""
        self.xml_root = ET.Element("OpcUaData")
        self.xml_root.set("timestamp", datetime.now().isoformat())
        self.xml_root.set("client", "OPC UA Client")
        self.save_xml()
        
    def save_xml(self):
        """Save XML data to file"""
        # Implementation to be added
        pass
        
    def add_node_to_xml(self, node_id, display_name, value):
        """
        Add or update a node in the XML output
        
        Args:
            node_id: Node ID
            display_name: Display name
            value: Current value
        """
        # Implementation to be added
        pass
        
    def remove_node_from_xml(self, node_id):
        """
        Remove a node from the XML output
        
        Args:
            node_id: Node ID to remove
        """
        # Implementation to be added
        pass
''',

    'opcua_client/security/__init__.py': '''"""
Security-related functionality for OPC UA
"""

from .certificate_manager import CertificateManager
from .security_policies import get_security_policy
''',

    'opcua_client/security/certificate_manager.py': '''"""
OPC UA Certificate management
"""

import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CertificateManager:
    """Manager for OPC UA certificates"""
    
    def __init__(self, config):
        """
        Initialize certificate manager
        
        Args:
            config: Client configuration
        """
        self.config = config
        
    def generate_self_signed_certificate(self):
        """
        Generate self-signed certificate for OPC UA client
        
        Returns:
            bool: True if successful, False otherwise
        """
        # Implementation to be added
        pass
        
    def validate_certificate(self, certificate):
        """
        Validate a certificate
        
        Args:
            certificate: Certificate data
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Implementation to be added
        pass
        
    def load_trusted_certificates(self):
        """
        Load trusted certificates
        
        Returns:
            list: List of trusted certificates
        """
        # Implementation to be added
        pass
        
    def is_certificate_trusted(self, certificate, trusted_certs=None):
        """
        Check if a certificate is trusted
        
        Args:
            certificate: Certificate to check
            trusted_certs: List of trusted certificates
            
        Returns:
            bool: True if trusted, False otherwise
        """
        # Implementation to be added
        pass
''',

    'opcua_client/security/security_policies.py': '''"""
OPC UA Security policies
"""

import logging
from enum import Enum
from typing import Dict, Any, Optional, Tuple

from asyncua.crypto import security_policies
from asyncua import ua

logger = logging.getLogger(__name__)

class SecurityPolicy(Enum):
    """Security policy options for OPC UA connections"""
    NO_SECURITY = "No security"
    BASIC128RSA15_SIGN = "Basic128Rsa15 - Sign"
    BASIC128RSA15_SIGN_ENCRYPT = "Basic128Rsa15 - Sign & Encrypt"
    BASIC256_SIGN = "Basic256 - Sign"
    BASIC256_SIGN_ENCRYPT = "Basic256 - Sign & Encrypt"
    BASIC256SHA256_SIGN = "Basic256Sha256 - Sign"
    BASIC256SHA256_SIGN_ENCRYPT = "Basic256Sha256 - Sign & Encrypt"
    AES128SHA256RSAOAEP_SIGN = "Aes128Sha256RsaOaep - Sign"
    AES128SHA256RSAOAEP_SIGN_ENCRYPT = "Aes128Sha256RsaOaep - Sign & Encrypt"
    AES256SHA256RSAPSS_SIGN = "Aes256Sha256RsaPss - Sign"
    AES256SHA256RSAPSS_SIGN_ENCRYPT = "Aes256Sha256RsaPss - Sign & Encrypt"

# Map SecurityPolicy enum to actual security policy classes and message security modes
SECURITY_POLICY_MAP = {
    SecurityPolicy.NO_SECURITY: (None, ua.MessageSecurityMode.None_),
    SecurityPolicy.BASIC128RSA15_SIGN: (security_policies.SecurityPolicyBasic128Rsa15, ua.MessageSecurityMode.Sign),
    SecurityPolicy.BASIC128RSA15_SIGN_ENCRYPT: (security_policies.SecurityPolicyBasic128Rsa15, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.BASIC256_SIGN: (security_policies.SecurityPolicyBasic256, ua.MessageSecurityMode.Sign),
    SecurityPolicy.BASIC256_SIGN_ENCRYPT: (security_policies.SecurityPolicyBasic256, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.BASIC256SHA256_SIGN: (security_policies.SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.Sign),
    SecurityPolicy.BASIC256SHA256_SIGN_ENCRYPT: (security_policies.SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.AES128SHA256RSAOAEP_SIGN: (security_policies.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityMode.Sign),
    SecurityPolicy.AES128SHA256RSAOAEP_SIGN_ENCRYPT: (security_policies.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.AES256SHA256RSAPSS_SIGN: (security_policies.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityMode.Sign),
    SecurityPolicy.AES256SHA256RSAPSS_SIGN_ENCRYPT: (security_policies.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityMode.SignAndEncrypt),
}

def get_security_policy(policy_enum):
    """
    Get security policy and mode from enum
    
    Args:
        policy_enum: SecurityPolicy enum value
        
    Returns:
        tuple: (policy_class, security_mode)
    """
    if policy_enum not in SECURITY_POLICY_MAP:
        return None, ua.MessageSecurityMode.None_
    
    return SECURITY_POLICY_MAP[policy_enum]
''',

    'opcua_client/utils/__init__.py': '''"""
Utility functions for OPC UA client
"""

from .logging import setup_logging, get_logger
from .constants import ConnectionStatus
from .async_helpers import run_async_task, create_task_with_cleanup
''',

    'opcua_client/utils/logging.py': '''"""
Logging setup for OPC UA client
"""

import os
import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler

def setup_logging(
    log_dir=None, 
    log_level=logging.INFO, 
    max_bytes=10*1024*1024,  # 10 MB
    backup_count=5
):
    """
    Set up logging for OPC UA client
    
    Args:
        log_dir: Directory for log files
        log_level: Logging level
        max_bytes: Maximum log file size
        backup_count: Number of backup files
        
    Returns:
        logging.Logger: Root logger
    """
    # Use default log directory if not specified
    if log_dir is None:
        log_dir = os.path.join(Path.home(), ".opcua-client", "logs")
    
    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create file handler
    log_file = os.path.join(log_dir, "opcua_client.log")
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(log_level)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger

def get_logger(name=None):
    """
    Get logger with specified name
    
    Args:
        name: Logger name
        
    Returns:
        logging.Logger: Logger instance
    """
    if name:
        return logging.getLogger(f"opcua_client.{name}")
    
    return logging.getLogger("opcua_client")
''',

    'opcua_client/utils/async_helpers.py': '''"""
Asyncio helper functions
"""

import asyncio
import logging
from typing import Callable, Coroutine, Any, Optional

logger = logging.getLogger(__name__)

async def run_async_task(coro, timeout=None):
    """
    Run async task with timeout
    
    Args:
        coro: Coroutine to run
        timeout: Timeout in seconds
        
    Returns:
        Any: Result of coroutine execution
        
    Raises:
        asyncio.TimeoutError: If task times out
        Exception: Any exception raised by the coroutine
    """
    if timeout:
        return await asyncio.wait_for(coro, timeout)
    
    return await coro

async def create_task_with_cleanup(coro, cleanup_func=None):
    """
    Create asyncio task with cleanup function
    
    Args:
        coro: Coroutine to run
        cleanup_func: Cleanup function to call when task is done
        
    Returns:
        asyncio.Task: The created task
    """
    task = asyncio.create_task(coro)
    
    if cleanup_func:
        task.add_done_callback(cleanup_func)
    
    return task
''',

    'opcua_client/utils/constants.py': '''"""
Constants for OPC UA client
"""

from enum import Enum

class ConnectionStatus(Enum):
    """Connection status enum"""
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    RECONNECTING = "Reconnecting"
    ERROR = "Error"

class NodeType(Enum):
    """Types of registered nodes"""
    STANDARD = "Standard"  # Regular node
    LIVEBIT = "LiveBit"    # Toggle between True/False at interval
    TOGGLE = "Toggle"      # Manually toggle between True/False
    CUSTOM = "Custom"      # Custom behavior
''',

    'opcua_client/config/__init__.py': '''"""
Configuration module for OPC UA client
"""

from .config_manager import Config
''',

    'opcua_client/config/config_manager.py': '''"""
Configuration management for OPC UA client
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from ..security.security_policies import SecurityPolicy
from ..utils.constants import NodeType

logger = logging.getLogger(__name__)

class Config:
    """OPC UA Client configuration manager"""
    
    def __init__(self):
        """Initialize configuration with default values"""
        # Connection settings
        self.endpoint = ""
        self.username = ""
        self.auto_connect = False
        self.security_policy = SecurityPolicy.NO_SECURITY
        self.certificate_path = ""
        self.private_key_path = ""
        self.server_certificate_path = ""
        
        # Reconnection settings
        self.auto_reconnect = True
        self.reconnect_delay = 5
        self.max_reconnect_delay = 60
        self.max_reconnect_attempts = 0  # 0 means infinite
        
        # Certificate validation settings
        self.verify_server_certificate = True
        self.check_certificate_trust = True
        self.check_certificate_revocation = True
        self.check_application_uri = True
        
        # Certificate settings
        self.certificate_info = {
            "common_name": "OPC UA Client",
            "organization": "OPC UA Tools",
            "organization_unit": "Development",
            "locality": "City",
            "state": "State",
            "country": "US",
            "days_valid": 365,
            "application_uri": None
        }
        
        # Output settings
        self.xml_output_path = os.path.join(
            os.path.expanduser("~"), 
            ".opcua-client", 
            "output", 
            "opcua_data.xml"
        )
        
        # Node lists
        self.subscribed_nodes = {}  # Dict[node_id, display_name]
        self.registered_nodes = {}  # Dict[node_id, node_info]
        
        # Create necessary directories
        self._ensure_dirs_exist()
    
    def _ensure_dirs_exist(self):
        """Ensure required directories exist"""
        # Implementation to be added
        pass
    
    def to_dict(self):
        """
        Convert configuration to dictionary for serialization
        
        Returns:
            Dict: Dictionary representation of the configuration
        """
        # Implementation to be added
        pass
    
    @classmethod
    def from_dict(cls, data):
        """
        Create configuration from dictionary
        
        Args:
            data: Dictionary with configuration data
            
        Returns:
            Config: Configuration object
        """
        # Implementation to be added
        pass
    
    def save(self, filename=None):
        """
        Save configuration to file
        
        Args:
            filename: Optional filename to save to
        """
        # Implementation to be added
        pass
    
    @classmethod
    def load(cls, filename=None):
        """
        Load configuration from file
        
        Args:
            filename: Optional filename to load from
            
        Returns:
            Config: Loaded configuration object
        """
        # Implementation to be added
        pass
''',

    'opcua_client/gui/__init__.py': '''"""
GUI components for OPC UA client
"""

from .main_window import OpcUaClientApplication
''',

    'opcua_client/gui/main_window.py': '''"""
Main window for OPC UA client application
"""

import sys
import os
import logging
from PyQt5.QtWidgets import QMainWindow, QWidget, QTabWidget, QVBoxLayout
from PyQt5.QtCore import Qt, QTimer

from ..config import Config
from ..core.client import OpcUaClient
from ..controllers.main_controller import MainController
from ..models.data_models import OpcUaModel
from .connection_widget import ConnectionWidget
from .browser_widget import BrowserWidget
from .subscription_widget import SubscriptionWidget

logger = logging.getLogger(__name__)

class OpcUaClientApplication(QMainWindow):
    """Main GUI application for OPC UA Client"""
    
    def __init__(self):
        """Initialize the application"""
        super().__init__()
        
        # Load configuration
        self.config = Config.load()
        
        # Initialize model
        self.model = OpcUaModel(self.config)
        
        # Initialize controller
        self.controller = MainController(self.model, self)
        
        # Initialize UI
        self.init_ui()
        
        # Start model
        self.model.start()
        
        # Auto-connect if configured
        if self.config.auto_connect:
            # Add small delay to ensure worker thread is running
            QTimer.singleShot(500, self.controller.connect_to_server)
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("OPC UA Client")
        self.setMinimumSize(800, 600)
        self.resize(1000, 700)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget for different sections
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Add tabs
        self.connection_widget = ConnectionWidget(self.controller)
        self.browser_widget = BrowserWidget(self.controller)
        self.subscription_widget = SubscriptionWidget(self.controller)
        
        self.tab_widget.addTab(self.connection_widget, "Connection")
        self.tab_widget.addTab(self.browser_widget, "Browser")
        self.tab_widget.addTab(self.subscription_widget, "Subscriptions")
        
        # Status bar
        self.status_bar = self.statusBar()
        
        # Connection status indicator
        self.connection_indicator = None  # Will be initialized in connection_widget
        
        # Status message
        self.status_message = None  # Will be initialized in connection_widget
    
    def closeEvent(self, event):
        """Handle application close event"""
        # Save config
        try:
            self.config.save()
        except Exception as e:
            logger.error(f"Error saving config: {str(e)}")
        
        # Stop client
        self.model.stop()
        
        # Accept close event
        event.accept()
''',

    'opcua_client/gui/connection_widget.py': '''"""
Connection configuration widget
"""

import logging
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QLabel, QLineEdit, QComboBox, QPushButton, QCheckBox
)
from PyQt5.QtCore import Qt

from ..security.security_policies import SecurityPolicy

logger = logging.getLogger(__name__)

class ConnectionWidget(QWidget):
    """Widget for connection configuration"""
    
    def __init__(self, controller):
        """
        Initialize connection widget
        
        Args:
            controller: Application controller
        """
        super().__init__()
        
        self.controller = controller
        self.init_ui()
        
        # Update UI from config
        self.update_ui_from_config()
    
    def init_ui(self):
        """Initialize the user interface"""
        main_layout = QVBoxLayout(self)
        
        # Server group
        server_group = QGroupBox("Server")
        server_layout = QFormLayout()
        
        # Endpoint
        self.endpoint_input = QLineEdit()
        self.endpoint_input.setPlaceholderText("opc.tcp://server:port/path")
        server_layout.addRow("Endpoint URL:", self.endpoint_input)
        
        # Auto-connect
        self.auto_connect_cb = QCheckBox("Auto-connect on startup")
        server_layout.addRow("", self.auto_connect_cb)
        
        server_group.setLayout(server_layout)
        main_layout.addWidget(server_group)
        
        # Authentication group
        auth_group = QGroupBox("Authentication")
        auth_layout = QFormLayout()
        
        # Username
        self.username_input = QLineEdit()
        auth_layout.addRow("Username:", self.username_input)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        auth_layout.addRow("Password:", self.password_input)
        
        auth_group.setLayout(auth_layout)
        main_layout.addWidget(auth_group)
        
        # Security group
        security_group = QGroupBox("Security")
        security_layout = QFormLayout()
        
        # Security policy
        self.security_policy_combo = QComboBox()
        for policy in SecurityPolicy:
            self.security_policy_combo.addItem(policy.value)
        security_layout.addRow("Security Policy:", self.security_policy_combo)
        
        # Certificate generation
        self.generate_cert_cb = QCheckBox("Generate self-signed certificates")
        security_layout.addRow("", self.generate_cert_cb)
        
        security_group.setLayout(security_layout)
        main_layout.addWidget(security_group)
        
        # Connection buttons
        buttons_layout = QHBoxLayout()
        
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.controller.connect_to_server)
        
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.controller.disconnect_from_server)
        self.disconnect_btn.setEnabled(False)
        
        buttons_layout.addWidget(self.connect_btn)
        buttons_layout.addWidget(self.disconnect_btn)
        
        # Config buttons
        self.save_config_btn = QPushButton("Save Configuration")
        self.save_config_btn.clicked.connect(self.controller.save_config)
        
        self.load_config_btn = QPushButton("Load Configuration")
        self.load_config_btn.clicked.connect(self.controller.load_config)
        
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(self.save_config_btn)
        buttons_layout.addWidget(self.load_config_btn)
        
        main_layout.addLayout(buttons_layout)
        main_layout.addStretch(1)
    
    def update_ui_from_config(self):
        """Update UI elements from configuration"""
        config = self.controller.model.config
        
        # Connection settings
        self.endpoint_input.setText(config.endpoint)
        self.username_input.setText(config.username)
        self.auto_connect_cb.setChecked(config.auto_connect)
        
        # Security settings
        index = self.security_policy_combo.findText(config.security_policy.value)
        if index >= 0:
            self.security_policy_combo.setCurrentIndex(index)
    
    def update_connection_status(self, status, message=None):
        """
        Update connection status indicator
        
        Args:
            status: Connection status
            message: Optional status message
        """
        # Implementation to be added
        pass
''',

    'opcua_client/gui/browser_widget.py': '''"""
Node browser widget
"""

import logging
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget,
    QTreeWidgetItem, QPushButton
)
from PyQt5.QtCore import Qt

logger = logging.getLogger(__name__)

class BrowserWidget(QWidget):
    """Widget for browsing OPC UA nodes"""
    
    def __init__(self, controller):
        """
        Initialize browser widget
        
        Args:
            controller: Application controller
        """
        super().__init__()
        
        self.controller = controller
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        main_layout = QVBoxLayout(self)
        
        # Splitter for browser and details
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side - Browser
        browser_widget = QWidget()
        browser_widget_layout = QVBoxLayout(browser_widget)
        
        # Browser tree
        self.node_tree = QTreeWidget()
        self.node_tree.setHeaderLabels(["Name", "Node ID", "Class"])
        self.node_tree.setColumnWidth(0, 300)
        self.node_tree.itemExpanded.connect(self.on_node_expanded)
        self.node_tree.itemClicked.connect(self.on_node_clicked)
        browser_widget_layout.addWidget(self.node_tree)
        
        # Browser buttons
        browser_buttons_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_node_tree)
        self.refresh_btn.setEnabled(False)
        
        self.subscribe_btn = QPushButton("Subscribe")
        self.subscribe_btn.clicked.connect(self.subscribe_to_selected)
        self.subscribe_btn.setEnabled(False)
        
        self.register_btn = QPushButton("Register")
        self.register_btn.clicked.connect(self.register_selected)
        self.register_btn.setEnabled(False)
        
        browser_buttons_layout.addWidget(self.refresh_btn)
        browser_buttons_layout.addWidget(self.subscribe_btn)
        browser_buttons_layout.addWidget(self.register_btn)
        browser_buttons_layout.addStretch(1)
        
        browser_widget_layout.addLayout(browser_buttons_layout)
        
        # Right side - Details
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Details content
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Attribute", "Value"])
        self.details_tree.setColumnWidth(0, 200)
        details_layout.addWidget(self.details_tree)
        
        # Add widgets to splitter
        splitter.addWidget(browser_widget)
        splitter.addWidget(details_widget)
        
        # Set initial sizes (60/40 split)
        splitter.setSizes([600, 400])
        
        main_layout.addWidget(splitter)
    
    def on_node_expanded(self, item):
        """
        Handle node tree item expansion
        
        Args:
            item: Expanded tree item
        """
        # Get node ID from item
        node_id = item.data(1, Qt.DisplayRole)
        if not node_id:
            return
        
        # Request child nodes
        self.controller.browse_nodes(node_id)
    
    def on_node_clicked(self, item, column):
        """
        Handle node tree item click
        
        Args:
            item: Clicked tree item
            column: Clicked column
        """
        # Get node ID from item
        node_id = item.data(1, Qt.DisplayRole)
        if not node_id:
            return
        
        # Request node details
        self.controller.get_node_details(node_id)
        
        # Enable/disable buttons based on node class
        node_class = item.data(2, Qt.DisplayRole)
        self.subscribe_btn.setEnabled(node_class == "Variable")
        self.register_btn.setEnabled(node_class == "Variable")
    
    def refresh_node_tree(self):
        """Refresh node tree"""
        # Implementation to be added
        pass
    
    def subscribe_to_selected(self):
        """Subscribe to selected node"""
        # Implementation to be added
        pass
    
    def register_selected(self):
        """Register selected node"""
        # Implementation to be added
        pass
    
    def update_node_details(self, details):
        """
        Update node details display
        
        Args:
            details: Node details dictionary
        """
        # Implementation to be added
        pass
''',

    'opcua_client/gui/subscription_widget.py': '''"""
Subscription management widget
"""

import logging
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget,
    QTreeWidgetItem, QPushButton
)
from PyQt5.QtCore import Qt

logger = logging.getLogger(__name__)

class SubscriptionWidget(QWidget):
    """Widget for managing OPC UA subscriptions"""
    
    def __init__(self, controller):
        """
        Initialize subscription widget
        
        Args:
            controller: Application controller
        """
        super().__init__()
        
        self.controller = controller
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        main_layout = QVBoxLayout(self)
        
        # Subscriptions tree
        self.subscriptions_tree = QTreeWidget()
        self.subscriptions_tree.setHeaderLabels(["Name", "Node ID", "Value", "Timestamp"])
        self.subscriptions_tree.setColumnWidth(0, 250)
        self.subscriptions_tree.setColumnWidth(1, 250)
        self.subscriptions_tree.setColumnWidth(2, 300)
        main_layout.addWidget(self.subscriptions_tree)
        
        # Subscription buttons
        sub_buttons_layout = QHBoxLayout()
        
        self.unsubscribe_btn = QPushButton("Unsubscribe Selected")
        self.unsubscribe_btn.clicked.connect(self.unsubscribe_selected)
        self.unsubscribe_btn.setEnabled(False)
        
        self.unsubscribe_all_btn = QPushButton("Unsubscribe All")
        self.unsubscribe_all_btn.clicked.connect(self.unsubscribe_all)
        self.unsubscribe_all_btn.setEnabled(False)
        
        sub_buttons_layout.addWidget(self.unsubscribe_btn)
        sub_buttons_layout.addWidget(self.unsubscribe_all_btn)
        sub_buttons_layout.addStretch(1)
        
        main_layout.addLayout(sub_buttons_layout)
    
    def unsubscribe_selected(self):
        """Unsubscribe from selected nodes"""
        # Implementation to be added
        pass
    
    def unsubscribe_all(self):
        """Unsubscribe from all nodes"""
        # Implementation to be added
        pass
    
    def update_subscription(self, node_id, display_name, value, timestamp):
        """
        Update subscription data
        
        Args:
            node_id: Node ID
            display_name: Display name
            value: Current value
            timestamp: Value timestamp
        """
        # Implementation to be added
        pass
''',

    'opcua_client/models/__init__.py': '''"""
Data models for OPC UA client
"""

from .data_models import OpcUaModel
''',

    'opcua_client/models/data_models.py': '''"""
Data models for OPC UA client
"""

import asyncio
import logging
import threading
from typing import Dict, Any, Optional, List, Set, Callable
from datetime import datetime

from ..core.client import OpcUaClient
from ..utils.constants import ConnectionStatus, NodeType

logger = logging.getLogger(__name__)

class Event:
    """Simple event implementation for model-view communication"""
    
    def __init__(self):
        """Initialize event with empty listener list"""
        self._listeners = set()
    
    def add_listener(self, listener):
        """
        Add listener function
        
        Args:
            listener: Callable to be invoked when event is fired
        """
        self._listeners.add(listener)
    
    def remove_listener(self, listener):
        """
        Remove listener function
        
        Args:
            listener: Listener to remove
        """
        self._listeners.discard(listener)
    
    def fire(self, *args, **kwargs):
        """
        Fire event to all listeners
        
        Args:
            *args: Positional arguments to pass to listeners
            **kwargs: Keyword arguments to pass to listeners
        """
        for listener in self._listeners:
            listener(*args, **kwargs)

class OpcUaModel:
    """Model class for OPC UA client application"""
    
    def __init__(self, config):
        """
        Initialize OPC UA model
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.subscribed_nodes = {}
        self.registered_nodes = {}
        
        # Create events
        self.on_connection_status_changed = Event()
        self.on_nodes_browsed = Event()
        self.on_node_details_available = Event()
        self.on_node_subscribed = Event()
        self.on_node_unsubscribed = Event()
        self.on_subscription_data_changed = Event()
        self.on_xml_updated = Event()
        self.on_reconnection_status = Event()
        self.on_method_called = Event()
        self.on_node_registered = Event()
        self.on_node_write_completed = Event()
        
        # Create OPC UA client
        self.client = OpcUaClient(config)
        
        # Worker thread for async operations
        self.worker_thread = None
        self.loop = None
    
    def start(self):
        """Start the model worker thread"""
        if self.worker_thread is not None and self.worker_thread.is_alive():
            logger.warning("Worker thread already running")
            return
        
        # Create and start worker thread
        self.worker_thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self.worker_thread.start()
        
        logger.info("Worker thread started")
    
    def stop(self):
        """Stop the model worker thread"""
        if self.worker_thread is None or not self.worker_thread.is_alive():
            logger.warning("Worker thread not running")
            return
        
        # Schedule disconnect if connected
        if self.connection_status == ConnectionStatus.CONNECTED:
            asyncio.run_coroutine_threadsafe(self.disconnect(), self.loop)
        
        # Stop event loop
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        
        # Wait for thread to finish
        self.worker_thread.join(timeout=5)
        
        logger.info("Worker thread stopped")
    
    def _run_event_loop(self):
        """Run asyncio event loop in worker thread"""
        # Create new event loop for this thread
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Connect client signals to model events
        self._connect_client_signals()
        
        # Run client
        try:
            self.client.start()
            self.loop.run_forever()
        except Exception as e:
            logger.error(f"Error in event loop: {str(e)}")
        finally:
            # Clean up
            self.loop.close()
            self.loop = None
    
    def _connect_client_signals(self):
        """Connect OPC UA client signals to model events"""
        # Implementation to be added
        pass
    
    async def connect(self):
        """
        Connect to OPC UA server
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        # Implementation to be added
        pass
    
    async def disconnect(self):
        """
        Disconnect from OPC UA server
        """
        # Implementation to be added
        pass
    
    async def browse_nodes(self, parent_node_id=None):
        """
        Browse nodes from the specified parent node
        
        Args:
            parent_node_id: Parent node ID (None for root)
            
        Returns:
            List[Dict]: List of nodes
        """
        # Implementation to be added
        pass
    
    async def get_node_details(self, node_id):
        """
        Get detailed information about a node
        
        Args:
            node_id: Node ID
            
        Returns:
            Dict: Node details
        """
        # Implementation to be added
        pass
''',

    'opcua_client/controllers/__init__.py': '''"""
Controllers for OPC UA client
"""

from .main_controller import MainController
''',

    'opcua_client/controllers/main_controller.py': '''"""
Main controller for OPC UA client application
"""

import asyncio
import logging
from typing import Dict, Any, Optional

from ..models.data_models import OpcUaModel
from ..utils.constants import ConnectionStatus

logger = logging.getLogger(__name__)

class MainController:
    """Controller class for OPC UA client application"""
    
    def __init__(self, model, view):
        """
        Initialize main controller
        
        Args:
            model: Application model
            view: Application view
        """
        self.model = model
        self.view = view
        
        # Connect model events to controller methods
        self._connect_model_events()
    
    def _connect_model_events(self):
        """Connect model events to controller methods"""
        self.model.on_connection_status_changed.add_listener(self.on_connection_status_changed)
        self.model.on_nodes_browsed.add_listener(self.on_nodes_browsed)
        self.model.on_node_details_available.add_listener(self.on_node_details_available)
        self.model.on_node_subscribed.add_listener(self.on_node_subscribed)
        self.model.on_node_unsubscribed.add_listener(self.on_node_unsubscribed)
        self.model.on_subscription_data_changed.add_listener(self.on_subscription_data_changed)
    
    def connect_to_server(self):
        """Connect to OPC UA server"""
        # Update UI
        self.view.connection_widget.update_connection_status(
            ConnectionStatus.CONNECTING,
            f"Connecting to {self.model.config.endpoint}..."
        )
        
        # Update config from UI
        self._update_config_from_ui()
        
        # Start async connection
        if hasattr(self.model, 'loop') and self.model.loop:
            asyncio.run_coroutine_threadsafe(self.model.connect(), self.model.loop)
    
    def disconnect_from_server(self):
        """Disconnect from OPC UA server"""
        # Update UI
        self.view.connection_widget.update_connection_status(
            ConnectionStatus.DISCONNECTED,
            "Disconnecting..."
        )
        
        # Start async disconnection
        if hasattr(self.model, 'loop') and self.model.loop:
            asyncio.run_coroutine_threadsafe(self.model.disconnect(), self.model.loop)
    
    def _update_config_from_ui(self):
        """Update configuration from UI values"""
        # Implementation to be added
        pass
    
    def save_config(self):
        """Save configuration to file"""
        # Implementation to be added
        pass
    
    def load_config(self):
        """Load configuration from file"""
        # Implementation to be added
        pass
    
    def browse_nodes(self, parent_node_id=None):
        """
        Browse nodes from the specified parent node
        
        Args:
            parent_node_id: Parent node ID (None for root)
        """
        # Start async browsing
        if hasattr(self.model, 'loop') and self.model.loop:
            asyncio.run_coroutine_threadsafe(
                self.model.browse_nodes(parent_node_id),
                self.model.loop
            )
    
    def get_node_details(self, node_id):
        """
        Get detailed information about a node
        
        Args:
            node_id: Node ID
        """
        # Start async operation
        if hasattr(self.model, 'loop') and self.model.loop:
            asyncio.run_coroutine_threadsafe(
                self.model.get_node_details(node_id),
                self.model.loop
            )
    
    # Event handlers for model events
    
    def on_connection_status_changed(self, status, message):
        """
        Handle connection status change
        
        Args:
            status: New connection status
            message: Status message
        """
        # Update UI
        self.view.connection_widget.update_connection_status(status, message)
        
        # Update button states
        self.view.connection_widget.connect_btn.setEnabled(
            status in (ConnectionStatus.DISCONNECTED, ConnectionStatus.ERROR)
        )
        self.view.connection_widget.disconnect_btn.setEnabled(
            status in (ConnectionStatus.CONNECTED, ConnectionStatus.CONNECTING)
        )
        
        # Update browser functionality
        self.view.browser_widget.refresh_btn.setEnabled(
            status == ConnectionStatus.CONNECTED
        )
    
    def on_nodes_browsed(self, nodes, parent_id):
        """
        Handle browsed nodes
        
        Args:
            nodes: List of node dictionaries
            parent_id: Parent node ID
        """
        # Implementation to be added
        pass
    
    def on_node_details_available(self, details):
        """
        Handle node details
        
        Args:
            details: Node details dictionary
        """
        # Implementation to be added
        pass
    
    def on_node_subscribed(self, node_id, display_name, initial_value):
        """
        Handle node subscription
        
        Args:
            node_id: Node ID
            display_name: Display name
            initial_value: Initial value
        """
        # Implementation to be added
        pass
    
    def on_node_unsubscribed(self, node_id):
        """
        Handle node unsubscription
        
        Args:
            node_id: Node ID
        """
        # Implementation to be added
        pass
    
    def on_subscription_data_changed(self, node_id, value, timestamp):
        """
        Handle subscription data change
        
        Args:
            node_id: Node ID
            value: New value
            timestamp: Value timestamp
        """
        # Implementation to be added
        pass
''',

    'opcua_client/tests/__init__.py': '''"""
Test package for OPC UA client
"""
''',

    'opcua_client/tests/test_client.py': '''"""
Tests for OPC UA client
"""

import unittest
import asyncio
from unittest.mock import MagicMock, patch

from asyncua import ua

from ..core.client import OpcUaClient
from ..config.config_manager import Config

class AsyncMock(MagicMock):
    """Mock for async functions"""
    
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)

class TestOpcUaClient(unittest.TestCase):
    """Test cases for OpcUaClient"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = MagicMock(spec=Config)
        self.client = OpcUaClient(self.config)
    
    def tearDown(self):
        """Clean up test environment"""
        pass
    
    @patch('opcua_client.core.client.Client')
    async def test_connect(self, mock_asyncua_client):
        """Test connect method"""
        # Setup mock
        mock_asyncua_client.return_value = AsyncMock()
        mock_asyncua_client.return_value.connect = AsyncMock()
        
        # Set config values
        self.config.endpoint = "opc.tcp://localhost:4840"
        self.config.security_policy.value = "No security"
        
        # Call connect
        result = await self.client.connect()
        
        # Assert
        self.assertTrue(result)
        mock_asyncua_client.assert_called_once_with(url="opc.tcp://localhost:4840")
        mock_asyncua_client.return_value.connect.assert_called_once()
        self.assertTrue(self.client.connected)
    
    @patch('opcua_client.core.client.Client')
    async def test_connect_error(self, mock_asyncua_client):
        """Test connect method with error"""
        # Setup mock to raise exception
        mock_asyncua_client.return_value = AsyncMock()
        mock_asyncua_client.return_value.connect = AsyncMock(side_effect=Exception("Connection error"))
        
        # Set config values
        self.config.endpoint = "opc.tcp://localhost:4840"
        self.config.security_policy.value = "No security"
        
        # Call connect
        result = await self.client.connect()
        
        # Assert
        self.assertFalse(result)
        mock_asyncua_client.assert_called_once_with(url="opc.tcp://localhost:4840")
        mock_asyncua_client.return_value.connect.assert_called_once()
        self.assertFalse(self.client.connected)

if __name__ == '__main__':
    unittest.main()
''',

    'opcua_client/tests/test_connection.py': '''"""
Tests for OPC UA connection management
"""

import unittest
import asyncio
from unittest.mock import MagicMock, patch

from asyncua import ua

from ..core.connection import ConnectionManager
from ..core.client import OpcUaClient
from ..config.config_manager import Config
from ..utils.constants import ConnectionStatus

class AsyncMock(MagicMock):
    """Mock for async functions"""
    
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)

class TestConnectionManager(unittest.TestCase):
    """Test cases for ConnectionManager"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = MagicMock(spec=Config)
        self.client = MagicMock(spec=OpcUaClient)
        self.client.config = self.config
        self.connection_manager = ConnectionManager(self.client)
    
    def tearDown(self):
        """Clean up test environment"""
        pass
    
    @patch('opcua_client.core.connection.Client')
    async def test_connect(self, mock_asyncua_client):
        """Test connect method"""
        # Setup mock
        mock_asyncua_client.return_value = AsyncMock()
        mock_asyncua_client.return_value.connect = AsyncMock()
        
        # Set config values
        self.config.endpoint = "opc.tcp://localhost:4840"
        self.config.security_policy.value = "No security"
        
        # Call connect
        result = await self.connection_manager.connect()
        
        # Assert
        self.assertTrue(result)
        self.assertEqual(self.connection_manager.connection_status, ConnectionStatus.CONNECTED)
    
    @patch('opcua_client.core.connection.Client')
    async def test_connect_error(self, mock_asyncua_client):
        """Test connect method with error"""
        # Setup mock to raise exception
        mock_asyncua_client.return_value = AsyncMock()
        mock_asyncua_client.return_value.connect = AsyncMock(side_effect=Exception("Connection error"))
        
        # Set config values
        self.config.endpoint = "opc.tcp://localhost:4840"
        self.config.security_policy.value = "No security"
        
        # Call connect
        result = await self.connection_manager.connect()
        
        # Assert
        self.assertFalse(result)
        self.assertEqual(self.connection_manager.connection_status, ConnectionStatus.ERROR)

if __name__ == '__main__':
    unittest.main()
'''
}

def create_directory_structure():
    """Create the package directory structure"""
    for package, files in PACKAGE_STRUCTURE.items():
        # Create package directory
        package_dir = Path(package)
        os.makedirs(package_dir, exist_ok=True)
        print(f"Created directory: {package_dir}")
        
        # Create files in package
        for file_path in files:
            # Create file
            full_path = package_dir / file_path
            
            # Create parent directories if needed
            os.makedirs(full_path.parent, exist_ok=True)
            
            # Get file content
            key = os.path.join(package, file_path)
            content = FILE_CONTENTS.get(key)
            
            # If not found, use default content for __init__.py
            if content is None and file_path.endswith('__init__.py'):
                module_name = os.path.basename(os.path.dirname(file_path))
                if not module_name:
                    module_name = package
                content = INIT_CONTENT.format(module_name=module_name)
            
            # Write file content
            if content is not None:
                with open(full_path, 'w') as f:
                    f.write(content)
                print(f"Created file: {full_path}")
            else:
                # Create empty file
                with open(full_path, 'w') as f:
                    pass
                print(f"Created empty file: {full_path}")

def setup_package():
    """Set up the package structure"""
    # Check if we're overwriting existing files
    main_dir = Path(list(PACKAGE_STRUCTURE.keys())[0])
    if main_dir.exists():
        overwrite = input(f"Directory {main_dir} already exists. Overwrite? (y/n): ")
        if overwrite.lower() != 'y':
            print("Aborted.")
            return
        
        # Remove existing directory
        print(f"Removing existing directory: {main_dir}")
        shutil.rmtree(main_dir)
    
    # Create directory structure
    create_directory_structure()
    
    # Create main.py in current directory
    with open('main.py', 'w') as f:
        f.write('''#!/usr/bin/env python
"""
Main entry point for the OPC UA client application
"""

import sys
import logging
from opcua_client.utils.logging import setup_logging
from opcua_client.gui.main_window import OpcUaClientApplication
from PyQt5.QtWidgets import QApplication

def main():
    """Main entry point"""
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
''')
    print("Created main.py")
    
    # Create requirements.txt
    with open('requirements.txt', 'w') as f:
        f.write('''# OPC UA Client requirements
asyncua>=1.0.0
PyQt5>=5.15.0
keyring>=23.0.0
cryptography>=36.0.0
pytest>=7.0.0
pytest-asyncio>=0.18.0
''')
    print("Created requirements.txt")
    
    print("\nSetup complete!")
    print("\nTo run the application:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run the application: python main.py")

if __name__ == '__main__':
    setup_package()