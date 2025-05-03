import sys
import os
import time
import asyncio
from typing import Dict, Any, Optional, List, Tuple, Union, Set
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, 
    QFormLayout, QGroupBox, QLabel, QLineEdit, QComboBox, 
    QPushButton, QCheckBox, QTreeWidget, QTreeWidgetItem, 
    QTextEdit, QFileDialog, QMessageBox, QSplitter, QProgressBar,
    QDialog, QDialogButtonBox, QTreeWidgetItemIterator
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QIcon, QColor, QIntValidator, QDoubleValidator 

from config_manager import Config, SecurityPolicy
from client_core import OpcUaClient
from utils import get_logger, ConnectionStatus, get_config_dir, get_certificates_dir, get_output_dir
from node_manager import NodeManager, NodeType

logger = get_logger("gui_app")

class ConfirmationDialog(QDialog):
    """Dialog for confirmation"""
    
    def __init__(self, title: str, message: str, parent=None):
        """
        Initialize confirmation dialog
        
        Args:
            title: Dialog title
            message: Dialog message
            parent: Parent widget
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Add message
        message_label = QLabel(message)
        layout.addWidget(message_label)
        
        # Add buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

class LogViewer(QWidget):
    """Widget for displaying log messages"""
    
    def __init__(self, parent=None):
        """
        Initialize log viewer
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Create log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        # Add controls
        controls_layout = QHBoxLayout()
        
        # Clear button
        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self.clear_log)
        controls_layout.addWidget(clear_btn)
        
        # Auto-scroll checkbox
        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        controls_layout.addWidget(self.auto_scroll_cb)
        
        controls_layout.addStretch(1)
        
        layout.addLayout(controls_layout)
        
        # Timer for updating log
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_log)
        self.update_timer.start(1000)  # Update every second
        
        # Log file path
        self.log_file_path = os.path.expanduser("~/.opcua-client/logs/opcua_client.log")
        
        # Last file position
        self.last_position = 0
        
        # Initial update
        self.update_log()
    
    def clear_log(self):
        """Clear the log view"""
        self.log_text.clear()
    
    def update_log(self):
        """Update log from file"""
        try:
            if os.path.exists(self.log_file_path):
                with open(self.log_file_path, 'r') as f:
                    # Go to last position
                    f.seek(self.last_position)
                    
                    # Read new lines
                    new_lines = f.read()
                    
                    # Update last position
                    self.last_position = f.tell()
                
                # Append new lines
                if new_lines:
                    self.log_text.append(new_lines)
                    
                    # Auto-scroll
                    if self.auto_scroll_cb.isChecked():
                        scrollbar = self.log_text.verticalScrollBar()
                        scrollbar.setValue(scrollbar.maximum())
        except Exception as e:
            logger.error(f"Error updating log: {str(e)}")

class OpcUaClientApplication(QMainWindow):
    """Main GUI application for OPC UA Client"""
    
    def __init__(self):
        """Initialize the application"""
        super().__init__()
        
        # Load configuration
        self.config = Config.load()
        
        # Initialize client
        self.client = OpcUaClient(self.config)
        
        # Initialize node manager
        self.node_manager = NodeManager()
        
        # Connect signals
        self.connect_signals()
        
        # Initialize UI
        self.init_ui()
        
        # Start client worker thread
        self.client.start()

        # Add to __init__ after other initializations
        self.connection_check_timer = QTimer(self)
        self.connection_check_timer.timeout.connect(self.check_connection_status)
        self.connection_check_timer.start(5000)  # Check every 5 seconds
        
        # Auto-connect if configured
        if self.config.auto_connect:
            # Add small delay to ensure worker thread is running
            QTimer.singleShot(500, self.connect_to_server)
    
    def connect_signals(self):
        """Connect signals from client to UI slots"""
        # Connection status
        self.client.connection_status_changed.connect(self.on_connection_status_changed)
        
        # Node browsing
        self.client.nodes_browsed.connect(self.on_nodes_browsed)
        self.client.node_details_available.connect(self.on_node_details_available)
        
        # Subscriptions
        self.client.node_subscribed.connect(self.on_node_subscribed)
        self.client.node_unsubscribed.connect(self.on_node_unsubscribed)
        self.client.subscription_data_changed.connect(self.on_subscription_data_changed)
        
        # XML
        self.client.xml_updated.connect(self.on_xml_updated)
        
        # Reconnection
        self.client.reconnection_status.connect(self.on_reconnection_status)
        
        # Method calls
        self.client.method_called.connect(self.on_method_called)
        
        # Registered nodes
        self.client.node_registered.connect(self.on_node_registered)
        self.client.node_write_completed.connect(self.on_node_write_completed)
        
        # Node manager
        self.node_manager.node_value_changed.connect(self.on_node_value_changed)
        
        # Register write callback
        self.node_manager.register_write_callback(self.write_node_value)
    
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
        self.init_connection_tab()
        self.init_browser_tab()
        self.init_subscriptions_tab()
        self.init_registered_nodes_tab()
        self.init_output_tab()
        self.init_log_tab()
        
        # Status bar
        self.status_bar = self.statusBar()
        
        # Connection status indicator
        self.connection_indicator = QLabel("●")
        self.connection_indicator.setStyleSheet("color: red; font-size: 16px;")
        self.status_bar.addPermanentWidget(self.connection_indicator)
        
        # Status message
        self.status_message = QLabel("Disconnected")
        self.status_bar.addWidget(self.status_message)
        
        # Update UI from config
        self.update_ui_from_config()
    
    def init_connection_tab(self):
        """Initialize the connection tab"""
        connection_tab = QTabWidget()
        
        # Basic Settings tab
        basic_settings = QWidget()
        basic_layout = QVBoxLayout(basic_settings)
        
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
        basic_layout.addWidget(server_group)
        
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
        basic_layout.addWidget(auth_group)
        
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
        self.generate_cert_cb.stateChanged.connect(self.on_generate_cert_changed)
        security_layout.addRow("", self.generate_cert_cb)
        
        # Certificate path
        self.cert_path_input = QLineEdit()
        self.cert_path_input.setReadOnly(True)
        cert_browse_btn = QPushButton("Browse...")
        cert_browse_btn.clicked.connect(self.browse_certificate)
        cert_layout = QHBoxLayout()
        cert_layout.addWidget(self.cert_path_input)
        cert_layout.addWidget(cert_browse_btn)
        security_layout.addRow("Certificate:", cert_layout)
        
        # Private key path
        self.key_path_input = QLineEdit()
        self.key_path_input.setReadOnly(True)
        key_browse_btn = QPushButton("Browse...")
        key_browse_btn.clicked.connect(self.browse_private_key)
        key_layout = QHBoxLayout()
        key_layout.addWidget(self.key_path_input)
        key_layout.addWidget(key_browse_btn)
        security_layout.addRow("Private Key:", key_layout)
        
        security_group.setLayout(security_layout)
        basic_layout.addWidget(security_group)
        
        # Connection buttons
        buttons_layout = QHBoxLayout()
        
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_to_server)
        
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect_from_server)
        self.disconnect_btn.setEnabled(False)
        
        buttons_layout.addWidget(self.connect_btn)
        buttons_layout.addWidget(self.disconnect_btn)
        
        # Config buttons
        self.save_config_btn = QPushButton("Save Configuration")
        self.save_config_btn.clicked.connect(self.save_config)
        
        self.load_config_btn = QPushButton("Load Configuration")
        self.load_config_btn.clicked.connect(self.load_config)
        
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(self.save_config_btn)
        buttons_layout.addWidget(self.load_config_btn)
        
        basic_layout.addLayout(buttons_layout)
        basic_layout.addStretch(1)
        
        # Add basic settings tab
        connection_tab.addTab(basic_settings, "Basic Settings")
        
        # Advanced Settings tab
        advanced_settings = QWidget()
        advanced_layout = QVBoxLayout(advanced_settings)
        
        # Reconnection group
        reconnect_group = QGroupBox("Reconnection")
        reconnect_layout = QFormLayout()
        
        # Auto reconnect
        self.auto_reconnect_cb = QCheckBox("Automatically reconnect if connection is lost")
        reconnect_layout.addRow("", self.auto_reconnect_cb)
        
        # Initial delay
        self.reconnect_delay_input = QLineEdit()
        self.reconnect_delay_input.setValidator(QIntValidator(1, 3600))
        reconnect_layout.addRow("Initial delay (seconds):", self.reconnect_delay_input)
        
        # Maximum delay
        self.max_reconnect_delay_input = QLineEdit()
        self.max_reconnect_delay_input.setValidator(QIntValidator(1, 3600))
        reconnect_layout.addRow("Maximum delay (seconds):", self.max_reconnect_delay_input)
        
        # Maximum attempts
        self.max_reconnect_attempts_input = QLineEdit()
        self.max_reconnect_attempts_input.setValidator(QIntValidator(0, 1000))
        reconnect_layout.addRow("Maximum attempts (0 = infinite):", self.max_reconnect_attempts_input)
        
        reconnect_group.setLayout(reconnect_layout)
        advanced_layout.addWidget(reconnect_group)
        
        # Output group
        output_group = QGroupBox("Output")
        output_layout = QFormLayout()
        
        # XML output path
        self.xml_path_input = QLineEdit()
        self.xml_path_input.setReadOnly(True)
        xml_browse_btn = QPushButton("Browse...")
        xml_browse_btn.clicked.connect(self.browse_xml_output)
        xml_layout = QHBoxLayout()
        xml_layout.addWidget(self.xml_path_input)
        xml_layout.addWidget(xml_browse_btn)
        output_layout.addRow("XML Output Path:", xml_layout)
        
        output_group.setLayout(output_layout)
        advanced_layout.addWidget(output_group)
        
        advanced_layout.addStretch(1)
        
        # Add advanced settings tab
        connection_tab.addTab(advanced_settings, "Advanced Settings")
        
        # Certificate Settings tab
        cert_settings = QWidget()
        cert_layout = QVBoxLayout(cert_settings)
        
        # Certificate info group
        cert_info_group = QGroupBox("Certificate Information")
        cert_info_layout = QFormLayout()
        
        # Common name
        self.common_name_input = QLineEdit()
        cert_info_layout.addRow("Common Name:", self.common_name_input)
        
        # Organization
        self.organization_input = QLineEdit()
        cert_info_layout.addRow("Organization:", self.organization_input)
        
        # Organization unit
        self.org_unit_input = QLineEdit()
        cert_info_layout.addRow("Organization Unit:", self.org_unit_input)
        
        # Locality
        self.locality_input = QLineEdit()
        cert_info_layout.addRow("Locality/City:", self.locality_input)
        
        # State
        self.state_input = QLineEdit()
        cert_info_layout.addRow("State/Province:", self.state_input)
        
        # Country
        self.country_input = QLineEdit()
        cert_info_layout.addRow("Country (2-letter code):", self.country_input)
        
        # Validity
        self.validity_input = QLineEdit()
        self.validity_input.setValidator(QIntValidator(1, 3650))
        cert_info_layout.addRow("Validity (days):", self.validity_input)
        
        # Generate button
        self.generate_cert_btn = QPushButton("Generate Certificate")
        self.generate_cert_btn.clicked.connect(self.generate_certificate)
        cert_info_layout.addRow("", self.generate_cert_btn)
        
        cert_info_group.setLayout(cert_info_layout)
        cert_layout.addWidget(cert_info_group)
        cert_layout.addStretch(1)
        
        # Add certificate settings tab
        connection_tab.addTab(cert_settings, "Certificate Settings")
        
        # Add connection tab to main tab widget
        self.tab_widget.addTab(connection_tab, "Connection")
    
    def init_browser_tab(self):
        """Initialize the browser tab"""
        browser_tab = QWidget()
        browser_layout = QVBoxLayout(browser_tab)
        
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
        details_widget = QTabWidget()
        
        # Attributes tab
        attributes_tab = QWidget()
        attributes_layout = QVBoxLayout(attributes_tab)
        
        self.attributes_tree = QTreeWidget()
        self.attributes_tree.setHeaderLabels(["Attribute", "Value"])
        self.attributes_tree.setColumnWidth(0, 200)
        attributes_layout.addWidget(self.attributes_tree)
        
        details_widget.addTab(attributes_tab, "Attributes")
        
        # References tab
        references_tab = QWidget()
        references_layout = QVBoxLayout(references_tab)
        
        self.references_tree = QTreeWidget()
        self.references_tree.setHeaderLabels(["Reference", "Target"])
        self.references_tree.setColumnWidth(0, 200)
        references_layout.addWidget(self.references_tree)
        
        details_widget.addTab(references_tab, "References")
        
        # Add widgets to splitter
        splitter.addWidget(browser_widget)
        splitter.addWidget(details_widget)
        
        # Set initial sizes (60/40 split)
        splitter.setSizes([600, 400])
        
        browser_layout.addWidget(splitter)
        
        # Add browser tab to main tab widget
        self.tab_widget.addTab(browser_tab, "Browser")
    
    def init_subscriptions_tab(self):
        """Initialize the subscriptions tab"""
        subscriptions_tab = QWidget()
        subscriptions_layout = QVBoxLayout(subscriptions_tab)
        
        # Subscriptions tree
        self.subscriptions_tree = QTreeWidget()
        self.subscriptions_tree.setHeaderLabels(["Name", "Node ID", "Value", "Timestamp"])
        self.subscriptions_tree.setColumnWidth(0, 250)
        self.subscriptions_tree.setColumnWidth(1, 250)
        self.subscriptions_tree.setColumnWidth(2, 300)
        subscriptions_layout.addWidget(self.subscriptions_tree)
        
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
        
        subscriptions_layout.addLayout(sub_buttons_layout)
        
        # Add subscriptions tab to main tab widget
        self.tab_widget.addTab(subscriptions_tab, "Subscriptions")
    
    def init_registered_nodes_tab(self):
        """Initialize the registered nodes tab"""
        registered_tab = QWidget()
        registered_layout = QVBoxLayout(registered_tab)
        
        # Splitter for node list and control panel
        splitter = QSplitter(Qt.Vertical)
        
        # Top widget - Registered nodes list
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        
        # Registered nodes tree
        self.registered_nodes_tree = QTreeWidget()
        self.registered_nodes_tree.setHeaderLabels(["Name", "Node ID", "Data Type", "Value", "Node Type", "Interval"])
        self.registered_nodes_tree.setColumnWidth(0, 200)
        self.registered_nodes_tree.setColumnWidth(1, 250)
        self.registered_nodes_tree.setColumnWidth(2, 100)
        self.registered_nodes_tree.setColumnWidth(3, 200)
        self.registered_nodes_tree.itemClicked.connect(self.on_registered_node_clicked)
        top_layout.addWidget(self.registered_nodes_tree)
        
        # Registered nodes buttons
        reg_buttons_layout = QHBoxLayout()
        
        self.unregister_btn = QPushButton("Unregister Selected")
        self.unregister_btn.clicked.connect(self.unregister_selected)
        self.unregister_btn.setEnabled(False)
        
        self.unregister_all_btn = QPushButton("Unregister All")
        self.unregister_all_btn.clicked.connect(self.unregister_all)
        self.unregister_all_btn.setEnabled(False)
        
        reg_buttons_layout.addWidget(self.unregister_btn)
        reg_buttons_layout.addWidget(self.unregister_all_btn)
        reg_buttons_layout.addStretch(1)
        
        top_layout.addLayout(reg_buttons_layout)
        
        # Bottom widget - Control panel
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        
        # Node info group
        node_info_group = QGroupBox("Node Information")
        node_info_layout = QFormLayout()
        
        self.reg_node_name_label = QLabel("None selected")
        node_info_layout.addRow("Name:", self.reg_node_name_label)
        
        self.reg_node_id_label = QLabel("")
        node_info_layout.addRow("Node ID:", self.reg_node_id_label)
        
        self.reg_node_type_label = QLabel("")
        node_info_layout.addRow("Data Type:", self.reg_node_type_label)
        
        node_info_group.setLayout(node_info_layout)
        bottom_layout.addWidget(node_info_group)
        
        # Control group
        control_group = QGroupBox("Node Control")
        control_layout = QFormLayout()
        
        # Node type selection
        self.node_type_combo = QComboBox()
        self.node_type_combo.addItems([t.value for t in NodeType])
        self.node_type_combo.currentIndexChanged.connect(self.on_node_type_changed)
        self.node_type_combo.setEnabled(False)
        control_layout.addRow("Node Type:", self.node_type_combo)
        
        # Toggle interval
        self.toggle_interval_input = QLineEdit()
        self.toggle_interval_input.setValidator(QDoubleValidator(0.1, 3600.0, 1))
        self.toggle_interval_input.setEnabled(False)
        control_layout.addRow("Toggle Interval (s):", self.toggle_interval_input)
        
        # Save value checkbox
        self.save_value_cb = QCheckBox("Save value for reconnection")
        self.save_value_cb.setChecked(True)
        self.save_value_cb.setEnabled(False)
        control_layout.addRow("", self.save_value_cb)
        
        # Apply button
        self.apply_config_btn = QPushButton("Apply Configuration")
        self.apply_config_btn.clicked.connect(self.apply_node_configuration)
        self.apply_config_btn.setEnabled(False)
        control_layout.addRow("", self.apply_config_btn)
        
        control_group.setLayout(control_layout)
        bottom_layout.addWidget(control_group)
        
        # Write group
        write_group = QGroupBox("Write Value")
        write_layout = QVBoxLayout()
        
        # Boolean value
        bool_layout = QHBoxLayout()
        bool_layout.addWidget(QLabel("Boolean:"))
        self.bool_value_combo = QComboBox()
        self.bool_value_combo.addItems(["True", "False"])
        bool_layout.addWidget(self.bool_value_combo)
        self.write_bool_btn = QPushButton("Write")
        self.write_bool_btn.clicked.connect(lambda: self.write_value_to_selected(self.bool_value_combo.currentText() == "True"))
        bool_layout.addWidget(self.write_bool_btn)
        write_layout.addLayout(bool_layout)
        
        # Toggle button (for boolean)
        self.toggle_btn = QPushButton("Toggle Boolean Value")
        self.toggle_btn.clicked.connect(self.toggle_selected_value)
        write_layout.addWidget(self.toggle_btn)
        
        # Numeric value
        num_layout = QHBoxLayout()
        num_layout.addWidget(QLabel("Number:"))
        self.num_value_input = QLineEdit()
        self.num_value_input.setValidator(QDoubleValidator())
        num_layout.addWidget(self.num_value_input)
        self.write_num_btn = QPushButton("Write")
        self.write_num_btn.clicked.connect(lambda: self.write_value_to_selected(float(self.num_value_input.text())))
        num_layout.addWidget(self.write_num_btn)
        write_layout.addLayout(num_layout)
        
        # String value
        str_layout = QHBoxLayout()
        str_layout.addWidget(QLabel("String:"))
        self.str_value_input = QLineEdit()
        str_layout.addWidget(self.str_value_input)
        self.write_str_btn = QPushButton("Write")
        self.write_str_btn.clicked.connect(lambda: self.write_value_to_selected(self.str_value_input.text()))
        str_layout.addWidget(self.write_str_btn)
        write_layout.addLayout(str_layout)
        
        write_group.setLayout(write_layout)
        bottom_layout.addWidget(write_group)
        
        # Add stretch
        bottom_layout.addStretch(1)
        
        # Add widgets to splitter
        splitter.addWidget(top_widget)
        splitter.addWidget(bottom_widget)
        
        # Set initial sizes (60/40 split)
        splitter.setSizes([600, 400])
        
        registered_layout.addWidget(splitter)
        
        # Add registered nodes tab to main tab widget
        self.tab_widget.addTab(registered_tab, "Registered Nodes")
    
    def init_output_tab(self):
        """Initialize the output tab"""
        output_tab = QWidget()
        output_layout = QVBoxLayout(output_tab)
        
        # XML preview
        self.xml_preview = QTextEdit()
        self.xml_preview.setReadOnly(True)
        output_layout.addWidget(self.xml_preview)
        
        # Output buttons
        output_buttons_layout = QHBoxLayout()
        
        self.refresh_xml_btn = QPushButton("Refresh XML")
        self.refresh_xml_btn.clicked.connect(self.refresh_xml)
        
        output_buttons_layout.addWidget(self.refresh_xml_btn)
        output_buttons_layout.addStretch(1)
        
        output_layout.addLayout(output_buttons_layout)
        
        # Add output tab to main tab widget
        self.tab_widget.addTab(output_tab, "Output")
    
    def init_log_tab(self):
        """Initialize the log tab"""
        log_tab = LogViewer()
        
        # Add log tab to main tab widget
        self.tab_widget.addTab(log_tab, "Log")
    
    def connect_to_server(self):
        """Connect to OPC UA server"""
        # Update config from UI
        self.update_config_from_ui()
        
        # Validate required fields
        if not self.config.endpoint:
            QMessageBox.warning(self, "Connection Error", "Endpoint URL is required")
            return
        
        # Validate security settings
        if self.config.security_policy != SecurityPolicy.NO_SECURITY:
            if self.config.generate_certificates:
                # Generate certificates if needed
                if not self.config.certificate_path or not self.config.private_key_path:
                    success = self.config.generate_self_signed_certificate()
                    if not success:
                        QMessageBox.critical(self, "Certificate Error", "Failed to generate certificates")
                        return
                    
                    # Update UI
                    self.cert_path_input.setText(self.config.certificate_path)
                    self.key_path_input.setText(self.config.private_key_path)
            elif not self.config.certificate_path or not self.config.private_key_path:
                QMessageBox.warning(self, "Security Error", 
                                  "Certificate and private key are required for the selected security policy")
                return
        
        # Update UI
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)
        self.status_message.setText("Connecting...")
        
        # Connect to server (async operation handled by signal)
        if hasattr(self.client, 'loop') and self.client.loop:
            asyncio.run_coroutine_threadsafe(self.client.connect(), self.client.loop)
    
    def check_connection_status(self):
        """Periodically check and update actual connection status"""
        if hasattr(self.client, 'connected'):
            is_connected = self.client.connected
            current_color = self.connection_indicator.styleSheet()
            
            # If indicator shows disconnected (red) but we're actually connected
            if "color: red" in current_color and is_connected:
                logger.info("Fixing incorrect disconnected status indicator")
                self.connection_indicator.setStyleSheet("color: green; font-size: 16px;")
                self.connect_btn.setEnabled(False)
                self.disconnect_btn.setEnabled(True)
                self.refresh_btn.setEnabled(True)
                self.status_message.setText("Connected to server")
            
            # If indicator shows connected (green) but we're actually disconnected
            elif "color: green" in current_color and not is_connected:
                logger.info("Fixing incorrect connected status indicator")
                self.connection_indicator.setStyleSheet("color: red; font-size: 16px;")
                self.connect_btn.setEnabled(True)
                self.disconnect_btn.setEnabled(False)
                self.refresh_btn.setEnabled(False)
                self.status_message.setText("Disconnected from server")

    def disconnect_from_server(self):
        """Disconnect from OPC UA server"""
        # Confirm disconnection
        dialog = ConfirmationDialog(
            "Confirm Disconnect", 
            "Are you sure you want to disconnect from the server?",
            self
        )
        
        if dialog.exec_() != QDialog.Accepted:
            return
        
        # Update UI
        self.status_message.setText("Disconnecting...")
        
        # Disconnect from server (async operation handled by signal)
        if hasattr(self.client, 'loop') and self.client.loop:
            asyncio.run_coroutine_threadsafe(self.client.disconnect(), self.client.loop)
    
    def update_config_from_ui(self):
        """Update configuration from UI values"""
        # Connection settings
        self.config.endpoint = self.endpoint_input.text()
        self.config.username = self.username_input.text()
        if self.password_input.text():
            self.config.save_password(self.password_input.text())
        self.config.auto_connect = self.auto_connect_cb.isChecked()
        
        # Security settings
        policy_text = self.security_policy_combo.currentText()
        for policy in SecurityPolicy:
            if policy.value == policy_text:
                self.config.security_policy = policy
                break
        
        self.config.certificate_path = self.cert_path_input.text()
        self.config.private_key_path = self.key_path_input.text()
        self.config.generate_certificates = self.generate_cert_cb.isChecked()
        
        # Certificate info
        self.config.certificate_info["common_name"] = self.common_name_input.text()
        self.config.certificate_info["organization"] = self.organization_input.text()
        self.config.certificate_info["organization_unit"] = self.org_unit_input.text()
        self.config.certificate_info["locality"] = self.locality_input.text()
        self.config.certificate_info["state"] = self.state_input.text()
        self.config.certificate_info["country"] = self.country_input.text()
        self.config.certificate_info["days_valid"] = int(self.validity_input.text() or "365")
        
        # Reconnection settings
        self.config.auto_reconnect = self.auto_reconnect_cb.isChecked()
        try:
            self.config.reconnect_delay = int(self.reconnect_delay_input.text())
        except (ValueError, TypeError):
            self.config.reconnect_delay = 5
        
        try:
            self.config.max_reconnect_delay = int(self.max_reconnect_delay_input.text())
        except (ValueError, TypeError):
            self.config.max_reconnect_delay = 60
        
        try:
            self.config.max_reconnect_attempts = int
            self.config.max_reconnect_attempts = int(self.max_reconnect_attempts_input.text())
        except (ValueError, TypeError):
            self.config.max_reconnect_attempts = 0
        
        # Output settings
        self.config.xml_output_path = self.xml_path_input.text()
    
    def update_ui_from_config(self):
        """Update UI elements from configuration"""
        # Connection settings
        self.endpoint_input.setText(self.config.endpoint)
        self.username_input.setText(self.config.username)
        self.auto_connect_cb.setChecked(self.config.auto_connect)
        
        # Security settings
        index = self.security_policy_combo.findText(self.config.security_policy.value)
        if index >= 0:
            self.security_policy_combo.setCurrentIndex(index)
        
        self.cert_path_input.setText(self.config.certificate_path)
        self.key_path_input.setText(self.config.private_key_path)
        self.generate_cert_cb.setChecked(self.config.generate_certificates)
        self.on_generate_cert_changed(self.generate_cert_cb.checkState())
        
        # Certificate info
        self.common_name_input.setText(self.config.certificate_info.get("common_name", "OPC UA Client"))
        self.organization_input.setText(self.config.certificate_info.get("organization", "Organization"))
        self.org_unit_input.setText(self.config.certificate_info.get("organization_unit", "Department"))
        self.locality_input.setText(self.config.certificate_info.get("locality", "City"))
        self.state_input.setText(self.config.certificate_info.get("state", "State"))
        self.country_input.setText(self.config.certificate_info.get("country", "US"))
        self.validity_input.setText(str(self.config.certificate_info.get("days_valid", 365)))
        
        # Reconnection settings
        self.auto_reconnect_cb.setChecked(self.config.auto_reconnect)
        self.reconnect_delay_input.setText(str(self.config.reconnect_delay))
        self.max_reconnect_delay_input.setText(str(self.config.max_reconnect_delay))
        self.max_reconnect_attempts_input.setText(str(self.config.max_reconnect_attempts))
        
        # Output settings
        self.xml_path_input.setText(self.config.xml_output_path)
    
    def save_config(self):
        """Save configuration to file"""
        # Update config from UI
        self.update_config_from_ui()
        
        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", get_config_dir(), "JSON Files (*.json)"
        )
        
        if not file_path:
            return
        
        # Ensure .json extension
        if not file_path.endswith('.json'):
            file_path += '.json'
        
        # Save config
        try:
            self.config.save(file_path)
            QMessageBox.information(self, "Configuration Saved", f"Configuration saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Error saving configuration: {str(e)}")
    
    def load_config(self):
        """Load configuration from file"""
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", get_config_dir(), "JSON Files (*.json)"
        )
        
        if not file_path:
            return
        
        # Load config
        try:
            self.config = Config.load(file_path)
            
            # Update UI
            self.update_ui_from_config()
            
            # Update client config
            self.client.config = self.config
            
            QMessageBox.information(self, "Configuration Loaded", f"Configuration loaded from {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Error loading configuration: {str(e)}")
    
    def browse_certificate(self):
        """Browse for certificate file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Certificate", get_certificates_dir(), 
            "Certificate Files (*.pem *.der *.crt);;All Files (*)"
        )
        
        if file_path:
            self.cert_path_input.setText(file_path)
    
    def browse_private_key(self):
        """Browse for private key file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Private Key", get_certificates_dir(), 
            "Key Files (*.pem *.key);;All Files (*)"
        )
        
        if file_path:
            self.key_path_input.setText(file_path)
    
    def browse_xml_output(self):
        """Browse for XML output file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Select XML Output", get_output_dir(), 
            "XML Files (*.xml);;All Files (*)"
        )
        
        if file_path:
            if not file_path.endswith('.xml'):
                file_path += '.xml'
            self.xml_path_input.setText(file_path)
    
    def on_generate_cert_changed(self, state):
        """Handle certificate generation checkbox state change"""
        enabled = not bool(state)
        
        # Enable/disable certificate and key path inputs
        self.cert_path_input.setEnabled(enabled)
        self.key_path_input.setEnabled(enabled)
        self.cert_path_input.parentWidget().findChild(QPushButton).setEnabled(enabled)
        self.key_path_input.parentWidget().findChild(QPushButton).setEnabled(enabled)
    
    def generate_certificate(self):
        """Generate self-signed certificate"""
        # Update certificate info from UI
        self.config.certificate_info["common_name"] = self.common_name_input.text()
        self.config.certificate_info["organization"] = self.organization_input.text()
        self.config.certificate_info["organization_unit"] = self.org_unit_input.text()
        self.config.certificate_info["locality"] = self.locality_input.text()
        self.config.certificate_info["state"] = self.state_input.text()
        self.config.certificate_info["country"] = self.country_input.text()
        
        try:
            self.config.certificate_info["days_valid"] = int(self.validity_input.text())
        except (ValueError, TypeError):
            self.config.certificate_info["days_valid"] = 365
        
        # Generate certificate
        success = self.config.generate_self_signed_certificate()
        
        if success:
            # Update UI
            self.cert_path_input.setText(self.config.certificate_path)
            self.key_path_input.setText(self.config.private_key_path)
            
            QMessageBox.information(self, "Certificate Generated", 
                                  f"Certificate and private key generated successfully.\n\n"
                                  f"Certificate: {self.config.certificate_path}\n"
                                  f"Private Key: {self.config.private_key_path}")
        else:
            QMessageBox.critical(self, "Certificate Error", 
                               "Failed to generate certificate. Check logs for details.")
    
    def on_connection_status_changed(self, status, message):
        """Handle connection status change with improved reliability"""
        # Update status bar
        self.status_message.setText(message)
        
        # Update status indicator based on actual client connection state
        is_actually_connected = self.client.connected if hasattr(self.client, 'connected') else False
        
        if status == ConnectionStatus.CONNECTED or is_actually_connected:
            self.connection_indicator.setStyleSheet("color: green; font-size: 16px;")
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
            self.refresh_btn.setEnabled(True)
        elif status == ConnectionStatus.CONNECTING or status == ConnectionStatus.RECONNECTING:
            self.connection_indicator.setStyleSheet("color: orange; font-size: 16px;")
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
            self.refresh_btn.setEnabled(False)
        elif status == ConnectionStatus.DISCONNECTED:
            if not is_actually_connected:  # Only change to disconnected if truly disconnected
                self.connection_indicator.setStyleSheet("color: red; font-size: 16px;")
                self.connect_btn.setEnabled(True)
                self.disconnect_btn.setEnabled(False)
                self.refresh_btn.setEnabled(False)
                self.subscribe_btn.setEnabled(False)
                self.register_btn.setEnabled(False)
        elif status == ConnectionStatus.ERROR:
            if not is_actually_connected:
                self.connection_indicator.setStyleSheet("color: red; font-size: 16px;")
            # Don't change button states for errors, they depend on current connection state
    
        # Log status change
        logger.info(f"Connection status changed to {status.name}: {message} (Actually connected: {is_actually_connected})")
    
    def on_reconnection_status(self, attempts, max_attempts, message):
        """Handle reconnection status updates"""
        if max_attempts > 0:
            status_text = f"Reconnection: {attempts}/{max_attempts} - {message}"
        else:
            status_text = f"Reconnection: attempt {attempts} - {message}"
        
        # Update status bar
        self.status_message.setText(status_text)
        
        # Make indicator blink by alternating colors
        if attempts % 2 == 0:
            self.connection_indicator.setStyleSheet("color: yellow; font-size: 16px;")
        else:
            self.connection_indicator.setStyleSheet("color: orange; font-size: 16px;")
    
    def refresh_node_tree(self):
        """Refresh node tree"""
        if not hasattr(self.client, 'loop') or not self.client.loop:
            return
        
        # Clear tree
        self.node_tree.clear()
        
        # Add root node
        root = QTreeWidgetItem(self.node_tree)
        root.setText(0, "Root")
        root.setText(1, "i=84")  # Root node ID is i=84
        root.setText(2, "Object")
        root.setData(0, Qt.UserRole, "i=84")
        
        # Add loading indicator
        loading = QTreeWidgetItem(root)
        loading.setText(0, "Loading...")
        
        # Expand root to trigger loading
        root.setExpanded(True)
    
    def on_node_expanded(self, item):
        """Handle node tree item expansion"""
        # Get node ID
        node_id = item.data(0, Qt.UserRole)
        if not node_id:
            return
        
        # Clear existing children
        while item.childCount() > 0:
            item.removeChild(item.child(0))
        
        # Add loading indicator
        loading = QTreeWidgetItem(item)
        loading.setText(0, "Loading...")
        
        # Browse nodes
        if hasattr(self.client, 'loop') and self.client.loop:
            asyncio.run_coroutine_threadsafe(
                self.client.browse_nodes(node_id),
                self.client.loop
            )
    
    def on_nodes_browsed(self, nodes, parent_id):
        """Handle browsed nodes"""
        # Find parent item
        parent_item = None
        
        if parent_id:
            # Find by node ID in data
            iterator = QTreeWidgetItemIterator(self.node_tree)
            while iterator.value():
                if iterator.value().data(0, Qt.UserRole) == parent_id:
                    parent_item = iterator.value()
                    break
                iterator += 1
        
        if not parent_item:
            parent_item = self.node_tree.topLevelItem(0)  # Default to first root item
        
        if not parent_item:
            logger.warning(f"Parent item for {parent_id} not found")
            return
        
        # Remove loading indicator
        for i in range(parent_item.childCount()):
            if parent_item.child(i).text(0) == "Loading...":
                parent_item.removeChild(parent_item.child(i))
                break
        
        # Add nodes
        for node in nodes:
            item = QTreeWidgetItem(parent_item)
            item.setText(0, node.get('display_name', 'Unknown'))
            item.setText(1, node.get('id', ''))
            item.setText(2, node.get('node_class', ''))
            item.setData(0, Qt.UserRole, node.get('id', ''))
            
            # Set icon based on node class
            node_class = node.get('node_class', '')
            
            # If has children, add placeholder to enable expansion
            if node.get('has_children', False):
                placeholder = QTreeWidgetItem(item)
                placeholder.setText(0, "Click to expand...")
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
    
    def on_node_clicked(self, item, column):
        """Handle node tree item click"""
        # Get node ID
        node_id = item.data(0, Qt.UserRole)
        if not node_id:
            return
        
        # Get node details
        if hasattr(self.client, 'loop') and self.client.loop:
            asyncio.run_coroutine_threadsafe(
                self.client.get_node_details(node_id),
                self.client.loop
            )
        
        # Enable buttons based on node class
        node_class = item.text(2)
        self.subscribe_btn.setEnabled(node_class == "Variable")
        self.register_btn.setEnabled(node_class == "Variable")
    
    def on_node_details_available(self, details):
        """Handle node details with improved hierarchical display"""
        # Clear existing details
        self.attributes_tree.clear()
        self.references_tree.clear()
        
        # Update attributes with hierarchical display
        if "attributes" in details:
            # Create root NodeId item first
            if "NodeId" in details["attributes"]:
                node_id_item = QTreeWidgetItem(self.attributes_tree)
                node_id_item.setText(0, "NodeId")
                node_id_item.setText(1, details["attributes"]["NodeId"])
                node_id_item.setExpanded(True)
                
                # Add namespace, identifier type, and identifier as children of NodeId
                if "NamespaceIndex" in details["attributes"]:
                    ns_item = QTreeWidgetItem(node_id_item)
                    ns_item.setText(0, "NamespaceIndex")
                    ns_item.setText(1, str(details["attributes"]["NamespaceIndex"]))
                
                if "IdentifierType" in details["attributes"]:
                    id_type_item = QTreeWidgetItem(node_id_item)
                    id_type_item.setText(0, "IdentifierType")
                    id_type_item.setText(1, details["attributes"]["IdentifierType"])
                
                if "Identifier" in details["attributes"]:
                    id_item = QTreeWidgetItem(node_id_item)
                    id_item.setText(0, "Identifier")
                    id_item.setText(1, str(details["attributes"]["Identifier"]))
            
            # Add NodeClass
            if "NodeClass" in details["attributes"]:
                node_class_item = QTreeWidgetItem(self.attributes_tree)
                node_class_item.setText(0, "NodeClass")
                node_class_item.setText(1, details["attributes"]["NodeClass"])
            
            # Add BrowseName and DisplayName
            if "BrowseName" in details["attributes"]:
                browse_name_item = QTreeWidgetItem(self.attributes_tree)
                browse_name_item.setText(0, "BrowseName")
                browse_name_item.setText(1, details["attributes"]["BrowseName"])
            
            if "DisplayName" in details["attributes"]:
                display_name_item = QTreeWidgetItem(self.attributes_tree)
                display_name_item.setText(0, "DisplayName")
                display_name_item.setText(1, details["attributes"]["DisplayName"])
            
            # Add Description
            if "Description" in details["attributes"]:
                desc_item = QTreeWidgetItem(self.attributes_tree)
                desc_item.setText(0, "Description")
                desc_item.setText(1, details["attributes"]["Description"])
            
            # For variables, add Value and DataType as expandable items
            if "Value" in details["attributes"]:
                value_item = QTreeWidgetItem(self.attributes_tree)
                value_item.setText(0, "Value")
                value_item.setExpanded(True)
                
                # Add value
                value_val_item = QTreeWidgetItem(value_item)
                value_val_item.setText(0, "Value")
                value_val_item.setText(1, str(details["attributes"]["Value"]))
                
                # Add timestamps if available
                if "SourceTimestamp" in details["attributes"]:
                    src_ts_item = QTreeWidgetItem(value_item)
                    src_ts_item.setText(0, "SourceTimestamp")
                    src_ts_item.setText(1, details["attributes"]["SourceTimestamp"])
                
                if "ServerTimestamp" in details["attributes"]:
                    srv_ts_item = QTreeWidgetItem(value_item)
                    srv_ts_item.setText(0, "ServerTimestamp")
                    srv_ts_item.setText(1, details["attributes"]["ServerTimestamp"])
                
                # Add StatusCode if available
                if "StatusCode" in details["attributes"]:
                    status_item = QTreeWidgetItem(value_item)
                    status_item.setText(0, "StatusCode")
                    status_item.setText(1, details["attributes"]["StatusCode"])
            
            # Add DataType section
            if "DataType" in details["attributes"]:
                data_type_item = QTreeWidgetItem(self.attributes_tree)
                data_type_item.setText(0, "DataType")
                data_type_item.setExpanded(True)
                
                # Add basic DataType
                dt_val_item = QTreeWidgetItem(data_type_item)
                dt_val_item.setText(0, "Identifier")
                dt_val_item.setText(1, details["attributes"]["DataType"])
                
                # Add ValueRank if available
                if "ValueRank" in details["attributes"]:
                    vr_item = QTreeWidgetItem(data_type_item)
                    vr_item.setText(0, "ValueRank")
                    vr_item.setText(1, details["attributes"]["ValueRank"])
                
                # Add ArrayDimensions if available
                if "ArrayDimensions" in details["attributes"]:
                    ad_item = QTreeWidgetItem(data_type_item)
                    ad_item.setText(0, "ArrayDimensions")
                    ad_item.setText(1, str(details["attributes"]["ArrayDimensions"]))
            
            # Add access level information
            if "AccessLevel" in details["attributes"]:
                access_item = QTreeWidgetItem(self.attributes_tree)
                access_item.setText(0, "AccessLevel")
                access_item.setText(1, details["attributes"]["AccessLevel"])
            
            # Add user access level if available
            if "UserAccessLevel" in details["attributes"]:
                user_access_item = QTreeWidgetItem(self.attributes_tree)
                user_access_item.setText(0, "UserAccessLevel")
                user_access_item.setText(1, details["attributes"]["UserAccessLevel"])
            
            # Add WriteMask and UserWriteMask
            if "WriteMask" in details["attributes"]:
                write_mask_item = QTreeWidgetItem(self.attributes_tree)
                write_mask_item.setText(0, "WriteMask")
                write_mask_item.setText(1, str(details["attributes"]["WriteMask"]))
            
            if "UserWriteMask" in details["attributes"]:
                user_write_mask_item = QTreeWidgetItem(self.attributes_tree)
                user_write_mask_item.setText(0, "UserWriteMask")
                user_write_mask_item.setText(1, str(details["attributes"]["UserWriteMask"]))
            
            # Add Role Permissions
            if "RolePermissions" in details["attributes"]:
                role_perms_item = QTreeWidgetItem(self.attributes_tree)
                role_perms_item.setText(0, "RolePermissions")
                role_perms_item.setText(1, details["attributes"]["RolePermissions"])
            
            # Add User Role Permissions
            if "UserRolePermissions" in details["attributes"]:
                user_role_perms = details["attributes"]["UserRolePermissions"]
                user_role_perms_item = QTreeWidgetItem(self.attributes_tree)
                user_role_perms_item.setText(0, "UserRolePermissions")
                
                if isinstance(user_role_perms, list):
                    user_role_perms_item.setText(1, f"RolePermissionType Array[{len(user_role_perms)}]")
                    
                    # Add array items
                    for i, perm in enumerate(user_role_perms):
                        array_item = QTreeWidgetItem(user_role_perms_item)
                        array_item.setText(0, f"[{i}]")
                        
                        # Add role permission details
                        if isinstance(perm, dict):
                            for key, value in perm.items():
                                perm_item = QTreeWidgetItem(array_item)
                                perm_item.setText(0, key)
                                perm_item.setText(1, str(value))
                else:
                    user_role_perms_item.setText(1, str(user_role_perms))
            
            # Add Access Restrictions
            if "AccessRestrictions" in details["attributes"]:
                access_rest_item = QTreeWidgetItem(self.attributes_tree)
                access_rest_item.setText(0, "AccessRestrictions")
                access_rest_item.setText(1, details["attributes"]["AccessRestrictions"])
            
            # Add remaining attributes that weren't specifically handled
            for name, value in details["attributes"].items():
                if name not in ["NodeId", "NamespaceIndex", "IdentifierType", "Identifier", 
                            "NodeClass", "BrowseName", "DisplayName", "Description",
                            "Value", "SourceTimestamp", "ServerTimestamp", "StatusCode",
                            "DataType", "ValueRank", "ArrayDimensions", 
                            "AccessLevel", "UserAccessLevel", "WriteMask", "UserWriteMask",
                            "RolePermissions", "UserRolePermissions", "AccessRestrictions"]:
                    
                    item = QTreeWidgetItem(self.attributes_tree)
                    item.setText(0, name)
                    
                    # Format complex values
                    if isinstance(value, (list, dict)):
                        try:
                            import json
                            item.setText(1, json.dumps(value, indent=2))
                        except:
                            item.setText(1, str(value))
                    else:
                        item.setText(1, str(value))
        
        # Update references
        if "references" in details:
            for ref in details["references"]:
                item = QTreeWidgetItem(self.references_tree)
                item.setText(0, ref.get("Display", ""))
                item.setText(1, ref.get("NodeId", ""))
    
    def subscribe_to_selected(self):
        """Subscribe to selected node"""
        selected_items = self.node_tree.selectedItems()
        if not selected_items:
            return
        
        for item in selected_items:
            node_id = item.data(0, Qt.UserRole)
            display_name = item.text(0)
            
            if node_id and display_name:
                # Subscribe to node
                if hasattr(self.client, 'loop') and self.client.loop:
                    asyncio.run_coroutine_threadsafe(
                        self.client.subscribe_to_node(node_id, display_name),
                        self.client.loop
                    )
    
    def on_node_subscribed(self, node_id, display_name, initial_value):
        """Handle subscribed node"""
        # Check if node already exists in tree
        for i in range(self.subscriptions_tree.topLevelItemCount()):
            item = self.subscriptions_tree.topLevelItem(i)
            if item.text(1) == node_id:
                # Update existing item
                item.setText(0, display_name)
                item.setText(2, str(initial_value))
                item.setText(3, datetime.now().isoformat())
                return
        
        # Add new item
        item = QTreeWidgetItem(self.subscriptions_tree)
        item.setText(0, display_name)
        item.setText(1, node_id)
        item.setText(2, str(initial_value))
        item.setText(3, datetime.now().isoformat())
        
        # Enable buttons
        self.unsubscribe_btn.setEnabled(True)
        self.unsubscribe_all_btn.setEnabled(True)
    
    def on_subscription_data_changed(self, node_id, value, timestamp):
        """Handle subscription data change with improved GUI updates"""
        # Update subscriptions tree
        for i in range(self.subscriptions_tree.topLevelItemCount()):
            item = self.subscriptions_tree.topLevelItem(i)
            if item.text(1) == node_id:
                item.setText(2, str(value))
                item.setText(3, timestamp)
                break
        
        # Update registered nodes tree
        updated = False
        for i in range(self.registered_nodes_tree.topLevelItemCount()):
            item = self.registered_nodes_tree.topLevelItem(i)
            if item.text(1) == node_id:
                item.setText(3, str(value))
                updated = True
                break
        
        # Update node manager
        if updated and hasattr(self, 'node_manager'):
            self.node_manager.update_node_value(node_id, value)
        
        # Update input fields if this node is currently selected
        selected_items = self.registered_nodes_tree.selectedItems()
        if selected_items and selected_items[0].text(1) == node_id:
            data_type = selected_items[0].text(2)
            
            # Update appropriate input field based on data type
            if data_type == "Boolean":
                if isinstance(value, bool) or str(value).lower() in ('true', 'false', '0', '1'):
                    bool_value = isinstance(value, bool) and value or str(value).lower() in ('true', '1')
                    self.bool_value_combo.setCurrentIndex(0 if bool_value else 1)
            elif data_type in ("Int32", "UInt32", "Int16", "UInt16", "Int64", "UInt64", "Float", "Double"):
                self.num_value_input.setText(str(value))
            elif data_type == "String":
                self.str_value_input.setText(str(value))
    
    def unsubscribe_selected(self):
        """Unsubscribe from selected nodes"""
        selected_items = self.subscriptions_tree.selectedItems()
        if not selected_items:
            return
        
        # Confirm unsubscribe
        dialog = ConfirmationDialog(
            "Confirm Unsubscribe", 
            f"Are you sure you want to unsubscribe from {len(selected_items)} node(s)?",
            self
        )
        
        if dialog.exec_() != QDialog.Accepted:
            return
        
        for item in selected_items:
            node_id = item.text(1)
            
            # Unsubscribe from node
            if hasattr(self.client, 'loop') and self.client.loop:
                asyncio.run_coroutine_threadsafe(
                    self.client.unsubscribe_from_node(node_id),
                    self.client.loop
                )
    
    def on_node_unsubscribed(self, node_id):
        """Handle unsubscribed node"""
        # Remove from subscriptions tree
        for i in range(self.subscriptions_tree.topLevelItemCount()):
            item = self.subscriptions_tree.topLevelItem(i)
            if item.text(1) == node_id:
                self.subscriptions_tree.takeTopLevelItem(i)
                break
        
        # Disable buttons if no subscriptions left
        if self.subscriptions_tree.topLevelItemCount() == 0:
            self.unsubscribe_btn.setEnabled(False)
            self.unsubscribe_all_btn.setEnabled(False)
    
    def unsubscribe_all(self):
        """Unsubscribe from all nodes"""
        if self.subscriptions_tree.topLevelItemCount() == 0:
            return
        
        # Confirm unsubscribe
        dialog = ConfirmationDialog(
            "Confirm Unsubscribe All", 
            "Are you sure you want to unsubscribe from all nodes?",
            self
        )
        
        if dialog.exec_() != QDialog.Accepted:
            return
        
        # Unsubscribe from all nodes
        if hasattr(self.client, 'loop') and self.client.loop:
            asyncio.run_coroutine_threadsafe(
                self.client.unsubscribe_all(),
                self.client.loop
            )
    
    def register_selected(self):
        """Register selected node for writing"""
        selected_items = self.node_tree.selectedItems()
        if not selected_items:
            return
        
        for item in selected_items:
            node_id = item.data(0, Qt.UserRole)
            display_name = item.text(0)
            
            if node_id and display_name:
                # Default node info
                node_info = {
                    "display_name": display_name,
                    "node_type": NodeType.STANDARD.value,
                    "toggle_interval": 1.0
                }
                
                # Register node
                if hasattr(self.client, 'loop') and self.client.loop:
                    asyncio.run_coroutine_threadsafe(
                        self.client.register_node(node_id, node_info),
                        self.client.loop
                    )
    
    def on_node_registered(self, node_id, display_name, data_type, initial_value):
        """Handle registered node"""
        # Get node type and toggle interval from config if available
        node_type = NodeType.STANDARD.value
        toggle_interval = 1.0
        
        if node_id in self.config.registered_nodes:
            node_type = self.config.registered_nodes[node_id].get("node_type", NodeType.STANDARD.value)
            toggle_interval = self.config.registered_nodes[node_id].get("toggle_interval", 1.0)
        
        # Check if node already exists in tree
        for i in range(self.registered_nodes_tree.topLevelItemCount()):
            item = self.registered_nodes_tree.topLevelItem(i)
            if item.text(1) == node_id:
                # Update existing item
                item.setText(0, display_name)
                item.setText(2, data_type)
                item.setText(3, str(initial_value))
                item.setText(4, node_type)  # Use the retrieved node type
                item.setText(5, str(toggle_interval))  # Use the retrieved toggle interval
                return
        
        # Add new item
        item = QTreeWidgetItem(self.registered_nodes_tree)
        item.setText(0, display_name)
        item.setText(1, node_id)
        item.setText(2, data_type)
        item.setText(3, str(initial_value))
        item.setText(4, node_type)  # Use the retrieved node type
        item.setText(5, str(toggle_interval))  # Use the retrieved toggle interval
        
        # Register in node manager
        self.node_manager.register_node(node_id, {
            "display_name": display_name,
            "data_type": data_type,
            "node_type": node_type,  # Use the retrieved node type
            "toggle_interval": toggle_interval,  # Use the retrieved toggle interval
            "last_value": initial_value
        })
        
        # Enable buttons
        self.unregister_btn.setEnabled(True)
        self.unregister_all_btn.setEnabled(True)
    
    def on_registered_node_clicked(self, item, column):
        """Handle registered node click"""
        node_id = item.text(1)
        display_name = item.text(0)
        data_type = item.text(2)
        value = item.text(3)
        node_type = item.text(4)
        interval = item.text(5)
        
        # Update node info
        self.reg_node_name_label.setText(display_name)
        self.reg_node_id_label.setText(node_id)
        self.reg_node_type_label.setText(data_type)
        
        # Update node type combo
        self.node_type_combo.setEnabled(True)
        index = self.node_type_combo.findText(node_type)
        if index >= 0:
            self.node_type_combo.setCurrentIndex(index)
        
        # Update toggle interval
        self.toggle_interval_input.setText(interval)
        self.toggle_interval_input.setEnabled(node_type in (NodeType.LIVEBIT.value, NodeType.TOGGLE.value))
        
        # Enable apply button
        self.apply_config_btn.setEnabled(True)
        
        # Enable save value checkbox
        self.save_value_cb.setEnabled(True)
        
        # Update write controls based on data type
        if data_type == "Boolean":
            self.bool_value_combo.setEnabled(True)
            self.write_bool_btn.setEnabled(True)
            self.toggle_btn.setEnabled(True)
            
            # Set current value
            if value.lower() in ("true", "1"):
                self.bool_value_combo.setCurrentIndex(0)  # True
            else:
                self.bool_value_combo.setCurrentIndex(1)  # False
        else:
            self.bool_value_combo.setEnabled(False)
            self.write_bool_btn.setEnabled(False)
            self.toggle_btn.setEnabled(False)
        
        if data_type in ("Int32", "UInt32", "Int16", "UInt16", "Int64", "UInt64", "Float", "Double"):
            self.num_value_input.setEnabled(True)
            self.write_num_btn.setEnabled(True)
            
            # Set current value
            try:
                self.num_value_input.setText(value)
            except:
                self.num_value_input.setText("0")
        else:
            self.num_value_input.setEnabled(False)
            self.write_num_btn.setEnabled(False)
        
        if data_type == "String":
            self.str_value_input.setEnabled(True)
            self.write_str_btn.setEnabled(True)
            
            # Set current value
            self.str_value_input.setText(value)
        else:
            self.str_value_input.setEnabled(False)
            self.write_str_btn.setEnabled(False)
    
    def on_node_type_changed(self, index):
        """Handle node type change"""
        selected_items = self.registered_nodes_tree.selectedItems()
        if not selected_items:
            return
        
        node_id = selected_items[0].text(1)
        node_type = self.node_type_combo.currentText()
        
        # Update toggle interval visibility
        self.toggle_interval_input.setEnabled(
            node_type in (NodeType.LIVEBIT.value, NodeType.TOGGLE.value)
        )
    
    def apply_node_configuration(self):
        """Apply node configuration"""
        selected_items = self.registered_nodes_tree.selectedItems()
        if not selected_items:
            return
        
        item = selected_items[0]
        node_id = item.text(1)
        node_type = self.node_type_combo.currentText()
        
        try:
            toggle_interval = float(self.toggle_interval_input.text())
        except (ValueError, TypeError):
            toggle_interval = 1.0
            self.toggle_interval_input.setText("1.0")
        
        # Update node type in tree
        item.setText(4, node_type)
        item.setText(5, str(toggle_interval))
        
        # Update node manager
        for nt in NodeType:
            if nt.value == node_type:
                self.node_manager.set_node_type(node_id, nt, toggle_interval)
                break
        
        # Update config
        if node_id in self.config.registered_nodes:
            # Update node settings
            self.config.registered_nodes[node_id]["node_type"] = node_type
            self.config.registered_nodes[node_id]["toggle_interval"] = toggle_interval
            
            # Save config immediately to ensure changes persist
            self.config.save()
            logger.info(f"Saved configuration with node {node_id} set to type {node_type}")
        
        # Update client settings
        if hasattr(self.client, 'loop') and self.client.loop:
            # Update client's registered node settings
            async def update_node_settings():
                if node_id in self.client.registered_nodes:
                    self.client.registered_nodes[node_id]["node_type"] = node_type
                    self.client.registered_nodes[node_id]["toggle_interval"] = toggle_interval
                    
                    # Set up or remove LiveBit functionality as needed
                    data_type = self.client.registered_nodes[node_id].get("data_type", "")
                    if node_type == "LiveBit" and data_type == "Boolean":
                        # Add to LiveBit nodes
                        self.client.livebit_nodes[node_id] = toggle_interval
                        self.client.last_toggle_time[node_id] = time.time()
                        logger.info(f"Enabled LiveBit for node {node_id} with interval {toggle_interval}")
                    elif node_id in self.client.livebit_nodes:
                        # Remove from LiveBit nodes
                        del self.client.livebit_nodes[node_id]
                        if node_id in self.client.last_toggle_time:
                            del self.client.last_toggle_time[node_id]
                        logger.info(f"Disabled LiveBit for node {node_id}")
            
            asyncio.run_coroutine_threadsafe(update_node_settings(), self.client.loop)
        
        self.status_message.setText(f"Applied configuration for {node_id}")
    
    def write_node_value(self, node_id, value, save_value=True):
        """Write value to node (callback for node manager)"""
        if hasattr(self.client, 'loop') and self.client.loop:
            asyncio.run_coroutine_threadsafe(
                self.client.write_value(node_id, value, save_value),
                self.client.loop
            )
    
    def write_value_to_selected(self, value):
        """Write value to selected node"""
        selected_items = self.registered_nodes_tree.selectedItems()
        if not selected_items:
            return
        
        node_id = selected_items[0].text(1)
        save_value = self.save_value_cb.isChecked()
        
        # Write value using node manager
        self.node_manager.write_value(node_id, value, save_value)
    
    def toggle_selected_value(self):
        """Toggle boolean value of selected node"""
        selected_items = self.registered_nodes_tree.selectedItems()
        if not selected_items:
            return
        
        node_id = selected_items[0].text(1)
        data_type = selected_items[0].text(2)
        
        if data_type != "Boolean":
            QMessageBox.warning(self, "Toggle Error", "Only Boolean values can be toggled")
            return
        
        # Toggle value using node manager
        self.node_manager.toggle_value(node_id)
    
    def on_node_value_changed(self, node_id, value):
        """Handle node value changed from node manager"""
        # Update registered nodes tree
        for i in range(self.registered_nodes_tree.topLevelItemCount()):
            item = self.registered_nodes_tree.topLevelItem(i)
            if item.text(1) == node_id:
                item.setText(3, str(value))
                break
    
    def on_node_write_completed(self, node_id, success, message):
        """Handle node write completion"""
        if success:
            self.status_message.setText(f"Value written to {node_id}")
        else:
            self.status_message.setText(f"Write error: {message}")
    
    def unregister_selected(self):
        """Unregister selected nodes"""
        selected_items = self.registered_nodes_tree.selectedItems()
        if not selected_items:
            return
        
        # Confirm unregister
        dialog = ConfirmationDialog(
            "Confirm Unregister", 
            f"Are you sure you want to unregister {len(selected_items)} node(s)?",
            self
        )
        
        if dialog.exec_() != QDialog.Accepted:
            return
        
        for item in selected_items:
            node_id = item.text(1)
            
            # Unregister from client
            if hasattr(self.client, 'loop') and self.client.loop:
                asyncio.run_coroutine_threadsafe(
                    self.client.unregister_node(node_id),
                    self.client.loop
                )
            
            # Unregister from node manager
            self.node_manager.unregister_node(node_id)
            
            # Remove from tree
            for i in range(self.registered_nodes_tree.topLevelItemCount()):
                if self.registered_nodes_tree.topLevelItem(i).text(1) == node_id:
                    self.registered_nodes_tree.takeTopLevelItem(i)
                    break
        
        # Clear node info
        self.reg_node_name_label.setText("None selected")
        self.reg_node_id_label.setText("")
        self.reg_node_type_label.setText("")
        
        # Disable buttons
        self.node_type_combo.setEnabled(False)
        self.toggle_interval_input.setEnabled(False)
        self.apply_config_btn.setEnabled(False)
        self.save_value_cb.setEnabled(False)
        
        # Disable write controls
        self.bool_value_combo.setEnabled(False)
        self.write_bool_btn.setEnabled(False)
        self.toggle_btn.setEnabled(False)
        self.num_value_input.setEnabled(False)
        self.write_num_btn.setEnabled(False)
        self.str_value_input.setEnabled(False)
        self.write_str_btn.setEnabled(False)
        
        # Disable unregister buttons if no nodes left
        if self.registered_nodes_tree.topLevelItemCount() == 0:
            self.unregister_btn.setEnabled(False)
            self.unregister_all_btn.setEnabled(False)
    
    def unregister_all(self):
        """Unregister all nodes"""
        if self.registered_nodes_tree.topLevelItemCount() == 0:
            return
        
        # Confirm unregister
        dialog = ConfirmationDialog(
            "Confirm Unregister All", 
            "Are you sure you want to unregister all nodes?",
            self
        )
        
        if dialog.exec_() != QDialog.Accepted:
            return
        
        # Get all node IDs
        node_ids = []
        for i in range(self.registered_nodes_tree.topLevelItemCount()):
            node_ids.append(self.registered_nodes_tree.topLevelItem(i).text(1))
        
        # Unregister each node
        for node_id in node_ids:
            # Unregister from client
            if hasattr(self.client, 'loop') and self.client.loop:
                asyncio.run_coroutine_threadsafe(
                    self.client.unregister_node(node_id),
                    self.client.loop
                )
            
            # Unregister from node manager
            self.node_manager.unregister_node(node_id)
        
        # Clear tree
        self.registered_nodes_tree.clear()
        
        # Clear node info
        self.reg_node_name_label.setText("None selected")
        self.reg_node_id_label.setText("")
        self.reg_node_type_label.setText("")
        
        # Disable buttons
        self.node_type_combo.setEnabled(False)
        self.toggle_interval_input.setEnabled(False)
        self.apply_config_btn.setEnabled(False)
        self.save_value_cb.setEnabled(False)
        
        # Disable write controls
        self.bool_value_combo.setEnabled(False)
        self.write_bool_btn.setEnabled(False)
        self.toggle_btn.setEnabled(False)
        self.num_value_input.setEnabled(False)
        self.write_num_btn.setEnabled(False)
        self.str_value_input.setEnabled(False)
        self.write_str_btn.setEnabled(False)
        
        # Disable unregister buttons
        self.unregister_btn.setEnabled(False)
        self.unregister_all_btn.setEnabled(False)
    
    def on_method_called(self, method_id, success, result):
        """Handle method call result"""
        if success:
            self.status_message.setText(f"Method {method_id} called successfully: {result}")
        else:
            self.status_message.setText(f"Method call error: {result}")
    
    def refresh_xml(self):
        """Refresh XML preview"""
        if not self.config.xml_output_path or not os.path.exists(self.config.xml_output_path):
            self.xml_preview.setPlainText("No XML file available")
            return
        
        try:
            with open(self.config.xml_output_path, 'r') as f:
                xml_content = f.read()
            
            self.xml_preview.setPlainText(xml_content)
        except Exception as e:
            self.xml_preview.setPlainText(f"Error loading XML: {str(e)}")
    
    def on_xml_updated(self):
        """Handle XML update"""
        self.refresh_xml()
    
    def closeEvent(self, event):
        """Handle application close event"""
        # Save config
        try:
            self.update_config_from_ui()
            self.config.save()
        except Exception as e:
            logger.error(f"Error saving config: {str(e)}")
        
        # Stop client
        if self.client:
            self.client.stop()
        
        # Accept close event
        event.accept()