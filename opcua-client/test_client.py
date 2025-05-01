#!/usr/bin/env python3
"""
Connection dialog for OPC UA Client
"""
import os
import logging
from pathlib import Path

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, 
    QLineEdit, QPushButton, QComboBox, QSpinBox, QCheckBox,
    QGroupBox, QFileDialog, QDialogButtonBox, QTabWidget, QWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

logger = logging.getLogger(__name__)

# Security policies
SECURITY_POLICIES = [
    "NO_SECURITY",
    "BASIC128RSA15_SIGN",
    "BASIC128RSA15_SIGN_ENCRYPT",
    "BASIC256_SIGN",
    "BASIC256_SIGN_ENCRYPT",
    "BASIC256SHA256_SIGN",
    "BASIC256SHA256_SIGN_ENCRYPT",
    "AES128SHA256RSAOAEP_SIGN",
    "AES128SHA256RSAOAEP_SIGN_ENCRYPT",
    "AES256SHA256RSAPSS_SIGN",
    "AES256SHA256RSAPSS_SIGN_ENCRYPT"
]

class ConnectionDialog(QDialog):
    """Dialog for configuring OPC UA server connection"""
    
    def __init__(self, config_handler, parent=None):
        """Initialize connection dialog
        
        Args:
            config_handler: Configuration handler
            parent: Parent widget
        """
        super().__init__(parent)
        self.config = config_handler
        
        self.setWindowTitle("Connect to OPC UA Server")
        self.setMinimumWidth(600)
        
        # Main layout
        self.layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget)
        
        # Create basic settings tab
        self.basic_tab = QWidget()
        self.basic_layout = QVBoxLayout(self.basic_tab)
        self.tab_widget.addTab(self.basic_tab, "Basic Settings")
        
        # Create security tab
        self.security_tab = QWidget()
        self.security_layout = QVBoxLayout(self.security_tab)
        self.tab_widget.addTab(self.security_tab, "Security")
        
        # Create advanced tab
        self.advanced_tab = QWidget()
        self.advanced_layout = QVBoxLayout(self.advanced_tab)
        self.tab_widget.addTab(self.advanced_tab, "Advanced")
        
        # Initialize UI components
        self.init_basic_settings()
        self.init_security_settings()
        self.init_advanced_settings()
        
        # Add button box
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)
        
        # Apply initial values from config
        self.apply_config_values()
    
    def init_basic_settings(self):
        """Initialize basic settings tab"""
        # Endpoint URL
        self.endpoint_form = QFormLayout()
        self.endpoint_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        
        self.endpoint_edit = QLineEdit()
        self.endpoint_edit.setPlaceholderText("opc.tcp://localhost:4840/")
        self.endpoint_form.addRow("Endpoint URL:", self.endpoint_edit)
        
        # Recent endpoints combo (future enhancement)
        
        # Authentication group
        self.auth_group = QGroupBox("Authentication")
        self.auth_group.setCheckable(True)
        self.auth_group.setChecked(False)
        self.auth_layout = QFormLayout(self.auth_group)
        
        self.username_edit = QLineEdit()
        self.auth_layout.addRow("Username:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.auth_layout.addRow("Password:", self.password_edit)
        
        # Auto-reconnect group
        self.reconnect_group = QGroupBox("Automatic Reconnection")
        self.reconnect_layout = QFormLayout(self.reconnect_group)
        
        self.auto_reconnect_check = QCheckBox("Enable automatic reconnection")
        self.auto_reconnect_check.setChecked(True)
        self.reconnect_layout.addRow(self.auto_reconnect_check)
        
        self.initial_delay_spin = QSpinBox()
        self.initial_delay_spin.setRange(1, 60)
        self.initial_delay_spin.setValue(5)
        self.initial_delay_spin.setSuffix(" seconds")
        self.reconnect_layout.addRow("Initial delay:", self.initial_delay_spin)
        
        self.max_delay_spin = QSpinBox()
        self.max_delay_spin.setRange(1, 300)
        self.max_delay_spin.setValue(60)
        self.max_delay_spin.setSuffix(" seconds")
        self.reconnect_layout.addRow("Maximum delay:", self.max_delay_spin)
        
        self.max_attempts_spin = QSpinBox()
        self.max_attempts_spin.setRange(0, 100)
        self.max_attempts_spin.setValue(0)
        self.max_attempts_spin.setSpecialValueText("Infinite")
        self.reconnect_layout.addRow("Maximum attempts:", self.max_attempts_spin)
        
        # Add widgets to basic layout
        self.basic_layout.addLayout(self.endpoint_form)
        self.basic_layout.addWidget(self.auth_group)
        self.basic_layout.addWidget(self.reconnect_group)
        self.basic_layout.addStretch(1)
    
    def init_security_settings(self):
        """Initialize security settings tab"""
        # Security policy group
        self.security_group = QGroupBox("Security Settings")
        self.security_group.setCheckable(True)
        self.security_group.setChecked(False)
        self.security_layout.addWidget(self.security_group)
        
        self.security_form = QFormLayout(self.security_group)
        
        # Security policy combo
        self.security_combo = QComboBox()
        self.security_combo.addItems(SECURITY_POLICIES)
        self.security_form.addRow("Security Policy:", self.security_combo)
        
        # Certificate & private key
        self.cert_layout = QHBoxLayout()
        self.certificate_edit = QLineEdit()
        self.certificate_edit.setReadOnly(True)
        self.certificate_button = QPushButton("Browse...")
        self.certificate_button.clicked.connect(self.browse_certificate)
        self.cert_layout.addWidget(self.certificate_edit)
        self.cert_layout.addWidget(self.certificate_button)
        self.security_form.addRow("Certificate:", self.cert_layout)
        
        self.key_layout = QHBoxLayout()
        self.private_key_edit = QLineEdit()
        self.private_key_edit.setReadOnly(True)
        self.private_key_button = QPushButton("Browse...")
        self.private_key_button.clicked.connect(self.browse_private_key)
        self.key_layout.addWidget(self.private_key_edit)
        self.key_layout.addWidget(self.private_key_button)
        self.security_form.addRow("Private Key:", self.key_layout)
        
        # Generate certificate button
        self.generate_cert_button = QPushButton("Generate Certificate...")
        self.generate_cert_button.clicked.connect(self.generate_certificate)
        self.security_layout.addWidget(self.generate_cert_button)
        
        # Certificate validation settings (future enhancement)
        
        self.security_layout.addStretch(1)
    
    def init_advanced_settings(self):
        """Initialize advanced settings tab"""
        # Session timeout
        self.session_form = QFormLayout()
        
        self.session_timeout_spin = QSpinBox()
        self.session_timeout_spin.setRange(10, 3600)
        self.session_timeout_spin.setValue(60)
        self.session_timeout_spin.setSuffix(" seconds")
        self.session_form.addRow("Session Timeout:", self.session_timeout_spin)
        
        # Secure channel lifetime
        self.secure_channel_spin = QSpinBox()
        self.secure_channel_spin.setRange(10, 3600)
        self.secure_channel_spin.setValue(60)
        self.secure_channel_spin.setSuffix(" seconds")
        self.session_form.addRow("Secure Channel Lifetime:", self.secure_channel_spin)
        
        # Add widgets to advanced layout
        self.advanced_layout.addLayout(self.session_form)
        self.advanced_layout.addStretch(1)
    
    def apply_config_values(self):
        """Apply initial values from config"""
        # Endpoint URL
        endpoint = self.config.get("connection", "endpoint")
        if endpoint:
            self.endpoint_edit.setText(endpoint)
        
        # Authentication
        # We don't load username/password for security reasons
        # User will need to enter them each time
        
        # Automatic reconnection
        auto_reconnect = self.config.get("connection", "auto_reconnect")
        if auto_reconnect is not None:
            self.auto_reconnect_check.setChecked(auto_reconnect)
        
        initial_delay = self.config.get("connection", "initial_delay")
        if initial_delay is not None:
            self.initial_delay_spin.setValue(initial_delay)
        
        max_delay = self.config.get("connection", "max_delay")
        if max_delay is not None:
            self.max_delay_spin.setValue(max_delay)
        
        max_attempts = self.config.get("connection", "max_attempts")
        if max_attempts is not None:
            self.max_attempts_spin.setValue(max_attempts)
        
        # Security
        security_policy = self.config.get("connection", "security_policy")
        if security_policy:
            index = self.security_combo.findText(security_policy)
            if index >= 0:
                self.security_combo.setCurrentIndex(index)
                self.security_group.setChecked(True)
        
        certificate = self.config.get("connection", "certificate")
        if certificate:
            self.certificate_edit.setText(certificate)
        
        private_key = self.config.get("connection", "private_key")
        if private_key:
            self.private_key_edit.setText(private_key)
    
    def browse_certificate(self):
        """Browse for certificate file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Certificate",
            "",
            "Certificate Files (*.pem *.der);;All Files (*)"
        )
        
        if file_path:
            self.certificate_edit.setText(file_path)
    
    def browse_private_key(self):
        """Browse for private key file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Private Key",
            "",
            "Private Key Files (*.pem *.der);;All Files (*)"
        )
        
        if file_path:
            self.private_key_edit.setText(file_path)
    
    def generate_certificate(self):
        """Generate new certificate"""
        # This will be implemented in a future version
        # For now, just show a message
        from PyQt5.QtWidgets import QMessageBox
        
        QMessageBox.information(
            self,
            "Generate Certificate",
            "Certificate generation is not implemented yet.",
            QMessageBox.Ok
        )