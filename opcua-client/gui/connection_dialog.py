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
    QGroupBox, QFileDialog, QDialogButtonBox, QTabWidget,
    QMessageBox, QWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

# Import certificate generation dialog
from datetime import datetime, timedelta

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)

# Security policies as string constants
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

class CertificateGenerationDialog(QDialog):
    """Dialog for generating OPC UA certificates"""
    
    def __init__(self, parent=None):
        """Initialize dialog"""
        super().__init__(parent)
        
        self.setWindowTitle("Generate Certificate")
        self.setMinimumWidth(500)
        
        self.main_layout = QVBoxLayout(self)
        
        # Certificate info group
        self.info_group = QGroupBox("Certificate Information")
        self.info_layout = QFormLayout(self.info_group)
        
        self.common_name_edit = QLineEdit("OPC UA Client")
        self.info_layout.addRow("Common Name:", self.common_name_edit)
        
        self.organization_edit = QLineEdit("My Organization")
        self.info_layout.addRow("Organization:", self.organization_edit)
        
        self.org_unit_edit = QLineEdit("IT Department")
        self.info_layout.addRow("Organizational Unit:", self.org_unit_edit)
        
        self.locality_edit = QLineEdit("My City")
        self.info_layout.addRow("Locality/City:", self.locality_edit)
        
        self.state_edit = QLineEdit("My State")
        self.info_layout.addRow("State/Province:", self.state_edit)
        
        self.country_edit = QLineEdit("US")
        self.info_layout.addRow("Country Code (2 letters):", self.country_edit)
        
        self.uri_edit = QLineEdit("urn:example.org:FreeOpcUa:python-opcua")
        self.info_layout.addRow("Application URI:", self.uri_edit)
        
        # Certificate parameters group
        self.params_group = QGroupBox("Certificate Parameters")
        self.params_layout = QFormLayout(self.params_group)
        
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["1024", "2048", "4096"])
        self.key_size_combo.setCurrentText("2048")
        self.params_layout.addRow("Key Size (bits):", self.key_size_combo)
        
        self.validity_spin = QSpinBox()
        self.validity_spin.setRange(1, 3650)
        self.validity_spin.setValue(365)
        self.validity_spin.setSuffix(" days")
        self.params_layout.addRow("Validity Period:", self.validity_spin)
        
        # Output paths group
        self.output_group = QGroupBox("Output Files")
        self.output_layout = QFormLayout(self.output_group)
        
        # Certificate path
        self.cert_path_layout = QHBoxLayout()
        self.cert_path_edit = QLineEdit()
        self.cert_path_edit.setReadOnly(True)
        self.cert_browse_button = QPushButton("Browse...")
        self.cert_browse_button.clicked.connect(self.browse_cert_path)
        self.cert_path_layout.addWidget(self.cert_path_edit)
        self.cert_path_layout.addWidget(self.cert_browse_button)
        self.output_layout.addRow("Certificate File:", self.cert_path_layout)
        
        # Private key path
        self.key_path_layout = QHBoxLayout()
        self.key_path_edit = QLineEdit()
        self.key_path_edit.setReadOnly(True)
        self.key_browse_button = QPushButton("Browse...")
        self.key_browse_button.clicked.connect(self.browse_key_path)
        self.key_path_layout.addWidget(self.key_path_edit)
        self.key_path_layout.addWidget(self.key_browse_button)
        self.output_layout.addRow("Private Key File:", self.key_path_layout)
        
        # Set default paths
        default_cert_dir = Path.home() / ".opcua_client" / "certs"
        default_cert_dir.mkdir(exist_ok=True, parents=True)
        self.cert_path_edit.setText(str(default_cert_dir / "client_cert.pem"))
        self.key_path_edit.setText(str(default_cert_dir / "client_key.pem"))
        
        # Add groups to main layout
        self.main_layout.addWidget(self.info_group)
        self.main_layout.addWidget(self.params_group)
        self.main_layout.addWidget(self.output_group)
        
        # Add button box
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.generate)
        self.button_box.rejected.connect(self.reject)
        self.main_layout.addWidget(self.button_box)
    
    def browse_cert_path(self):
        """Browse for certificate file path"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Certificate As",
            self.cert_path_edit.text(),
            "Certificate Files (*.pem *.der);;All Files (*)"
        )
        
        if file_path:
            self.cert_path_edit.setText(file_path)
    
    def browse_key_path(self):
        """Browse for private key file path"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Private Key As",
            self.key_path_edit.text(),
            "Private Key Files (*.pem *.der);;All Files (*)"
        )
        
        if file_path:
            self.key_path_edit.setText(file_path)
    
    def generate(self):
        """Generate certificate and private key"""
        try:
            # Get parameters from UI
            common_name = self.common_name_edit.text()
            organization = self.organization_edit.text()
            org_unit = self.org_unit_edit.text()
            locality = self.locality_edit.text()
            state = self.state_edit.text()
            country = self.country_edit.text()
            app_uri = self.uri_edit.text()
            
            key_size = int(self.key_size_combo.currentText())
            validity_days = self.validity_spin.value()
            
            cert_path = self.cert_path_edit.text()
            key_path = self.key_path_edit.text()
            
            # Validate inputs
            if not common_name:
                QMessageBox.warning(self, "Validation Error", "Common Name is required")
                return
                
            if len(country) != 2:
                QMessageBox.warning(self, "Validation Error", "Country Code must be exactly 2 letters")
                return
                
            if not cert_path:
                QMessageBox.warning(self, "Validation Error", "Certificate file path is required")
                return
                
            if not key_path:
                QMessageBox.warning(self, "Validation Error", "Private key file path is required")
                return
            
            # Create directories if they don't exist
            Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
            Path(key_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Create certificate subject
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            ])
            
            # Certificate validity period
            now = datetime.utcnow()
            cert_builder = x509.CertificateBuilder(
                issuer_name=issuer,
                subject_name=subject,
                public_key=private_key.public_key(),
                serial_number=x509.random_serial_number(),
                not_valid_before=now,
                not_valid_after=now + timedelta(days=validity_days)
            )
            
            # Add Subject Alternative Names (SAN) extensions
            san_list = []
            
            # Add URI
            san_list.append(x509.UniformResourceIdentifier(app_uri))
            
            # Add DNS name (hostname)
            import socket
            hostname = socket.gethostname()
            san_list.append(x509.DNSName(hostname))
            
            # Add SAN extension
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
            
            # Add Basic Constraints
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            
            # Add Key Usage
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            # Add Extended Key Usage
            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=True
            )
            
            # Sign the certificate with the private key
            certificate = cert_builder.sign(
                private_key=private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
            
            # Write private key to file
            with open(key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write certificate to file
            with open(cert_path, 'wb') as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            # Show success message
            QMessageBox.information(
                self,
                "Certificate Generated",
                f"Certificate and private key have been generated successfully.\n\n"
                f"Certificate: {cert_path}\n"
                f"Private Key: {key_path}\n\n"
                f"The certificate is valid for {validity_days} days.",
                QMessageBox.Ok
            )
            
            # Accept dialog
            self.accept()
            
        except Exception as e:
            logger.exception(f"Error generating certificate: {e}")
            QMessageBox.critical(
                self,
                "Generation Error",
                f"An error occurred while generating the certificate:\n\n{str(e)}",
                QMessageBox.Ok
            )

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
        for policy in SECURITY_POLICIES:
            self.security_combo.addItem(policy)
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
        if not CRYPTO_AVAILABLE:
            QMessageBox.warning(
                self,
                "Missing Dependencies",
                "Certificate generation requires the 'cryptography' package.\n"
                "Please install it with: pip install cryptography",
                QMessageBox.Ok
            )
            return
            
        try:
            # Create and show certificate generation dialog
            cert_dialog = CertificateGenerationDialog(self)
            
            if cert_dialog.exec_():
                # Set certificate and private key paths from dialog
                self.certificate_edit.setText(cert_dialog.cert_path_edit.text())
                self.private_key_edit.setText(cert_dialog.key_path_edit.text())
                
                # Enable security settings
                self.security_group.setChecked(True)
        except Exception as e:
            logger.exception(f"Error during certificate generation: {e}")
            QMessageBox.critical(
                self,
                "Certificate Generation Error",
                f"An error occurred while generating the certificate:\n\n{str(e)}",
                QMessageBox.Ok
            )