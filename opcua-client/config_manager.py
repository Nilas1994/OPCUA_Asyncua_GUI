import os
import json
import keyring
import getpass
from typing import Dict, Any, Optional, List
from enum import Enum
from pathlib import Path
from datetime import datetime

from utils import get_logger, get_config_dir, get_certificates_dir

logger = get_logger("config_manager")

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

class NodeRegistrationType(Enum):
    """Types of node registration"""
    STANDARD = "Standard"
    LIVEBIT = "LiveBit" 
    TOGGLE = "Toggle"
    CUSTOM = "Custom"

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
        
        # Reconnection settings
        self.auto_reconnect = True
        self.reconnect_delay = 5
        self.max_reconnect_delay = 60
        self.max_reconnect_attempts = 0  # 0 means infinite
        
        # Certificate settings
        self.generate_certificates = False
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
        config_dir = get_config_dir()
        cert_dir = get_certificates_dir()
        os.makedirs(os.path.dirname(self.xml_output_path), exist_ok=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary for serialization
        
        Returns:
            Dictionary representation of the configuration
        """
        return {
            "endpoint": self.endpoint,
            "username": self.username,
            "auto_connect": self.auto_connect,
            "security_policy": self.security_policy.name,
            "certificate_path": self.certificate_path,
            "private_key_path": self.private_key_path,
            "auto_reconnect": self.auto_reconnect,
            "reconnect_delay": self.reconnect_delay,
            "max_reconnect_delay": self.max_reconnect_delay,
            "max_reconnect_attempts": self.max_reconnect_attempts,
            "generate_certificates": self.generate_certificates,
            "certificate_info": self.certificate_info,
            "xml_output_path": self.xml_output_path,
            "subscribed_nodes": self.subscribed_nodes,
            "registered_nodes": self.registered_nodes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """
        Create configuration from dictionary
        
        Args:
            data: Dictionary with configuration data
            
        Returns:
            Configuration object
        """
        config = cls()
        
        # Basic settings
        config.endpoint = data.get("endpoint", "")
        config.username = data.get("username", "")
        config.auto_connect = data.get("auto_connect", False)
        
        # Security policy
        policy_name = data.get("security_policy", "NO_SECURITY")
        try:
            config.security_policy = SecurityPolicy[policy_name]
        except KeyError:
            logger.warning(f"Unknown security policy: {policy_name}, using NO_SECURITY")
            config.security_policy = SecurityPolicy.NO_SECURITY
        
        # Certificate paths
        config.certificate_path = data.get("certificate_path", "")
        config.private_key_path = data.get("private_key_path", "")
        
        # Reconnection settings
        config.auto_reconnect = data.get("auto_reconnect", True)
        config.reconnect_delay = data.get("reconnect_delay", 5)
        config.max_reconnect_delay = data.get("max_reconnect_delay", 60)
        config.max_reconnect_attempts = data.get("max_reconnect_attempts", 0)
        
        # Certificate generation
        config.generate_certificates = data.get("generate_certificates", False)
        if "certificate_info" in data:
            config.certificate_info = data["certificate_info"]
        
        # Output settings
        config.xml_output_path = data.get("xml_output_path", config.xml_output_path)
        
        # Node lists
        config.subscribed_nodes = data.get("subscribed_nodes", {})
        config.registered_nodes = data.get("registered_nodes", {})
        
        return config
    
    def save(self, filename: Optional[str] = None) -> None:
        """
        Save configuration to file
        
        Args:
            filename: Optional filename to save to (default: config.json in config dir)
        """
        if not filename:
            filename = os.path.join(get_config_dir(), "config.json")
        
        try:
            # Ensure registered_nodes has proper node_type values preserved
            for node_id, node_info in self.registered_nodes.items():
                if "node_type" not in node_info:
                    node_info["node_type"] = "Standard"
            
            # Save configuration to file
            with open(filename, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)
            
            # If using keyring, store password securely
            if self.username:
                self.save_password()
                
            logger.info(f"Configuration saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            raise
    
    @classmethod
    def load(cls, filename: Optional[str] = None) -> 'Config':
        """
        Load configuration from file
        
        Args:
            filename: Optional filename to load from (default: config.json in config dir)
            
        Returns:
            Loaded configuration object
        """
        if not filename:
            filename = os.path.join(get_config_dir(), "config.json")
        
        if not os.path.exists(filename):
            logger.info(f"Configuration file {filename} does not exist, creating default")
            config = cls()
            config.save(filename)
            return config
        
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            config = cls.from_dict(data)
            
            # Load password from keyring if username is provided
            if config.username:
                config.load_password()
                
            logger.info(f"Configuration loaded from {filename}")
            return config
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            return cls()
    
    def save_password(self, password: Optional[str] = None) -> None:
        """
        Save password to keyring
        
        Args:
            password: Optional password to save (uses stored password if not provided)
        """
        if not self.username:
            logger.warning("Cannot save password: no username provided")
            return
        
        service_name = "opcua_client"
        username = self.username
        
        try:
            keyring.set_password(service_name, username, password or "")
            logger.info(f"Password saved to keyring for user {username}")
        except Exception as e:
            logger.error(f"Error saving password to keyring: {str(e)}")
    
    def load_password(self) -> Optional[str]:
        """
        Load password from keyring
        
        Returns:
            Password if found, None otherwise
        """
        if not self.username:
            logger.warning("Cannot load password: no username provided")
            return None
        
        service_name = "opcua_client"
        username = self.username
        
        try:
            password = keyring.get_password(service_name, username)
            if password:
                logger.info(f"Password loaded from keyring for user {username}")
            else:
                logger.warning(f"No password found in keyring for user {username}")
            return password
        except Exception as e:
            logger.error(f"Error loading password from keyring: {str(e)}")
            return None
    
    def generate_self_signed_certificate(self) -> bool:
        """
        Generate self-signed certificate for OPC UA client
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if cryptography module is available
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.backends import default_backend
                import datetime as dt
            except ImportError:
                logger.error("Cryptography module not available. Install with: pip install cryptography")
                return False
            
            # Create certificate directory
            cert_dir = get_certificates_dir()
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Get hostname for application URI
            import socket
            hostname = socket.gethostname()
            
            # Create application URI
            org_name = self.certificate_info["organization"].lower().replace(" ", "")
            app_uri = f"urn:{org_name}:{hostname}:opcuaclient"
            self.certificate_info["application_uri"] = app_uri
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.certificate_info["common_name"]),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.certificate_info["organization"]),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.certificate_info["organization_unit"]),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.certificate_info["locality"]),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.certificate_info["state"]),
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.certificate_info["country"]),
            ])
            
            # Build certificate
            cert_builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                dt.datetime.utcnow()
            ).not_valid_after(
                dt.datetime.utcnow() + dt.timedelta(days=self.certificate_info["days_valid"])
            )
            
            # Add Subject Alternative Name extension
            san = x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(hostname),
                x509.UniformResourceIdentifier(app_uri)
            ])
            cert_builder = cert_builder.add_extension(san, critical=False)
            
            # Add Basic Constraints extension
            basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
            cert_builder = cert_builder.add_extension(basic_constraints, critical=True)
            
            # Add Key Usage extension
            key_usage = x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            )
            cert_builder = cert_builder.add_extension(key_usage, critical=True)
            
            # Add Extended Key Usage extension
            extended_key_usage = x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ])
            cert_builder = cert_builder.add_extension(extended_key_usage, critical=True)
            
            # Sign the certificate
            certificate = cert_builder.sign(
                private_key=private_key, 
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
            
            # Save private key and certificate
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            cert_filename = f"opcua_client_cert_{timestamp}.pem"
            key_filename = f"opcua_client_key_{timestamp}.pem"
            
            cert_path = os.path.join(cert_dir, cert_filename)
            key_path = os.path.join(cert_dir, key_filename)
            
            # Write private key to file
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write certificate to file
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            # Update config with paths
            self.certificate_path = cert_path
            self.private_key_path = key_path
            
            logger.info(f"Self-signed certificate generated: {cert_path}")
            logger.info(f"Private key saved to: {key_path}")
            
            return True
        
        except Exception as e:
            logger.error(f"Error generating certificate: {str(e)}")
            return False