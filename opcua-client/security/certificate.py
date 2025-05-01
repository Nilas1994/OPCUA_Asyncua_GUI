#!/usr/bin/env python3
"""
Certificate management for OPC UA Client
"""
import os
import logging
import subprocess
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


def generate_certificate(
    cert_path: Path,
    private_key_path: Path,
    common_name: str = "OPC UA Client",
    organization: str = "Python OPC UA",
    organizational_unit: str = "Development",
    locality: str = "City",
    state: str = "State",
    country: str = "US",
    application_uri: str = "urn:example.org:FreeOpcUa:python-opcua",
    dns_names: Optional[list] = None,
    ip_addresses: Optional[list] = None,
    key_size: int = 2048,
    validity_days: int = 365
) -> Tuple[Path, Path]:
    """Generate a self-signed certificate for OPC UA Client
    
    Args:
        cert_path: Path to save certificate
        private_key_path: Path to save private key
        common_name: Certificate common name
        organization: Organization name
        organizational_unit: Organizational unit
        locality: Locality/City
        state: State/Province
        country: Country (2-letter code)
        application_uri: OPC UA application URI
        dns_names: List of DNS names
        ip_addresses: List of IP addresses
        key_size: RSA key size
        validity_days: Certificate validity in days
        
    Returns:
        Tuple of (certificate_path, private_key_path)
    """
    logger.info(f"Generating certificate: CN={common_name}, URI={application_uri}")
    
    # Create directories if they don't exist
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    
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
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
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
    san_list.append(x509.UniformResourceIdentifier(application_uri))
    
    # Add DNS names
    if dns_names:
        for dns_name in dns_names:
            san_list.append(x509.DNSName(dns_name))
    
    # Add IP addresses
    if ip_addresses:
        for ip in ip_addresses:
            san_list.append(x509.IPAddress(ip))
    
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
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate to file
    with open(cert_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    logger.info(f"Certificate and private key generated successfully")
    logger.info(f"Certificate: {cert_path}")
    logger.info(f"Private key: {private_key_path}")
    
    return cert_path, private_key_path


def load_certificate_details(cert_path: Path) -> Dict[str, Any]:
    """Load and parse certificate details
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Dictionary of certificate details
    """
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract basic information
        details = {
            "subject": {
                "common_name": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                "organization": cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None,
                "organizational_unit": cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME) else None,
                "locality": cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME) else None,
                "state": cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME) else None,
                "country": cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME) else None,
            },
            "issuer": {
                "common_name": cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                "organization": cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None,
            },
            "validity": {
                "not_before": cert.not_valid_before,
                "not_after": cert.not_valid_after,
                "days_remaining": (cert.not_valid_after - datetime.utcnow()).days,
            },
            "serial_number": cert.serial_number,
            "version": cert.version,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "public_key": {
                "type": "RSA" if isinstance(cert.public_key(), rsa.RSAPublicKey) else "Unknown",
                "key_size": cert.public_key().key_size if isinstance(cert.public_key(), rsa.RSAPublicKey) else None,
            },
            "extensions": {}
        }
        
        # Extract Subject Alternative Names
        try:
            san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            details["extensions"]["subject_alternative_name"] = {
                "uris": [san.value for san in san_extension.value if isinstance(san, x509.UniformResourceIdentifier)],
                "dns_names": [san.value for san in san_extension.value if isinstance(san, x509.DNSName)],
                "ip_addresses": [str(san.value) for san in san_extension.value if isinstance(san, x509.IPAddress)],
            }
        except x509.extensions.ExtensionNotFound:
            pass
        
        return details
    except Exception as e:
        logger.error(f"Error loading certificate: {e}")
        return {
            "error": str(e)
        }


def verify_certificate(cert_path: Path, trusted_certs_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Verify certificate against trusted certificates
    
    Args:
        cert_path: Path to certificate to verify
        trusted_certs_dir: Path to directory containing trusted certificates
        
    Returns:
        Dictionary with verification results
    """
    result = {
        "valid": False,
        "errors": [],
        "warnings": []
    }
    
    try:
        # Load certificate
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Check if certificate is expired
        now = datetime.utcnow()
        if cert.not_valid_before > now:
            result["errors"].append(f"Certificate is not yet valid (valid from {cert.not_valid_before})")
        elif cert.not_valid_after < now:
            result["errors"].append(f"Certificate has expired (expired on {cert.not_valid_after})")
            
        # Check days remaining
        days_remaining = (cert.not_valid_after - now).days
        if days_remaining < 30:
            result["warnings"].append(f"Certificate will expire in {days_remaining} days")
            
        # If trusted_certs_dir is provided, check trust chain
        if trusted_certs_dir and trusted_certs_dir.exists():
            # This would require implementing a proper certificate chain validation
            # For now, we just note that this is not implemented
            result["warnings"].append("Certificate trust chain validation is not implemented")
            
        # If no errors, mark as valid
        if not result["errors"]:
            result["valid"] = True
            
        return result
    except Exception as e:
        logger.error(f"Error verifying certificate: {e}")
        result["errors"].append(str(e))
        return result