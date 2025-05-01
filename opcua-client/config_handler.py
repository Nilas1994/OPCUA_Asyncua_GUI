#!/usr/bin/env python3
"""
Configuration management for OPC UA Client
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
import keyring

logger = logging.getLogger(__name__)

# Application identifier for keyring
APP_ID = "opcua_client"

# Default configuration template
DEFAULT_CONFIG = {
    "connection": {
        "endpoint": "",
        "auto_reconnect": True,
        "initial_delay": 5,
        "max_delay": 60,
        "max_attempts": 0,  # 0 = infinite
        "security_policy": "NO_SECURITY",
        "message_security_mode": "None_",
        "certificate": "",
        "private_key": ""
    },
    "ui": {
        "theme": "dark",
        "window_size": [1024, 768],
        "window_position": [100, 100],
        "last_active_tab": 0
    },
    "browser": {
        "auto_expand_depth": 2,
        "show_references": True,
        "show_attributes": True
    },
    "subscriptions": {
        "default_interval": 1000,
        "auto_subscribe": False
    },
    "registered_nodes": {
        "poll_interval": 1000,
        "livebit_interval": 5000
    },
    "logging": {
        "level": "INFO",
        "console_level": "INFO",
        "file_level": "DEBUG",
        "max_file_size": 10485760,  # 10MB
        "backup_count": 5
    },
    "export": {
        "default_format": "json",
        "auto_export": False,
        "export_path": ""
    }
}


class ConfigHandler:
    """Manages application configuration with secure credential storage"""
    
    def __init__(self, config_dir: Union[str, Path]):
        """Initialize configuration handler
        
        Args:
            config_dir: Path to configuration directory
        """
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "config.json"
        self.config = {}
        
        # Load or create configuration
        if not self.config_file.exists():
            logger.info("No configuration file found, creating default")
            self.config = DEFAULT_CONFIG.copy()
            self.save_config()
        else:
            self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                loaded_config = json.load(f)
            
            # Update with default values for any missing keys
            self._update_with_defaults(loaded_config, DEFAULT_CONFIG)
            self.config = loaded_config
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            logger.info("Using default configuration")
            self.config = DEFAULT_CONFIG.copy()
    
    def save_config(self) -> None:
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
    
    def get(self, section: str, key: Optional[str] = None) -> Any:
        """Get configuration value
        
        Args:
            section: Configuration section
            key: Configuration key (optional)
            
        Returns:
            Configuration value or section dict if key is None
        """
        if section not in self.config:
            logger.warning(f"Section '{section}' not found in configuration")
            return None
        
        if key is None:
            return self.config[section]
        
        if key not in self.config[section]:
            logger.warning(f"Key '{key}' not found in section '{section}'")
            return None
            
        return self.config[section][key]
    
    def set(self, section: str, key: str, value: Any) -> None:
        """Set configuration value
        
        Args:
            section: Configuration section
            key: Configuration key
            value: Value to set
        """
        if section not in self.config:
            logger.info(f"Creating new section '{section}'")
            self.config[section] = {}
        
        self.config[section][key] = value
        logger.debug(f"Updated config: {section}.{key} = {value}")
        self.save_config()
    
    def save_credentials(self, endpoint: str, username: str, password: str) -> None:
        """Save credentials securely in the system keyring
        
        Args:
            endpoint: Server endpoint
            username: Username
            password: Password
        """
        try:
            # Use the endpoint as part of the service name for endpoint-specific credentials
            service_id = f"{APP_ID}_{endpoint}"
            keyring.set_password(service_id, username, password)
            logger.info(f"Saved credentials for user '{username}' on endpoint '{endpoint}'")
        except Exception as e:
            logger.error(f"Error saving credentials: {e}")
    
    def get_credentials(self, endpoint: str, username: str) -> Optional[str]:
        """Get credentials from the system keyring
        
        Args:
            endpoint: Server endpoint
            username: Username
            
        Returns:
            Password or None if not found
        """
        try:
            service_id = f"{APP_ID}_{endpoint}"
            password = keyring.get_password(service_id, username)
            return password
        except Exception as e:
            logger.error(f"Error retrieving credentials: {e}")
            return None
    
    def delete_credentials(self, endpoint: str, username: str) -> bool:
        """Delete credentials from the system keyring
        
        Args:
            endpoint: Server endpoint
            username: Username
            
        Returns:
            True if successful, False otherwise
        """
        try:
            service_id = f"{APP_ID}_{endpoint}"
            keyring.delete_password(service_id, username)
            logger.info(f"Deleted credentials for user '{username}' on endpoint '{endpoint}'")
            return True
        except Exception as e:
            logger.error(f"Error deleting credentials: {e}")
            return False
    
    def _update_with_defaults(self, config: Dict, defaults: Dict) -> None:
        """Recursively update configuration with default values
        
        Args:
            config: Configuration to update
            defaults: Default values
        """
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
            elif isinstance(value, dict) and isinstance(config[key], dict):
                self._update_with_defaults(config[key], value)