"""
Configuration Manager for RedTeam Terminal
Handles loading, validating, and accessing configuration settings
"""

import configparser
import os
from typing import Optional, Union, Any


class ConfigManager:
    """
    Configuration Manager class to handle application settings
    """
    
    def __init__(self, config_file: str = "config.ini"):
        """
        Initialize the configuration manager
        
        Args:
            config_file (str): Path to the configuration file
        """
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self) -> None:
        """
        Load configuration from file, create default if doesn't exist
        """
        if not os.path.exists(self.config_file):
            self.create_default_config()
        
        self.config.read(self.config_file)
    
    def create_default_config(self) -> None:
        """
        Create a default configuration file
        """
        # Create the default configuration
        self.config['GENERAL'] = {
            'version': '2.1.0',
            'theme': 'cyberpunk',
            'debug_mode': 'false'
        }
        
        self.config['NETWORK_RECON'] = {
            'default_scan_type': 'port',
            'max_concurrent_scans': '5',
            'timeout_seconds': '30',
            'default_ports': '22,80,443,8080,3306,5432,3389,27017',
            'simulation_mode': 'true'
        }
        
        self.config['VULN_SCANNER'] = {
            'default_severity_threshold': 'medium',
            'cve_database_url': 'https://cve.mitre.org',
            'scan_depth': 'medium',
            'report_format': 'console'
        }
        
        self.config['PASSWORD_TESTER'] = {
            'min_length': '8',
            'require_uppercase': 'true',
            'require_lowercase': 'true',
            'require_numbers': 'true',
            'require_special_chars': 'true',
            'entropy_threshold': '3.0'
        }
        
        self.config['OSINT_TOOLS'] = {
            'default_timeout': '60',
            'max_requests_per_minute': '10',
            'enable_rate_limiting': 'true',
            'use_tor_proxy': 'false'
        }
        
        self.config['SECURITY'] = {
            'require_consent': 'true',
            'log_actions': 'true',
            'log_file_path': './logs/actions.log',
            'consent_timeout': '30'
        }
        
        self.config['REPORTING'] = {
            'default_format': 'json',
            'enable_pdf_export': 'false',
            'enable_csv_export': 'true',
            'enable_json_export': 'true',
            'report_directory': './reports'
        }
        
        self.config['ADVANCED'] = {
            'max_retries': '3',
            'retry_delay': '2',
            'use_threads': 'true',
            'max_threads': '10',
            'show_advanced_options': 'false'
        }
        
        # Write the default configuration to file
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
    
    def get(self, section: str, key: str, fallback: Optional[Any] = None) -> Union[str, Any]:
        """
        Get a configuration value
        
        Args:
            section (str): Configuration section name
            key (str): Configuration key name
            fallback (Any, optional): Fallback value if key doesn't exist
        
        Returns:
            Configuration value or fallback
        """
        return self.config.get(section, key, fallback=fallback)
    
    def get_boolean(self, section: str, key: str, fallback: bool = False) -> bool:
        """
        Get a boolean configuration value
        
        Args:
            section (str): Configuration section name
            key (str): Configuration key name
            fallback (bool): Fallback value if key doesn't exist
        
        Returns:
            Boolean configuration value or fallback
        """
        try:
            return self.config.getboolean(section, key, fallback=fallback)
        except ValueError:
            return fallback
    
    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """
        Get an integer configuration value
        
        Args:
            section (str): Configuration section name
            key (str): Configuration key name
            fallback (int): Fallback value if key doesn't exist
        
        Returns:
            Integer configuration value or fallback
        """
        try:
            return self.config.getint(section, key, fallback=fallback)
        except ValueError:
            return fallback
    
    def get_float(self, section: str, key: str, fallback: float = 0.0) -> float:
        """
        Get a float configuration value
        
        Args:
            section (str): Configuration section name
            key (str): Configuration key name
            fallback (float): Fallback value if key doesn't exist
        
        Returns:
            Float configuration value or fallback
        """
        try:
            return self.config.getfloat(section, key, fallback=fallback)
        except ValueError:
            return fallback
    
    def get_list(self, section: str, key: str, fallback: list = None) -> list:
        """
        Get a list configuration value (comma-separated string)
        
        Args:
            section (str): Configuration section name
            key (str): Configuration key name
            fallback (list): Fallback value if key doesn't exist
        
        Returns:
            List configuration value or fallback
        """
        if fallback is None:
            fallback = []
        
        try:
            value = self.config.get(section, key)
            return [item.strip() for item in value.split(',')]
        except (configparser.NoOptionError, configparser.NoSectionError):
            return fallback
    
    def set(self, section: str, key: str, value: str) -> None:
        """
        Set a configuration value
        
        Args:
            section (str): Configuration section name
            key (str): Configuration key name
            value (str): Configuration value to set
        """
        if not self.config.has_section(section):
            self.config.add_section(section)
        
        self.config.set(section, key, value)
        
        # Save the configuration to file
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
    
    def reload(self) -> None:
        """
        Reload the configuration from file
        """
        self.load_config()


# Global configuration instance
config_manager = ConfigManager()


def get_config_manager():
    """Get the global configuration manager instance"""
    global config_manager
    return config_manager