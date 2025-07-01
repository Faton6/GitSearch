"""
Configuration and constants for deep scanning operations.

This module contains configuration settings and constants used by the
deep scanning functionality in the GitSearch project.
"""

from typing import Dict, List
from enum import Enum

class ScanMode(Enum):
    """Enumeration of scanning modes."""
    STANDARD = 1
    MEDIUM = 2
    DEEP = 3

class ScanStatus(Enum):
    """Enumeration of scan status codes."""
    NOT_SCANNED = 0
    SCAN_COMPLETE = 1
    SCAN_ERROR = 2
    SCAN_TIMEOUT = 3
    DEEP_SCAN_REQUIRED = 5

# Deep scan configuration
DEEP_SCAN_CONFIG = {
    'max_retries': 3,
    'timeout_multiplier': 3.0,  # Deep scans take 3x longer than standard
    'batch_size': 5,  # Process 5 repositories at a time
    'enable_ai_analysis': True,
    'required_scanners': [
        'gitleaks',
        'gitsecrets', 
        'grepscan',
        'deepsecrets',
        'ioc_finder'
    ]
}

# List scan configuration
LIST_SCAN_CONFIG = {
    'max_urls_per_batch': 10,
    'url_validation_enabled': True,
    'auto_mark_processed': True,
    'supported_hosts': [
        'github.com',
        'gist.github.com'
    ]
}

# Scan comparison thresholds
COMPARISON_THRESHOLDS = {
    'min_difference_count': 1,  # Minimum difference to consider results changed
    'compare_scanners': [
        'grepscan',
        'trufflehog', 
        'deepsecrets',
        'gitleaks',
        'gitsecrets'
    ]
}

def get_deep_scan_timeout() -> int:
    """
    Get the timeout value for deep scans.
    
    Returns:
        Timeout in seconds for deep scan operations
    """
    from src import constants
    return int(constants.MAX_TIME_TO_SCAN_BY_UTIL_DEEP * DEEP_SCAN_CONFIG['timeout_multiplier'])

def is_scanner_enabled(scanner_name: str) -> bool:
    """
    Check if a specific scanner is enabled for deep scanning.
    
    Args:
        scanner_name: Name of the scanner to check
        
    Returns:
        True if scanner is enabled, False otherwise
    """
    return scanner_name in DEEP_SCAN_CONFIG['required_scanners']

def validate_url_format(url: str) -> bool:
    """
    Validate if URL matches supported format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL format is valid, False otherwise
    """
    if not LIST_SCAN_CONFIG['url_validation_enabled']:
        return True
        
    for host in LIST_SCAN_CONFIG['supported_hosts']:
        if host in url:
            return True
    return False
