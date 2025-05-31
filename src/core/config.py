#!/usr/bin/env python3

# Scanner Configuration
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 1
DEFAULT_BANNER_TIMEOUT = 2
DEFAULT_SCAN_TYPE = 'sS'

# Port ranges
COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Scan types
SCAN_TYPES = {
    'sS': 'TCP SYN scan',
    'sT': 'TCP Connect scan',
    'sU': 'UDP scan'
}

# Output formats
OUTPUT_FORMATS = ['json', 'txt', 'csv']

# Color codes
COLORS = {
    'open': 'green',
    'closed': 'red',
    'filtered': 'yellow',
    'info': 'cyan',
    'error': 'red'
} 