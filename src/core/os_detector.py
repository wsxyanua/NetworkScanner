"""OS Detection Module for Network Scanner"""

import socket
import struct
import platform
from scapy.all import IP, TCP, sr1, RandShort
from typing import Dict, Optional, Tuple

class OSDetector:
    """Class for detecting operating system of target hosts"""
    
    def __init__(self, timeout: float = 1.0):
        """
        Initialize OS Detector
        
        Args:
            timeout (float): Timeout for network operations
        """
        self.timeout = timeout
        self.ttl_values = {
            32: "Windows 95/98/ME",
            64: "Linux/Unix",
            128: "Windows NT/2000/XP/2003",
            255: "Network device"
        }
        
        self.window_sizes = {
            (0, 64): "Linux/Unix",
            (64, 128): "Windows",
            (128, 256): "Solaris/AIX",
            (256, 512): "BSD/MacOS"
        }

    def get_ttl_os(self, ttl: int) -> str:
        """
        Get OS based on TTL value
        
        Args:
            ttl (int): TTL value from response
            
        Returns:
            str: Detected OS
        """
        for ttl_value, os_name in self.ttl_values.items():
            if abs(ttl - ttl_value) <= 5:  # Allow small variations
                return os_name
        return "Unknown"

    def get_window_size_os(self, window_size: int) -> str:
        """
        Get OS based on TCP window size
        
        Args:
            window_size (int): TCP window size from response
            
        Returns:
            str: Detected OS
        """
        for (min_size, max_size), os_name in self.window_sizes.items():
            if min_size <= window_size < max_size:
                return os_name
        return "Unknown"

    def detect_os(self, target: str) -> Dict[str, str]:
        """
        Detect operating system of target host
        
        Args:
            target (str): Target IP address
            
        Returns:
            Dict[str, str]: OS detection results
        """
        results = {
            "ttl_based": "Unknown",
            "window_based": "Unknown",
            "combined": "Unknown"
        }
        
        try:
            # Create TCP SYN packet
            ip = IP(dst=target)
            tcp = TCP(
                sport=RandShort(),
                dport=80,
                flags="S",
                window=65535
            )
            
            # Send packet and get response
            response = sr1(ip/tcp, timeout=self.timeout, verbose=0)
            
            if response:
                # TTL-based detection
                ttl = response.ttl
                results["ttl_based"] = self.get_ttl_os(ttl)
                
                # Window size-based detection
                window = response[TCP].window
                results["window_based"] = self.get_window_size_os(window)
                
                # Combined detection
                if results["ttl_based"] == results["window_based"]:
                    results["combined"] = results["ttl_based"]
                else:
                    results["combined"] = f"{results['ttl_based']} or {results['window_based']}"
            
        except Exception as e:
            print(f"Error during OS detection: {str(e)}")
        
        return results

    def get_os_fingerprint(self, target: str) -> Dict[str, any]:
        """
        Get detailed OS fingerprint
        
        Args:
            target (str): Target IP address
            
        Returns:
            Dict[str, any]: Detailed OS fingerprint information
        """
        fingerprint = {
            "os_detection": self.detect_os(target),
            "timestamp": None,
            "confidence": "Low"
        }
        
        # Add timestamp
        from datetime import datetime
        fingerprint["timestamp"] = datetime.now().isoformat()
        
        # Calculate confidence based on detection methods
        if fingerprint["os_detection"]["ttl_based"] != "Unknown" and \
           fingerprint["os_detection"]["window_based"] != "Unknown":
            if fingerprint["os_detection"]["ttl_based"] == fingerprint["os_detection"]["window_based"]:
                fingerprint["confidence"] = "High"
            else:
                fingerprint["confidence"] = "Medium"
        
        return fingerprint 