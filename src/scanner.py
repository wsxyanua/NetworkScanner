#!/usr/bin/env python3

import argparse
import sys
import ipaddress
import socket
import threading
import queue
import time
from datetime import datetime
from scapy.all import *
from colorama import init, Fore, Style
import nmap
import os
from typing import Dict, List, Union

from core.config import *
from utils.output_handler import OutputHandler
from core.os_detector import OSDetector

# Initialize colorama
init()

class Scanner:
    """Network Scanner with OS Detection"""
    
    def __init__(self, target: str, ports: str, scan_type: str = "syn",
                 threads: int = DEFAULT_THREADS, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize scanner
        
        Args:
            target (str): Target IP address or network range
            ports (str): Port range to scan
            scan_type (str): Type of scan (syn, connect, udp)
            threads (int): Number of threads to use
            timeout (float): Timeout for network operations
        """
        self.target = target
        self.ports = self._parse_ports(ports)
        self.scan_type = scan_type
        self.threads = threads
        self.timeout = timeout
        self.os_detector = OSDetector(timeout=timeout)
        self.port_queue = queue.Queue()
        self.results = {}
        self.lock = threading.Lock()
        
    def _parse_ports(self, ports: str) -> List[int]:
        """Parse port range string into list of ports"""
        if ports == "common":
            return COMMON_PORTS
            
        result = []
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                result.extend(range(start, end + 1))
            else:
                result.append(int(part))
        return result

    def _get_banner(self, port: int) -> str:
        """Get service banner from open port"""
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, port))
            banner = s.recv(1024).decode().strip()
            s.close()
            return banner
        except:
            return ""

    def _worker(self):
        """Worker thread for port scanning"""
        while True:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break

            try:
                if self.scan_type == "syn":
                    self._syn_scan_port(port)
                elif self.scan_type == "connect":
                    self._connect_scan_port(port)
                elif self.scan_type == "udp":
                    self._udp_scan_port(port)
            except Exception as e:
                print(f"Error scanning port {port}: {str(e)}")
            finally:
                self.port_queue.task_done()

    def _syn_scan_port(self, port: int):
        """Perform SYN scan on a single port"""
        ip = IP(dst=self.target)
        syn = TCP(dport=port, flags='S')
        syn_ack = sr1(ip/syn, timeout=self.timeout, verbose=0)

        if syn_ack and syn_ack.haslayer(TCP):
            if syn_ack[TCP].flags == 0x12:  # SYN-ACK
                rst = TCP(dport=port, flags='R')
                send(ip/rst, verbose=0)
                banner = self._get_banner(port)
                with self.lock:
                    self.results[str(port)] = {
                        "state": "open",
                        "service": self._get_service_name(port),
                        "banner": banner,
                        "timestamp": datetime.now().isoformat()
                    }
            else:
                with self.lock:
                    self.results[str(port)] = {
                        "state": "closed",
                        "service": "",
                        "banner": "",
                        "timestamp": datetime.now().isoformat()
                    }
        else:
            with self.lock:
                self.results[str(port)] = {
                    "state": "filtered",
                    "service": "",
                    "banner": "",
                    "timestamp": datetime.now().isoformat()
                }

    def _connect_scan_port(self, port: int):
        """Perform Connect scan on a single port"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                banner = self._get_banner(port)
                with self.lock:
                    self.results[str(port)] = {
                        "state": "open",
                        "service": self._get_service_name(port),
                        "banner": banner,
                        "timestamp": datetime.now().isoformat()
                    }
            else:
                with self.lock:
                    self.results[str(port)] = {
                        "state": "closed",
                        "service": "",
                        "banner": "",
                        "timestamp": datetime.now().isoformat()
                    }
            s.close()
        except:
            with self.lock:
                self.results[str(port)] = {
                    "state": "filtered",
                    "service": "",
                    "banner": "",
                    "timestamp": datetime.now().isoformat()
                }

    def _udp_scan_port(self, port: int):
        """Perform UDP scan on a single port"""
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, arguments=f'-sU -p{port}')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', '')
                    with self.lock:
                        self.results[str(port)] = {
                            "state": state,
                            "service": service,
                            "banner": "",
                            "timestamp": datetime.now().isoformat()
                        }
        except Exception as e:
            print(f"Error during UDP scan: {str(e)}")

    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        common_services = {
            20: "ftp-data",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            8080: "http-proxy"
        }
        return common_services.get(port, "unknown")
        
    def scan(self) -> Dict[str, any]:
        """
        Perform network scan with OS detection
        
        Returns:
            Dict[str, any]: Scan results including OS detection
        """
        try:
            # Validate target
            ipaddress.ip_address(self.target)
            
            print(f"\n{Fore.CYAN}[*] Starting scan on {self.target}")
            print(f"[*] Scanning {len(self.ports)} ports with {self.threads} threads{Style.RESET_ALL}\n")
            
            start_time = time.time()
            
            # Add ports to queue
            for port in self.ports:
                self.port_queue.put(port)
            
            # Create and start threads
            thread_list = []
            for _ in range(self.threads):
                t = threading.Thread(target=self._worker)
                t.daemon = True
                t.start()
                thread_list.append(t)
            
            # Wait for all threads to complete
            self.port_queue.join()
            
            # Calculate scan duration
            duration = time.time() - start_time
            print(f"\n{Fore.CYAN}[*] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
            
            # Perform OS detection
            os_results = self.os_detector.get_os_fingerprint(self.target)
            
            # Combine results
            results = {
                "target": self.target,
                "ports": self.results,
                "os_detection": os_results,
                "scan_type": self.scan_type,
                "timestamp": os_results["timestamp"]
            }
            
            return results
            
        except ValueError:
            print(f"{Fore.RED}[!] Invalid IP address: {self.target}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Network Scanner with OS Detection")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or network range")
    parser.add_argument("-p", "--ports", required=True, help="Port range (e.g., 1-1000, 80,443,8080, common)")
    parser.add_argument("-sS", action="store_true", help="TCP SYN scan (stealth)")
    parser.add_argument("-sT", action="store_true", help="TCP Connect scan")
    parser.add_argument("-sU", action="store_true", help="UDP scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-T", "--threads", type=int, default=DEFAULT_THREADS, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json", help="Output format")
    
    args = parser.parse_args()
    
    # Determine scan type
    scan_type = "syn"  # default
    if args.sT:
        scan_type = "connect"
    elif args.sU:
        scan_type = "udp"
    
    try:
        # Initialize scanner
        scanner = Scanner(
            target=args.target,
            ports=args.ports,
            scan_type=scan_type,
            threads=args.threads
        )
        
        # Perform scan
        results = scanner.scan()
        
        # Handle output
        if args.output:
            handler = OutputHandler(args.output, args.format)
            handler.save_results(results)
        else:
            # Print results to console
            print("\nScan Results:")
            print(f"Target: {results['target']}")
            print("\nOS Detection:")
            print(f"Detected OS: {results['os_detection']['os_detection']['combined']}")
            print(f"Confidence: {results['os_detection']['confidence']}")
            print("\nOpen Ports:")
            for port, info in results['ports'].items():
                if info['state'] == 'open':
                    print(f"Port {port}: {info['service']} - {info['banner']}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 