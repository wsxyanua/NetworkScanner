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

from core.config import *
from utils.output_handler import OutputHandler

# Initialize colorama
init()

class AdvancedNetworkScanner:
    def __init__(self, target, ports, scan_type=DEFAULT_SCAN_TYPE, verbose=False, 
                 threads=DEFAULT_THREADS, output_file=None, output_format='json'):
        self.target = target
        self.ports = self._parse_ports(ports)
        self.scan_type = scan_type
        self.verbose = verbose
        self.threads = threads
        self.output_handler = OutputHandler(output_file, output_format)
        self.nm = nmap.PortScanner()
        self.port_queue = queue.Queue()
        self.lock = threading.Lock()
        self.start_time = None
        self.end_time = None

    def _parse_ports(self, ports):
        """Parse port range string into list of ports"""
        if ports == 'common':
            return COMMON_PORTS
        elif ',' in ports:
            return [int(p) for p in ports.split(',')]
        elif '-' in ports:
            start, end = map(int, ports.split('-'))
            return range(start, end + 1)
        else:
            return [int(ports)]

    def _get_banner(self, ip, port):
        """Get service banner from open port"""
        try:
            s = socket.socket()
            s.settimeout(DEFAULT_BANNER_TIMEOUT)
            s.connect((ip, port))
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
                if self.scan_type == 'sS':
                    self._syn_scan_port(port)
                elif self.scan_type == 'sT':
                    self._connect_scan_port(port)
                elif self.scan_type == 'sU':
                    self._udp_scan_port(port)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error scanning port {port}: {str(e)}{Style.RESET_ALL}")
            finally:
                self.port_queue.task_done()

    def _syn_scan_port(self, port):
        """Perform SYN scan on a single port"""
        ip = IP(dst=self.target)
        syn = TCP(dport=port, flags='S')
        syn_ack = sr1(ip/syn, timeout=DEFAULT_TIMEOUT, verbose=0)

        if syn_ack and syn_ack.haslayer(TCP):
            if syn_ack[TCP].flags == 0x12:  # SYN-ACK
                rst = TCP(dport=port, flags='R')
                send(ip/rst, verbose=0)
                banner = self._get_banner(self.target, port)
                self.output_handler.add_result(port, 'open', banner=banner)
            else:
                self.output_handler.add_result(port, 'closed')
        else:
            self.output_handler.add_result(port, 'filtered')

    def _connect_scan_port(self, port):
        """Perform Connect scan on a single port"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(DEFAULT_TIMEOUT)
            result = s.connect_ex((self.target, port))
            if result == 0:
                banner = self._get_banner(self.target, port)
                self.output_handler.add_result(port, 'open', banner=banner)
            else:
                self.output_handler.add_result(port, 'closed')
            s.close()
        except:
            self.output_handler.add_result(port, 'filtered')

    def _udp_scan_port(self, port):
        """Perform UDP scan on a single port"""
        try:
            self.nm.scan(self.target, arguments=f'-sU -p{port}')
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    state = self.nm[host][proto][port]['state']
                    service = self.nm[host][proto][port].get('name', '')
                    self.output_handler.add_result(port, state, service)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error during UDP scan: {str(e)}{Style.RESET_ALL}")

    def scan(self):
        """Main scanning method"""
        try:
            # Validate target
            ipaddress.ip_address(self.target)
            
            print(f"\n{Fore.CYAN}[*] Starting {SCAN_TYPES[self.scan_type]} on {self.target}")
            print(f"[*] Scanning {len(self.ports)} ports with {self.threads} threads{Style.RESET_ALL}\n")
            
            self.start_time = time.time()
            
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
            self.end_time = time.time()
            duration = self.end_time - self.start_time
            
            # Print results
            self.output_handler.print_results()
            
            print(f"\n{Fore.CYAN}[*] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
            
            # Save results if output file specified
            self.output_handler.save_results()

        except ValueError:
            print(f"{Fore.RED}[!] Invalid IP address: {self.target}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Scanner Tool')
    parser.add_argument('-t', '--target', required=True, help='Target IP address or network range')
    parser.add_argument('-p', '--ports', required=True, 
                      help='Port range (e.g., 1-1000, 80,443,8080, common for common ports)')
    parser.add_argument('-sS', action='store_true', help='TCP SYN scan')
    parser.add_argument('-sT', action='store_true', help='TCP Connect scan')
    parser.add_argument('-sU', action='store_true', help='UDP scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-T', '--threads', type=int, default=DEFAULT_THREADS, 
                      help=f'Number of threads (default: {DEFAULT_THREADS})')
    parser.add_argument('-o', '--output', help='Output file for scan results')
    parser.add_argument('-f', '--format', choices=OUTPUT_FORMATS, default='json',
                      help='Output format (default: json)')

    args = parser.parse_args()

    # Determine scan type
    scan_type = DEFAULT_SCAN_TYPE
    if args.sT:
        scan_type = 'sT'
    elif args.sU:
        scan_type = 'sU'

    scanner = AdvancedNetworkScanner(
        args.target,
        args.ports,
        scan_type,
        args.verbose,
        args.threads,
        args.output,
        args.format
    )
    scanner.scan()

if __name__ == '__main__':
    main() 