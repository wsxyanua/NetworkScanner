#!/usr/bin/env python3

import json
import csv
from datetime import datetime
from colorama import Fore, Style

class OutputHandler:
    def __init__(self, output_file=None, output_format='json'):
        self.output_file = output_file
        self.output_format = output_format
        self.results = {}

    def add_result(self, port, state, service='', banner=''):
        """Add scan result to results dictionary"""
        self.results[port] = {
            'state': state,
            'service': service,
            'banner': banner,
            'timestamp': datetime.now().isoformat()
        }

    def save_results(self):
        """Save results to file in specified format"""
        if not self.output_file:
            return

        if self.output_format == 'json':
            self._save_json()
        elif self.output_format == 'csv':
            self._save_csv()
        elif self.output_format == 'txt':
            self._save_txt()

    def _save_json(self):
        """Save results in JSON format"""
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=4)

    def _save_csv(self):
        """Save results in CSV format"""
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'State', 'Service', 'Banner', 'Timestamp'])
            for port, data in self.results.items():
                writer.writerow([
                    port,
                    data['state'],
                    data['service'],
                    data['banner'],
                    data['timestamp']
                ])

    def _save_txt(self):
        """Save results in TXT format"""
        with open(self.output_file, 'w') as f:
            for port, data in self.results.items():
                f.write(f"Port: {port}\n")
                f.write(f"State: {data['state']}\n")
                f.write(f"Service: {data['service']}\n")
                if data['banner']:
                    f.write(f"Banner: {data['banner']}\n")
                f.write(f"Timestamp: {data['timestamp']}\n")
                f.write("-" * 50 + "\n")

    def print_results(self):
        """Print results with color coding"""
        for port, data in self.results.items():
            if data['state'] == 'open':
                print(f"{Fore.GREEN}[+] Port {port} is {data['state']} - {data['service']}")
                if data['banner']:
                    print(f"{Fore.GREEN}    Banner: {data['banner']}{Style.RESET_ALL}")
            elif data['state'] == 'closed':
                print(f"{Fore.RED}[-] Port {port} is {data['state']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] Port {port} is {data['state']}{Style.RESET_ALL}") 