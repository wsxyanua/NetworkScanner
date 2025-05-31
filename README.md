# Network Scanner

A powerful and flexible network scanning tool written in Python, inspired by Nmap. This tool allows you to perform various types of network reconnaissance and port scanning with ease.

## Features

### Scanning Capabilities
- **TCP SYN Scan**: Fast and stealthy port scanning
- **TCP Connect Scan**: Full TCP connection scanning
- **UDP Scan**: UDP port scanning
- **Common Ports**: Quick scan of commonly used ports
- **Custom Port Ranges**: Scan specific ports or ranges

### Advanced Features
- **Multi-threaded Scanning**: Fast scanning with configurable thread count
- **Banner Grabbing**: Detect service banners on open ports
- **Multiple Output Formats**: JSON, CSV, and TXT output support
- **Color-coded Results**: Easy-to-read colored terminal output
- **Detailed Logging**: Comprehensive scan results with timestamps

### Performance & Usability
- **Configurable Timeouts**: Adjust scan timeouts for different networks
- **Progress Tracking**: Real-time scan progress and duration
- **Error Handling**: Robust error handling and reporting
- **Verbose Mode**: Detailed output for debugging

## Quick Start

### Installation
1. Clone the repository:
```bash
git clone https://github.com/username/NetworkScanner.git
cd NetworkScanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan common ports
sudo python src/scanner.py -t 192.168.1.1 -p common

# Scan specific ports
sudo python src/scanner.py -t 192.168.1.1 -p 80,443,8080

# Scan port range
sudo python src/scanner.py -t 192.168.1.1 -p 1-1000
```

### Advanced Usage
```bash
# TCP SYN scan with 100 threads
sudo python src/scanner.py -t 192.168.1.1 -p 1-1000 -sS -T 100

# TCP Connect scan with verbose output
sudo python src/scanner.py -t 192.168.1.1 -p 1-1000 -sT -v

# UDP scan with JSON output
sudo python src/scanner.py -t 192.168.1.1 -p 1-1000 -sU -o results.json -f json

# Scan network range
sudo python src/scanner.py -t 192.168.1.0/24 -p 80,443
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target IP address or network range |
| `-p, --ports` | Port range (e.g., 1-1000, 80,443,8080, common) |
| `-sS` | TCP SYN scan (stealth) |
| `-sT` | TCP Connect scan |
| `-sU` | UDP scan |
| `-v, --verbose` | Verbose output |
| `-T, --threads` | Number of threads (default: 50) |
| `-o, --output` | Output file for scan results |
| `-f, --format` | Output format (json, csv, txt) |

## Output Formats

### JSON Format
```json
{
    "80": {
        "state": "open",
        "service": "http",
        "banner": "HTTP/1.1 200 OK",
        "timestamp": "2024-03-14T12:00:00"
    }
}
```

### CSV Format
```csv
Port,State,Service,Banner,Timestamp
80,open,http,"HTTP/1.1 200 OK",2024-03-14T12:00:00
```

### TXT Format
```
Port: 80
State: open
Service: http
Banner: HTTP/1.1 200 OK
Timestamp: 2024-03-14T12:00:00
--------------------------------------------------
```

## Project Structure
```
NetworkScanner/
├── src/
│   ├── core/
│   │   ├── config.py
│   │   └── __init__.py
│   ├── utils/
│   │   ├── output_handler.py
│   │   └── __init__.py
│   ├── scanner.py
│   └── __init__.py
├── output/
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Security Notice

This tool is designed for educational and legitimate network testing purposes only. Always ensure you have proper authorization before scanning any network. Unauthorized scanning may be illegal and unethical.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 