# Recon Agent

Ethical hacking reconnaissance CLI tool. Performs port scanning, subdomain enumeration, and OSINT gathering on authorized targets.

> **⚠ Legal Disclaimer:** Only use this tool on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal under the CFAA and similar laws.

## Features

- **Port Scanning** — Multithreaded TCP connect scan with banner grabbing; optional nmap integration for service/version detection
- **Subdomain Enumeration** — Certificate Transparency logs (crt.sh) + DNS brute-force with 100+ common prefixes
- **OSINT Gathering** — WHOIS registration data, DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA), HTTP header analysis, and technology fingerprinting (WordPress, React, Cloudflare, and more)
- **Reporting** — Rich formatted terminal output + timestamped JSON report export

## Requirements

- Python 3.8+
- macOS, Linux, or Windows
- (Optional) [nmap](https://nmap.org/) for advanced port scanning

## Installation

### From source

```bash
git clone https://github.com/gtfo5150/recon-agent.git
cd recon-agent
pip3 install -e .
```

This installs the `recon-agent` command globally. If it's not on your PATH, add the pip scripts directory:

```bash
# macOS (system Python)
export PATH="$HOME/Library/Python/3.9/bin:$PATH"

# Or use a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Optional: Install nmap

```bash
# macOS
brew install nmap

# Debian/Ubuntu
sudo apt install nmap

# Fedora/RHEL
sudo dnf install nmap
```

Without nmap, the tool uses built-in socket-based scanning which works out of the box.

## Quick Start

```bash
# Full recon scan (OSINT → Subdomains → Ports → JSON report)
recon-agent scan example.com

# Port scan only
recon-agent portscan example.com

# Subdomain enumeration only
recon-agent subdomains example.com

# OSINT only
recon-agent osint example.com
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Full reconnaissance scan (all phases) |
| `portscan` | Port scanning only |
| `subdomains` | Subdomain enumeration only |
| `osint` | OSINT gathering only (WHOIS, DNS, HTTP) |

### `scan` — Full Reconnaissance

Runs all three phases in order: OSINT → Subdomain Enumeration → Port Scanning, then exports a JSON report.

```bash
recon-agent scan <target> [OPTIONS]
```

**Options:**

```
-p, --ports TEXT       Comma-separated ports to scan (default: common ports)
-t, --threads INT      Number of threads (default: 50)
    --timeout FLOAT    Socket timeout in seconds (default: 1.5)
    --nmap             Use nmap instead of socket scanning
    --nmap-args TEXT   Arguments for nmap (default: "-sV -sC")
    --no-ports         Skip port scanning phase
    --no-subdomains    Skip subdomain enumeration phase
    --no-osint         Skip OSINT gathering phase
    --no-crtsh         Skip crt.sh certificate transparency lookup
    --no-bruteforce    Skip DNS brute-force enumeration
    --no-whois         Skip WHOIS lookup
    --no-dns           Skip DNS record queries
    --no-http          Skip HTTP header probe
    --no-report        Skip JSON report generation
-o, --output PATH      Output file path for JSON report
```

**Examples:**

```bash
# Basic full scan
recon-agent scan example.com

# Scan with nmap on specific ports
recon-agent scan example.com --nmap --ports 80,443,8080,8443

# OSINT + subdomains only (skip port scanning)
recon-agent scan example.com --no-ports

# Fast scan: crt.sh + ports only, no brute-force or WHOIS
recon-agent scan example.com --no-bruteforce --no-whois

# Save report to specific file
recon-agent scan example.com -o ~/reports/target_report.json

# High-performance scan with more threads
recon-agent scan example.com --threads 100 --timeout 2.0
```

### `portscan` — Port Scanning

```bash
recon-agent portscan <target> [OPTIONS]
```

```bash
# Scan common ports using built-in socket scanner
recon-agent portscan example.com

# Scan specific ports
recon-agent portscan example.com --ports 22,80,443,3306,5432

# Use nmap for service version detection
recon-agent portscan example.com --nmap
```

### `subdomains` — Subdomain Enumeration

```bash
recon-agent subdomains <domain> [OPTIONS]
```

```bash
# Full enumeration (crt.sh + DNS brute-force)
recon-agent subdomains example.com

# Certificate transparency only (faster)
recon-agent subdomains example.com --no-bruteforce

# DNS brute-force only
recon-agent subdomains example.com --no-crtsh
```

### `osint` — OSINT Gathering

```bash
recon-agent osint <target> [OPTIONS]
```

```bash
# Full OSINT (WHOIS + DNS + HTTP)
recon-agent osint example.com

# DNS records only
recon-agent osint example.com --no-whois --no-http

# HTTP technology fingerprinting only
recon-agent osint example.com --no-whois --no-dns
```

## Output

### Terminal

Results are displayed as rich formatted tables with color-coded output:
- Open ports with service names and banners
- Subdomains with resolved IPs and discovery source
- WHOIS registration details in a panel
- DNS records in a table
- HTTP headers with detected technologies

### JSON Report

By default, `scan` exports a timestamped JSON report:

```
recon_example_com_20260524_160000.json
```

Report structure:

```json
{
  "target": "example.com",
  "timestamp": "2026-05-24T16:00:00+00:00",
  "results": {
    "osint": {
      "whois_info": { "domain_name": "...", "registrar": "..." },
      "dns_records": [{ "record_type": "A", "values": ["..."] }],
      "http_info": { "server": "...", "technologies": ["..."] }
    },
    "subdomains": {
      "domain": "example.com",
      "total_found": 42,
      "subdomains": [{ "subdomain": "www.example.com", "ip": "..." }]
    },
    "port_scan": {
      "target": "example.com",
      "ip": "93.184.216.34",
      "ports": [{ "port": 80, "state": "open", "service": "HTTP" }]
    }
  }
}
```

## Project Structure

```
recon-agent/
├── README.md
├── setup.py
├── requirements.txt
├── .gitignore
├── recon_agent/
│   ├── __init__.py
│   ├── cli.py              # Click CLI entry point
│   ├── agent.py            # Main orchestrator
│   ├── modules/
│   │   ├── port_scanner.py  # TCP/nmap port scanning
│   │   ├── subdomain_enum.py # crt.sh + DNS brute-force
│   │   └── osint.py         # WHOIS, DNS, HTTP, tech detection
│   └── reporting/
│       └── reporter.py      # Rich display + JSON export
└── tests/
    ├── test_port_scanner.py
    ├── test_subdomain_enum.py
    ├── test_osint.py
    └── test_reporter.py
```

## Testing

All network calls are mocked, so tests run fully offline.

```bash
pip install pytest
python3 -m pytest tests -v
```

```
57 passed in 0.14s
```

## License

MIT
