# Recon Agent

Ethical hacking reconnaissance CLI tool. Performs port scanning, subdomain enumeration, and OSINT gathering on authorized targets.

> **⚠ Legal Disclaimer:** Only use this tool on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal under the CFAA and similar laws.

## Setup (macOS)

### 1. Install Python dependencies

```bash
cd ~/recon-agent
pip3 install -e .
```

### 2. (Optional) Install nmap for advanced port scanning

```bash
brew install nmap
```

Without nmap, the tool uses built-in socket-based scanning which works out of the box.

## Usage

### Full reconnaissance scan

```bash
recon-agent scan example.com
```

This runs all three phases: OSINT → Subdomain Enumeration → Port Scanning, then exports a JSON report.

### Individual modules

```bash
# Port scan only
recon-agent portscan example.com
recon-agent portscan example.com --ports 80,443,8080 --nmap

# Subdomain enumeration only
recon-agent subdomains example.com

# OSINT only (WHOIS + DNS + HTTP headers)
recon-agent osint example.com
```

### Options

```bash
# Skip specific phases
recon-agent scan example.com --no-ports          # skip port scanning
recon-agent scan example.com --no-subdomains     # skip subdomain enum
recon-agent scan example.com --no-osint          # skip OSINT

# Skip specific sub-modules
recon-agent scan example.com --no-bruteforce     # skip DNS brute-force
recon-agent scan example.com --no-crtsh          # skip crt.sh lookup
recon-agent scan example.com --no-whois          # skip WHOIS

# Custom output
recon-agent scan example.com -o report.json

# Use nmap with custom args
recon-agent scan example.com --nmap --nmap-args "-sV -A"

# Adjust threads and timeout
recon-agent scan example.com --threads 100 --timeout 2.0
```

## Modules

- **Port Scanner** — TCP connect scan with banner grabbing (socket-based), optional nmap integration for service/version detection
- **Subdomain Enumeration** — Certificate Transparency logs (crt.sh) + DNS brute-force with 100+ common prefixes
- **OSINT** — WHOIS registration data, DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA), HTTP header analysis, and technology fingerprinting

## Output

Results are displayed as rich formatted tables in the terminal and exported to a timestamped JSON report file.
