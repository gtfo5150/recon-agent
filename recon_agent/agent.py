"""Main reconnaissance agent — orchestrates all modules."""

from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel

from recon_agent.modules import port_scanner, subdomain_enum, osint
from recon_agent.modules.port_scanner import ScanResult
from recon_agent.modules.subdomain_enum import EnumResult
from recon_agent.modules.osint import OsintResult
from recon_agent.reporting.reporter import (
    display_port_scan,
    display_subdomains,
    display_osint,
    export_json,
)

console = Console()

BANNER = r"""
    ____                           ___                    __
   / __ \___  _________  ____     /   | ____ ____  ____  / /_
  / /_/ / _ \/ ___/ __ \/ __ \   / /| |/ __ `/ _ \/ __ \/ __/
 / _, _/  __/ /__/ /_/ / / / /  / ___ / /_/ /  __/ / / / /_
/_/ |_|\___/\___/\____/_/ /_/  /_/  |_\__, /\___/_/ /_/\__/
                                     /____/
    Ethical Reconnaissance Toolkit v0.1
"""


@dataclass
class ReconConfig:
    """Configuration for a reconnaissance run."""
    target: str
    # Port scanning
    do_port_scan: bool = True
    use_nmap: bool = False
    ports: Optional[List[int]] = None
    scan_threads: int = 50
    scan_timeout: float = 1.5
    nmap_args: str = "-sV -sC"
    # Subdomain enumeration
    do_subdomain_enum: bool = True
    use_crtsh: bool = True
    use_bruteforce: bool = True
    enum_threads: int = 20
    # OSINT
    do_osint: bool = True
    do_whois: bool = True
    do_dns: bool = True
    do_http: bool = True
    # Output
    export_report: bool = True
    output_path: Optional[str] = None


def run(config: ReconConfig) -> dict:
    """Run a full reconnaissance scan based on the config."""
    console.print(Panel(BANNER, style="cyan", expand=False))
    console.print(f"\n[bold]Target:[/bold] {config.target}\n")

    # Disclaimer
    console.print(
        "[yellow]⚠  DISCLAIMER: Only use this tool on systems you own or have "
        "explicit written authorization to test. Unauthorized scanning is illegal.[/yellow]\n"
    )

    results = {
        "port_scan": None,
        "subdomains": None,
        "osint": None,
    }

    # 1. OSINT Gathering
    if config.do_osint:
        console.rule("[bold blue]Phase 1: OSINT Gathering[/bold blue]")
        osint_result = osint.gather(
            config.target,
            do_whois=config.do_whois,
            do_dns=config.do_dns,
            do_http=config.do_http,
        )
        results["osint"] = osint_result
        display_osint(osint_result)
        console.print()

    # 2. Subdomain Enumeration
    if config.do_subdomain_enum:
        console.rule("[bold blue]Phase 2: Subdomain Enumeration[/bold blue]")
        enum_result = subdomain_enum.enumerate(
            config.target,
            use_crtsh=config.use_crtsh,
            use_bruteforce=config.use_bruteforce,
            threads=config.enum_threads,
        )
        results["subdomains"] = enum_result
        display_subdomains(enum_result)
        console.print()

    # 3. Port Scanning
    if config.do_port_scan:
        console.rule("[bold blue]Phase 3: Port Scanning[/bold blue]")
        scan_result = port_scanner.scan(
            config.target,
            ports=config.ports,
            use_nmap=config.use_nmap,
            scan_args=config.nmap_args,
            threads=config.scan_threads,
            timeout=config.scan_timeout,
        )
        results["port_scan"] = scan_result
        display_port_scan(scan_result)
        console.print()

    # 4. Export Report
    if config.export_report:
        console.rule("[bold blue]Report[/bold blue]")
        export_json(
            target=config.target,
            port_scan=results["port_scan"],
            subdomains=results["subdomains"],
            osint=results["osint"],
            output_path=config.output_path,
        )

    console.print("\n[bold green]✓ Reconnaissance complete.[/bold green]")
    return results
