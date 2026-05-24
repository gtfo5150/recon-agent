"""Report generation — JSON export and rich console display."""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from recon_agent.modules.port_scanner import ScanResult
from recon_agent.modules.subdomain_enum import EnumResult
from recon_agent.modules.osint import OsintResult

console = Console()


def display_port_scan(result: ScanResult) -> None:
    """Pretty-print port scan results."""
    if not result.ports:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    table = Table(title=f"Open Ports — {result.target} ({result.ip})", show_lines=False)
    table.add_column("Port", style="cyan", width=8)
    table.add_column("State", style="green", width=10)
    table.add_column("Service", style="yellow", width=15)
    table.add_column("Version / Banner", style="dim", max_width=50)

    for port in result.ports:
        table.add_row(str(port.port), port.state, port.service, port.version or "")

    console.print(table)
    console.print(f"\n[dim]Scan type: {result.scan_type} | Open ports: {len(result.ports)}[/dim]")


def display_subdomains(result: EnumResult) -> None:
    """Pretty-print subdomain enumeration results."""
    if not result.subdomains:
        console.print("[yellow]No subdomains found.[/yellow]")
        return

    table = Table(title=f"Subdomains — {result.domain}", show_lines=False)
    table.add_column("Subdomain", style="cyan", min_width=30)
    table.add_column("IP Address", style="green", width=18)
    table.add_column("Source", style="dim", width=12)

    for sub in result.subdomains:
        table.add_row(sub.subdomain, sub.ip or "[dim]unresolved[/dim]", sub.source)

    console.print(table)
    console.print(f"\n[dim]Total subdomains found: {result.total_found}[/dim]")


def display_osint(result: OsintResult) -> None:
    """Pretty-print OSINT results."""
    # WHOIS
    if result.whois_info:
        w = result.whois_info
        whois_lines = []
        if w.domain_name:
            whois_lines.append(f"Domain:      {w.domain_name}")
        if w.registrar:
            whois_lines.append(f"Registrar:   {w.registrar}")
        if w.creation_date:
            whois_lines.append(f"Created:     {w.creation_date}")
        if w.expiration_date:
            whois_lines.append(f"Expires:     {w.expiration_date}")
        if w.registrant_org:
            whois_lines.append(f"Org:         {w.registrant_org}")
        if w.registrant_country:
            whois_lines.append(f"Country:     {w.registrant_country}")
        if w.name_servers:
            whois_lines.append(f"Nameservers: {', '.join(w.name_servers[:4])}")
        if w.emails:
            whois_lines.append(f"Emails:      {', '.join(w.emails[:4])}")

        if whois_lines:
            console.print(Panel("\n".join(whois_lines), title="WHOIS", border_style="blue"))

    # DNS Records
    if result.dns_records:
        table = Table(title="DNS Records", show_lines=False)
        table.add_column("Type", style="cyan", width=8)
        table.add_column("Values", style="green")

        for rec in result.dns_records:
            table.add_row(rec.record_type, "\n".join(rec.values[:5]))

        console.print(table)

    # HTTP Info
    if result.http_info:
        h = result.http_info
        http_lines = [
            f"URL:          {h.url}",
            f"Status:       {h.status_code}",
            f"Server:       {h.server or 'N/A'}",
        ]
        if h.technologies:
            http_lines.append(f"Technologies: {', '.join(h.technologies)}")
        if h.redirect_chain:
            http_lines.append(f"Redirects:    {' → '.join(h.redirect_chain[:5])}")

        console.print(Panel("\n".join(http_lines), title="HTTP Probe", border_style="green"))


def export_json(
    target: str,
    port_scan: Optional[ScanResult] = None,
    subdomains: Optional[EnumResult] = None,
    osint: Optional[OsintResult] = None,
    output_path: Optional[str] = None,
) -> str:
    """Export all results to a JSON file."""
    report = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": {},
    }

    if port_scan:
        report["results"]["port_scan"] = asdict(port_scan)
    if subdomains:
        report["results"]["subdomains"] = asdict(subdomains)
    if osint:
        # Remove raw WHOIS to keep JSON clean
        osint_dict = asdict(osint)
        if osint_dict.get("whois_info"):
            osint_dict["whois_info"].pop("raw", None)
        report["results"]["osint"] = osint_dict

    if not output_path:
        safe_target = target.replace(".", "_").replace("/", "_")
        output_path = f"recon_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    path = Path(output_path)
    path.write_text(json.dumps(report, indent=2, default=str))
    console.print(f"\n[green]Report saved to: {path.absolute()}[/green]")
    return str(path.absolute())
