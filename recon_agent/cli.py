"""CLI entry point for Recon Agent."""

import click

from recon_agent.agent import ReconConfig, run


@click.group()
@click.version_option(version="0.1.0", prog_name="recon-agent")
def cli():
    """Recon Agent — Ethical Hacking Reconnaissance Toolkit.

    Only use on systems you own or have explicit written authorization to test.
    """


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default=None, help="Comma-separated ports to scan (default: common ports).")
@click.option("--nmap", "use_nmap", is_flag=True, default=False, help="Use nmap instead of socket scanning.")
@click.option("--nmap-args", default="-sV -sC", help="Arguments for nmap scan.")
@click.option("--threads", "-t", default=50, help="Number of threads for scanning.")
@click.option("--timeout", default=1.5, help="Socket timeout in seconds.")
@click.option("--no-ports", is_flag=True, default=False, help="Skip port scanning.")
@click.option("--no-subdomains", is_flag=True, default=False, help="Skip subdomain enumeration.")
@click.option("--no-osint", is_flag=True, default=False, help="Skip OSINT gathering.")
@click.option("--no-crtsh", is_flag=True, default=False, help="Skip crt.sh lookup.")
@click.option("--no-bruteforce", is_flag=True, default=False, help="Skip DNS brute-force.")
@click.option("--no-whois", is_flag=True, default=False, help="Skip WHOIS lookup.")
@click.option("--no-dns", is_flag=True, default=False, help="Skip DNS record lookup.")
@click.option("--no-http", is_flag=True, default=False, help="Skip HTTP probe.")
@click.option("--no-report", is_flag=True, default=False, help="Skip JSON report generation.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
def scan(target, ports, use_nmap, nmap_args, threads, timeout,
         no_ports, no_subdomains, no_osint, no_crtsh, no_bruteforce,
         no_whois, no_dns, no_http, no_report, output):
    """Run a full reconnaissance scan on TARGET (domain or IP).

    Examples:

        recon-agent scan example.com

        recon-agent scan example.com --nmap --ports 80,443,8080

        recon-agent scan example.com --no-ports --no-bruteforce
    """
    port_list = None
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            click.echo("Error: --ports must be comma-separated integers.", err=True)
            raise SystemExit(1)

    config = ReconConfig(
        target=target,
        do_port_scan=not no_ports,
        use_nmap=use_nmap,
        ports=port_list,
        scan_threads=threads,
        scan_timeout=timeout,
        nmap_args=nmap_args,
        do_subdomain_enum=not no_subdomains,
        use_crtsh=not no_crtsh,
        use_bruteforce=not no_bruteforce,
        enum_threads=threads,
        do_osint=not no_osint,
        do_whois=not no_whois,
        do_dns=not no_dns,
        do_http=not no_http,
        export_report=not no_report,
        output_path=output,
    )

    run(config)


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default=None, help="Comma-separated ports to scan.")
@click.option("--nmap", "use_nmap", is_flag=True, default=False, help="Use nmap.")
@click.option("--threads", "-t", default=50, help="Number of threads.")
@click.option("--timeout", default=1.5, help="Socket timeout in seconds.")
def portscan(target, ports, use_nmap, threads, timeout):
    """Run only a port scan on TARGET."""
    from recon_agent.modules import port_scanner
    from recon_agent.reporting.reporter import display_port_scan

    port_list = None
    if ports:
        port_list = [int(p.strip()) for p in ports.split(",")]

    result = port_scanner.scan(target, ports=port_list, use_nmap=use_nmap,
                               threads=threads, timeout=timeout)
    display_port_scan(result)


@cli.command()
@click.argument("domain")
@click.option("--no-crtsh", is_flag=True, default=False, help="Skip crt.sh.")
@click.option("--no-bruteforce", is_flag=True, default=False, help="Skip DNS brute-force.")
@click.option("--threads", "-t", default=20, help="Number of threads.")
def subdomains(domain, no_crtsh, no_bruteforce, threads):
    """Enumerate subdomains for DOMAIN."""
    from recon_agent.modules import subdomain_enum
    from recon_agent.reporting.reporter import display_subdomains

    result = subdomain_enum.enumerate(domain, use_crtsh=not no_crtsh,
                                      use_bruteforce=not no_bruteforce, threads=threads)
    display_subdomains(result)


@cli.command()
@click.argument("target")
@click.option("--no-whois", is_flag=True, default=False, help="Skip WHOIS.")
@click.option("--no-dns", is_flag=True, default=False, help="Skip DNS records.")
@click.option("--no-http", is_flag=True, default=False, help="Skip HTTP probe.")
def osint(target, no_whois, no_dns, no_http):
    """Gather OSINT (WHOIS, DNS, HTTP) for TARGET."""
    from recon_agent.modules import osint as osint_mod
    from recon_agent.reporting.reporter import display_osint

    result = osint_mod.gather(target, do_whois=not no_whois,
                              do_dns=not no_dns, do_http=not no_http)
    display_osint(result)


def main():
    cli()


if __name__ == "__main__":
    main()
