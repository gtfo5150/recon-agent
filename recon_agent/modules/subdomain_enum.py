"""Subdomain enumeration via certificate transparency logs and DNS brute-force."""

import concurrent.futures
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Set

import dns.resolver
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Common subdomain wordlist for brute-forcing
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "staging", "api",
    "app", "admin", "portal", "test", "vpn", "cdn", "cloud", "git", "gitlab",
    "jenkins", "jira", "confluence", "wiki", "docs", "support", "help", "forum",
    "store", "shop", "status", "monitor", "grafana", "kibana", "elastic", "redis",
    "db", "database", "mysql", "postgres", "mongo", "cache", "proxy", "gateway",
    "auth", "sso", "login", "register", "static", "assets", "media", "img",
    "images", "video", "files", "upload", "download", "backup", "old", "new",
    "beta", "alpha", "demo", "sandbox", "internal", "intranet", "extranet",
    "remote", "office", "exchange", "autodiscover", "owa", "cpanel", "whm",
    "plesk", "webdisk", "webhost", "m", "mobile", "secure", "ssl", "payment",
    "pay", "billing", "invoice", "crm", "erp", "hr", "marketing", "sales",
]


@dataclass
class SubdomainResult:
    subdomain: str
    ip: Optional[str] = None
    source: str = ""  # "crt.sh", "dns-brute", "both"


@dataclass
class EnumResult:
    domain: str
    subdomains: List[SubdomainResult] = field(default_factory=list)
    total_found: int = 0


def query_crtsh(domain: str) -> Set[str]:
    """Query crt.sh certificate transparency logs for subdomains."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        # Remove wildcard prefix
                        sub = sub.lstrip("*.")
                        if sub:
                            subdomains.add(sub)
    except Exception as e:
        console.print(f"[yellow]crt.sh query failed: {e}[/yellow]")
    return subdomains


def _resolve_subdomain(subdomain: str) -> Optional[str]:
    """Try to resolve a subdomain to an IP."""
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None


def _brute_check(domain: str, prefix: str) -> Optional[str]:
    """Check if a subdomain exists via DNS resolution."""
    fqdn = f"{prefix}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A")
        if answers:
            return fqdn
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, Exception):
        pass
    return None


def dns_bruteforce(domain: str, wordlist: Optional[List[str]] = None, threads: int = 20) -> Set[str]:
    """Brute-force subdomains using a wordlist and DNS resolution."""
    words = wordlist or COMMON_SUBDOMAINS
    found = set()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"DNS brute-force ({len(words)} prefixes)...", total=len(words))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(_brute_check, domain, prefix): prefix
                for prefix in words
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)
                progress.advance(task)

    return found


def enumerate(
    domain: str,
    use_crtsh: bool = True,
    use_bruteforce: bool = True,
    wordlist: Optional[List[str]] = None,
    threads: int = 20,
) -> EnumResult:
    """Enumerate subdomains for a given domain."""
    console.print(f"[cyan]Enumerating subdomains for: {domain}[/cyan]")
    all_subdomains: Set[str] = set()
    sources: dict = {}  # subdomain -> source

    # Certificate Transparency
    if use_crtsh:
        console.print("[dim]Querying crt.sh certificate transparency logs...[/dim]")
        crt_results = query_crtsh(domain)
        for sub in crt_results:
            sources[sub] = "crt.sh"
        all_subdomains.update(crt_results)
        console.print(f"  [green]crt.sh found {len(crt_results)} subdomains[/green]")

    # DNS Brute-force
    if use_bruteforce:
        console.print("[dim]Running DNS brute-force...[/dim]")
        brute_results = dns_bruteforce(domain, wordlist, threads)
        for sub in brute_results:
            if sub in sources:
                sources[sub] = "both"
            else:
                sources[sub] = "dns-brute"
        all_subdomains.update(brute_results)
        console.print(f"  [green]DNS brute-force found {len(brute_results)} subdomains[/green]")

    # Resolve IPs
    console.print("[dim]Resolving IP addresses...[/dim]")
    result = EnumResult(domain=domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(_resolve_subdomain, sub): sub
            for sub in sorted(all_subdomains)
        }
        for future in concurrent.futures.as_completed(future_map):
            sub = future_map[future]
            ip = future.result()
            result.subdomains.append(SubdomainResult(
                subdomain=sub,
                ip=ip,
                source=sources.get(sub, "unknown"),
            ))

    result.subdomains.sort(key=lambda s: s.subdomain)
    result.total_found = len(result.subdomains)
    return result
