"""OSINT module — WHOIS, DNS records, HTTP headers, and technology detection."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import dns.resolver
import requests
import whois
from rich.console import Console

console = Console()


@dataclass
class DnsRecord:
    record_type: str
    values: List[str] = field(default_factory=list)


@dataclass
class WhoisInfo:
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    emails: List[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class HttpInfo:
    url: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)


@dataclass
class OsintResult:
    target: str
    whois_info: Optional[WhoisInfo] = None
    dns_records: List[DnsRecord] = field(default_factory=list)
    http_info: Optional[HttpInfo] = None


# Common HTTP headers that reveal technologies
TECH_HEADERS = {
    "x-powered-by": lambda v: v,
    "server": lambda v: v,
    "x-aspnet-version": lambda v: f"ASP.NET {v}",
    "x-drupal-cache": lambda _: "Drupal",
    "x-generator": lambda v: v,
    "x-shopify-stage": lambda _: "Shopify",
    "x-wix-request-id": lambda _: "Wix",
    "cf-ray": lambda _: "Cloudflare",
    "x-amz-cf-id": lambda _: "AWS CloudFront",
    "x-vercel-id": lambda _: "Vercel",
    "x-netlify-request-id": lambda _: "Netlify",
    "fly-request-id": lambda _: "Fly.io",
}


def lookup_whois(domain: str) -> Optional[WhoisInfo]:
    """Perform a WHOIS lookup on the domain."""
    console.print(f"[dim]Looking up WHOIS for {domain}...[/dim]")
    try:
        w = whois.whois(domain)
        info = WhoisInfo(raw=str(w))

        info.domain_name = _first_or_str(w.domain_name)
        info.registrar = w.registrar
        info.creation_date = str(_first_or_str(w.creation_date)) if w.creation_date else None
        info.expiration_date = str(_first_or_str(w.expiration_date)) if w.expiration_date else None
        info.updated_date = str(_first_or_str(w.updated_date)) if w.updated_date else None
        info.registrant_org = getattr(w, "org", None)
        info.registrant_country = getattr(w, "country", None)

        if w.name_servers:
            ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            info.name_servers = [str(n).lower() for n in ns]

        if w.emails:
            emails = w.emails if isinstance(w.emails, list) else [w.emails]
            info.emails = [str(e) for e in emails]

        return info
    except Exception as e:
        console.print(f"[yellow]WHOIS lookup failed: {e}[/yellow]")
        return None


def lookup_dns(domain: str) -> List[DnsRecord]:
    """Query common DNS record types for a domain."""
    console.print(f"[dim]Querying DNS records for {domain}...[/dim]")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    records = []

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            values = [str(rdata) for rdata in answers]
            if values:
                records.append(DnsRecord(record_type=rtype, values=values))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.resolver.Timeout, Exception):
            pass

    return records


def probe_http(target: str) -> Optional[HttpInfo]:
    """Probe HTTP/HTTPS endpoints for headers and technology fingerprints."""
    console.print(f"[dim]Probing HTTP headers for {target}...[/dim]")

    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "ReconAgent/0.1"})
            info = HttpInfo(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                redirect_chain=[r.url for r in resp.history],
            )

            # Detect technologies from headers
            for header, extractor in TECH_HEADERS.items():
                value = resp.headers.get(header)
                if value:
                    tech = extractor(value)
                    if tech and tech not in info.technologies:
                        info.technologies.append(tech)

            info.server = resp.headers.get("server", "")

            # Check for common meta patterns in HTML
            content_type = resp.headers.get("content-type", "")
            if "text/html" in content_type:
                body = resp.text[:10000].lower()
                _detect_from_html(body, info)

            return info
        except requests.RequestException:
            continue

    return None


def _detect_from_html(body: str, info: HttpInfo) -> None:
    """Detect technologies from HTML body content."""
    patterns = {
        "wp-content": "WordPress",
        "joomla": "Joomla",
        "drupal": "Drupal",
        "react": "React",
        "angular": "Angular",
        "vue.js": "Vue.js",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "bootstrap": "Bootstrap",
        "tailwind": "Tailwind CSS",
        "jquery": "jQuery",
        "google-analytics": "Google Analytics",
        "gtag": "Google Tag Manager",
    }
    for pattern, name in patterns.items():
        if pattern in body and name not in info.technologies:
            info.technologies.append(name)


def _first_or_str(value: Any) -> Optional[str]:
    """Return the first item if list, otherwise the value as string."""
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value) if value else None


def gather(target: str, do_whois: bool = True, do_dns: bool = True, do_http: bool = True) -> OsintResult:
    """Gather all OSINT data for a target domain."""
    console.print(f"[cyan]Gathering OSINT for: {target}[/cyan]")
    result = OsintResult(target=target)

    if do_whois:
        result.whois_info = lookup_whois(target)

    if do_dns:
        result.dns_records = lookup_dns(target)

    if do_http:
        result.http_info = probe_http(target)

    return result
