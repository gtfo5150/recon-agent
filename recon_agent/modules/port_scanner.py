"""Port scanning module with socket-based fallback and optional nmap integration."""

import socket
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Common ports to scan when no specific range is given
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017,
]

WELL_KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "HTTP-Alt", 27017: "MongoDB",
}


@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""
    version: str = ""


@dataclass
class ScanResult:
    target: str
    ip: str
    ports: List[PortResult] = field(default_factory=list)
    scan_type: str = "socket"  # "socket" or "nmap"


def resolve_host(target: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _check_port(target: str, port: int, timeout: float = 1.5) -> Optional[PortResult]:
    """Check if a single port is open using a TCP socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = WELL_KNOWN_SERVICES.get(port, "unknown")
                # Try to grab the banner
                banner = ""
                try:
                    sock.settimeout(2)
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        banner = banner.split("\n")[0][:80]
                except Exception:
                    pass
                return PortResult(port=port, state="open", service=service, version=banner)
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def socket_scan(
    target: str, ports: Optional[List[int]] = None, threads: int = 50, timeout: float = 1.5
) -> ScanResult:
    """Scan ports using raw sockets (no nmap required)."""
    ip = resolve_host(target)
    if not ip:
        console.print(f"[red]Could not resolve host: {target}[/red]")
        return ScanResult(target=target, ip="unresolved")

    scan_ports = ports or COMMON_PORTS
    result = ScanResult(target=target, ip=ip, scan_type="socket")

    console.print(f"[cyan]Scanning {target} ({ip}) — {len(scan_ports)} ports (socket mode)[/cyan]")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning ports...", total=len(scan_ports))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(_check_port, ip, port, timeout): port
                for port in scan_ports
            }
            for future in concurrent.futures.as_completed(futures):
                port_result = future.result()
                if port_result:
                    result.ports.append(port_result)
                progress.advance(task)

    result.ports.sort(key=lambda p: p.port)
    return result


def nmap_scan(
    target: str, ports: Optional[List[int]] = None, scan_args: str = "-sV -sC"
) -> ScanResult:
    """Scan using nmap (requires nmap to be installed)."""
    try:
        import nmap
    except ImportError:
        console.print("[yellow]python-nmap not installed. Falling back to socket scan.[/yellow]")
        return socket_scan(target, ports)

    ip = resolve_host(target)
    if not ip:
        console.print(f"[red]Could not resolve host: {target}[/red]")
        return ScanResult(target=target, ip="unresolved")

    port_arg = ",".join(str(p) for p in ports) if ports else ",".join(str(p) for p in COMMON_PORTS)
    console.print(f"[cyan]Scanning {target} ({ip}) with nmap ({scan_args})[/cyan]")

    nm = nmap.PortScanner()
    try:
        nm.scan(ip, port_arg, arguments=scan_args)
    except nmap.PortScannerError as e:
        console.print(f"[red]nmap error: {e}. Falling back to socket scan.[/red]")
        return socket_scan(target, ports)

    result = ScanResult(target=target, ip=ip, scan_type="nmap")

    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in sorted(nm[ip][proto].keys()):
                info = nm[ip][proto][port]
                result.ports.append(PortResult(
                    port=port,
                    state=info.get("state", "unknown"),
                    service=info.get("name", "unknown"),
                    version=f"{info.get('product', '')} {info.get('version', '')}".strip(),
                ))

    return result


def scan(
    target: str,
    ports: Optional[List[int]] = None,
    use_nmap: bool = False,
    scan_args: str = "-sV -sC",
    threads: int = 50,
    timeout: float = 1.5,
) -> ScanResult:
    """Run a port scan on the target. Uses nmap if requested, otherwise sockets."""
    if use_nmap:
        return nmap_scan(target, ports, scan_args)
    return socket_scan(target, ports, threads, timeout)
