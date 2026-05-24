"""Tests for the port scanner module."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from recon_agent.modules.port_scanner import (
    COMMON_PORTS,
    WELL_KNOWN_SERVICES,
    PortResult,
    ScanResult,
    _check_port,
    resolve_host,
    scan,
    socket_scan,
)


class TestResolveHost(unittest.TestCase):
    @patch("recon_agent.modules.port_scanner.socket.gethostbyname")
    def test_resolve_valid_host(self, mock_resolve):
        mock_resolve.return_value = "93.184.216.34"
        self.assertEqual(resolve_host("example.com"), "93.184.216.34")
        mock_resolve.assert_called_once_with("example.com")

    @patch("recon_agent.modules.port_scanner.socket.gethostbyname")
    def test_resolve_invalid_host(self, mock_resolve):
        mock_resolve.side_effect = socket.gaierror("Name resolution failed")
        self.assertIsNone(resolve_host("not-a-real-host.invalid"))


class TestCheckPort(unittest.TestCase):
    @patch("recon_agent.modules.port_scanner.socket.socket")
    def test_open_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.side_effect = socket.timeout

        result = _check_port("127.0.0.1", 80, timeout=0.5)

        self.assertIsNotNone(result)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.service, "HTTP")

    @patch("recon_agent.modules.port_scanner.socket.socket")
    def test_closed_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 111  # Connection refused

        result = _check_port("127.0.0.1", 9999, timeout=0.5)
        self.assertIsNone(result)

    @patch("recon_agent.modules.port_scanner.socket.socket")
    def test_timeout_returns_none(self, mock_socket_cls):
        mock_socket_cls.return_value.__enter__ = MagicMock(
            side_effect=socket.timeout("timed out")
        )
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = _check_port("127.0.0.1", 80, timeout=0.1)
        self.assertIsNone(result)


class TestSocketScan(unittest.TestCase):
    @patch("recon_agent.modules.port_scanner._check_port")
    @patch("recon_agent.modules.port_scanner.resolve_host")
    def test_scan_returns_open_ports(self, mock_resolve, mock_check):
        mock_resolve.return_value = "93.184.216.34"
        mock_check.side_effect = lambda ip, port, timeout: (
            PortResult(port=port, state="open", service="HTTP")
            if port == 80
            else None
        )

        result = socket_scan("example.com", ports=[80, 443], threads=2, timeout=0.5)

        self.assertEqual(result.target, "example.com")
        self.assertEqual(result.ip, "93.184.216.34")
        self.assertEqual(result.scan_type, "socket")
        self.assertEqual(len(result.ports), 1)
        self.assertEqual(result.ports[0].port, 80)

    @patch("recon_agent.modules.port_scanner.resolve_host")
    def test_scan_unresolvable_host(self, mock_resolve):
        mock_resolve.return_value = None
        result = socket_scan("bad-host.invalid", ports=[80])
        self.assertEqual(result.ip, "unresolved")
        self.assertEqual(len(result.ports), 0)


class TestScanDispatch(unittest.TestCase):
    @patch("recon_agent.modules.port_scanner.socket_scan")
    def test_scan_defaults_to_socket(self, mock_socket_scan):
        mock_socket_scan.return_value = ScanResult(target="t", ip="1.2.3.4")
        scan("example.com", use_nmap=False)
        mock_socket_scan.assert_called_once()

    @patch("recon_agent.modules.port_scanner.nmap_scan")
    def test_scan_uses_nmap_when_requested(self, mock_nmap):
        mock_nmap.return_value = ScanResult(target="t", ip="1.2.3.4", scan_type="nmap")
        result = scan("example.com", use_nmap=True)
        mock_nmap.assert_called_once()
        self.assertEqual(result.scan_type, "nmap")


class TestPortResultDataclass(unittest.TestCase):
    def test_defaults(self):
        pr = PortResult(port=443, state="open")
        self.assertEqual(pr.service, "")
        self.assertEqual(pr.version, "")

    def test_full_init(self):
        pr = PortResult(port=22, state="open", service="SSH", version="OpenSSH 8.9")
        self.assertEqual(pr.service, "SSH")
        self.assertEqual(pr.version, "OpenSSH 8.9")


class TestWellKnownServices(unittest.TestCase):
    def test_common_ports_have_services(self):
        for port in [22, 80, 443, 3306]:
            self.assertIn(port, WELL_KNOWN_SERVICES)

    def test_common_ports_list_not_empty(self):
        self.assertGreater(len(COMMON_PORTS), 10)


if __name__ == "__main__":
    unittest.main()
