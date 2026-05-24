"""Tests for the subdomain enumeration module."""

import socket
import unittest
from unittest.mock import MagicMock, patch

import dns.resolver

from recon_agent.modules.subdomain_enum import (
    COMMON_SUBDOMAINS,
    EnumResult,
    SubdomainResult,
    _brute_check,
    _resolve_subdomain,
    dns_bruteforce,
    enumerate,
    query_crtsh,
)


class TestQueryCrtsh(unittest.TestCase):
    @patch("recon_agent.modules.subdomain_enum.requests.get")
    def test_parses_crtsh_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com\napi.example.com"},
            {"name_value": "*.example.com"},
        ]
        mock_get.return_value = mock_resp

        results = query_crtsh("example.com")

        self.assertIn("www.example.com", results)
        self.assertIn("mail.example.com", results)
        self.assertIn("api.example.com", results)
        self.assertIn("example.com", results)  # wildcard stripped

    @patch("recon_agent.modules.subdomain_enum.requests.get")
    def test_handles_crtsh_failure(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")
        results = query_crtsh("example.com")
        self.assertEqual(len(results), 0)

    @patch("recon_agent.modules.subdomain_enum.requests.get")
    def test_handles_non_200(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp

        results = query_crtsh("example.com")
        self.assertEqual(len(results), 0)

    @patch("recon_agent.modules.subdomain_enum.requests.get")
    def test_filters_unrelated_domains(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "evil.other.com"},
        ]
        mock_get.return_value = mock_resp

        results = query_crtsh("example.com")
        self.assertIn("www.example.com", results)
        self.assertNotIn("evil.other.com", results)


class TestResolveSubdomain(unittest.TestCase):
    @patch("recon_agent.modules.subdomain_enum.socket.gethostbyname")
    def test_resolves_ip(self, mock_resolve):
        mock_resolve.return_value = "1.2.3.4"
        self.assertEqual(_resolve_subdomain("www.example.com"), "1.2.3.4")

    @patch("recon_agent.modules.subdomain_enum.socket.gethostbyname")
    def test_returns_none_on_failure(self, mock_resolve):
        mock_resolve.side_effect = socket.gaierror
        self.assertIsNone(_resolve_subdomain("nope.example.com"))


class TestBruteCheck(unittest.TestCase):
    @patch("recon_agent.modules.subdomain_enum.dns.resolver.resolve")
    def test_found_subdomain(self, mock_resolve):
        mock_resolve.return_value = [MagicMock()]
        result = _brute_check("example.com", "www")
        self.assertEqual(result, "www.example.com")

    @patch("recon_agent.modules.subdomain_enum.dns.resolver.resolve")
    def test_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        result = _brute_check("example.com", "nonexistent")
        self.assertIsNone(result)

    @patch("recon_agent.modules.subdomain_enum.dns.resolver.resolve")
    def test_timeout(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.Timeout
        result = _brute_check("example.com", "slow")
        self.assertIsNone(result)


class TestDnsBruteforce(unittest.TestCase):
    @patch("recon_agent.modules.subdomain_enum._brute_check")
    def test_returns_found_subdomains(self, mock_check):
        mock_check.side_effect = lambda d, p: f"{p}.{d}" if p in ("www", "api") else None

        results = dns_bruteforce("example.com", wordlist=["www", "api", "nope"], threads=2)
        self.assertEqual(len(results), 2)
        self.assertIn("www.example.com", results)
        self.assertIn("api.example.com", results)

    @patch("recon_agent.modules.subdomain_enum._brute_check")
    def test_empty_when_none_found(self, mock_check):
        mock_check.return_value = None
        results = dns_bruteforce("example.com", wordlist=["a", "b"], threads=2)
        self.assertEqual(len(results), 0)


class TestEnumerate(unittest.TestCase):
    @patch("recon_agent.modules.subdomain_enum._resolve_subdomain")
    @patch("recon_agent.modules.subdomain_enum.dns_bruteforce")
    @patch("recon_agent.modules.subdomain_enum.query_crtsh")
    def test_combines_sources(self, mock_crt, mock_brute, mock_resolve):
        mock_crt.return_value = {"www.example.com", "mail.example.com"}
        mock_brute.return_value = {"www.example.com", "api.example.com"}
        mock_resolve.return_value = "1.2.3.4"

        result = enumerate("example.com")

        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.total_found, 3)
        names = {s.subdomain for s in result.subdomains}
        self.assertEqual(names, {"www.example.com", "mail.example.com", "api.example.com"})

    @patch("recon_agent.modules.subdomain_enum._resolve_subdomain")
    @patch("recon_agent.modules.subdomain_enum.dns_bruteforce")
    @patch("recon_agent.modules.subdomain_enum.query_crtsh")
    def test_source_tracking(self, mock_crt, mock_brute, mock_resolve):
        mock_crt.return_value = {"www.example.com"}
        mock_brute.return_value = {"www.example.com", "api.example.com"}
        mock_resolve.return_value = "1.2.3.4"

        result = enumerate("example.com")

        source_map = {s.subdomain: s.source for s in result.subdomains}
        self.assertEqual(source_map["www.example.com"], "both")
        self.assertEqual(source_map["api.example.com"], "dns-brute")

    @patch("recon_agent.modules.subdomain_enum.query_crtsh")
    def test_crtsh_only(self, mock_crt):
        mock_crt.return_value = {"www.example.com"}

        with patch("recon_agent.modules.subdomain_enum._resolve_subdomain", return_value="1.2.3.4"):
            result = enumerate("example.com", use_bruteforce=False)

        self.assertEqual(result.total_found, 1)


class TestDataclasses(unittest.TestCase):
    def test_subdomain_result_defaults(self):
        sr = SubdomainResult(subdomain="www.example.com")
        self.assertIsNone(sr.ip)
        self.assertEqual(sr.source, "")

    def test_enum_result_defaults(self):
        er = EnumResult(domain="example.com")
        self.assertEqual(er.subdomains, [])
        self.assertEqual(er.total_found, 0)

    def test_common_subdomains_not_empty(self):
        self.assertGreater(len(COMMON_SUBDOMAINS), 50)
        self.assertIn("www", COMMON_SUBDOMAINS)
        self.assertIn("api", COMMON_SUBDOMAINS)


if __name__ == "__main__":
    unittest.main()
