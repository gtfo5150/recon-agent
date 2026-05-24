"""Tests for the OSINT module."""

import unittest
from unittest.mock import MagicMock, patch

import dns.resolver

from recon_agent.modules.osint import (
    DnsRecord,
    HttpInfo,
    OsintResult,
    WhoisInfo,
    _detect_from_html,
    _first_or_str,
    gather,
    lookup_dns,
    lookup_whois,
    probe_http,
)


class TestFirstOrStr(unittest.TestCase):
    def test_string_value(self):
        self.assertEqual(_first_or_str("hello"), "hello")

    def test_list_value(self):
        self.assertEqual(_first_or_str(["first", "second"]), "first")

    def test_empty_list(self):
        self.assertIsNone(_first_or_str([]))

    def test_none_value(self):
        self.assertIsNone(_first_or_str(None))

    def test_integer_value(self):
        self.assertEqual(_first_or_str(42), "42")


class TestLookupWhois(unittest.TestCase):
    @patch("recon_agent.modules.osint.whois.whois")
    def test_successful_lookup(self, mock_whois):
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.registrar = "Test Registrar"
        mock_w.creation_date = "2000-01-01"
        mock_w.expiration_date = "2030-01-01"
        mock_w.updated_date = "2024-01-01"
        mock_w.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_w.emails = ["admin@example.com"]
        mock_w.org = "Example Inc"
        mock_w.country = "US"
        mock_whois.return_value = mock_w

        result = lookup_whois("example.com")

        self.assertIsNotNone(result)
        self.assertEqual(result.domain_name, "example.com")
        self.assertEqual(result.registrar, "Test Registrar")
        self.assertEqual(result.registrant_org, "Example Inc")
        self.assertEqual(len(result.name_servers), 2)
        self.assertEqual(len(result.emails), 1)

    @patch("recon_agent.modules.osint.whois.whois")
    def test_whois_failure(self, mock_whois):
        mock_whois.side_effect = Exception("WHOIS server unreachable")
        result = lookup_whois("bad.example")
        self.assertIsNone(result)

    @patch("recon_agent.modules.osint.whois.whois")
    def test_whois_with_list_fields(self, mock_whois):
        mock_w = MagicMock()
        mock_w.domain_name = ["EXAMPLE.COM", "example.com"]
        mock_w.creation_date = ["2000-01-01", "2000-01-02"]
        mock_w.expiration_date = None
        mock_w.updated_date = None
        mock_w.name_servers = None
        mock_w.emails = None
        mock_w.registrar = None
        mock_w.org = None
        mock_w.country = None
        mock_whois.return_value = mock_w

        result = lookup_whois("example.com")
        self.assertEqual(result.domain_name, "EXAMPLE.COM")
        self.assertIsNone(result.expiration_date)


class TestLookupDns(unittest.TestCase):
    @patch("recon_agent.modules.osint.dns.resolver.resolve")
    def test_returns_records(self, mock_resolve):
        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "93.184.216.34"
        mock_resolve.return_value = [mock_a]

        records = lookup_dns("example.com")
        # Should have attempted multiple record types; at least A should succeed
        self.assertGreater(len(records), 0)
        a_record = next((r for r in records if r.record_type == "A"), None)
        self.assertIsNotNone(a_record)
        self.assertIn("93.184.216.34", a_record.values)

    @patch("recon_agent.modules.osint.dns.resolver.resolve")
    def test_handles_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        records = lookup_dns("nonexistent.invalid")
        self.assertEqual(len(records), 0)


class TestProbeHttp(unittest.TestCase):
    @patch("recon_agent.modules.osint.requests.get")
    def test_successful_probe(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "server": "nginx/1.25",
            "content-type": "text/html",
            "cf-ray": "abc123",
        }
        mock_resp.history = []
        mock_resp.text = "<html><head></head><body>Hello</body></html>"
        mock_get.return_value = mock_resp

        result = probe_http("example.com")

        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.server, "nginx/1.25")
        self.assertIn("Cloudflare", result.technologies)
        self.assertIn("nginx/1.25", result.technologies)

    @patch("recon_agent.modules.osint.requests.get")
    def test_follows_redirects(self, mock_get):
        redirect = MagicMock()
        redirect.url = "http://example.com"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"server": "apache", "content-type": "text/html"}
        mock_resp.history = [redirect]
        mock_resp.text = "<html></html>"
        mock_get.return_value = mock_resp

        result = probe_http("example.com")
        self.assertEqual(len(result.redirect_chain), 1)

    @patch("recon_agent.modules.osint.requests.get")
    def test_all_schemes_fail(self, mock_get):
        from requests.exceptions import ConnectionError
        mock_get.side_effect = ConnectionError("refused")

        result = probe_http("unreachable.invalid")
        self.assertIsNone(result)


class TestDetectFromHtml(unittest.TestCase):
    def test_detects_wordpress(self):
        info = HttpInfo()
        _detect_from_html('<link rel="stylesheet" href="/wp-content/themes/foo">', info)
        self.assertIn("WordPress", info.technologies)

    def test_detects_react(self):
        info = HttpInfo()
        _detect_from_html('<div id="root"></div><script src="/static/js/react.js"></script>', info)
        self.assertIn("React", info.technologies)

    def test_detects_multiple(self):
        info = HttpInfo()
        body = '<script src="jquery.min.js"></script><link href="bootstrap.css">'
        _detect_from_html(body, info)
        self.assertIn("jQuery", info.technologies)
        self.assertIn("Bootstrap", info.technologies)

    def test_no_duplicates(self):
        info = HttpInfo(technologies=["jQuery"])
        _detect_from_html("jquery jquery jquery", info)
        self.assertEqual(info.technologies.count("jQuery"), 1)

    def test_empty_body(self):
        info = HttpInfo()
        _detect_from_html("", info)
        self.assertEqual(len(info.technologies), 0)


class TestGather(unittest.TestCase):
    @patch("recon_agent.modules.osint.probe_http")
    @patch("recon_agent.modules.osint.lookup_dns")
    @patch("recon_agent.modules.osint.lookup_whois")
    def test_gathers_all(self, mock_whois, mock_dns, mock_http):
        mock_whois.return_value = WhoisInfo(domain_name="example.com")
        mock_dns.return_value = [DnsRecord(record_type="A", values=["1.2.3.4"])]
        mock_http.return_value = HttpInfo(url="https://example.com", status_code=200)

        result = gather("example.com")

        self.assertEqual(result.target, "example.com")
        self.assertIsNotNone(result.whois_info)
        self.assertEqual(len(result.dns_records), 1)
        self.assertIsNotNone(result.http_info)

    @patch("recon_agent.modules.osint.probe_http")
    @patch("recon_agent.modules.osint.lookup_dns")
    @patch("recon_agent.modules.osint.lookup_whois")
    def test_skips_disabled_modules(self, mock_whois, mock_dns, mock_http):
        result = gather("example.com", do_whois=False, do_dns=False, do_http=False)

        mock_whois.assert_not_called()
        mock_dns.assert_not_called()
        mock_http.assert_not_called()
        self.assertIsNone(result.whois_info)
        self.assertEqual(len(result.dns_records), 0)
        self.assertIsNone(result.http_info)


class TestDataclasses(unittest.TestCase):
    def test_osint_result_defaults(self):
        r = OsintResult(target="example.com")
        self.assertIsNone(r.whois_info)
        self.assertEqual(r.dns_records, [])
        self.assertIsNone(r.http_info)

    def test_http_info_defaults(self):
        h = HttpInfo()
        self.assertEqual(h.status_code, 0)
        self.assertEqual(h.technologies, [])
        self.assertEqual(h.redirect_chain, [])


if __name__ == "__main__":
    unittest.main()
