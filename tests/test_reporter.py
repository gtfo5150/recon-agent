"""Tests for the reporter module."""

import json
import os
import tempfile
import unittest

from recon_agent.modules.osint import DnsRecord, HttpInfo, OsintResult, WhoisInfo
from recon_agent.modules.port_scanner import PortResult, ScanResult
from recon_agent.modules.subdomain_enum import EnumResult, SubdomainResult
from recon_agent.reporting.reporter import export_json


class TestExportJson(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_exports_full_report(self):
        port_scan = ScanResult(
            target="example.com",
            ip="93.184.216.34",
            ports=[PortResult(port=80, state="open", service="HTTP")],
            scan_type="socket",
        )
        subdomains = EnumResult(
            domain="example.com",
            subdomains=[SubdomainResult(subdomain="www.example.com", ip="1.2.3.4", source="crt.sh")],
            total_found=1,
        )
        osint_data = OsintResult(
            target="example.com",
            whois_info=WhoisInfo(domain_name="example.com", registrar="Test"),
            dns_records=[DnsRecord(record_type="A", values=["93.184.216.34"])],
            http_info=HttpInfo(url="https://example.com", status_code=200),
        )

        out_path = os.path.join(self.tmpdir, "report.json")
        result_path = export_json(
            "example.com",
            port_scan=port_scan,
            subdomains=subdomains,
            osint=osint_data,
            output_path=out_path,
        )

        self.assertTrue(os.path.exists(result_path))
        with open(result_path) as f:
            report = json.load(f)

        self.assertEqual(report["target"], "example.com")
        self.assertIn("timestamp", report)
        self.assertIn("port_scan", report["results"])
        self.assertIn("subdomains", report["results"])
        self.assertIn("osint", report["results"])

        # Verify port scan data
        ps = report["results"]["port_scan"]
        self.assertEqual(ps["ip"], "93.184.216.34")
        self.assertEqual(len(ps["ports"]), 1)
        self.assertEqual(ps["ports"][0]["port"], 80)

        # Verify subdomains data
        sd = report["results"]["subdomains"]
        self.assertEqual(sd["total_found"], 1)
        self.assertEqual(sd["subdomains"][0]["subdomain"], "www.example.com")

        # Verify OSINT data
        oi = report["results"]["osint"]
        self.assertEqual(oi["whois_info"]["domain_name"], "example.com")

    def test_exports_partial_report(self):
        out_path = os.path.join(self.tmpdir, "partial.json")
        export_json("example.com", output_path=out_path)

        with open(out_path) as f:
            report = json.load(f)

        self.assertEqual(report["target"], "example.com")
        self.assertEqual(report["results"], {})

    def test_strips_raw_whois(self):
        osint_data = OsintResult(
            target="example.com",
            whois_info=WhoisInfo(domain_name="example.com", raw="HUGE RAW WHOIS DATA"),
        )
        out_path = os.path.join(self.tmpdir, "stripped.json")
        export_json("example.com", osint=osint_data, output_path=out_path)

        with open(out_path) as f:
            report = json.load(f)

        self.assertNotIn("raw", report["results"]["osint"]["whois_info"])

    def test_auto_generates_filename(self):
        path = export_json("example.com")
        self.assertTrue(os.path.exists(path))
        self.assertIn("recon_example_com_", path)
        os.remove(path)

    def test_safe_target_in_filename(self):
        path = export_json("sub.example.com")
        self.assertIn("sub_example_com", path)
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
