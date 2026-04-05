#!/usr/bin/env python3
"""Tests for scan-report and scan-issues CLI commands."""

import json
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import (
    _parse_grype_cves,
    _parse_trivy_cves,
    _deduplicate_findings,
    cmd_scan_report,
)


SAMPLE_GRYPE = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2026-1234",
                "severity": "Critical",
                "description": "Buffer overflow in libfoo",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                "fix": {"versions": [{"version": "1.2.4"}]},
            },
            "artifact": {
                "name": "libfoo",
                "version": "1.2.3",
                "type": "deb",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2026-5678",
                "severity": "High",
                "description": "Use-after-free in libbar",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2026-5678",
                "fix": {"versions": []},
            },
            "artifact": {
                "name": "libbar",
                "version": "2.0.0",
                "type": "deb",
            },
        },
    ]
}

SAMPLE_TRIVY = {
    "Results": [
        {
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-1234",
                    "PkgName": "libfoo",
                    "InstalledVersion": "1.2.3",
                    "FixedVersion": "1.2.4",
                    "Severity": "CRITICAL",
                    "Description": "Buffer overflow in libfoo",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                },
                {
                    "VulnerabilityID": "CVE-2026-9999",
                    "PkgName": "libbaz",
                    "InstalledVersion": "3.0.0",
                    "Severity": "MEDIUM",
                    "Description": "Info leak",
                    "PrimaryURL": "",
                },
            ],
        }
    ]
}


class TestParseGrype:
    def test_parse_grype_findings(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE))

        findings = _parse_grype_cves(grype_file)
        assert len(findings) == 2
        assert findings[0]["cve"] == "CVE-2026-1234"
        assert findings[0]["severity"] == "Critical"
        assert findings[0]["package"] == "libfoo"
        assert findings[0]["fix_versions"] == ["1.2.4"]
        assert findings[1]["fix_versions"] == []

    def test_parse_grype_missing_file(self, tmp_path):
        assert _parse_grype_cves(tmp_path / "nope.json") == []


class TestParseTrivy:
    def test_parse_trivy_findings(self, tmp_path):
        trivy_file = tmp_path / "trivy.json"
        trivy_file.write_text(json.dumps(SAMPLE_TRIVY))

        findings = _parse_trivy_cves(trivy_file)
        assert len(findings) == 2
        assert findings[0]["cve"] == "CVE-2026-1234"
        assert findings[0]["severity"] == "Critical"
        assert findings[1]["cve"] == "CVE-2026-9999"

    def test_parse_trivy_missing_file(self, tmp_path):
        assert _parse_trivy_cves(tmp_path / "nope.json") == []


class TestDeduplication:
    def test_dedup_same_cve_package(self):
        findings = [
            {"cve": "CVE-1", "severity": "High", "package": "libfoo", "version": "1.0", "fix_versions": [], "scanner": "grype"},
            {"cve": "CVE-1", "severity": "Critical", "package": "libfoo", "version": "1.0", "fix_versions": ["1.1"], "scanner": "trivy"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "Critical"

    def test_dedup_different_packages(self):
        findings = [
            {"cve": "CVE-1", "severity": "High", "package": "libfoo", "version": "1.0", "fix_versions": [], "scanner": "grype"},
            {"cve": "CVE-1", "severity": "High", "package": "libbar", "version": "2.0", "fix_versions": [], "scanner": "grype"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 2


class TestScanReport:
    def test_scan_report_writes_files(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE))
        report_dir = tmp_path / "reports"

        class Args:
            grype = str(grype_file)
            trivy = None
            image = "alpine"
            dir = str(report_dir)

        rc = cmd_scan_report(Args())
        assert rc == 0
        assert (report_dir / "vulnerability-report.json").exists()
        assert (report_dir / "vulnerability-report.md").exists()

        report = json.loads((report_dir / "vulnerability-report.json").read_text())
        assert report["image"] == "alpine"
        assert report["summary"]["critical"] == 1
        assert report["summary"]["high"] == 1
        assert len(report["findings"]) == 2

    def test_scan_report_no_input(self):
        class Args:
            grype = None
            trivy = None
            image = "test"
            dir = "/tmp/x"

        rc = cmd_scan_report(Args())
        assert rc == 1
