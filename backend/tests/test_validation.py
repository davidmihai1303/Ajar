"""Validation Set tests: exactly the 24 expected rows, no extra rows, all 8 scores (incl. ERROR).

This test validates the core contract for 30% of the hackathon grade.
Matches the official answer key exactly.
"""
import csv
import os
import tempfile
import unittest
from pathlib import Path

from netcheck.analysis.export import export_results
from netcheck.analysis.parser import parse_nmap_xml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "validation"


class TestValidationSet(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = FIXTURES_DIR
        self.assertTrue(self.fixtures_dir.exists(), f"Fixtures directory {self.fixtures_dir} missing")

        # Find all validation XMLs
        self.xml_files = sorted(list(self.fixtures_dir.glob("*.xml")))
        self.assertEqual(len(self.xml_files), 8, f"Expected 8 validation files, found {len(self.xml_files)}")

        # Temporary directory for exported CSVs
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_validation_findings_and_scores_match_expected(self):
        # 1. Parse all XML files
        results = [parse_nmap_xml(f) for f in self.xml_files]

        # 2. Export CSVs
        findings_path, scores_path = export_results(results, self.temp_dir.name)

        # 3. Read generated findings vs expected findings
        with open(findings_path, mode="r", encoding="utf-8") as f:
            generated_findings_rows = [line.strip() for line in f if line.strip()]

        expected_findings_file = self.fixtures_dir / "expected_findings.csv"
        with open(expected_findings_file, mode="r", encoding="utf-8") as f:
            expected_findings_rows = [line.strip() for line in f if line.strip()]

        # Check total rows (1 header + 24 finding rows)
        self.assertEqual(
            len(generated_findings_rows),
            25,
            f"Expected exactly 24 finding rows + header (25 total), got {len(generated_findings_rows)}",
        )
        self.assertEqual(
            generated_findings_rows,
            expected_findings_rows,
            "Generated findings.csv does not match expected_findings.csv",
        )

        # 4. Read generated scores vs expected scores
        with open(scores_path, mode="r", encoding="utf-8") as f:
            generated_scores_rows = [line.strip() for line in f if line.strip()]

        expected_scores_file = self.fixtures_dir / "expected_scores.csv"
        with open(expected_scores_file, mode="r", encoding="utf-8") as f:
            expected_scores_rows = [line.strip() for line in f if line.strip()]

        # Check scores (1 header + 8 score rows)
        self.assertEqual(
            len(generated_scores_rows),
            9,
            f"Expected exactly 8 score rows + header (9 total), got {len(generated_scores_rows)}",
        )
        self.assertEqual(
            generated_scores_rows,
            expected_scores_rows,
            "Generated scores.csv does not match expected_scores.csv",
        )


if __name__ == "__main__":
    unittest.main()
