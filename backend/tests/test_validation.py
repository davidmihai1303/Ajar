"""Validation Set: exactly the 24 expected rows, no extra rows, all 8 scores (incl. ERROR)."""
import csv
import os
import tempfile
import unittest
from pathlib import Path

from netcheck.analysis.export import export_folder

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "validation"
EXPECTED_FINDINGS = FIXTURES_DIR / "expected_findings.csv"
EXPECTED_SCORES = FIXTURES_DIR / "expected_scores.csv"


class TestValidation(unittest.TestCase):
    def test_validation_set_exact_match(self):
        """Validates that export_folder on the Validation Set matches expected CSVs exactly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            findings_path, scores_path = export_folder(str(FIXTURES_DIR), tmp_dir)

            # Check findings.csv
            with open(findings_path, encoding="utf-8") as f:
                generated_findings = list(csv.reader(f))

            with open(EXPECTED_FINDINGS, encoding="utf-8") as f:
                expected_findings = list(csv.reader(f))

            # Check exact count: 1 header + 24 finding rows = 25 rows
            self.assertEqual(
                len(generated_findings), 25,
                f"Expected 25 rows (1 header + 24 findings), got {len(generated_findings)}"
            )
            self.assertEqual(generated_findings, expected_findings, "findings.csv does not match expected_findings.csv")

            # Check scores.csv
            with open(scores_path, encoding="utf-8") as f:
                generated_scores = list(csv.reader(f))

            with open(EXPECTED_SCORES, encoding="utf-8") as f:
                expected_scores = list(csv.reader(f))

            self.assertEqual(
                len(generated_scores), 9,
                f"Expected 9 rows (1 header + 8 scores), got {len(generated_scores)}"
            )
            self.assertEqual(generated_scores, expected_scores, "scores.csv does not match expected_scores.csv")


if __name__ == "__main__":
    unittest.main()
