"""Determinism tests (NFR-05): Same input file gives identical findings, severities and scores on every run."""
import tempfile
import unittest
from pathlib import Path

from netcheck.analysis.export import export_results
from netcheck.analysis.parser import parse_nmap_xml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "validation"


class TestDeterminism(unittest.TestCase):
    def test_same_file_gives_identical_results_across_runs(self):
        xml_files = sorted(list(FIXTURES_DIR.glob("*.xml")))

        # Run 1
        run1 = [parse_nmap_xml(f) for f in xml_files]
        # Run 2
        run2 = [parse_nmap_xml(f) for f in xml_files]
        # Run 3
        run3 = [parse_nmap_xml(f) for f in xml_files]

        for i in range(len(xml_files)):
            # Compare score and error
            self.assertEqual(run1[i].score, run2[i].score)
            self.assertEqual(run1[i].score, run3[i].score)
            self.assertEqual(run1[i].error, run2[i].error)

            # Compare findings count
            self.assertEqual(len(run1[i].findings), len(run2[i].findings))
            self.assertEqual(len(run1[i].findings), len(run3[i].findings))

            # Compare finding contents
            for f1, f2, f3 in zip(run1[i].findings, run2[i].findings, run3[i].findings):
                self.assertEqual(f1.code, f2.code)
                self.assertEqual(f1.code, f3.code)
                self.assertEqual(f1.severity, f2.severity)
                self.assertEqual(f1.points, f2.points)
                self.assertEqual(f1.ip, f2.ip)
                self.assertEqual(f1.port, f2.port)

        # Export CSVs in temporary directories and compare
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            f1, s1 = export_results(run1, d1)
            f2, s2 = export_results(run2, d2)

            self.assertEqual(f1.read_text(encoding="utf-8"), f2.read_text(encoding="utf-8"))
            self.assertEqual(s1.read_text(encoding="utf-8"), s2.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
