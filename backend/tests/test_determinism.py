"""Same file analysed 3 times -> identical findings, severities and scores (NFR-05)."""
import unittest
from pathlib import Path
from netcheck.analysis.parser import parse_xml_file

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "validation"


class TestDeterminism(unittest.TestCase):
    def test_determinism_multiple_runs(self):
        """Runs each validation file 3 times and ensures output is byte-for-byte identical."""
        for xml_file in sorted(FIXTURES_DIR.glob("*.xml")):
            results = [parse_xml_file(str(xml_file)) for _ in range(3)]
            
            # All 3 runs have same error status
            self.assertEqual(results[0].error, results[1].error)
            self.assertEqual(results[1].error, results[2].error)
            
            # All 3 runs have same score
            self.assertEqual(results[0].score, results[1].score)
            self.assertEqual(results[1].score, results[2].score)
            
            # All 3 runs have exact same findings count
            self.assertEqual(len(results[0].findings), len(results[1].findings))
            self.assertEqual(len(results[1].findings), len(results[2].findings))
            
            for f1, f2, f3 in zip(results[0].findings, results[1].findings, results[2].findings):
                self.assertEqual(f1.ip, f2.ip)
                self.assertEqual(f2.ip, f3.ip)
                self.assertEqual(f1.port, f2.port)
                self.assertEqual(f2.port, f3.port)
                self.assertEqual(f1.finding_code, f2.finding_code)
                self.assertEqual(f2.finding_code, f3.finding_code)
                self.assertEqual(f1.severity, f2.severity)
                self.assertEqual(f2.severity, f3.severity)
                self.assertEqual(f1.points, f2.points)
                self.assertEqual(f2.points, f3.points)


if __name__ == "__main__":
    unittest.main()
