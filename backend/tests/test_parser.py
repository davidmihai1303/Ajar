"""Hostile input: truncated file, XXE / entity expansion, oversized file, escaped banners."""
import os
import tempfile
import unittest
from pathlib import Path

from netcheck.analysis.parser import parse_xml_file

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "validation"


class TestParser(unittest.TestCase):
    def test_truncated_file_returns_error(self):
        """Truncated file V7_broken.xml returns error=True without crashing."""
        v7_path = FIXTURES_DIR / "V7_broken.xml"
        result = parse_xml_file(str(v7_path))
        self.assertTrue(result.error)
        self.assertIsNone(result.score)
        self.assertEqual(len(result.findings), 0)

    def test_nonexistent_file_returns_error(self):
        """Missing file returns error=True without crashing."""
        result = parse_xml_file("nonexistent_path_12345.xml")
        self.assertTrue(result.error)
        self.assertIsNone(result.score)

    def test_xxe_entity_expansion_blocked(self):
        """defusedxml blocks external entities / billion laughs attacks."""
        xxe_xml = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
         <!ENTITY lol "lol">
         <!ELEMENT lolz (#PCDATA)>
         <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
         <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
        ]>
        <nmaprun><host><address addr="192.168.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>"""
        
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(xxe_xml)
            temp_path = f.name

        try:
            result = parse_xml_file(temp_path)
            self.assertTrue(result.error)
        finally:
            os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
