"""Hostile input tests (NFR-03):

Verifies:
1. Truncated XML file returns error gracefully without crashing.
2. Missing file returns clear error.
3. Oversized file exceeds MAX_XML_BYTES and returns error.
4. Malicious XML payloads (XXE entity expansion) are rejected/handled safely.
"""
import os
import tempfile
import unittest
from pathlib import Path

from netcheck.analysis.parser import parse_nmap_xml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "validation"


class TestParserSafety(unittest.TestCase):
    def test_truncated_xml_v7_returns_error_gracefully(self):
        v7_path = FIXTURES_DIR / "V7_broken.xml"
        self.assertTrue(v7_path.exists())

        res = parse_nmap_xml(v7_path)
        self.assertIsNotNone(res.error, "Broken file must set error attribute")
        self.assertIsNone(res.score, "Broken file must have score=None")
        self.assertEqual(len(res.findings), 0, "Broken file must produce 0 findings")

    def test_nonexistent_file_returns_error(self):
        res = parse_nmap_xml(Path("does_not_exist_xyz.xml"))
        self.assertIsNotNone(res.error)
        self.assertIn("not found", res.error.lower())

    def test_oversized_file_rejected(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as f:
            # Create a file exceeding the size limit
            f.write(b"<nmaprun>" + b" " * 1024 + b"</nmaprun>")
            temp_path = f.name

        try:
            # Temporarily set max bytes to 512
            import netcheck.analysis.parser as parser_mod
            orig_max = parser_mod.MAX_XML_BYTES
            parser_mod.MAX_XML_BYTES = 512

            res = parse_nmap_xml(temp_path)
            self.assertIsNotNone(res.error)
            self.assertIn("exceeds size limit", res.error.lower())
        finally:
            parser_mod.MAX_XML_BYTES = orig_max
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_xxe_payload_handled_safely(self):
        xxe_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <nmaprun scanner="nmap">
        <host><address addr="192.168.1.1" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="&xxe;"/></port></ports></host>
        </nmaprun>
        """
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write(xxe_xml)
            temp_path = f.name

        try:
            res = parse_nmap_xml(temp_path)
            # Either defusedxml raises DTDForbidden / entities forbidden, or entity is not expanded to /etc/passwd contents
            if not res.error and res.devices:
                for d in res.devices:
                    for p in d.ports:
                        self.assertNotIn("root:", p.product)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
