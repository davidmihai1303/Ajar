"""Analysis package: pure, deterministic nmap XML evaluation and scoring."""
from netcheck.analysis.catalog import CATALOG, CatalogEntry
from netcheck.analysis.device_type import guess_device_type
from netcheck.analysis.export import export_results
from netcheck.analysis.models import Device, Finding, Port, ScanResult
from netcheck.analysis.parser import parse_nmap_xml
from netcheck.analysis.privacy import mask_mac
from netcheck.analysis.rules import analyze_device_findings, analyze_devices, classify_port_findings
from netcheck.analysis.scoring import calculate_score
from netcheck.analysis.versions import check_outdated_service, parse_version_tuple

__all__ = [
    "CATALOG",
    "CatalogEntry",
    "Device",
    "Port",
    "Finding",
    "ScanResult",
    "mask_mac",
    "guess_device_type",
    "parse_version_tuple",
    "check_outdated_service",
    "calculate_score",
    "classify_port_findings",
    "analyze_device_findings",
    "analyze_devices",
    "parse_nmap_xml",
    "export_results",
]
