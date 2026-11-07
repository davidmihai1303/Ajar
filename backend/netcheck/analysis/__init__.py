"""④⑤ Deterministic analysis: XML -> devices, findings, score. No network, no LLM, no DB."""
from .catalog import CATALOG, CatalogEntry
from .device_type import guess_device_type
from .export import analyze_file, export_folder
from .models import Device, Finding, Port, ScanResult
from .parser import parse_scan
from .privacy import mask_mac, mask_macs_in_text
from .rules import evaluate_devices
from .scoring import compute_score

# Aliases for convenience
parse_nmap_xml = parse_scan
export_results = export_folder
calculate_score = compute_score
analyze_devices = evaluate_devices

__all__ = [
    "CATALOG",
    "CatalogEntry",
    "Device",
    "Port",
    "Finding",
    "ScanResult",
    "mask_mac",
    "mask_macs_in_text",
    "guess_device_type",
    "compute_score",
    "calculate_score",
    "evaluate_devices",
    "analyze_devices",
    "parse_scan",
    "parse_nmap_xml",
    "analyze_file",
    "export_folder",
    "export_results",
]
