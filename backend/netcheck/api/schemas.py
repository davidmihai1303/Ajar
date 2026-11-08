"""Local HTTP contract shared with the React client."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

Lang = Literal["en", "ro"]
Severity = Literal["high", "medium", "low", "info"]
Source = Literal["live", "import", "unknown"]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Network(Input):
    interface: str
    subnet: str
    gateway: str | None
    ssid: str | None
    confirmation_id: str | None = None


class ScanRequest(Input):
    confirm: StrictBool
    expected_network: Network


class Port(BaseModel):
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    http_title: str | None
    tunnel: str | None


class Device(BaseModel):
    ip: str
    mac_masked: str | None
    vendor: str | None
    hostname: str | None
    device_type: str
    ports: list[Port]


class Finding(BaseModel):
    ip: str
    port: int | None
    protocol: str | None
    code: str
    severity: Severity
    points: int
    evidence: str


class Snapshot(BaseModel):
    id: str
    file: str
    created_at: str
    source: Source
    ssid: str | None
    subnet: str | None
    network_id: str | None
    findings_available: bool
    score: int | None
    error: str | None


class Scan(Snapshot):
    devices: list[Device]
    findings: list[Finding]


class HistoryItem(Snapshot):
    device_count: int
    finding_count: int


class ImportResult(BaseModel):
    file: str
    scan_id: str | None
    score: int | None
    error: str | None


class PortRef(BaseModel):
    ip: str
    port: int
    protocol: str
    service: str | None


class Diff(BaseModel):
    from_id: str
    to_id: str
    score_before: int | None
    score_after: int | None
    devices_added: list[str]
    devices_removed: list[str]
    ports_opened: list[PortRef]
    ports_closed: list[PortRef]
    findings_resolved: list[Finding]
    findings_new: list[Finding]


class Explanation(BaseModel):
    code: str
    lang: Lang
    title: str
    explanation: str
    steps: list[str]


class FindingRef(Input):
    code: str
    ip: str
    port: int | None
    protocol: str | None


class PersonalizeRequest(FindingRef):
    scan_id: str
    lang: Lang = "ro"


class AskRequest(Input):
    scan_id: str
    question: str = Field(min_length=1, max_length=500)
    lang: Lang = "ro"


class Answer(BaseModel):
    available: bool
    can_answer: bool
    answer: str | None


class ModelStatus(BaseModel):
    available: bool
    state: Literal["idle", "starting", "ready", "failed"] | None = None
    reason: Literal["gpu", "memory", "weights", "port", "load", "timeout", "server"] | None = None
