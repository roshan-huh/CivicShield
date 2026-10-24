"""Pydantic schemas shared by every CivicShield stage."""
import uuid
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator

# Entity IDs end up in log lines and shell-adjacent strings, so restrict them strictly.
ID_PATTERN = r"^[A-Za-z0-9_.\-]{1,64}$"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------- enums
class WaterStatus(str, Enum):
    SAFE = "SAFE"
    HAZARDOUS = "HAZARDOUS"


class FleetStatus(str, Enum):
    NORMAL = "NORMAL"
    DOS = "DOS"
    MALICIOUS_PAYLOAD = "MALICIOUS_PAYLOAD"


class DeviceType(str, Enum):
    STREETLAMP = "streetlamp"
    TRAFFIC_COUNTER = "traffic_counter"
    WATER_METER = "water_meter"


class Protocol(str, Enum):
    MQTT = "MQTT"
    COAP = "CoAP"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    QUARANTINED = "QUARANTINED"


class AttackType(str, Enum):
    DOS_FLOOD = "DOS_FLOOD"
    MALICIOUS_PAYLOAD = "MALICIOUS_PAYLOAD"
    DATA_POISONING = "DATA_POISONING"


# ------------------------------------------------------------ telemetry
class WaterRecord(BaseModel):
    """One water-quality reading from a treatment/distribution sensor node."""
    node_id: str = Field(pattern=ID_PATTERN)
    location: str = Field("Unknown", max_length=120)
    ip_address: IPv4Address
    ph: float = Field(ge=0, le=14)
    turbidity_ntu: float = Field(ge=0, le=4000)
    tds_ppm: float = Field(ge=0, le=100000)
    timestamp: datetime = Field(default_factory=utcnow)
    # Filled in by Stage 2 (client-supplied values are always overwritten).
    status: WaterStatus = WaterStatus.SAFE
    flags: list[str] = Field(default_factory=list)
    sentinel_latency_ms: float = 0.0


class FleetRecord(BaseModel):
    """One MQTT/CoAP message summary from a municipal IoT endpoint."""
    device_id: str = Field(pattern=ID_PATTERN)
    device_type: DeviceType
    protocol: Protocol = Protocol.MQTT
    topic: str = Field("", max_length=256)
    ip_address: IPv4Address
    request_rate_hz: float = Field(ge=0, le=1_000_000)
    payload: str = Field("", max_length=65536)
    payload_size_bytes: Optional[int] = Field(None, ge=0)
    timestamp: datetime = Field(default_factory=utcnow)
    # Filled in by Stage 2.
    status: FleetStatus = FleetStatus.NORMAL
    flags: list[str] = Field(default_factory=list)
    sentinel_latency_ms: float = 0.0

    @model_validator(mode="after")
    def _fill_payload_size(self):
        # Never trust a declared size smaller than the real one.
        actual = len(self.payload.encode("utf-8", errors="ignore"))
        self.payload_size_bytes = max(actual, self.payload_size_bytes or 0)
        return self


# ------------------------------------------------------- triage / alerts
class TriageResponse(BaseModel):
    """Stage 3 output for a single alert."""
    alert_id: str
    summary: str                 # 2 plain-English sentences for city managers
    cve_mapping: str             # suspected CVE / CWE (AI-suggested, verify against NVD)
    remediation_script: str      # exactly 3 validated Bash lines
    model_used: str
    fallback_used: bool = False  # True when no LLM provider produced a usable answer
    notes: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    generated_at: datetime = Field(default_factory=utcnow)


class AlertPayload(BaseModel):
    """An incident raised by Stage 2 and enriched by Stage 3."""
    alert_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    source: Literal["WATER", "FLEET"]
    entity_id: str
    ip_address: str
    threat_type: str             # WATER_HAZARDOUS | DOS | MALICIOUS_PAYLOAD
    severity: Severity
    title: str
    details: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    status: AlertStatus = AlertStatus.OPEN
    occurrences: int = 1
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    triage: Optional[TriageResponse] = None
    remediation_log: list[str] = Field(default_factory=list)


# ------------------------------------------------------ request/response
class AttackTrigger(BaseModel):
    attack_type: AttackType
    target_id: Optional[str] = Field(None, pattern=ID_PATTERN)
    intensity: int = Field(3, ge=1, le=10)


class AttackResult(BaseModel):
    attack_type: AttackType
    target_id: str
    injected: int
    blocked: int
    alert_ids: list[str]
    message: str


class IngestResult(BaseModel):
    accepted: bool
    entity_id: str
    status: str
    flags: list[str]
    alert_id: Optional[str] = None
    sentinel_latency_ms: float


class AlertRef(BaseModel):
    alert_id: str


class QuarantineResult(BaseModel):
    alert_id: str
    executed: bool
    mode: str
    commands: list[str]
    output: list[str]
    status: AlertStatus