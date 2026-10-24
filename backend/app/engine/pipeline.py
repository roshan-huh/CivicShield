"""Stage 1 -> Stage 2 glue: every record (HTTP POST or simulated attack) takes this path."""
from typing import Optional

from app.database import db
from app.engine.sentinel_rules import evaluate_fleet
from app.engine.water_rules import evaluate_water
from app.schemas.models import (
    AlertPayload, FleetRecord, FleetStatus, Severity, WaterRecord, WaterStatus,
)


class QuarantinedError(Exception):
    """Raised when telemetry arrives from an entity that has been isolated."""


def _alert_from_water(rec: WaterRecord) -> AlertPayload:
    return AlertPayload(
        source="WATER",
        entity_id=rec.node_id,
        ip_address=str(rec.ip_address),
        threat_type="WATER_HAZARDOUS",
        severity=Severity.CRITICAL if len(rec.flags) >= 2 else Severity.HIGH,
        title=f"Hazardous water parameters at {rec.location}",
        details="; ".join(rec.flags),
        evidence={
            "location": rec.location, "ph": rec.ph, "turbidity_ntu": rec.turbidity_ntu,
            "tds_ppm": rec.tds_ppm, "flags": rec.flags,
        },
    )


def _alert_from_fleet(rec: FleetRecord) -> AlertPayload:
    malicious = rec.status == FleetStatus.MALICIOUS_PAYLOAD
    return AlertPayload(
        source="FLEET",
        entity_id=rec.device_id,
        ip_address=str(rec.ip_address),
        threat_type=rec.status.value,
        severity=Severity.CRITICAL if malicious else Severity.HIGH,
        title=f"{'Malicious payload' if malicious else 'DoS flood'} from {rec.device_type.value} {rec.device_id}",
        details="; ".join(rec.flags),
        evidence={
            "device_type": rec.device_type.value, "protocol": rec.protocol.value, "topic": rec.topic,
            "request_rate_hz": rec.request_rate_hz, "payload_size_bytes": rec.payload_size_bytes,
            "payload_preview": rec.payload[:200], "flags": rec.flags,
        },
    )


def ingest_water(record: WaterRecord) -> tuple[WaterRecord, Optional[AlertPayload]]:
    if db.is_quarantined(record.node_id):
        raise QuarantinedError(record.node_id)
    evaluate_water(record)                      # Stage 2
    db.add_water(record)
    alert = db.add_alert(_alert_from_water(record)) if record.status == WaterStatus.HAZARDOUS else None
    return record, alert


def ingest_fleet(record: FleetRecord) -> tuple[FleetRecord, Optional[AlertPayload]]:
    if db.is_quarantined(record.device_id):
        raise QuarantinedError(record.device_id)
    evaluate_fleet(record)                      # Stage 2
    alert = db.add_alert(_alert_from_fleet(record)) if record.status != FleetStatus.NORMAL else None
    record.payload = record.payload[:512]       # keep memory bounded; real size is in payload_size_bytes
    db.add_fleet(record)
    return record, alert