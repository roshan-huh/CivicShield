"""Stage 1 endpoints: GET/POST /api/water and /api/fleet.
Every POST is screened by Stage 2 before it is stored."""
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.database import db
from app.engine.pipeline import QuarantinedError, ingest_fleet, ingest_water
from app.schemas.models import FleetRecord, IngestResult, WaterRecord

router = APIRouter(prefix="/api", tags=["telemetry"])


@router.get("/water", response_model=list[WaterRecord])
def get_water(
    limit: int = Query(200, ge=1, le=2000),
    node_id: Optional[str] = None,
    latest_only: bool = False,
):
    """Water readings (oldest->newest), or only the newest reading per node."""
    return db.latest_water() if latest_only else db.list_water(limit, node_id)


@router.post("/water", response_model=IngestResult, status_code=201)
def post_water(record: WaterRecord):
    try:
        rec, alert = ingest_water(record)
    except QuarantinedError:
        raise HTTPException(status_code=423, detail=f"Node {record.node_id} is quarantined; telemetry dropped.")
    return IngestResult(
        accepted=True, entity_id=rec.node_id, status=rec.status.value, flags=rec.flags,
        alert_id=alert.alert_id if alert else None, sentinel_latency_ms=rec.sentinel_latency_ms,
    )


@router.get("/fleet", response_model=list[FleetRecord])
def get_fleet(
    limit: int = Query(200, ge=1, le=2000),
    device_id: Optional[str] = None,
    latest_only: bool = False,
):
    """Fleet messages (oldest->newest), or only the newest message per device."""
    return db.latest_fleet() if latest_only else db.list_fleet(limit, device_id)


@router.post("/fleet", response_model=IngestResult, status_code=201)
def post_fleet(record: FleetRecord):
    try:
        rec, alert = ingest_fleet(record)
    except QuarantinedError:
        raise HTTPException(status_code=423, detail=f"Device {record.device_id} is quarantined; packet dropped.")
    return IngestResult(
        accepted=True, entity_id=rec.device_id, status=rec.status.value, flags=rec.flags,
        alert_id=alert.alert_id if alert else None, sentinel_latency_ms=rec.sentinel_latency_ms,
    )