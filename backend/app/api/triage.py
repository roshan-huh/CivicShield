"""Stage 3 endpoints plus incident-feed and remediation endpoints used by the dashboard."""
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.agents.llm_triage import triage_alert
from app.database import db
from app.engine.remediation import RemediationRejected, execute_remediation
from app.schemas.models import AlertPayload, AlertRef, AlertStatus, QuarantineResult, TriageResponse

router = APIRouter(prefix="/api", tags=["triage"])


@router.get("/alerts", response_model=list[AlertPayload])
def list_alerts(status: Optional[AlertStatus] = None):
    return db.list_alerts(status)


@router.get("/alerts/{alert_id}", response_model=AlertPayload)
def get_alert(alert_id: str):
    alert = db.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert


@router.post("/triage/analyze", response_model=TriageResponse)
async def analyze(ref: AlertRef):
    """Stage 3: LLM reasoning (summary, CVE/CWE mapping, 3-line remediation)."""
    alert = db.get_alert(ref.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    triage = await triage_alert(alert)
    db.attach_triage(alert.alert_id, triage)
    return triage


@router.post("/triage/quarantine", response_model=QuarantineResult)
def quarantine(ref: AlertRef):
    """1-click remediation: re-validates the script, executes it (simulate/live), marks quarantined."""
    alert = db.get_alert(ref.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    if alert.triage is None:
        raise HTTPException(status_code=409, detail="Run AI triage before executing remediation.")
    if alert.status == AlertStatus.QUARANTINED:
        raise HTTPException(status_code=409, detail="Alert is already quarantined.")
    try:
        return execute_remediation(alert)
    except RemediationRejected as exc:
        raise HTTPException(status_code=422, detail=f"Remediation blocked by safety validator: {exc}")