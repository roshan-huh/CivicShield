"""CivicShield API entrypoint.  Run:  cd backend && uvicorn app.main:app --reload --port 8000"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.api import attack, telemetry, triage
from app.config import settings
from app.database import db

app = FastAPI(title="CivicShield API", version="1.0.0",
              description="Hybrid edge-IoT defense pipeline for municipal water grids and smart-city endpoints.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(telemetry.router)
app.include_router(attack.router)
app.include_router(triage.router)


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}


@app.get("/api/stats", tags=["system"])
def stats():
    """Aggregate metrics for the dashboard header cards and sidebar."""
    s = db.stats()
    s["system_status"] = "CRITICAL" if s["critical_threats"] else ("ELEVATED" if s["active_threats"] else "NOMINAL")
    s["thresholds"] = {
        "ph_min": settings.ph_min, "ph_max": settings.ph_max,
        "turbidity_max_ntu": settings.turbidity_max_ntu, "tds_max_ppm": settings.tds_max_ppm,
        "dos_threshold_hz": settings.dos_threshold_hz, "max_payload_bytes": settings.max_payload_bytes,
    }
    s["llm_providers"] = [n for n, k in (("groq", settings.groq_api_key), ("openai", settings.openai_api_key)) if k]
    s["remediation_mode"] = settings.remediation_mode
    s["attack_simulator_enabled"] = settings.enable_attack_simulator
    return s


@app.post("/api/reset", tags=["system"])
def reset_demo():
    """Re-seed the in-memory store (demo only)."""
    if not settings.enable_attack_simulator:
        raise HTTPException(status_code=403, detail="Reset is disabled on this deployment.")
    db.reset()
    return {"status": "reset"}