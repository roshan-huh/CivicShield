"""Stage 2a: deterministic water-chemistry evaluator (pure arithmetic, microseconds)."""
import time

from app.config import settings
from app.schemas.models import WaterRecord, WaterStatus


def evaluate_water(record: WaterRecord) -> WaterRecord:
    """Annotate `record` in place with status + flags and return it.

    HAZARDOUS if any of:
      * pH < 5.0 or pH > 9.0
      * turbidity > 30 NTU
      * TDS > 1000 ppm
    """
    started = time.perf_counter()
    flags: list[str] = []

    if record.ph < settings.ph_min:
        flags.append(f"PH_LOW({record.ph:.2f}<{settings.ph_min})")
    elif record.ph > settings.ph_max:
        flags.append(f"PH_HIGH({record.ph:.2f}>{settings.ph_max})")

    if record.turbidity_ntu > settings.turbidity_max_ntu:
        flags.append(f"TURBIDITY_HIGH({record.turbidity_ntu:.1f}NTU>{settings.turbidity_max_ntu:g})")

    if record.tds_ppm > settings.tds_max_ppm:
        flags.append(f"TDS_HIGH({record.tds_ppm:.0f}ppm>{settings.tds_max_ppm:g})")

    record.flags = flags
    record.status = WaterStatus.HAZARDOUS if flags else WaterStatus.SAFE
    record.sentinel_latency_ms = round((time.perf_counter() - started) * 1000, 4)
    return record