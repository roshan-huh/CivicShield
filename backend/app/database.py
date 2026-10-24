"""In-memory datastore (thread-safe), seeded with realistic municipal data.
Swap this module for TimescaleDB/Postgres in production; the interface stays the same."""
import json
import random
import threading
from datetime import timedelta
from typing import Optional

from app.engine.sentinel_rules import evaluate_fleet
from app.engine.water_rules import evaluate_water
from app.schemas.models import (
    AlertPayload, AlertStatus, DeviceType, FleetRecord, Protocol, TriageResponse, WaterRecord, utcnow,
)

# node_id, location, ip, base pH, base turbidity (NTU), base TDS (ppm)
_WATER_NODES = [
    ("WQ-001", "North Intake Plant", "10.20.1.11", 7.4, 2.1, 310),
    ("WQ-002", "Eastside Reservoir", "10.20.1.12", 7.6, 1.4, 285),
    ("WQ-003", "Riverfront Pump Station", "10.20.1.13", 7.2, 4.8, 420),
    ("WQ-004", "Hillcrest Storage Tank", "10.20.1.14", 7.8, 0.9, 260),
    ("WQ-005", "Downtown Distribution Hub", "10.20.1.15", 7.5, 1.8, 340),
    ("WQ-006", "Harbor Treatment Annex", "10.20.1.16", 7.1, 6.2, 520),
]

# device_id, type, protocol, ip
_FLEET_DEVICES = (
    [(f"SL-100{i}", DeviceType.STREETLAMP, Protocol.MQTT, f"10.30.2.{20 + i}") for i in range(1, 6)]
    + [(f"TC-200{i}", DeviceType.TRAFFIC_COUNTER, Protocol.COAP, f"10.30.3.{20 + i}") for i in range(1, 6)]
    + [(f"WM-300{i}", DeviceType.WATER_METER, Protocol.COAP if i == 2 else Protocol.MQTT, f"10.30.4.{20 + i}")
       for i in range(1, 5)]
)


def _topic_and_payload(rng: random.Random, device_id: str, dtype: DeviceType):
    if dtype is DeviceType.STREETLAMP:
        return (f"city/lights/{device_id}/telemetry",
                json.dumps({"lux": rng.randint(300, 480), "dim_pct": rng.choice([60, 70, 80]), "fault": 0}),
                rng.uniform(0.2, 1.0))
    if dtype is DeviceType.TRAFFIC_COUNTER:
        return (f"city/traffic/{device_id}/count",
                json.dumps({"lane": rng.randint(1, 3), "vehicles": rng.randint(5, 60), "avg_kph": rng.randint(25, 55)}),
                rng.uniform(1.0, 5.0))
    return (f"city/water/{device_id}/reading",
            json.dumps({"volume_m3": round(rng.uniform(100, 900), 1), "flow_lpm": round(rng.uniform(4, 25), 1)}),
            rng.uniform(0.05, 0.5))


class InMemoryDB:
    MAX_WATER = 5000
    MAX_FLEET = 5000

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.reset()

    # ------------------------------------------------------------ lifecycle
    def reset(self) -> None:
        with self._lock:
            self._water: list[WaterRecord] = []
            self._fleet: list[FleetRecord] = []
            self._alerts: dict[str, AlertPayload] = {}
            self._quarantined: set[str] = set()
            self._seed()

    def _seed(self) -> None:
        """24h of hourly water readings and 6 five-minute fleet heartbeats per device.
        Seeds are generated chronologically and pass through the same Stage 2 rules."""
        rng = random.Random(42)
        now = utcnow()
        for h in range(24):
            ts = now - timedelta(hours=23 - h)
            for node_id, loc, ip, ph, turb, tds in _WATER_NODES:
                rec = WaterRecord(
                    node_id=node_id, location=loc, ip_address=ip, timestamp=ts,
                    ph=round(rng.gauss(ph, 0.08), 2),
                    turbidity_ntu=round(max(0.1, rng.gauss(turb, 0.35)), 2),
                    tds_ppm=round(max(50, rng.gauss(tds, 12)), 1),
                )
                self._water.append(evaluate_water(rec))
        for k in range(6):
            ts = now - timedelta(minutes=5 * (5 - k))
            for device_id, dtype, proto, ip in _FLEET_DEVICES:
                topic, payload, rate = _topic_and_payload(rng, device_id, dtype)
                rec = FleetRecord(device_id=device_id, device_type=dtype, protocol=proto, topic=topic,
                                  ip_address=ip, request_rate_hz=round(rate, 2), payload=payload, timestamp=ts)
                self._fleet.append(evaluate_fleet(rec))

    # ------------------------------------------------------------- telemetry
    def add_water(self, rec: WaterRecord) -> None:
        with self._lock:
            self._water.append(rec)
            del self._water[: max(0, len(self._water) - self.MAX_WATER)]

    def add_fleet(self, rec: FleetRecord) -> None:
        with self._lock:
            self._fleet.append(rec)
            del self._fleet[: max(0, len(self._fleet) - self.MAX_FLEET)]

    def list_water(self, limit: int = 200, node_id: Optional[str] = None) -> list[WaterRecord]:
        with self._lock:
            rows = [r for r in self._water if node_id is None or r.node_id == node_id]
            return rows[-limit:]

    def list_fleet(self, limit: int = 200, device_id: Optional[str] = None) -> list[FleetRecord]:
        with self._lock:
            rows = [r for r in self._fleet if device_id is None or r.device_id == device_id]
            return rows[-limit:]

    def latest_water(self) -> list[WaterRecord]:
        with self._lock:
            latest = {r.node_id: r for r in self._water}  # chronological list -> last write wins
            return sorted(latest.values(), key=lambda r: r.node_id)

    def latest_fleet(self) -> list[FleetRecord]:
        with self._lock:
            latest = {r.device_id: r for r in self._fleet}
            return sorted(latest.values(), key=lambda r: r.device_id)

    # ---------------------------------------------------------------- alerts
    def add_alert(self, alert: AlertPayload) -> AlertPayload:
        """Store an alert, de-duplicating repeats for the same entity+threat while still open."""
        with self._lock:
            for existing in self._alerts.values():
                if (existing.entity_id == alert.entity_id and existing.threat_type == alert.threat_type
                        and existing.status != AlertStatus.QUARANTINED):
                    existing.occurrences += 1
                    existing.updated_at = utcnow()
                    existing.evidence = alert.evidence
                    existing.details = alert.details
                    return existing
            self._alerts[alert.alert_id] = alert
            return alert

    def get_alert(self, alert_id: str) -> Optional[AlertPayload]:
        with self._lock:
            return self._alerts.get(alert_id)

    def list_alerts(self, status: Optional[AlertStatus] = None) -> list[AlertPayload]:
        with self._lock:
            rows = [a for a in self._alerts.values() if status is None or a.status == status]
            return sorted(rows, key=lambda a: a.created_at, reverse=True)

    def attach_triage(self, alert_id: str, triage: TriageResponse) -> None:
        with self._lock:
            alert = self._alerts[alert_id]
            alert.triage = triage
            alert.updated_at = utcnow()
            if alert.status == AlertStatus.OPEN:
                alert.status = AlertStatus.TRIAGED

    def mark_quarantined(self, alert_id: str, log_lines: list[str]) -> None:
        with self._lock:
            alert = self._alerts[alert_id]
            alert.status = AlertStatus.QUARANTINED
            alert.remediation_log = list(log_lines)
            alert.updated_at = utcnow()
            self._quarantined.add(alert.entity_id)

    def is_quarantined(self, entity_id: str) -> bool:
        with self._lock:
            return entity_id in self._quarantined

    # ----------------------------------------------------------------- stats
    def stats(self) -> dict:
        with self._lock:
            active = [a for a in self._alerts.values() if a.status != AlertStatus.QUARANTINED]
            return {
                "water_nodes": len({r.node_id for r in self._water}),
                "fleet_devices": len({r.device_id for r in self._fleet}),
                "water_records": len(self._water),
                "fleet_records": len(self._fleet),
                "total_alerts": len(self._alerts),
                "active_threats": len(active),
                "critical_threats": sum(1 for a in active if a.severity.value == "CRITICAL"),
                "quarantined_entities": len(self._quarantined),
            }


db = InMemoryDB()