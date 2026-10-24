
"""Stage 4: CivicShield Security Operations Center (Streamlit).
Run from repo root:  streamlit run dashboard/app.py"""
from __future__ import annotations
import os
import time

import pandas as pd
import requests
import streamlit as st

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")

st.set_page_config(page_title="CivicShield SOC", page_icon="🛡️", layout="wide")
st.session_state.setdefault("flash", [])

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
STATUS_ICON = {"OPEN": "🚨", "TRIAGED": "🧠", "QUARANTINED": "🔒"}
ATTACK_LABELS = {
    "DOS_FLOOD": "DoS flood (>100 Hz)",
    "MALICIOUS_PAYLOAD": "Malicious payload (SQLi / cmd injection / oversize)",
    "DATA_POISONING": "Sensor data poisoning (water)",
}


# ------------------------------------------------------------------ API helpers
def api_get(path: str, params: dict | None = None):
    try:
        resp = requests.get(f"{API_BASE}{path}", params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return None


def api_post(path: str, payload: dict | None = None, timeout: int = 45):
    """Returns (data, error_message)."""
    try:
        resp = requests.post(f"{API_BASE}{path}", json=payload or {}, timeout=timeout)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except ValueError:
                detail = resp.text
            return None, f"{resp.status_code}: {detail}"
        return resp.json(), None
    except requests.RequestException as exc:
        return None, f"API unreachable ({type(exc).__name__})"


def flash(kind: str, msg: str) -> None:
    st.session_state.flash.append((kind, msg))


# ------------------------------------------------------------------- sidebar
stats = api_get("/api/stats")
water_latest = api_get("/api/water", {"latest_only": "true"}) or []
fleet_latest = api_get("/api/fleet", {"latest_only": "true"}) or []

with st.sidebar:
    st.title("🛡️ CivicShield")
    st.caption("Municipal Water & Smart-City Defense")

    if stats:
        st.success("● API ONLINE")
        providers = ", ".join(stats["llm_providers"]) or "none (deterministic playbook)"
        st.caption(f"LLM providers: **{providers}**")
        st.caption(f"Remediation mode: **{stats['remediation_mode']}**")
    else:
        st.error("● API OFFLINE")
        st.caption(f"Expected at {API_BASE}")

    st.divider()
    st.subheader("⚔️ Attack Injection Console")
    st.caption("Injects synthetic records into this system's own pipeline for detection testing.")

    if stats and not stats["attack_simulator_enabled"]:
        st.info("Attack simulator is disabled on this deployment.")
    else:
        attack_type = st.selectbox("Attack vector", list(ATTACK_LABELS), format_func=ATTACK_LABELS.get)
        if attack_type == "DATA_POISONING":
            target_options = [r["node_id"] for r in water_latest]
        else:
            target_options = [r["device_id"] for r in fleet_latest]
        target = st.selectbox("Target", ["(random)"] + target_options)
        intensity = st.slider("Intensity (records injected)", 1, 10, 3)

        if st.button("🚀 Inject attack", type="primary", disabled=stats is None):
            body = {"attack_type": attack_type, "intensity": intensity}
            if target != "(random)":
                body["target_id"] = target
            data, err = api_post("/api/attack/trigger", body)
            flash("error", err) if err else flash("warning", data["message"])

        if st.button("♻️ Reset demo data", disabled=stats is None):
            _, err = api_post("/api/reset")
            flash("error", err) if err else flash("success", "Demo data re-seeded.")

    st.divider()
    live = st.toggle("Live refresh (5 s)", value=True, key="live_refresh")

# --------------------------------------------------------------------- header
st.title("Security Operations Center")

for kind, msg in st.session_state.flash:
    getattr(st, kind)(msg)
st.session_state.flash = []

if stats is None:
    st.error(f"Cannot reach the CivicShield API at {API_BASE}. Start it with "
             "`cd backend && uvicorn app.main:app --port 8000`.")
    st.stop()

m1, m2, m3, m4 = st.columns(4)
m1.metric("💧 Water Nodes", stats["water_nodes"])
m2.metric("📡 Fleet Devices", stats["fleet_devices"])
m3.metric("🚨 Active Threats", stats["active_threats"],
          delta=f"{stats['critical_threats']} critical" if stats["critical_threats"] else None,
          delta_color="inverse")
status_icon = {"NOMINAL": "🟢", "ELEVATED": "🟠", "CRITICAL": "🔴"}[stats["system_status"]]
m4.metric("System Status", f"{status_icon} {stats['system_status']}")

tab_water, tab_fleet, tab_threats = st.tabs(
    ["💧 Water Quality", "📡 Municipal IoT Fleet", "🚨 Threat & Incident Feed"]
)
th = stats["thresholds"]

# --------------------------------------------------------------- Tab 1: water
with tab_water:
    df = pd.DataFrame(water_latest)
    if df.empty:
        st.info("No water telemetry yet.")
    else:
        df["state"] = df["status"].map({"SAFE": "🟢 SAFE", "HAZARDOUS": "🔴 HAZARDOUS"})
        df["flags"] = df["flags"].apply(lambda f: ", ".join(f))
        st.subheader("Latest reading per node")
        st.dataframe(
            df[["node_id", "location", "state", "ph", "turbidity_ntu", "tds_ppm", "flags", "timestamp"]],
            hide_index=True,
        )
        st.caption(f"Hazard limits: pH < {th['ph_min']} or > {th['ph_max']} · turbidity > "
                   f"{th['turbidity_max_ntu']:g} NTU · TDS > {th['tds_max_ppm']:g} ppm")

        st.subheader("Parameter trends")
        node = st.selectbox("Node", df["node_id"].tolist(), key="water_node")
        hist = pd.DataFrame(api_get("/api/water", {"node_id": node, "limit": 200}) or [])
        if not hist.empty:
            hist["timestamp"] = pd.to_datetime(hist["timestamp"])
            hist = hist.sort_values("timestamp").set_index("timestamp")
            c1, c2, c3 = st.columns(3)
            c1.markdown(f"**pH** (safe {th['ph_min']}–{th['ph_max']})")
            c1.line_chart(hist[["ph"]])
            c2.markdown(f"**Turbidity NTU** (max {th['turbidity_max_ntu']:g})")
            c2.line_chart(hist[["turbidity_ntu"]])
            c3.markdown(f"**TDS ppm** (max {th['tds_max_ppm']:g})")
            c3.line_chart(hist[["tds_ppm"]])

# ---------------------------------------------------------------- Tab 2: fleet
with tab_fleet:
    fdf = pd.DataFrame(fleet_latest)
    if fdf.empty:
        st.info("No fleet telemetry yet.")
    else:
        fdf["state"] = fdf["status"].map({"NORMAL": "🟢 NORMAL", "DOS": "🟠 DOS", "MALICIOUS_PAYLOAD": "🔴 MALICIOUS"})
        fdf["flags"] = fdf["flags"].apply(lambda f: ", ".join(f))
        st.subheader("Latest message per device")
        st.dataframe(
            fdf[["device_id", "device_type", "protocol", "state", "request_rate_hz",
                 "payload_size_bytes", "ip_address", "topic", "flags", "timestamp"]],
            hide_index=True,
        )
        st.subheader("Request rate by device (Hz)")
        st.bar_chart(fdf.set_index("device_id")[["request_rate_hz"]])
        st.caption(f"DoS threshold: > {th['dos_threshold_hz']:g} Hz · max payload: {th['max_payload_bytes']} bytes")

# ------------------------------------------------------------ Tab 3: incidents
with tab_threats:
    alerts = api_get("/api/alerts") or []
    show_closed = st.checkbox("Include quarantined incidents", value=True)
    if not show_closed:
        alerts = [a for a in alerts if a["status"] != "QUARANTINED"]

    if not alerts:
        st.success("No incidents. Use the Attack Injection Console in the sidebar to test detection.")

    for idx, a in enumerate(alerts):
        aid = a["alert_id"]
        repeat = f" ×{a['occurrences']}" if a["occurrences"] > 1 else ""
        label = (f"{SEV_ICON.get(a['severity'], '⚪')} [{a['severity']}] {a['threat_type']} — "
                 f"{a['entity_id']}{repeat} · {STATUS_ICON.get(a['status'], '')} {a['status']}")
        with st.expander(label, expanded=(idx == 0 and a["status"] != "QUARANTINED")):
            st.markdown(f"**{a['title']}**")
            st.write(a["details"])
            c1, c2, c3 = st.columns(3)
            c1.caption(f"Source: {a['source']}")
            c2.caption(f"Target IP: {a['ip_address']}")
            c3.caption(f"Raised: {a['created_at']}")
            with st.popover("Evidence"):
                st.json(a["evidence"])

            triage = a.get("triage")
            if triage is None:
                if st.button("🧠 Run AI Triage", key=f"triage-{aid}"):
                    with st.spinner("Stage 3 agent is analysing the incident..."):
                        data, err = api_post("/api/triage/analyze", {"alert_id": aid})
                    flash("error", err) if err else flash("success", f"Triage complete for {a['entity_id']}.")
                    st.rerun()
            else:
                st.markdown("##### Executive summary")
                st.write(triage["summary"])
                st.markdown(f"**Suspected weakness:** `{triage['cve_mapping']}`")
                st.caption("AI-suggested mapping. Verify against NVD / MITRE before relying on it.")
                st.markdown("##### Remediation script")
                st.code(triage["remediation_script"], language="bash")
                st.caption(f"Model: {triage['model_used']} · {triage['latency_ms']:.0f} ms"
                           + (" · deterministic fallback" if triage["fallback_used"] else ""))
                for note in triage.get("notes", []):
                    st.caption(f"ℹ️ {note}")

                if a["status"] == "QUARANTINED":
                    st.success(f"🔒 {a['entity_id']} is quarantined.")
                    st.code("\n".join(a["remediation_log"]) or "(no output)", language="bash")
                else:
                    if a["source"] == "WATER":
                        st.warning("Hazardous readings may be a genuine physical event. Verify on site before "
                                   "isolating the sensor, or you may lose visibility of real contamination.")
                    if st.button("⚡ 1-Click Execute Remediation Script", type="primary", key=f"exec-{aid}"):
                        data, err = api_post("/api/triage/quarantine", {"alert_id": aid})
                        if err:
                            flash("error", err)
                        else:
                            tag = "SIMULATED" if data["mode"] == "simulate" else "EXECUTED"
                            flash("success", f"{tag}: {a['entity_id']} marked quarantined.")
                        st.rerun()

# --------------------------------------------------------------- live refresh
if live:
    time.sleep(5)
    st.rerun()