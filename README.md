# CivicShield 🛡️💧

> **Autonomous Hybrid Edge-IoT Defense Pipeline for Municipal Water Infrastructure**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.25%2B-FF4B4B.svg)](https://streamlit.io/)
[![Groq SDK](https://img.shields.io/badge/Groq-llama--3.1--8b--instant-f05032.svg)](https://groq.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Executive Summary

Municipal water grids rely on lightweight IoT sensors (pH, flow rate, turbidity) that lack onboard compute and encryption. This leaves critical water distribution networks vulnerable to:
1. **Volumetric DoS Floods:** Overwhelming edge controllers to block legitimate telemetry.
2. **Command & Payload Injections:** Inserting SQL/Shell payloads into sensor reporting strings.
3. **Physical Data Poisoning:** Falsifying sensor telemetry (e.g., masking sudden toxic pH drops).

Traditional Security Operations Centers (SOCs) react in minutes—whereas chemical water contamination occurs in seconds. **CivicShield** decouples threat mitigation into a synchronous **sub-10ms edge filtering path** and an asynchronous **background AI triage agent**, ensuring zero-latency protection without processing bottlenecks.

---

## 🏗️ Architecture & Pipeline Stages

[ Inbound IoT Sensor Telemetry ]
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 1: Ingestion & Validation                         │
│ FastAPI + Pydantic v2 (Strict Schema Enforcement)       │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 2: Hot-Path Sentinel Rule Engine (<10ms)          │
│ Rate Limiting (>100Hz) | Payload Regex | Water Limits   │
└──────────────┬───────────────────────────┬──────────────┘
               │                           │
               │ (Clean)                   │ (Malicious / Anomalous)
               ▼                           ▼
 ┌───────────────────────────┐   ┌───────────────────────────┐
 │ Thread-Safe In-Memory     │   │ Quarantined In RAM        │
 │ Telemetry Datastore       │   └─────────────┬─────────────┘
 └───────────────────────────┘                 │ (Async Non-Blocking Task)
                                               ▼
                                 ┌───────────────────────────┐
                                 │ Stage 3: Cold-Path AI     │
                                 │ Groq SDK (Llama 3.1 8B)   │
                                 │ CVE Mapping & Fix Script  │
                                 └─────────────┬─────────────┘
                                               │
                                               ▼
                                 ┌───────────────────────────┐
                                 │ Stage 4: SOC Operations   │
                                 │ Streamlit Panel (Port 8501│
                                 └───────────────────────────┘

---

## 🚀 Key Features

* **Sub-10ms Hot Path:** Deterministic inspection engine (sentinel_rules.py, water_rules.py) filters packets before storage access.
* **Thread-Safe Memory Store:** Custom volatile RAM datastore (backend/app/database.py) prevents disk write-lock bottlenecks during DoS attacks.
* **Asynchronous AI Triage:** Background Groq LLM integration (llama-3.1-8b-instant) provides instant CVE mapping and remediation scripts without blocking packet throughput.
* **Real-Time SOC Panel:** Interactive Streamlit operational dashboard with Plotly telemetry graphs and 1-click active device quarantine controls.

---

## 🛠️ Tech Stack & Storage Rationale

| Layer | Technology | Rationale |
| :--- | :--- | :--- |
| **Ingestion Engine** | FastAPI + Uvicorn | Asynchronous ASGI server capable of handling thousands of concurrent requests. |
| **Data Contracts** | Pydantic v2 | High-speed schema validation ensuring corrupt payloads fail at ingestion. |
| **Hot Storage** | Python threading.Lock + Memory | Eliminates disk I/O latency (15 to 50 ms) under 1,000 req/sec DoS floods. |
| **AI Threat Agent** | Groq SDK (llama-3.1-8b-instant) | Ultra-low latency inference for structured JSON CVE contextualization. |
| **Operations Panel** | Streamlit + Plotly | Native Python data-binding directly to backend Pydantic data schemas. |

---

## ⚙️ Getting Started

### 1. Prerequisites & Installation

Clone the repository and install dependencies:

git clone https://github.com/roshan-huh/CivicShield.git
cd CivicShield
pip install -r backend/requirements.txt

Create a .env file in the root directory:

GROQ_API_KEY=your_groq_api_key_here

---

### 2. Running the Application

Open two separate terminal windows:

#### Terminal 1: Backend API (Port 8000)
py -m uvicorn app.main:app --app-dir backend --reload --port 8000

API docs available at: http://localhost:8000/docs

#### Terminal 2: Streamlit SOC Dashboard (Port 8501)
py -m streamlit run dashboard/app.py

Dashboard opens automatically at: http://localhost:8501

---

## 🧪 Testing & Attack Simulation

Run synthetic telemetry and inject threat vectors using the provided CLI tools:

# Inject DoS Packet Flood
py simulators/attack_injector.py --type dos --rate 250

# Inject Toxic pH Data Poisoning Payload
py simulators/attack_injector.py --type poisoning --ph 2.1

---

## 📄 License

Distributed under the MIT License. See LICENSE for details.
