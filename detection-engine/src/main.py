import hashlib
import json
import math
import os
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import Any

import numpy as np
import requests
from fastapi import FastAPI
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest


DECISION_ENGINE_URL = os.getenv("DECISION_ENGINE_URL", "http://localhost:8080")
AUDIT_LOG_URL = os.getenv("AUDIT_LOG_URL", "http://localhost:8010")

app = FastAPI(title="NADACS Detection Engine", version="0.1.0")

recent_flows: deque[dict[str, Any]] = deque(maxlen=500)
src_port_history: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=100))
model = IsolationForest(contamination=0.15, random_state=42)
model_ready = False


class Flow(BaseModel):
    agent_id: str
    segment: str
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str
    bytes: int = Field(ge=0)
    packets: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    start_time: str
    end_time: str
    tcp_flags: list[str] = []
    metadata: dict[str, Any] = {}
    flow_id: str | None = None


def stable_flow_id(flow: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(flow, sort_keys=True, default=str).encode()).hexdigest()


def feature_vector(flow: dict[str, Any]) -> list[float]:
    duration = max(flow["duration_ms"], 1)
    packets = max(flow["packets"], 1)
    return [
        math.log1p(flow["bytes"]),
        math.log1p(packets),
        flow["bytes"] / packets,
        packets / duration,
        flow["dst_port"] / 65535,
        1.0 if "SYN" in flow.get("tcp_flags", []) and "ACK" not in flow.get("tcp_flags", []) else 0.0,
        1.0 if flow.get("metadata", {}).get("encrypted") else 0.0,
    ]


def port_entropy(ports: list[int]) -> float:
    if not ports:
        return 0.0
    counts = Counter(ports)
    total = len(ports)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def heuristic_score(flow: dict[str, Any]) -> tuple[float, list[str], list[str]]:
    labels: list[str] = []
    reasons: list[str] = []
    score = 0.0

    history = src_port_history[flow["src_ip"]]
    history.append(flow["dst_port"])
    entropy = port_entropy(list(history))

    syn_only = "SYN" in flow.get("tcp_flags", []) and "ACK" not in flow.get("tcp_flags", [])
    packet_rate = flow["packets"] / max(flow["duration_ms"], 1)
    bytes_per_packet = flow["bytes"] / max(flow["packets"], 1)

    if len(history) >= 8 and entropy >= 2.5:
        score += 0.35
        labels.append("port_scan")
        reasons.append("High destination port entropy for source")

    if syn_only and flow["packets"] <= 8:
        score += 0.25
        labels.append("syn_probe")
        reasons.append("SYN-heavy short flow")

    if packet_rate > 0.4 and flow["packets"] > 80:
        score += 0.25
        labels.append("traffic_spike")
        reasons.append("Packet rate exceeds segment baseline")

    if bytes_per_packet < 90 and flow["packets"] > 40:
        score += 0.15
        labels.append("low_payload_scan")
        reasons.append("Many small packets with low payload density")

    return min(score, 1.0), sorted(set(labels)), reasons


def ml_score(flow: dict[str, Any]) -> float:
    global model_ready
    if not model_ready:
        return 0.0
    vector = np.array([feature_vector(flow)])
    raw = model.decision_function(vector)[0]
    return float(max(0.0, min(1.0, 0.5 - raw)))


def audit(event_type: str, payload: dict[str, Any]) -> None:
    try:
        requests.post(f"{AUDIT_LOG_URL}/events", json={"event_type": event_type, "payload": payload}, timeout=2)
    except requests.RequestException:
        pass


def forward_detection(result: dict[str, Any]) -> None:
    try:
        requests.post(f"{DECISION_ENGINE_URL}/detections", json=result, timeout=4)
    except requests.RequestException:
        audit("decision_forward_failed", result)


@app.get("/health")
def health():
    return {"status": "ok", "model_ready": model_ready, "recent_flows": len(recent_flows)}


@app.post("/model/train")
def train_model(flows: list[Flow]):
    global model_ready
    vectors = [feature_vector(flow.model_dump()) for flow in flows]
    if len(vectors) < 10:
        return {"status": "skipped", "reason": "At least 10 flows are required"}
    model.fit(np.array(vectors))
    model_ready = True
    return {"status": "trained", "samples": len(vectors)}


@app.post("/flows")
def ingest_flow(flow: Flow):
    flow_dict = flow.model_dump()
    flow_dict["flow_id"] = flow.flow_id or stable_flow_id(flow_dict)
    recent_flows.append(flow_dict)

    heuristic, labels, reasons = heuristic_score(flow_dict)
    anomaly = max(heuristic, ml_score(flow_dict))
    confidence = min(0.99, 0.45 + anomaly * 0.55)
    if not labels and anomaly >= 0.65:
        labels = ["ml_anomaly"]
        reasons.append("Isolation Forest marked flow as anomalous")

    result = {
        "flow_id": flow_dict["flow_id"],
        "agent_id": flow.agent_id,
        "segment": flow.segment,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "anomaly_score": round(anomaly, 4),
        "confidence": round(confidence, 4),
        "labels": labels,
        "reasons": reasons or ["Flow observed within current baseline"],
        "flow": flow_dict,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }

    audit("detection_created", result)
    forward_detection(result)
    return result

