# NADACS API Contract

## Flow Features

`capture-agent -> detection-engine`

```json
{
  "agent_id": "seg-a-agent-01",
  "segment": "lab-segment-a",
  "src_ip": "10.0.0.12",
  "dst_ip": "10.0.0.8",
  "src_port": 54012,
  "dst_port": 443,
  "protocol": "TCP",
  "bytes": 128000,
  "packets": 92,
  "duration_ms": 1200,
  "start_time": "2026-07-09T13:30:00Z",
  "end_time": "2026-07-09T13:30:01Z",
  "tcp_flags": ["SYN", "ACK"],
  "metadata": {
    "encrypted": true
  }
}
```

## Detection Result

`detection-engine -> decision-engine`

```json
{
  "flow_id": "sha256",
  "agent_id": "seg-a-agent-01",
  "segment": "lab-segment-a",
  "src_ip": "10.0.0.12",
  "dst_ip": "10.0.0.8",
  "anomaly_score": 0.91,
  "confidence": 0.88,
  "labels": ["port_scan"],
  "reasons": ["High destination port entropy", "Elevated SYN-heavy flow rate"],
  "flow": {}
}
```

## Decision

`decision-engine -> enforcement`

```json
{
  "decision_id": "uuid",
  "flow_id": "sha256",
  "action": "contain",
  "confidence": 0.88,
  "target": {
    "ip": "10.0.0.12",
    "segment": "lab-segment-a"
  },
  "reason": "High-confidence anomaly crossed auto-containment threshold"
}
```

## Enforcement Result

```json
{
  "action_id": "uuid",
  "decision_id": "uuid",
  "status": "simulated",
  "mode": "simulated-openflow",
  "command": "deny ip host 10.0.0.12 any on lab-segment-a"
}
```

