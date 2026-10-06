# NADACS: Distributed Network Anomaly Detection & Auto-Containment System

NADACS is a placement-grade network security project that demonstrates distributed capture, flow-based anomaly detection, human-aware response policy, simulated enforcement, and tamper-evident audit logging.

The system intentionally avoids deep packet inspection as the default path. It works on flow metadata so it can reason about encrypted traffic, scale beyond toy packet demos, and keep privacy boundaries clear.

## Architecture

```text
Mirrored traffic or generated lab flows
  -> capture-agent
  -> detection-engine
  -> decision-engine
  -> enforcement
  -> audit-log
  -> dashboard
```

## Services

- `capture-agent`: Python agent that extracts or generates flow features and submits them to the detection engine.
- `detection-engine`: FastAPI service with statistical heuristics plus Isolation Forest scoring.
- `decision-engine`: Express service that applies confidence thresholds and containment policy.
- `enforcement`: Express service that simulates SDN/OpenFlow or iptables containment actions.
- `audit-log`: FastAPI service that persists tamper-evident hash-chained audit events.
- `dashboard`: React + Tailwind dashboard for alerts, decisions, and enforcement actions.

## Quick Start

1. Copy `.env.example` to `.env` and adjust values if needed.
2. Start the backend services:

```powershell
docker compose up --build
```

3. In another terminal, run the capture agent once to seed events:

```powershell
cd capture-agent
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python src/agent.py --mode synthetic --count 25
```

4. Open the dashboard at `http://localhost:5173`.

## Confidence Policy

NADACS is conservative by design:

- High confidence anomalies are automatically contained.
- Medium confidence anomalies are queued for analyst review.
- Low confidence events are observed and logged.

This prevents the common final-year-project flaw where false positives can cause accidental outages.

## Explicit Limitations

- TLS payloads are not inspected. The system relies on metadata such as flow size, timing, destination entropy, and connection rates.
- Enforcement is simulated by default. Real switch or firewall integrations are intentionally out of scope for a final-year implementation unless the lab environment provides safe APIs.
- Agent partition behavior is explicit: services fail open by default, but the policy can be changed through configuration.

## Development

Run Python checks:

```powershell
python -m compileall capture-agent detection-engine audit-log
```

Run Node checks:

```powershell
cd decision-engine; npm install; npm test
cd ..\\enforcement; npm install; npm test
cd ..\\dashboard; npm install; npm run build
```

