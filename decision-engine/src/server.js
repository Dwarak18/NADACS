import cors from "cors";
import express from "express";
import { v4 as uuidv4 } from "uuid";
import { decide, loadPolicyConfig } from "./policy.js";

const app = express();
const port = Number(process.env.PORT || 8080);
const enforcementUrl = process.env.ENFORCEMENT_URL || "http://localhost:8090";
const auditLogUrl = process.env.AUDIT_LOG_URL || "http://localhost:8010";
const config = loadPolicyConfig();

const detections = [];
const decisions = [];

app.use(cors());
app.use(express.json({ limit: "1mb" }));

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}`);
  }
  return response.json();
}

async function audit(eventType, payload) {
  try {
    await postJson(`${auditLogUrl}/events`, { event_type: eventType, payload });
  } catch {
    // Audit service outage must not block fail-open demo operation.
  }
}

app.get("/health", (req, res) => {
  res.json({ status: "ok", config, detections: detections.length, decisions: decisions.length });
});

app.get("/detections", (req, res) => {
  res.json(detections.slice(-100).reverse());
});

app.get("/decisions", (req, res) => {
  res.json(decisions.slice(-100).reverse());
});

app.post("/detections", async (req, res) => {
  const detection = req.body;
  detections.push(detection);

  const decision = {
    decision_id: uuidv4(),
    flow_id: detection.flow_id,
    confidence: detection.confidence,
    labels: detection.labels || [],
    ...decide(detection, config),
    created_at: new Date().toISOString()
  };
  decisions.push(decision);
  await audit("decision_created", decision);

  if (decision.action === "contain") {
    try {
      decision.enforcement = await postJson(`${enforcementUrl}/actions`, decision);
    } catch (error) {
      decision.enforcement = { status: "failed", error: error.message, failure_mode: config.failureMode };
      await audit("enforcement_failed", decision);
    }
  }

  res.status(201).json(decision);
});

app.post("/decisions/:decisionId/approve", async (req, res) => {
  const decision = decisions.find((item) => item.decision_id === req.params.decisionId);
  if (!decision) {
    return res.status(404).json({ error: "Decision not found" });
  }
  if (decision.action !== "review") {
    return res.status(409).json({ error: "Only review decisions can be approved" });
  }

  const containment = { ...decision, action: "contain", reason: "Analyst approved containment" };
  containment.enforcement = await postJson(`${enforcementUrl}/actions`, containment);
  decision.action = "contain";
  decision.reason = containment.reason;
  decision.enforcement = containment.enforcement;
  await audit("decision_approved", decision);
  return res.json(decision);
});

app.listen(port, () => {
  console.log(`Decision engine listening on ${port}`);
});

