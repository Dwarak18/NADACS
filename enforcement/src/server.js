import cors from "cors";
import express from "express";
import { v4 as uuidv4 } from "uuid";
import { buildCommand } from "./enforcer.js";

const app = express();
const port = Number(process.env.PORT || 8090);
const mode = process.env.ENFORCEMENT_MODE || "simulated-openflow";
const auditLogUrl = process.env.AUDIT_LOG_URL || "http://localhost:8010";
const actions = [];

app.use(cors());
app.use(express.json({ limit: "1mb" }));

async function audit(eventType, payload) {
  try {
    await fetch(`${auditLogUrl}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event_type: eventType, payload })
    });
  } catch {
    // Enforcement still returns the simulated command when audit is unavailable.
  }
}

app.get("/health", (req, res) => {
  res.json({ status: "ok", mode, actions: actions.length });
});

app.get("/actions", (req, res) => {
  res.json(actions.slice(-100).reverse());
});

app.post("/actions", async (req, res) => {
  try {
    const command = buildCommand(req.body, mode);
    const result = {
      action_id: uuidv4(),
      decision_id: req.body.decision_id,
      status: "simulated",
      mode,
      command,
      created_at: new Date().toISOString()
    };
    actions.push(result);
    await audit("enforcement_action_created", result);
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Enforcement service listening on ${port}`);
});

