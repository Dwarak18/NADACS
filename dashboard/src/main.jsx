import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, AlertTriangle, FileCheck2, ShieldCheck } from "lucide-react";
import "./styles.css";

const DECISION_URL = import.meta.env.VITE_DECISION_ENGINE_URL || "http://localhost:8080";
const ENFORCEMENT_URL = import.meta.env.VITE_ENFORCEMENT_URL || "http://localhost:8090";
const AUDIT_URL = import.meta.env.VITE_AUDIT_LOG_URL || "http://localhost:8010";

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}`);
  }
  return response.json();
}

function StatusCard({ icon: Icon, label, value, detail }) {
  return (
    <section className="status-card">
      <Icon size={22} />
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{detail}</span>
      </div>
    </section>
  );
}

function DecisionRow({ decision, onApprove }) {
  return (
    <tr>
      <td>
        <span className={`pill ${decision.action}`}>{decision.action}</span>
      </td>
      <td>{decision.target?.ip || "unknown"}</td>
      <td>{decision.labels?.join(", ") || "none"}</td>
      <td>{Math.round(Number(decision.confidence || 0) * 100)}%</td>
      <td>{decision.reason}</td>
      <td>
        {decision.action === "review" ? (
          <button onClick={() => onApprove(decision.decision_id)}>Contain</button>
        ) : (
          <span className="muted">-</span>
        )}
      </td>
    </tr>
  );
}

function App() {
  const [decisions, setDecisions] = useState([]);
  const [actions, setActions] = useState([]);
  const [events, setEvents] = useState([]);
  const [verify, setVerify] = useState({ valid: false, events: 0 });
  const [error, setError] = useState("");

  async function load() {
    try {
      const [decisionData, actionData, eventData, verifyData] = await Promise.all([
        fetchJson(`${DECISION_URL}/decisions`),
        fetchJson(`${ENFORCEMENT_URL}/actions`),
        fetchJson(`${AUDIT_URL}/events`),
        fetchJson(`${AUDIT_URL}/verify`)
      ]);
      setDecisions(decisionData);
      setActions(actionData);
      setEvents(eventData);
      setVerify(verifyData);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }

  async function approve(decisionId) {
    await fetch(`${DECISION_URL}/decisions/${decisionId}/approve`, { method: "POST" });
    await load();
  }

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  const summary = useMemo(() => {
    return {
      contain: decisions.filter((item) => item.action === "contain").length,
      review: decisions.filter((item) => item.action === "review").length,
      observe: decisions.filter((item) => item.action === "observe").length
    };
  }, [decisions]);

  return (
    <main>
      <header>
        <div>
          <h1>NADACS</h1>
          <p>Distributed anomaly detection and auto-containment console</p>
        </div>
        <button onClick={load}>Refresh</button>
      </header>

      {error ? <div className="error">Service connection issue: {error}</div> : null}

      <section className="status-grid">
        <StatusCard icon={AlertTriangle} label="Review Queue" value={summary.review} detail="Human approval required" />
        <StatusCard icon={ShieldCheck} label="Contained" value={summary.contain} detail="Simulated enforcement actions" />
        <StatusCard icon={Activity} label="Observed" value={summary.observe} detail="Below response threshold" />
        <StatusCard icon={FileCheck2} label="Audit Chain" value={verify.valid ? "Valid" : "Check"} detail={`${verify.events || 0} events`} />
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Decision Queue</h2>
          <span>{decisions.length} recent decisions</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Action</th>
                <th>Source</th>
                <th>Labels</th>
                <th>Confidence</th>
                <th>Reason</th>
                <th>Review</th>
              </tr>
            </thead>
            <tbody>
              {decisions.map((decision) => (
                <DecisionRow key={decision.decision_id} decision={decision} onApprove={approve} />
              ))}
              {!decisions.length ? (
                <tr>
                  <td colSpan="6" className="empty">No detections received yet.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="two-column">
        <div className="panel">
          <div className="panel-heading">
            <h2>Enforcement</h2>
            <span>{actions.length} actions</span>
          </div>
          <ul className="list">
            {actions.map((action) => (
              <li key={action.action_id}>
                <strong>{action.status}</strong>
                <code>{action.command}</code>
              </li>
            ))}
            {!actions.length ? <li className="empty">No containment actions yet.</li> : null}
          </ul>
        </div>

        <div className="panel">
          <div className="panel-heading">
            <h2>Audit Events</h2>
            <span>{events.length} latest</span>
          </div>
          <ul className="list">
            {events.slice(0, 8).map((event) => (
              <li key={event.id}>
                <strong>{event.event_type}</strong>
                <code>{String(event.event_hash).slice(0, 18)}...</code>
              </li>
            ))}
            {!events.length ? <li className="empty">Audit log is empty.</li> : null}
          </ul>
        </div>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);

