import assert from "node:assert/strict";
import test from "node:test";
import { decide } from "./policy.js";

test("contains high-confidence labeled detections", () => {
  const decision = decide(
    { confidence: 0.91, labels: ["port_scan"], src_ip: "10.0.0.5", segment: "lab" },
    { autoContainThreshold: 0.85, reviewThreshold: 0.6 }
  );
  assert.equal(decision.action, "contain");
});

test("queues medium-confidence detections for review", () => {
  const decision = decide(
    { confidence: 0.7, labels: ["traffic_spike"], src_ip: "10.0.0.5", segment: "lab" },
    { autoContainThreshold: 0.85, reviewThreshold: 0.6 }
  );
  assert.equal(decision.action, "review");
});

