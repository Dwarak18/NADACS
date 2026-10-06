import assert from "node:assert/strict";
import test from "node:test";
import { buildCommand } from "./enforcer.js";

test("builds simulated OpenFlow command", () => {
  const command = buildCommand({ target: { ip: "10.0.0.5", segment: "lab" } });
  assert.equal(command, "deny ip host 10.0.0.5 any on lab");
});

test("requires target IP", () => {
  assert.throws(() => buildCommand({ target: {} }), /required/);
});

