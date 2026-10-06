export function buildCommand(action, mode = "simulated-openflow") {
  const ip = action.target?.ip;
  const segment = action.target?.segment || "unknown-segment";
  if (!ip) {
    throw new Error("Containment target IP is required");
  }

  if (mode === "simulated-iptables") {
    return `iptables -A INPUT -s ${ip} -j DROP # segment=${segment}`;
  }

  return `deny ip host ${ip} any on ${segment}`;
}

