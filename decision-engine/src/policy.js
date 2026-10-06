export function decide(detection, config) {
  const confidence = Number(detection.confidence || 0);
  const labels = detection.labels || [];
  const target = {
    ip: detection.src_ip,
    segment: detection.segment
  };

  if (confidence >= config.autoContainThreshold && labels.length > 0) {
    return {
      action: "contain",
      target,
      reason: "High-confidence anomaly crossed auto-containment threshold"
    };
  }

  if (confidence >= config.reviewThreshold) {
    return {
      action: "review",
      target,
      reason: "Medium-confidence anomaly queued for analyst review"
    };
  }

  return {
    action: "observe",
    target,
    reason: "Below review threshold; retained for baseline and audit"
  };
}

export function loadPolicyConfig(env = process.env) {
  return {
    autoContainThreshold: Number(env.AUTO_CONTAIN_THRESHOLD || 0.85),
    reviewThreshold: Number(env.REVIEW_THRESHOLD || 0.6),
    failureMode: env.FAILURE_MODE || "fail-open"
  };
}

