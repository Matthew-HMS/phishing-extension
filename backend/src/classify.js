// Pure verdict-classification helpers, shared by the server and the test suite.
// No I/O, no side effects — easy to unit-test and tune.

export const RISK = { SAFE: "SAFE", LOW: "LOW", SUSPICIOUS: "SUSPICIOUS", HIGH: "HIGH" };

// Map Safe Browsing threat types to a user-facing category.
export function categoryFromThreats(threats = []) {
  if (threats.includes("SOCIAL_ENGINEERING")) return "phishing";
  if (
    threats.includes("MALWARE") ||
    threats.includes("UNWANTED_SOFTWARE") ||
    threats.includes("POTENTIALLY_HARMFUL_APPLICATION")
  ) {
    return "malware";
  }
  return "phishing";
}

// Map a local heuristic score (0..100) to a risk level.
export function riskFromHeuristics(score) {
  if (score >= 70) return RISK.HIGH;
  if (score >= 40) return RISK.SUSPICIOUS;
  if (score >= 15) return RISK.LOW;
  return RISK.SAFE;
}

// Map an LLM verdict ({ phishing, confidence }) to a risk level.
export function riskFromLLM(llm) {
  if (llm?.phishing && llm.confidence >= 0.7) return RISK.HIGH;
  if (llm?.phishing && llm.confidence >= 0.4) return RISK.SUSPICIOUS;
  return RISK.LOW;
}
