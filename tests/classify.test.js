import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RISK,
  categoryFromThreats,
  riskFromHeuristics,
  riskFromLLM,
} from "../backend/src/classify.js";

test("categoryFromThreats maps Safe Browsing threat types", () => {
  assert.equal(categoryFromThreats(["SOCIAL_ENGINEERING"]), "phishing");
  assert.equal(categoryFromThreats(["MALWARE"]), "malware");
  assert.equal(categoryFromThreats(["UNWANTED_SOFTWARE"]), "malware");
  assert.equal(categoryFromThreats([]), "phishing"); // default
});

test("riskFromHeuristics thresholds", () => {
  assert.equal(riskFromHeuristics(80), RISK.HIGH);
  assert.equal(riskFromHeuristics(70), RISK.HIGH);
  assert.equal(riskFromHeuristics(40), RISK.SUSPICIOUS);
  assert.equal(riskFromHeuristics(15), RISK.LOW);
  assert.equal(riskFromHeuristics(0), RISK.SAFE);
});

test("riskFromLLM uses phishing flag + confidence", () => {
  assert.equal(riskFromLLM({ phishing: true, confidence: 0.9 }), RISK.HIGH);
  assert.equal(riskFromLLM({ phishing: true, confidence: 0.5 }), RISK.SUSPICIOUS);
  assert.equal(riskFromLLM({ phishing: true, confidence: 0.2 }), RISK.LOW);
  assert.equal(riskFromLLM({ phishing: false, confidence: 0.99 }), RISK.LOW);
  assert.equal(riskFromLLM(null), RISK.LOW);
});
