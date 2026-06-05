// Central config for the extension.
// Point this at your running backend proxy (see /backend).
// In production this should be your deployed HTTPS endpoint, e.g.
//   "https://phishing-guard-xxxx.run.app"
// For local testing: comment the cloud line, uncomment localhost, reload the extension.
// export const BACKEND_URL = "http://localhost:8787";
export const BACKEND_URL = "https://phishing-guard-1087009224061.asia-east1.run.app";

// Shared-secret token sent as "Authorization: Bearer <token>". Must match the
// backend's API_TOKEN env var. Leave empty for open local dev.
// NOTE: this ships inside the extension, so treat it as abuse-deterrence, not
// strong auth (anyone who unzips the extension can read it).
export const API_TOKEN = "3cbd8af215f4f1042c74a791926c3c7d3cb1334248af0bb62b7d81593e745b20";

// How long a verdict for a domain is trusted before re-checking (ms).
export const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Risk levels returned by the backend / heuristics.
export const RISK = {
  SAFE: "SAFE",
  LOW: "LOW",
  SUSPICIOUS: "SUSPICIOUS",
  HIGH: "HIGH",
};
