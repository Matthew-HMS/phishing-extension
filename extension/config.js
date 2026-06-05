// Central config for the extension.
// Point this at your running backend proxy (see /backend).
// In production this should be your deployed HTTPS endpoint, e.g.
//   "https://phishing-guard-xxxx.run.app"
export const BACKEND_URL = "http://localhost:8787";

// Shared-secret token sent as "Authorization: Bearer <token>". Must match the
// backend's API_TOKEN env var. Leave empty for open local dev.
// NOTE: this ships inside the extension, so treat it as abuse-deterrence, not
// strong auth (anyone who unzips the extension can read it).
export const API_TOKEN = "";

// How long a verdict for a domain is trusted before re-checking (ms).
export const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Risk levels returned by the backend / heuristics.
export const RISK = {
  SAFE: "SAFE",
  LOW: "LOW",
  SUSPICIOUS: "SUSPICIOUS",
  HIGH: "HIGH",
};
