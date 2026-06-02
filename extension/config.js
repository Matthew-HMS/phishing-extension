// Central config for the extension.
// Point this at your running backend proxy (see /backend).
// In production this should be your deployed HTTPS endpoint.
export const BACKEND_URL = "http://localhost:8787";

// How long a verdict for a domain is trusted before re-checking (ms).
export const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Risk levels returned by the backend / heuristics.
export const RISK = {
  SAFE: "SAFE",
  LOW: "LOW",
  SUSPICIOUS: "SUSPICIOUS",
  HIGH: "HIGH",
};
