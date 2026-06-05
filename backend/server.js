// Phishing Guard backend proxy.
//
// Why this exists: a browser extension cannot safely hold API keys (anyone can
// unzip it). This thin server holds the keys, runs the reputation + LLM tiers,
// caches verdicts, and rate-limits clients.
//
// Endpoints:
//   POST /scan     URL-only check (allowlist already handled client-side):
//                  Safe Browsing + heuristic score -> risk level.
//   POST /analyze  Deep check with page signals -> may escalate to the LLM.
import dotenv from "dotenv";
// override: true so keys in backend/.env win over any stale values already
// exported in the shell environment (otherwise dotenv leaves the shell's wins).
dotenv.config({ override: true });
import express from "express";
import cors from "cors";
import { TtlCache } from "./src/cache.js";
import { checkSafeBrowsing, checkSafeBrowsingBatch } from "./src/safeBrowsing.js";
import { classifyWithLLM, classifyUrlsWithLLM } from "./src/llm.js";
import {
  RISK,
  categoryFromThreats,
  riskFromHeuristics,
  riskFromLLM,
} from "./src/classify.js";

const app = express();
app.set("trust proxy", true); // behind Cloud Run / a reverse proxy: real client IP
// CORS: lock to a specific origin in production via ALLOWED_ORIGIN; open in dev.
// (Note: MV3 extension fetches with host permission bypass CORS anyway — the
// API token below is the real access control.)
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
app.use(cors(ALLOWED_ORIGIN ? { origin: ALLOWED_ORIGIN } : {}));
app.use(express.json({ limit: "256kb" }));

// Shared-secret gate for the spending endpoints. If API_TOKEN is set (in the
// cloud), every protected request must send "Authorization: Bearer <token>".
// If unset (local dev), the gate is open.
const API_TOKEN = process.env.API_TOKEN;
function requireToken(req, res, next) {
  if (!API_TOKEN) return next();
  const h = req.get("authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (tok !== API_TOKEN) return res.status(401).json({ error: "unauthorized" });
  next();
}

const verdictCache = new TtlCache(60 * 60 * 1000); // 1h, keyed by hostname

// --- crude per-IP rate limiter (token bucket) ----------------------------
const RATE = { capacity: 60, refillPerSec: 1 }; // ~60 req burst, 1/s sustained
const buckets = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || "unknown";
  const now = Date.now();
  let b = buckets.get(ip);
  if (!b) b = { tokens: RATE.capacity, ts: now };
  b.tokens = Math.min(RATE.capacity, b.tokens + ((now - b.ts) / 1000) * RATE.refillPerSec);
  b.ts = now;
  if (b.tokens < 1) {
    buckets.set(ip, b);
    return res.status(429).json({ error: "rate limited" });
  }
  b.tokens -= 1;
  buckets.set(ip, b);
  next();
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Verdict cache key: origin + path (query/fragment dropped). Per-page rather
// than per-host, so one bad/safe page doesn't determine the verdict for every
// other path on the same host.
function cacheKeyOf(url) {
  try {
    const u = new URL(url);
    return u.origin.toLowerCase() + u.pathname;
  } catch {
    return null;
  }
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    safeBrowsing: !!process.env.GOOGLE_SAFE_BROWSING_KEY,
    llm: !!process.env.OPENAI_API_KEY,
  });
});

// --- /scan: fast, URL-only -----------------------------------------------
app.post("/scan", requireToken, rateLimit, async (req, res) => {
  const { url, heuristicScore = 0, heuristicReasons = [] } = req.body || {};
  const host = hostnameOf(url);
  if (!host) return res.status(400).json({ error: "invalid url" });
  const key = cacheKeyOf(url);

  const cached = verdictCache.get(key);
  if (cached) return res.json(cached);

  const sb = await checkSafeBrowsing(url);
  let verdict;
  if (sb.listed) {
    verdict = {
      risk: RISK.HIGH,
      reasons: [`Listed by Google Safe Browsing (${sb.threats.join(", ")})`],
      category: categoryFromThreats(sb.threats),
      source: "safe-browsing",
    };
  } else {
    verdict = {
      risk: riskFromHeuristics(heuristicScore),
      reasons: heuristicReasons,
      category: "phishing",
      source: "heuristics",
    };
  }

  // Only cache confident verdicts; SUSPICIOUS is re-evaluated by /analyze.
  if (verdict.risk === RISK.HIGH || verdict.risk === RISK.SAFE) {
    verdictCache.set(key, verdict);
  }
  res.json(verdict);
});

// --- /scan-batch: many URLs in one request (used by "scan page links") -----
// Body: { items: [{ url, heuristicScore, heuristicReasons }, ...] }
// One Safe Browsing call covers all URLs, so this is far cheaper than N /scan
// calls and avoids the per-request rate limit.
app.post("/scan-batch", requireToken, rateLimit, async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items.slice(0, 500) : [];
  const urls = items.map((it) => it.url).filter(Boolean);
  const sbMap = await checkSafeBrowsingBatch(urls);

  const results = items.map((it) => {
    const key = cacheKeyOf(it.url);
    if (!key) return { url: it.url, risk: RISK.SAFE, reasons: ["invalid url"], source: "error" };

    const cached = verdictCache.get(key);
    if (cached) return { url: it.url, ...cached };

    const threats = sbMap.get(it.url) || [];
    let verdict;
    if (threats.length) {
      verdict = {
        risk: RISK.HIGH,
        reasons: [`Listed by Google Safe Browsing (${threats.join(", ")})`],
        category: categoryFromThreats(threats),
        source: "safe-browsing",
      };
    } else {
      verdict = {
        risk: riskFromHeuristics(it.heuristicScore || 0),
        reasons: it.heuristicReasons || [],
        category: "phishing",
        source: "heuristics",
      };
    }
    if (verdict.risk === RISK.HIGH || verdict.risk === RISK.SAFE) verdictCache.set(key, verdict);
    return { url: it.url, ...verdict };
  });

  res.json({ results });
});

// --- /diagnose-links: LLM judgment over a list of URLs (no page fetch) ----
// Body: { urls: [...] }  -> { results: [{url, phishing, confidence, reason}], available }
app.post("/diagnose-links", requireToken, rateLimit, async (req, res) => {
  const urls = Array.isArray(req.body?.urls) ? req.body.urls.slice(0, 50) : [];
  if (urls.length === 0) return res.json({ results: [], available: true });

  const llm = await classifyUrlsWithLLM(urls);
  if (!llm) return res.json({ results: [], available: false }); // no key / error / billing
  res.json({ results: llm, available: true });
});

// --- /analyze: deep, may use the LLM -------------------------------------
app.post("/analyze", requireToken, rateLimit, async (req, res) => {
  const { url, heuristicScore = 0, heuristicReasons = [], page } = req.body || {};
  const host = hostnameOf(url);
  if (!host) return res.status(400).json({ error: "invalid url" });
  const key = cacheKeyOf(url);

  // Reputation first (cached upstream).
  const sb = await checkSafeBrowsing(url);
  if (sb.listed) {
    const verdict = {
      risk: RISK.HIGH,
      reasons: [`Listed by Google Safe Browsing (${sb.threats.join(", ")})`],
      category: categoryFromThreats(sb.threats),
      source: "safe-browsing",
    };
    verdictCache.set(key, verdict);
    return res.json(verdict);
  }

  // Decide whether the LLM tier is worth invoking.
  const crossOriginForm =
    Array.isArray(page?.formTargets) &&
    page.formTargets.some((h) => h && h !== page.currentHost);
  const hasPassword = (page?.passwordFields ?? 0) > 0;
  const shouldUseLLM = heuristicScore >= 30 || hasPassword || crossOriginForm;

  if (!shouldUseLLM) {
    return res.json({
      risk: riskFromHeuristics(heuristicScore),
      reasons: heuristicReasons,
      category: "phishing",
      source: "heuristics",
    });
  }

  const llm = await classifyWithLLM({ url, page });
  if (!llm) {
    // LLM unavailable — fall back to heuristics.
    return res.json({
      risk: riskFromHeuristics(heuristicScore),
      reasons: heuristicReasons,
      category: "phishing",
      source: "heuristics",
    });
  }

  const risk = riskFromLLM(llm);

  const reasons = [...heuristicReasons];
  if (llm.impersonated_brand) {
    reasons.unshift(`Appears to impersonate ${llm.impersonated_brand}`);
  }

  const verdict = {
    risk,
    reasons,
    explanation: llm.reason,
    category: "phishing",
    source: "llm",
  };
  if (risk === RISK.HIGH) verdictCache.set(key, verdict);
  res.json(verdict);
});

const PORT = process.env.PORT || 8787;
app.listen(PORT, () => {
  console.log(`Phishing Guard backend listening on http://localhost:${PORT}`);
  console.log(`  Safe Browsing: ${process.env.GOOGLE_SAFE_BROWSING_KEY ? "enabled" : "DISABLED (set GOOGLE_SAFE_BROWSING_KEY)"}`);
  console.log(`  OpenAI LLM:    ${process.env.OPENAI_API_KEY ? "enabled" : "DISABLED (set OPENAI_API_KEY)"}`);
  console.log(`  API token:     ${API_TOKEN ? "REQUIRED" : "open (set API_TOKEN to lock down)"}`);
});
