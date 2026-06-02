// Google Safe Browsing (Lookup API v4) — Tier 3 of the cascade.
// Free, purpose-built, and the same data Chrome itself uses. This should be
// the first *network* check for any unknown URL.
//
// Get a key: https://developers.google.com/safe-browsing/v4/get-started
// Set it as GOOGLE_SAFE_BROWSING_KEY. If unset, this tier is skipped.
import { TtlCache } from "./cache.js";

const cache = new TtlCache(30 * 60 * 1000); // 30 min

const THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING", // <- phishing / deceptive
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

/**
 * @returns {Promise<{listed: boolean, threats: string[], available: boolean}>}
 */
export async function checkSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) return { listed: false, threats: [], available: false };

  const cached = cache.get(url);
  if (cached) return cached;

  const endpoint =
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
    encodeURIComponent(key);

  const body = {
    client: { clientId: "phishing-guard", clientVersion: "0.1.0" },
    threatInfo: {
      threatTypes: THREAT_TYPES,
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      console.warn("Safe Browsing error:", res.status, await res.text());
      return { listed: false, threats: [], available: true };
    }
    const data = await res.json();
    const threats = (data.matches || []).map((m) => m.threatType);
    const result = { listed: threats.length > 0, threats, available: true };
    cache.set(url, result);
    return result;
  } catch (err) {
    console.warn("Safe Browsing request failed:", err.message);
    return { listed: false, threats: [], available: true };
  }
}
