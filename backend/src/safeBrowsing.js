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

// Batch variant — looks up many URLs in a single API call (used for "scan all
// links on this page"). Returns a Map<url, threats[]>. The API accepts up to
// 500 entries per request, so we chunk. Cache is shared with the single lookup.
export async function checkSafeBrowsingBatch(urls) {
  const result = new Map();
  const unique = [...new Set(urls.filter(Boolean))];

  // Serve from cache; collect the misses.
  const misses = [];
  for (const u of unique) {
    const c = cache.get(u);
    if (c) result.set(u, c.threats);
    else misses.push(u);
  }

  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key || misses.length === 0) {
    for (const u of misses) result.set(u, []); // no key => treat as not-listed
    return result;
  }

  const endpoint =
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
    encodeURIComponent(key);

  for (let i = 0; i < misses.length; i += 500) {
    const chunk = misses.slice(i, i + 500);
    const body = {
      client: { clientId: "phishing-guard", clientVersion: "0.1.0" },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: chunk.map((u) => ({ url: u })),
      },
    };
    // Default every URL in the chunk to "not listed".
    const chunkThreats = new Map(chunk.map((u) => [u, []]));
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        const data = await res.json();
        for (const m of data.matches || []) {
          const u = m.threat?.url;
          if (u && chunkThreats.has(u)) chunkThreats.get(u).push(m.threatType);
        }
      } else {
        console.warn("Safe Browsing batch error:", res.status);
      }
    } catch (err) {
      console.warn("Safe Browsing batch request failed:", err.message);
    }
    for (const [u, threats] of chunkThreats) {
      result.set(u, threats);
      cache.set(u, { listed: threats.length > 0, threats, available: true });
    }
  }
  return result;
}
