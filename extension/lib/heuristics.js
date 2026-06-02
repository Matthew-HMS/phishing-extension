// Tier 2 of the cascade: cheap, local, network-free signals.
// These run in the background service worker on every non-allowlisted URL.
// They never make a verdict on their own at low scores — they decide whether
// it's worth escalating to the backend (reputation + LLM tiers).
import { BRANDS } from "./allowlist.js";
import { getRegistrableDomain, getPublicSuffix } from "./psl.js";

const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "xyz", "top", "club", "click", "link", "live", "icu",
  "rest", "cyou", "sbs", "cfd", "work", "gq", "ml", "ga", "cf", "tk",
]);

// Levenshtein edit distance (small strings, simple DP).
export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    let cur = [i];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[n];
}

// Shannon entropy of a string — random-looking hostnames (DGA, throwaway
// subdomains) score high.
export function entropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const ch in freq) {
    const p = freq[ch] / str.length;
    e -= p * Math.log2(p);
  }
  return e;
}

// Closest brand match by edit distance against the registrable label.
function closestBrand(label) {
  let best = null;
  for (const brand of BRANDS) {
    const d = levenshtein(label, brand);
    if (best === null || d < best.distance) best = { brand, distance: d };
  }
  return best;
}

// Run all local heuristics. Returns a score (0..100) and human-readable
// reasons. Score is advisory — the backend makes the final call.
export function runHeuristics(url) {
  const reasons = [];
  let score = 0;

  let u;
  try {
    u = new URL(url);
  } catch {
    return { score: 0, reasons: [], hostname: null };
  }
  const hostname = u.hostname.toLowerCase();
  const tld = hostname.split(".").pop();

  // PSL-derived registrable domain ("eTLD+1") and its leftmost label.
  const regDomain = getRegistrableDomain(hostname); // null for IPs / bare suffixes
  const regLabel = regDomain ? regDomain.split(".")[0] : null;

  // Punycode / IDN homograph attack.
  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    score += 35;
    reasons.push("Internationalized (Punycode) domain — possible homograph attack");
  }

  // Raw IP address as host.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    reasons.push("URL uses a raw IP address instead of a domain name");
  }

  // '@' in the URL (credential-in-URL / host spoofing trick).
  if (url.includes("@")) {
    score += 25;
    reasons.push("URL contains '@', which can disguise the real destination");
  }

  // Suspicious / abuse-heavy TLD.
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 15;
    reasons.push(`Uncommon top-level domain (.${tld}) frequently used for abuse`);
  }

  // Excessive subdomain depth, measured against the registrable domain so
  // legit deep hosts on multi-part suffixes (e.g. a.b.example.com.tw) aren't
  // penalised the way a raw label count would (e.g. login.paypal.com.evil.tw).
  const regLabels = regDomain ? regDomain.split(".").length : 2;
  const subdomainDepth = hostname.split(".").length - regLabels;
  if (subdomainDepth >= 3) {
    score += 15;
    reasons.push("Unusually deep subdomain chain");
  }

  // Brand impersonation: registrable label looks almost like a known brand.
  if (regLabel && regLabel.length >= 4) {
    const brand = closestBrand(regLabel);
    if (brand && brand.distance > 0 && brand.distance <= 2) {
      score += 40;
      reasons.push(`Domain closely resembles "${brand.brand}" (typosquatting)`);
    }
  }
  // Brand name appears in the host's name part but isn't the registrable
  // domain (e.g. paypal.login.evil.tw, where the real site is evil.tw).
  // Search only outside the public suffix so brands embedded in a suffix
  // (e.g. github in github.io) don't false-positive.
  const suffix = getPublicSuffix(hostname);
  const namePart = hostname.endsWith(suffix)
    ? hostname.slice(0, hostname.length - suffix.length)
    : hostname;
  for (const b of BRANDS) {
    if (namePart.includes(b) && regLabel !== b) {
      score += 20;
      reasons.push(`Mentions "${b}" but is not the real ${b} domain`);
      break;
    }
  }

  // Random-looking host.
  if (entropy(hostname) > 4.0 && hostname.length > 20) {
    score += 10;
    reasons.push("Host name looks randomly generated");
  }

  // Very long URL.
  if (url.length > 120) {
    score += 5;
    reasons.push("Unusually long URL");
  }

  return { score: Math.min(score, 100), reasons, hostname };
}
