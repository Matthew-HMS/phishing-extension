// Public Suffix List lookups — correct registrable-domain ("eTLD+1") parsing.
//
// Replaces the naive "last two labels" approximation, which is wrong for
// multi-part suffixes (e.g. com.tw, edu.tw, co.uk) and for private suffixes
// (e.g. github.io, where each subdomain is a distinct site).
//
// Implements the algorithm from https://publicsuffix.org/list/ :
//   - exact rules           e.g. "com.tw"
//   - wildcard rules "*.x"  match any single label in that position
//   - exception rules "!x"  override a wildcard (most specific, win priority)
import { PSL_RULES } from "./psl-data.js";

const exact = new Set();
const wildcards = new Set(); // parent of "*.parent"
const exceptions = new Set(); // full rule after stripping "!"

for (const rule of PSL_RULES.split("\n")) {
  if (!rule) continue;
  if (rule.startsWith("!")) {
    exceptions.add(rule.slice(1));
  } else if (rule.startsWith("*.")) {
    wildcards.add(rule.slice(2));
  } else {
    exact.add(rule);
  }
}

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

// Return the public suffix (eTLD) for a hostname, per PSL rules.
export function getPublicSuffix(hostname) {
  const host = String(hostname).toLowerCase().replace(/\.$/, "");
  if (!host || IP_RE.test(host)) return host;
  const labels = host.split(".");

  // Longest candidate first (most labels) so the most specific rule wins.
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".");
    // Exception rules are the most specific and take priority.
    if (exceptions.has(candidate)) {
      return labels.slice(i + 1).join("."); // drop leftmost label
    }
    if (exact.has(candidate)) return candidate;
    // Wildcard: "*.<rest>" matches this candidate if <rest> is a wildcard parent.
    const rest = labels.slice(i + 1).join(".");
    if (rest && wildcards.has(rest)) return candidate;
  }
  // Default rule "*": the rightmost label is the public suffix.
  return labels[labels.length - 1];
}

// Return the registrable domain (public suffix + one more label), or null when
// the hostname *is* a public suffix or has no registrable part (e.g. an IP).
export function getRegistrableDomain(hostname) {
  const host = String(hostname).toLowerCase().replace(/\.$/, "");
  if (!host || IP_RE.test(host)) return null;

  const suffix = getPublicSuffix(host);
  if (host === suffix) return null;

  const suffixLabels = suffix.split(".").length;
  const labels = host.split(".");
  if (labels.length <= suffixLabels) return null;
  return labels.slice(labels.length - suffixLabels - 1).join(".");
}
