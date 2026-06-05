// declarativeNetRequest hardening — turns the synced blocklist into dynamic
// DNR rules so known-bad URLs are blocked at the network layer, before the
// request leaves the browser, and even while the service worker is asleep.
//
// Each block rule redirects a main-frame request to the warning page (with the
// blocked URL + category baked into the redirect, so the page is self-
// contained). "Proceed anyway" adds a higher-priority allow rule for the host.
//
// Rule ID ranges:
//   block rules:  1 .. BYPASS_ID_BASE-1   (rebuilt on every blocklist refresh)
//   bypass rules: BYPASS_ID_BASE ..        (added on demand, survive refreshes)

const WARNING_PATH = "warning/warning.html";
const MAX_RULES = 28000; // < chrome's 30k dynamic-rule cap, leaves room for bypass
const BLOCK_PRIORITY = 1;
const BYPASS_PRIORITY = 2;
export const BYPASS_ID_BASE = 1_000_000;

// Convert a normalized blocklist key ("host" or "host/path") into a DNR
// urlFilter. Returns null for keys we can't safely express (non-ASCII or keys
// containing DNR meta-characters) — those stay covered by the JS check.
export function toUrlFilter(key) {
  if (!key || !/^[\x21-\x7E]+$/.test(key)) return null; // printable ASCII only
  if (/[*^|]/.test(key)) return null; // DNR meta-characters
  return key.includes("/") ? "||" + key : "||" + key + "^";
}

// Build block rules from a blocklist index (Map or iterable of [key, category]).
// `makeRedirectUrl(key, category)` is injected so this stays pure/testable.
export function buildBlockRules(index, makeRedirectUrl, opts = {}) {
  const { startId = 1, max = MAX_RULES } = opts;
  const rules = [];
  let id = startId;
  for (const [key, category] of index) {
    if (rules.length >= max) break;
    const urlFilter = toUrlFilter(key);
    if (!urlFilter) continue;
    rules.push({
      id: id++,
      priority: BLOCK_PRIORITY,
      action: { type: "redirect", redirect: { url: makeRedirectUrl(key, category) } },
      condition: { urlFilter, resourceTypes: ["main_frame"] },
    });
  }
  return rules;
}

function makeRedirectUrl(key, category) {
  const u = new URL(chrome.runtime.getURL(WARNING_PATH));
  u.searchParams.set("url", "https://" + key);
  u.searchParams.set("category", category);
  u.searchParams.set("source", "blocklist");
  return u.toString();
}

function available() {
  return typeof chrome !== "undefined" && !!chrome.declarativeNetRequest;
}

// Rebuild all block rules from the current index (keeps bypass rules intact).
export async function syncDnrRules(index) {
  if (!available()) return 0;
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.filter((r) => r.id < BYPASS_ID_BASE).map((r) => r.id);
  const addRules = buildBlockRules(index, makeRedirectUrl);
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  console.log(`[dnr] synced ${addRules.length} block rules`);
  return addRules.length;
}

// Add a higher-priority allow rule so a "proceed anyway" host isn't re-blocked
// by DNR. Survives refreshes (lives in the bypass ID range).
export async function addBypassRule(host) {
  if (!available() || !host) return;
  const filter = toUrlFilter(host);
  if (!filter) return;
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const maxId = existing
    .filter((r) => r.id >= BYPASS_ID_BASE)
    .reduce((m, r) => Math.max(m, r.id), BYPASS_ID_BASE - 1);
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [
      {
        id: maxId + 1,
        priority: BYPASS_PRIORITY,
        action: { type: "allow" },
        condition: { urlFilter: filter, resourceTypes: ["main_frame"] },
      },
    ],
  });
}
