// Offline blocklist sync — catches known-bad URLs instantly, with no backend
// round-trip and even when the backend is down.
//
// Feeds are free, key-less, plain-text lists:
//   - OpenPhish community feed  (phishing URLs)
//   - URLhaus online feed        (malware-distribution URLs)
//
// Entries are normalized to "host + path" (scheme dropped, query/fragment
// dropped, trailing slash trimmed). This matches a phishing URL precisely
// WITHOUT over-blocking an entire shared host (e.g. a single bad path on a
// hosting provider). The navigation URL is normalized the same way for lookup.

const FEEDS = [
  // OpenPhish community feed now lives on GitHub (openphish.com/feed.txt 302s here).
  {
    name: "OpenPhish",
    url: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    category: "phishing",
  },
  { name: "URLhaus", url: "https://urlhaus.abuse.ch/downloads/text_online/", category: "malware" },
];

const STORAGE_KEY = "blocklist";
const MAX_PER_FEED = 30000; // keep memory/storage bounded
export const BLOCKLIST_ALARM = "phishguard-blocklist-refresh";
export const REFRESH_INTERVAL_MIN = 360; // 6 hours
const STALE_MS = REFRESH_INTERVAL_MIN * 60 * 1000;

// In-memory index: Map<normalizedKey, category>. Rebuilt on each SW spin-up.
let index = null;
let loadPromise = null;

// Normalize a URL or bare domain to a scheme-agnostic "host/path" key.
export function normalizeKey(raw) {
  let s = String(raw).trim();
  if (!s) return null;
  // Feeds usually include a scheme, but tolerate bare "host/path" entries.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}/i.test(s)) return null;
    s = "http://" + s;
  }
  try {
    const u = new URL(s);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const path = u.pathname.replace(/\/+$/, ""); // trim trailing slashes
    return u.hostname.toLowerCase() + path;
  } catch {
    return null;
  }
}

// Parse a feed body into [key, category] pairs (ignores blanks/comments).
export function parseFeed(text, category, cap = MAX_PER_FEED) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const key = normalizeKey(t);
    if (key) out.push([key, category]);
    if (out.length >= cap) break;
  }
  return out;
}

// Ensure the in-memory index is loaded from storage; refresh if stale/missing.
export async function ensureLoaded() {
  if (index) return index;
  if (!loadPromise) loadPromise = loadFromStorage();
  return loadPromise;
}

async function loadFromStorage() {
  const data = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
  index = new Map(Object.entries(data?.entries || {}));
  if (!data || Date.now() - data.ts > STALE_MS) {
    refreshBlocklist().catch((e) => console.warn("[blocklist] refresh failed:", e.message));
  }
  return index;
}

// Synchronous lookup. Returns the threat category ("phishing"|"malware") or
// null. Call ensureLoaded() first.
export function lookup(url) {
  if (!index) return null;
  const key = normalizeKey(url);
  if (!key) return null;
  return index.get(key) || null;
}

// Fetch all feeds, rebuild the index, and persist it.
export async function refreshBlocklist() {
  const entries = {};
  let total = 0;
  for (const feed of FEEDS) {
    try {
      const res = await fetch(feed.url, { cache: "no-store" });
      if (!res.ok) {
        console.warn(`[blocklist] ${feed.name} -> HTTP ${res.status}`);
        continue;
      }
      const pairs = parseFeed(await res.text(), feed.category);
      for (const [key, cat] of pairs) entries[key] = cat;
      total += pairs.length;
      console.log(`[blocklist] ${feed.name}: ${pairs.length} entries`);
    } catch (e) {
      console.warn(`[blocklist] ${feed.name} fetch failed:`, e.message);
    }
  }
  // Keep the previous index if every feed failed (don't wipe protection).
  if (total === 0 && index && index.size > 0) {
    console.warn("[blocklist] all feeds failed; keeping existing index");
    return index.size;
  }
  index = new Map(Object.entries(entries));
  await chrome.storage.local.set({ [STORAGE_KEY]: { entries, ts: Date.now() } });
  console.log(`[blocklist] refreshed: ${total} entries`);
  return total;
}

// Size + last-refresh timestamp, for the popup status line.
export async function blocklistMeta() {
  await ensureLoaded();
  const data = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
  return { size: index ? index.size : 0, ts: data?.ts || null };
}
