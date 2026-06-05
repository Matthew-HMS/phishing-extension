// Background service worker — orchestrates the tiered detection cascade.
//
// Phase 1 (this file, on navigation): allowlist -> verdict cache -> local
// heuristics -> backend /scan (Safe Browsing + reputation). Known-bad URLs are
// redirected to the warning page before the page is trusted.
//
// Phase 2 (content.js, after the page loads): extracts page signals and asks
// the backend /analyze endpoint, which escalates to the LLM only when needed.
import { BACKEND_URL, API_TOKEN, CACHE_TTL_MS, RISK } from "./config.js";
import { ALLOWLIST } from "./lib/allowlist.js";
import { runHeuristics } from "./lib/heuristics.js";
import {
  ensureLoaded as ensureBlocklist,
  lookup as blocklistLookup,
  refreshBlocklist,
  blocklistMeta,
  BLOCKLIST_ALARM,
  REFRESH_INTERVAL_MIN,
} from "./lib/blocklist.js";
import { syncDnrRules, addBypassRule } from "./lib/dnr.js";

// domain -> { risk, reasons, source, ts }
const verdictCache = new Map();

// Hostnames the user explicitly chose to proceed to from a warning. Cleared
// when the worker restarts (treated as a per-session bypass).
const bypassed = new Set();

// ---- blocklist lifecycle -------------------------------------------------

// Refresh the feeds, then rebuild the DNR rules from the new index. DNR rules
// persist in Chrome across worker restarts, so we only rebuild on refresh.
async function refreshAndSync() {
  await refreshBlocklist();
  const index = await ensureBlocklist();
  await syncDnrRules(index).catch((e) => console.warn("dnr sync failed:", e.message));
}

// Load the cached blocklist into memory whenever the worker spins up.
ensureBlocklist().catch((e) => console.warn("blocklist load failed:", e.message));

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(BLOCKLIST_ALARM, { periodInMinutes: REFRESH_INTERVAL_MIN });
  refreshAndSync().catch((e) => console.warn("blocklist refresh failed:", e.message));
});

chrome.runtime.onStartup.addListener(() => {
  ensureBlocklist().catch(() => {});
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === BLOCKLIST_ALARM) {
    refreshAndSync().catch((e) => console.warn("blocklist refresh failed:", e.message));
  }
});

// ---- allowlist -----------------------------------------------------------

function registrableEndsWith(hostname, domain) {
  return hostname === domain || hostname.endsWith("." + domain);
}

// Verdict cache key: origin + path (per-page, not per-host) so one page's
// verdict doesn't leak to sibling paths. Mirrors the backend.
function cacheKeyOf(url) {
  try {
    const u = new URL(url);
    return u.origin.toLowerCase() + u.pathname;
  } catch {
    return null;
  }
}

async function getUserAllowlist() {
  const { userAllowlist = [] } = await chrome.storage.local.get("userAllowlist");
  return userAllowlist;
}

async function isAllowlisted(hostname) {
  if (ALLOWLIST.some((d) => registrableEndsWith(hostname, d))) return true;
  const user = await getUserAllowlist();
  return user.some((d) => registrableEndsWith(hostname, d));
}

// ---- enabled toggle ------------------------------------------------------

async function isEnabled() {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  return enabled;
}

// ---- verdict cache -------------------------------------------------------

function getCached(domain) {
  const hit = verdictCache.get(domain);
  if (!hit) return null;
  if (Date.now() - hit.ts > CACHE_TTL_MS) {
    verdictCache.delete(domain);
    return null;
  }
  return hit;
}

function setCached(domain, verdict) {
  verdictCache.set(domain, { ...verdict, ts: Date.now() });
}

// ---- per-tab status (for popup + badge) ----------------------------------

async function setTabStatus(tabId, status) {
  await chrome.storage.session.set({ [`tab:${tabId}`]: status });
  updateBadge(tabId, status.risk);
}

async function getTabStatus(tabId) {
  const key = `tab:${tabId}`;
  const data = await chrome.storage.session.get(key);
  return data[key] || null;
}

function updateBadge(tabId, risk) {
  const map = {
    [RISK.SAFE]: { text: "", color: "#2e7d32" },
    [RISK.LOW]: { text: "", color: "#2e7d32" },
    [RISK.SUSPICIOUS]: { text: "!", color: "#f9a825" },
    [RISK.HIGH]: { text: "!", color: "#c62828" },
  };
  const cfg = map[risk] || { text: "", color: "#666" };
  chrome.action.setBadgeText({ tabId, text: cfg.text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color }).catch(() => {});
}

// ---- backend calls -------------------------------------------------------

async function callBackend(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (API_TOKEN) headers["Authorization"] = `Bearer ${API_TOKEN}`;
  const res = await fetch(`${BACKEND_URL}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`backend ${path} -> ${res.status}`);
  return res.json();
}

// ---- warning redirect ----------------------------------------------------

function warningUrl(blockedUrl, verdict) {
  const u = new URL(chrome.runtime.getURL("warning/warning.html"));
  u.searchParams.set("url", blockedUrl);
  u.searchParams.set("risk", verdict.risk);
  u.searchParams.set("category", verdict.category || "phishing");
  u.searchParams.set("reasons", JSON.stringify(verdict.reasons || []));
  return u.toString();
}

function redirectToWarning(tabId, blockedUrl, verdict) {
  chrome.tabs.update(tabId, { url: warningUrl(blockedUrl, verdict) });
}

// ---- Phase 1: navigation check ------------------------------------------

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const { url, tabId } = details;
  if (!/^https?:\/\//.test(url)) return;

  if (!(await isEnabled())) return;

  let hostname;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return;
  }

  // Tier 1: allowlist — skip everything.
  if (await isAllowlisted(hostname)) {
    await setTabStatus(tabId, { url, hostname, risk: RISK.SAFE, reasons: [], source: "allowlist" });
    return;
  }

  const cacheKey = cacheKeyOf(url) || hostname;

  // Verdict cache (per-page).
  const cached = getCached(cacheKey);
  if (cached) {
    await applyVerdict(tabId, url, hostname, cached);
    return;
  }

  // Tier 2a: offline blocklist (known-bad). Instant, no network round-trip.
  await ensureBlocklist();
  const blockedCategory = blocklistLookup(url);
  if (blockedCategory) {
    const verdict = {
      risk: RISK.HIGH,
      reasons: [
        blockedCategory === "malware"
          ? "Listed on a known malware-distribution blocklist (URLhaus)"
          : "Listed on a known phishing blocklist (OpenPhish)",
      ],
      category: blockedCategory,
      source: "blocklist",
    };
    setCached(cacheKey, verdict);
    await applyVerdict(tabId, url, hostname, verdict);
    return;
  }

  // Tier 2b: local heuristics.
  const heur = runHeuristics(url);

  // Tier 3: backend reputation (Safe Browsing). Falls back to local-only.
  let verdict;
  try {
    const data = await callBackend("/scan", {
      url,
      heuristicScore: heur.score,
      heuristicReasons: heur.reasons,
    });
    verdict = {
      risk: data.risk,
      reasons: data.reasons || [],
      category: data.category || "phishing",
      source: data.source || "backend",
    };
  } catch (err) {
    // Backend unreachable: decide locally from heuristics alone.
    const risk = heur.score >= 70 ? RISK.HIGH : heur.score >= 40 ? RISK.SUSPICIOUS : RISK.LOW;
    verdict = { risk, reasons: heur.reasons, source: "heuristics-offline" };
  }

  setCached(cacheKey, verdict);
  await applyVerdict(tabId, url, hostname, verdict);
});

async function applyVerdict(tabId, url, hostname, verdict) {
  await setTabStatus(tabId, { url, hostname, ...verdict });
  if (verdict.risk === RISK.HIGH && !bypassed.has(hostname)) {
    redirectToWarning(tabId, url, verdict);
  }
}

// ---- Phase 2 + popup messaging ------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === "ANALYZE_PAGE") {
        sendResponse(await handleAnalyzePage(msg.payload, sender));
      } else if (msg.type === "SCAN_LINKS") {
        sendResponse(await handleScanLinks(msg.tabId));
      } else if (msg.type === "AI_DIAGNOSE_LINKS") {
        sendResponse(await handleAiDiagnose(msg.tabId));
      } else if (msg.type === "GET_TAB_STATUS") {
        sendResponse(await getTabStatus(msg.tabId));
      } else if (msg.type === "ADD_ALLOWLIST") {
        const user = await getUserAllowlist();
        if (!user.includes(msg.domain)) user.push(msg.domain);
        await chrome.storage.local.set({ userAllowlist: user });
        verdictCache.delete(msg.domain);
        sendResponse({ ok: true, userAllowlist: user });
      } else if (msg.type === "BYPASS") {
        if (msg.domain) {
          bypassed.add(msg.domain);
          await addBypassRule(msg.domain); // override the DNR block rule too
        }
        sendResponse({ ok: true });
      } else if (msg.type === "LEAVE_SITE") {
        // Reliable "back to safety": close the offending tab. (history.back()
        // can bounce to the still-blocked URL when it committed before redirect.)
        const tabId = sender.tab?.id;
        if (tabId != null) chrome.tabs.remove(tabId).catch(() => {});
        sendResponse({ ok: true });
      } else if (msg.type === "SET_ENABLED") {
        await chrome.storage.local.set({ enabled: msg.enabled });
        sendResponse({ ok: true });
      } else if (msg.type === "GET_ENABLED") {
        sendResponse({ enabled: await isEnabled() });
      } else if (msg.type === "REFRESH_BLOCKLIST") {
        await refreshAndSync();
        sendResponse(await blocklistMeta());
      } else if (msg.type === "GET_BLOCKLIST_INFO") {
        sendResponse(await blocklistMeta());
      } else {
        sendResponse({ error: "unknown message" });
      }
    } catch (err) {
      sendResponse({ error: String(err) });
    }
  })();
  return true; // async response
});

async function handleAnalyzePage(payload, sender) {
  if (!(await isEnabled())) return { risk: RISK.SAFE, reasons: [] };
  const tabId = sender.tab?.id;
  let hostname;
  try {
    hostname = new URL(payload.url).hostname.toLowerCase();
  } catch {
    return { risk: RISK.SAFE, reasons: [] };
  }

  // Allowlisted pages are never deep-analyzed.
  if (await isAllowlisted(hostname)) return { risk: RISK.SAFE, reasons: [] };

  const heur = runHeuristics(payload.url);

  let verdict;
  try {
    const data = await callBackend("/analyze", {
      url: payload.url,
      heuristicScore: heur.score,
      heuristicReasons: heur.reasons,
      page: payload.page, // title, text snippet, form targets, password fields...
    });
    verdict = {
      risk: data.risk,
      reasons: data.reasons || [],
      category: data.category || "phishing",
      source: data.source || "analyze",
      explanation: data.explanation,
    };
  } catch (err) {
    return { risk: RISK.SAFE, reasons: [], source: "analyze-offline" };
  }

  setCached(cacheKeyOf(payload.url) || hostname, verdict);
  if (tabId != null) await setTabStatus(tabId, { url: payload.url, hostname, ...verdict });
  return verdict;
}

// ---- scan all links on a page -------------------------------------------

const MAX_SCAN_LINKS = 200;

// Injected into the page to collect unique http(s) anchor targets.
function collectPageLinks() {
  const set = new Set();
  for (const a of document.querySelectorAll("a[href]")) {
    const href = a.href;
    if (href && (href.startsWith("http://") || href.startsWith("https://"))) set.add(href);
  }
  return Array.from(set);
}

function chunk(arr, n) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
}

// Scan every link on the tab through the URL-level cascade (allowlist ->
// blocklist -> cache -> heuristics -> backend reputation). The LLM tier is not
// used here: it needs each page's loaded content, which we don't fetch.
async function handleScanLinks(tabId) {
  if (tabId == null) return { error: "no active tab" };
  if (!(await isEnabled())) return { error: "protection is disabled" };

  let links = [];
  try {
    const res = await chrome.scripting.executeScript({ target: { tabId }, func: collectPageLinks });
    links = res?.[0]?.result || [];
  } catch (e) {
    return { error: "Can't scan this page" }; // chrome:// pages, PDF viewer, etc.
  }

  const found = links.length;
  await ensureBlocklist();

  // De-duplicate by per-page cache key.
  const seen = new Set();
  const unique = [];
  for (const u of links) {
    const k = cacheKeyOf(u) || u;
    if (!seen.has(k)) {
      seen.add(k);
      unique.push(u);
    }
  }
  const capped = unique.slice(0, MAX_SCAN_LINKS);

  const verdicts = new Map();
  const pending = [];
  for (const url of capped) {
    let host;
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (await isAllowlisted(host)) {
      verdicts.set(url, { risk: RISK.SAFE, source: "allowlist", reasons: [] });
      continue;
    }
    const cat = blocklistLookup(url);
    if (cat) {
      verdicts.set(url, {
        risk: RISK.HIGH,
        category: cat,
        source: "blocklist",
        reasons: [cat === "malware" ? "On malware blocklist" : "On phishing blocklist"],
      });
      continue;
    }
    const ck = cacheKeyOf(url) || host;
    const cached = getCached(ck);
    if (cached) {
      verdicts.set(url, cached);
      continue;
    }
    const heur = runHeuristics(url);
    pending.push({ url, ck, heuristicScore: heur.score, heuristicReasons: heur.reasons });
  }

  const total = capped.length;
  const riskyCount = () => {
    let n = 0;
    for (const v of verdicts.values()) if (v.risk === RISK.HIGH || v.risk === RISK.SUSPICIOUS) n++;
    return n;
  };
  const emit = () =>
    chrome.runtime
      .sendMessage({
        type: "SCAN_PROGRESS",
        found,
        unique: unique.length,
        total,
        scanned: verdicts.size,
        risky: riskyCount(),
      })
      .catch(() => {});

  emit(); // after local tiers

  // Batch the unknowns to the backend reputation tier.
  for (const part of chunk(pending, 100)) {
    try {
      const data = await callBackend("/scan-batch", {
        items: part.map((p) => ({
          url: p.url,
          heuristicScore: p.heuristicScore,
          heuristicReasons: p.heuristicReasons,
        })),
      });
      const byUrl = new Map((data.results || []).map((r) => [r.url, r]));
      for (const p of part) {
        const r = byUrl.get(p.url);
        const v = r
          ? { risk: r.risk, reasons: r.reasons || [], category: r.category, source: r.source }
          : { risk: RISK.LOW, reasons: p.heuristicReasons, source: "heuristics" };
        verdicts.set(p.url, v);
        if (v.risk === RISK.HIGH || v.risk === RISK.SAFE) setCached(p.ck, v);
      }
    } catch (e) {
      // Backend unreachable: fall back to local heuristics only.
      for (const p of part) {
        const risk =
          p.heuristicScore >= 70 ? RISK.HIGH : p.heuristicScore >= 40 ? RISK.SUSPICIOUS : RISK.LOW;
        verdicts.set(p.url, { risk, reasons: p.heuristicReasons, source: "heuristics-offline" });
      }
    }
    emit();
  }

  // Build the risky list for display.
  const riskyList = [];
  for (const [url, v] of verdicts) {
    if (v.risk === RISK.HIGH || v.risk === RISK.SUSPICIOUS) {
      let host = url;
      try {
        host = new URL(url).hostname;
      } catch {}
      riskyList.push({ url, host, risk: v.risk, reason: (v.reasons && v.reasons[0]) || v.source });
    }
  }
  riskyList.sort((a, b) => (a.risk === RISK.HIGH ? -1 : 1) - (b.risk === RISK.HIGH ? -1 : 1));

  return {
    found,
    unique: unique.length,
    scanned: verdicts.size,
    risky: riskyList.length,
    riskyList: riskyList.slice(0, 25),
  };
}

// ---- AI diagnosis of page links -----------------------------------------

const MAX_AI_LINKS = 40; // bound LLM cost per diagnosis

// Send the page's links to the LLM for a URL-string judgement. Allowlisted
// hosts are skipped (trusted, and saves tokens). Unlike the rule scan, this
// asks the model to reason about each URL.
async function handleAiDiagnose(tabId) {
  if (tabId == null) return { error: "no active tab" };
  if (!(await isEnabled())) return { error: "protection is disabled" };

  let links = [];
  try {
    const res = await chrome.scripting.executeScript({ target: { tabId }, func: collectPageLinks });
    links = res?.[0]?.result || [];
  } catch (e) {
    return { error: "Can't scan this page" };
  }

  // De-dup and drop allowlisted (trusted) hosts.
  const seen = new Set();
  const candidates = [];
  for (const u of links) {
    const k = cacheKeyOf(u) || u;
    if (seen.has(k)) continue;
    seen.add(k);
    let host;
    try {
      host = new URL(u).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (await isAllowlisted(host)) continue;
    candidates.push(u);
  }

  if (candidates.length === 0) {
    return { results: [], analyzed: 0, totalCandidates: 0 };
  }
  const capped = candidates.slice(0, MAX_AI_LINKS);

  try {
    const data = await callBackend("/diagnose-links", { urls: capped });
    if (data.available === false) {
      return { error: "AI unavailable — check the OpenAI key/billing on the backend." };
    }
    const flagged = (data.results || [])
      .filter((r) => r.phishing)
      .map((r) => ({ url: r.url, confidence: r.confidence, reason: r.reason }))
      .sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    return { results: flagged, analyzed: capped.length, totalCandidates: candidates.length };
  } catch (e) {
    return { error: "Backend unreachable — start it with `npm start`." };
  }
}

// Clean up per-tab session status when tabs close.
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(`tab:${tabId}`).catch(() => {});
});
