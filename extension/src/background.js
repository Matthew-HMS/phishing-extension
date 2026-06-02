import { analyzeUrl } from "./rules/localRules.js";

const DEFAULT_STATS = { scanned: 0, suspicious: 0, highRisk: 0, lastUpdated: null, lastFindings: [] };
const API_BASE_URL = "http://127.0.0.1:8000";

async function getTabStats(tabId) {
  const key = `tab:${tabId}`;
  const stored = await chrome.storage.local.get(key);
  return stored[key] || { ...DEFAULT_STATS };
}

async function setTabStats(tabId, stats) {
  await chrome.storage.local.set({ [`tab:${tabId}`]: stats });
}

async function updateStats(tabId, results) {
  if (!tabId || tabId < 0) return;
  const previous = await getTabStats(tabId);
  const suspiciousResults = results.filter((result) => result.riskLevel !== "LOW");
  const highRiskResults = results.filter((result) => result.riskLevel === "HIGH");
  await setTabStats(tabId, {
    scanned: previous.scanned + results.length,
    suspicious: previous.suspicious + suspiciousResults.length,
    highRisk: previous.highRisk + highRiskResults.length,
    lastUpdated: new Date().toISOString(),
    lastFindings: [...suspiciousResults, ...previous.lastFindings].slice(0, 10)
  });
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function collectPageContext(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: "COLLECT_PAGE_CONTEXT" });
    return response?.ok ? response.data : null;
  } catch {
    return null;
  }
}

async function requestAiAnalysis() {
  const tab = await getActiveTab();
  if (!tab?.id) throw new Error("找不到目前分頁");

  const stats = await getTabStats(tab.id);
  const pageContext = await collectPageContext(tab.id);
  const payload = {
    url: tab.url || pageContext?.url || "",
    pageTitle: tab.title || pageContext?.pageTitle || "",
    context: pageContext?.context || "",
    links: pageContext?.links || [],
    localFindings: (stats.lastFindings || []).map((item) => ({
      url: item.normalizedUrl || item.input || "",
      riskLevel: item.riskLevel,
      score: item.score,
      reasons: item.reasons || []
    }))
  };

  const response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`後端回應錯誤 ${response.status}: ${text.slice(0, 120)}`);
  }

  const result = await response.json();
  await chrome.storage.local.set({ [`ai:${tab.id}`]: { ...result, analyzedAt: new Date().toISOString(), targetUrl: payload.url } });
  return result;
}

chrome.runtime.onInstalled.addListener(() => chrome.storage.local.set({ extensionStatus: "active" }));
chrome.tabs?.onUpdated?.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") setTabStats(tabId, { ...DEFAULT_STATS });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === "CHECK_ITEMS") {
      const items = Array.isArray(message.items) ? message.items : [];
      const results = items.map((item) => ({ id: item.id, source: item.source || "unknown", ...analyzeUrl(item.url, item.context) }));
      await updateStats(sender.tab?.id, results);
      sendResponse({ ok: true, results });
      return;
    }

    if (message?.type === "GET_TAB_STATS") {
      const tab = await getActiveTab();
      const stats = tab?.id ? await getTabStats(tab.id) : { ...DEFAULT_STATS };
      const aiStored = tab?.id ? await chrome.storage.local.get(`ai:${tab.id}`) : {};
      sendResponse({ ok: true, stats, tabUrl: tab?.url || "", aiResult: aiStored[`ai:${tab?.id}`] || null });
      return;
    }

    if (message?.type === "REQUEST_AI_ANALYSIS") {
      try {
        const result = await requestAiAnalysis();
        sendResponse({ ok: true, result });
      } catch (error) {
        sendResponse({ ok: false, message: error.message || "AI 分析失敗" });
      }
      return;
    }

    sendResponse({ ok: false, message: "Unknown message type" });
  })();
  return true;
});
