const URL_REGEX = /https?:\/\/[^\s<>'"\u3000]+/gi;
const SCAN_BATCH_LIMIT = 30;
const SCAN_DEBOUNCE_MS = 800;
const seenUrls = new Set();
const elementById = new Map();
let pendingTimer = null;
let itemSequence = 0;

function makeItem(url, context, element, source) {
  const id = `pg-${Date.now()}-${itemSequence++}`;
  elementById.set(id, element);
  return { id, url, context, source };
}

function extractFromAnchors(root = document) {
  return Array.from(root.querySelectorAll?.("a[href]") || []).map((anchor) => {
    const url = anchor.href;
    if (!url || seenUrls.has(url)) return null;
    seenUrls.add(url);
    const context = anchor.innerText || anchor.textContent || anchor.getAttribute("aria-label") || "";
    return makeItem(url, context, anchor, "anchor");
  }).filter(Boolean);
}

function extractFromText() {
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      const tag = parent.tagName?.toLowerCase();
      if (["script", "style", "textarea", "input"].includes(tag)) return NodeFilter.FILTER_REJECT;
      URL_REGEX.lastIndex = 0;
      return URL_REGEX.test(node.nodeValue || "") ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    }
  });
  const items = [];
  while (walker.nextNode() && items.length < SCAN_BATCH_LIMIT) {
    const text = walker.currentNode.nodeValue || "";
    URL_REGEX.lastIndex = 0;
    const matches = text.match(URL_REGEX) || [];
    for (const url of matches) {
      if (seenUrls.has(url)) continue;
      seenUrls.add(url);
      items.push(makeItem(url, text.slice(0, 180), walker.currentNode.parentElement, "text"));
    }
  }
  return items;
}

function createBadge(result) {
  const badge = document.createElement("span");
  badge.className = "phishing-guard-badge";
  badge.textContent = result.riskLevel === "HIGH" ? "⚠ 高風險連結" : "⚠ 可疑連結";
  badge.title = `${result.score}/100\n${(result.reasons || []).join("\n")}`;
  badge.style.cssText = ["display:inline-block", "margin-left:6px", "padding:2px 6px", "border-radius:6px", "font-size:12px", "font-weight:700", "line-height:1.4", "color:#fff", `background:${result.riskLevel === "HIGH" ? "#b91c1c" : "#d97706"}`, "z-index:2147483647", "position:relative"].join(";");
  return badge;
}

function markElement(result) {
  if (result.riskLevel === "LOW") return;
  const element = elementById.get(result.id);
  if (!element || element.dataset?.phishingGuardMarked === "true") return;
  if (element.dataset) element.dataset.phishingGuardMarked = "true";
  element.style.outline = result.riskLevel === "HIGH" ? "2px solid #b91c1c" : "2px solid #d97706";
  element.style.borderRadius = "4px";
  element.insertAdjacentElement("afterend", createBadge(result));
}

async function sendItems(items) {
  if (!items.length) return;
  try {
    const response = await chrome.runtime.sendMessage({ type: "CHECK_ITEMS", items });
    if (response?.ok) response.results.forEach(markElement);
  } catch (error) {
    console.warn("Phishing Guard scan failed", error);
  }
}

function scheduleScan() {
  clearTimeout(pendingTimer);
  pendingTimer = setTimeout(() => {
    const items = [...extractFromAnchors(), ...extractFromText()].slice(0, SCAN_BATCH_LIMIT);
    sendItems(items);
  }, SCAN_DEBOUNCE_MS);
}

function startObserver() {
  scheduleScan();
  new MutationObserver(scheduleScan).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
}

startObserver();

function collectVisibleText(limit = 3500) {
  const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
  return text.slice(0, limit);
}

function collectLinks(limit = 60) {
  return Array.from(document.querySelectorAll("a[href]"))
    .map((anchor) => anchor.href)
    .filter(Boolean)
    .slice(0, limit);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "COLLECT_PAGE_CONTEXT") {
    sendResponse({
      ok: true,
      data: {
        url: location.href,
        pageTitle: document.title,
        context: collectVisibleText(),
        links: collectLinks()
      }
    });
  }
  return true;
});
