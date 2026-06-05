// Popup — shows the current tab's verdict and exposes the enable toggle, a
// per-site "trust" (allowlist) action, and blocklist status/refresh. It reads
// state the background worker already computed; it does not run checks itself.

const RISK_LABEL = {
  SAFE: "Safe",
  LOW: "Looks OK",
  SUSPICIOUS: "Suspicious",
  HIGH: "Dangerous",
};
const RISK_ICON = {
  SAFE: "✅",
  LOW: "✅",
  SUSPICIOUS: "⚠️",
  HIGH: "⛔",
  unknown: "🛡️",
};

function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function relativeTime(ts) {
  if (!ts) return "never";
  const sec = Math.round((Date.now() - ts) / 1000);
  if (sec < 60) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.round(hr / 24)}d ago`;
}

function render(status) {
  const statusEl = document.getElementById("status");
  const riskEl = document.getElementById("risk");
  const iconEl = document.getElementById("statusIcon");
  const hostEl = document.getElementById("host");
  const sourceEl = document.getElementById("source");
  const reasonsEl = document.getElementById("reasons");
  const allowBtn = document.getElementById("allowBtn");

  const risk = status?.risk || "unknown";
  statusEl.className = "status status--" + risk;
  iconEl.textContent = RISK_ICON[risk] || RISK_ICON.unknown;
  riskEl.textContent = status ? RISK_LABEL[risk] || risk : "No data yet";
  hostEl.textContent = status?.hostname || "";
  sourceEl.textContent = status?.source ? `via ${status.source}` : "";

  reasonsEl.innerHTML = "";
  for (const r of status?.reasons || []) {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsEl.appendChild(li);
  }
  if (status?.explanation) {
    const li = document.createElement("li");
    li.textContent = status.explanation;
    reasonsEl.appendChild(li);
  }

  // Offer "trust" only when there's a real host and it isn't already trusted.
  if (status?.hostname && status.source !== "allowlist") {
    allowBtn.hidden = false;
    allowBtn.disabled = false;
    allowBtn.textContent = "Trust this site";
    allowBtn.onclick = async () => {
      await send({ type: "ADD_ALLOWLIST", domain: status.hostname });
      allowBtn.textContent = "Trusted ✓";
      allowBtn.disabled = true;
    };
  } else {
    allowBtn.hidden = true;
  }
}

async function loadBlocklistInfo() {
  const info = await send({ type: "GET_BLOCKLIST_INFO" });
  const el = document.getElementById("blInfo");
  const size = info?.size ?? 0;
  el.textContent = `Blocklist: ${size.toLocaleString()} URLs · ${relativeTime(info?.ts)}`;
}

// ---- scan links on this page --------------------------------------------

function setCounts({ found, unique, risky }) {
  if (found != null) document.getElementById("scFound").textContent = found;
  if (unique != null) document.getElementById("scUnique").textContent = unique;
  if (risky != null) document.getElementById("scRisky").textContent = risky;
}

// Live progress while the background scans.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "SCAN_PROGRESS") {
    setCounts({ found: msg.found, unique: msg.unique, risky: msg.risky });
    if (msg.scanned < msg.total) {
      document.getElementById("scNote").textContent = `Scanning… ${msg.scanned}/${msg.total}`;
    }
  }
});

function renderScanResult(result) {
  const note = document.getElementById("scNote");
  const list = document.getElementById("scList");
  list.innerHTML = "";

  if (result?.error) {
    note.textContent = result.error;
    return;
  }

  setCounts(result);
  note.textContent =
    result.scanned < result.unique
      ? `Scanned first ${result.scanned} of ${result.unique} unique links.`
      : result.risky === 0
        ? "No risky links found."
        : "";

  for (const item of result.riskyList || []) {
    const li = document.createElement("li");
    const head = document.createElement("div");
    head.className = "linkhead";
    const tag = document.createElement("span");
    tag.className = `tag tag-${item.risk}`;
    tag.textContent = item.risk === "HIGH" ? "⛔" : "⚠️";
    const link = document.createElement("span");
    link.className = "url";
    link.textContent = item.url; // full link, not just the domain
    head.append(tag, link);
    const why = document.createElement("div");
    why.className = "why";
    why.textContent = item.reason || "";
    li.append(head, why);
    li.title = item.url;
    list.appendChild(li);
  }
}

// Runs automatically when the popup opens — rule-based scan of every link.
async function runRuleScan() {
  const tab = await currentTab();
  if (!tab || !/^https?:/.test(tab.url || "")) {
    renderScanResult({ error: "Can't scan this page." });
    return;
  }
  const result = await send({ type: "SCAN_LINKS", tabId: tab.id });
  renderScanResult(result);
}

function renderAiResult(result) {
  const note = document.getElementById("aiNote");
  const list = document.getElementById("aiList");
  list.innerHTML = "";

  if (result?.error) {
    note.textContent = result.error;
    return;
  }
  const flagged = result.results || [];
  if ((result.analyzed ?? 0) === 0) {
    note.textContent = "No external links to diagnose on this page.";
    return;
  }
  note.textContent = flagged.length
    ? `AI flagged ${flagged.length} of ${result.analyzed} link(s) checked:`
    : `AI checked ${result.analyzed} link(s); none look like phishing.`;

  for (const item of flagged) {
    const li = document.createElement("li");
    const head = document.createElement("div");
    head.className = "linkhead";
    const tag = document.createElement("span");
    tag.className = "tag tag-HIGH";
    tag.textContent = "🤖";
    const link = document.createElement("span");
    link.className = "url";
    link.textContent = item.url;
    head.append(tag, link);
    const why = document.createElement("div");
    why.className = "why";
    const conf = item.confidence != null ? ` (${Math.round(item.confidence * 100)}%)` : "";
    why.textContent = (item.reason || "") + conf;
    li.append(head, why);
    li.title = item.url;
    list.appendChild(li);
  }
}

function initAiButton() {
  const aiBtn = document.getElementById("aiBtn");
  aiBtn.addEventListener("click", async () => {
    const tab = await currentTab();
    if (!tab || !/^https?:/.test(tab.url || "")) {
      document.getElementById("aiNote").textContent = "Can't scan this page.";
      return;
    }
    aiBtn.disabled = true;
    aiBtn.textContent = "🤖 Diagnosing…";
    document.getElementById("aiList").innerHTML = "";
    document.getElementById("aiNote").textContent = "Sending links to AI…";

    const result = await send({ type: "AI_DIAGNOSE_LINKS", tabId: tab.id });
    renderAiResult(result);
    aiBtn.disabled = false;
    aiBtn.textContent = "🤖 AI Diagnosis";
  });
}

async function init() {
  const enabledEl = document.getElementById("enabled");
  const { enabled } = await send({ type: "GET_ENABLED" });
  enabledEl.checked = enabled !== false;
  enabledEl.addEventListener("change", () =>
    send({ type: "SET_ENABLED", enabled: enabledEl.checked })
  );

  const refreshBtn = document.getElementById("refreshBtn");
  refreshBtn.addEventListener("click", async () => {
    refreshBtn.disabled = true;
    refreshBtn.textContent = "…";
    const info = await send({ type: "REFRESH_BLOCKLIST" });
    document.getElementById("blInfo").textContent =
      `Blocklist: ${(info?.size ?? 0).toLocaleString()} URLs · just now`;
    refreshBtn.disabled = false;
    refreshBtn.textContent = "Refresh";
  });

  loadBlocklistInfo();
  initAiButton();
  runRuleScan();

  const tab = await currentTab();
  if (!tab) return render(null);
  const status = await send({ type: "GET_TAB_STATUS", tabId: tab.id });
  render(status);
}

init();
