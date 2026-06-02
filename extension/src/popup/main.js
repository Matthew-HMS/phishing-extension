const scannedEl = document.getElementById("scanned");
const suspiciousEl = document.getElementById("suspicious");
const highRiskEl = document.getElementById("highRisk");
const findingsEl = document.getElementById("findings");
const aiButton = document.getElementById("aiButton");
const aiMessage = document.getElementById("aiMessage");
const aiResultEl = document.getElementById("aiResult");

function escapeHtml(value = "") {
  return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));
}

function renderFindings(findings = []) {
  findingsEl.innerHTML = "";
  if (!findings.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "尚未發現可疑連結";
    findingsEl.appendChild(li);
    return;
  }
  findings.slice(0, 5).forEach((finding) => {
    const li = document.createElement("li");
    li.innerHTML = `<strong>${escapeHtml(finding.riskLevel)} · ${Number(finding.score || 0)}/100</strong><span>${escapeHtml(finding.normalizedUrl || finding.input)}</span><small>${escapeHtml((finding.reasons || []).slice(0, 2).join("；"))}</small>`;
    findingsEl.appendChild(li);
  });
}

function renderAiResult(result) {
  if (!result) {
    aiResultEl.innerHTML = "";
    return;
  }
  const reasons = (result.reasons || []).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("");
  aiResultEl.innerHTML = `
    <div class="ai-card ${escapeHtml(String(result.riskLevel || "LOW").toLowerCase())}">
      <strong>AI 判斷：${escapeHtml(result.riskLevel)} · ${Number(result.score || 0)}/100</strong>
      <p>${escapeHtml(result.aiSummary || "無摘要")}</p>
      <ul>${reasons}</ul>
      <small>來源：${escapeHtml(result.source || "backend")}</small>
    </div>
  `;
}

async function loadStats() {
  try {
    const response = await chrome.runtime.sendMessage({ type: "GET_TAB_STATS" });
    const stats = response?.stats || {};
    scannedEl.textContent = stats.scanned || 0;
    suspiciousEl.textContent = stats.suspicious || 0;
    highRiskEl.textContent = stats.highRisk || 0;
    renderFindings(stats.lastFindings || []);
    renderAiResult(response?.aiResult || null);
  } catch {
    aiMessage.textContent = "無法讀取目前分頁狀態。";
  }
}

aiButton.addEventListener("click", async () => {
  aiButton.disabled = true;
  aiMessage.textContent = "正在呼叫後端與 OpenAI Responses API...";
  renderAiResult(null);
  try {
    const response = await chrome.runtime.sendMessage({ type: "REQUEST_AI_ANALYSIS" });
    if (!response?.ok) throw new Error(response?.message || "AI 分析失敗");
    aiMessage.textContent = "AI 分析完成。";
    renderAiResult(response.result);
  } catch (error) {
    aiMessage.textContent = `無法完成 AI 分析：${error.message}`;
  } finally {
    aiButton.disabled = false;
  }
});

loadStats();
