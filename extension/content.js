// Content script — Phase 2 of the cascade.
// Runs after the page settles, extracts lightweight signals, and asks the
// background worker for a deep verdict (which may escalate to the LLM).
// If the verdict is HIGH, it overlays a full-page warning.
(function () {
  // Only the top frame, and never on our own pages.
  if (window.top !== window) return;
  if (location.protocol !== "http:" && location.protocol !== "https:") return;

  // Respect a per-session "proceed anyway" bypass.
  if (sessionStorage.getItem("phishguard-bypass") === "1") return;

  // --- collect lightweight, privacy-conscious page signals ---------------
  function collectSignals() {
    const text = (document.body?.innerText || "").slice(0, 1500);

    const passwordFields = document.querySelectorAll('input[type="password"]').length;
    const inputs = document.querySelectorAll("input").length;

    // Where do forms submit? Cross-origin form targets are a strong phishing
    // signal. We send only the hostname of each target, never values.
    const formTargets = [];
    for (const form of document.forms) {
      try {
        const action = form.getAttribute("action") || location.href;
        const host = new URL(action, location.href).hostname;
        if (host && !formTargets.includes(host)) formTargets.push(host);
      } catch {
        /* ignore malformed action */
      }
    }

    const ogSite = document
      .querySelector('meta[property="og:site_name"]')
      ?.getAttribute("content");

    return {
      title: document.title?.slice(0, 200) || "",
      text,
      passwordFields,
      inputs,
      formTargets,
      currentHost: location.hostname,
      ogSiteName: ogSite || null,
    };
  }

  // Heuristic gate: only bother the backend when the page actually looks like
  // it could be collecting credentials. Saves cost/latency on benign pages.
  function worthAnalyzing(signals) {
    if (signals.passwordFields > 0) return true;
    const crossOrigin = signals.formTargets.some((h) => h !== signals.currentHost);
    if (crossOrigin) return true;
    const lure = /(verify|confirm|suspend|login|sign in|password|account|billing|unusual activity)/i;
    return lure.test(signals.title) || lure.test(signals.text.slice(0, 400));
  }

  const signals = collectSignals();
  if (!worthAnalyzing(signals)) return;

  chrome.runtime.sendMessage(
    { type: "ANALYZE_PAGE", payload: { url: location.href, page: signals } },
    (verdict) => {
      if (chrome.runtime.lastError || !verdict) return;
      if (verdict.risk === "HIGH") {
        showOverlay(verdict);
      }
    }
  );

  // --- full-page blocking overlay ---------------------------------------
  function showOverlay(verdict) {
    if (document.getElementById("phishguard-overlay")) return;

    const reasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];
    const overlay = document.createElement("div");
    overlay.id = "phishguard-overlay";
    overlay.attachShadow({ mode: "open" });

    const isMalware = verdict.category === "malware";
    const badge = isMalware ? "☣️" : "⚠️";
    const heading = isMalware
      ? "This site may be dangerous"
      : "This site may be phishing";

    const reasonItems = reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("");
    const explanation = verdict.explanation
      ? `<p class="explain">${escapeHtml(verdict.explanation)}</p>`
      : "";

    overlay.shadowRoot.innerHTML = `
      <style>
        .wrap {
          position: fixed; inset: 0; z-index: 2147483647;
          background: #7f1d1d; color: #fff;
          font-family: system-ui, -apple-system, sans-serif;
          display: flex; align-items: center; justify-content: center;
        }
        .card {
          max-width: 560px; padding: 32px; text-align: center;
        }
        .badge { font-size: 56px; }
        h1 { font-size: 26px; margin: 12px 0 8px; }
        .host { font-family: monospace; background: rgba(0,0,0,.25);
          padding: 4px 8px; border-radius: 6px; word-break: break-all; }
        ul { text-align: left; margin: 18px auto; max-width: 420px;
          line-height: 1.5; }
        .explain { background: rgba(0,0,0,.2); padding: 12px; border-radius: 8px;
          font-size: 14px; }
        .actions { margin-top: 24px; display: flex; gap: 12px;
          justify-content: center; }
        button { padding: 10px 18px; border: 0; border-radius: 8px;
          font-size: 15px; cursor: pointer; }
        .back { background: #fff; color: #7f1d1d; font-weight: 600; }
        .proceed { background: transparent; color: #fecaca;
          border: 1px solid #fecaca; }
      </style>
      <div class="wrap">
        <div class="card">
          <div class="badge">${badge}</div>
          <h1>${heading}</h1>
          <div class="host">${escapeHtml(location.hostname)}</div>
          ${explanation}
          ${reasonItems ? `<ul>${reasonItems}</ul>` : ""}
          <div class="actions">
            <button class="back">Go back to safety</button>
            <button class="proceed">Ignore &amp; proceed</button>
          </div>
        </div>
      </div>`;

    document.documentElement.appendChild(overlay);

    overlay.shadowRoot.querySelector(".back").addEventListener("click", () => {
      if (history.length > 1) history.back();
      else location.href = "about:blank";
    });
    overlay.shadowRoot.querySelector(".proceed").addEventListener("click", () => {
      sessionStorage.setItem("phishguard-bypass", "1");
      overlay.remove();
    });
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
