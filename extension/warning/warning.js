// Interstitial warning page shown when Phase 1 blocks a navigation.
const params = new URLSearchParams(location.search);
const blockedUrl = params.get("url") || "";
let reasons = [];
try {
  reasons = JSON.parse(params.get("reasons") || "[]");
} catch {
  reasons = [];
}

const category = params.get("category") || "phishing";

let host = blockedUrl;
try {
  host = new URL(blockedUrl).hostname;
} catch {
  /* keep raw */
}
document.getElementById("host").textContent = host;

// Adapt the message to the kind of threat Safe Browsing / the LLM reported.
const COPY = {
  phishing: {
    badge: "⚠️",
    title: "Deceptive site blocked",
    subtitle: "This site may be trying to steal your passwords or personal information.",
  },
  malware: {
    badge: "☣️",
    title: "Dangerous site blocked",
    subtitle: "This site may try to install malware or harmful software on your device.",
  },
};
const copy = COPY[category] || COPY.phishing;
document.getElementById("badge").textContent = copy.badge;
document.getElementById("title").textContent = copy.title;
document.getElementById("subtitle").textContent = copy.subtitle;

const reasonsEl = document.getElementById("reasons");
for (const r of reasons) {
  const li = document.createElement("li");
  li.textContent = r;
  reasonsEl.appendChild(li);
}
if (reasons.length === 0) {
  reasonsEl.remove();
}

// Closing the tab is the only reliable "back to safety": the blocked URL may
// have committed into history before we redirected, so history.back() would
// bounce straight back here.
document.getElementById("back").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "LEAVE_SITE" });
});

// Proceeding registers a per-session bypass in the background worker (so the
// navigation isn't immediately re-blocked) and then opens the original URL.
document.getElementById("proceed").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "BYPASS", domain: host }, () => {
    location.href = blockedUrl;
  });
});
