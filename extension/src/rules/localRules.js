const SUSPICIOUS_KEYWORDS = ["login", "verify", "account", "password", "secure", "security", "update", "confirm", "wallet", "bank", "signin", "auth"];
const SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "reurl.cc", "is.gd", "cutt.ly", "shorturl.at"];
const TRUSTED_LOCAL_SCHEMES = ["chrome:", "chrome-extension:", "about:", "file:"];

function isIpAddress(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[[0-9a-f:]+\]$/i.test(hostname);
}

function hasExcessiveSubdomains(hostname) {
  return hostname.split(".").filter(Boolean).length >= 5;
}

function scoreToRiskLevel(score) {
  if (score >= 70) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

export function analyzeUrl(rawUrl, context = "") {
  const reasons = [];
  let url;

  try {
    url = new URL(rawUrl, location?.href || "https://example.invalid");
  } catch {
    return { input: rawUrl, normalizedUrl: rawUrl, riskLevel: "MEDIUM", score: 40, reasons: ["URL 格式異常，無法正常解析"] };
  }

  if (TRUSTED_LOCAL_SCHEMES.includes(url.protocol)) {
    return { input: rawUrl, normalizedUrl: url.href, riskLevel: "LOW", score: 0, reasons: [] };
  }

  const hostname = url.hostname.toLowerCase();
  const lowerHref = url.href.toLowerCase();
  const lowerContext = String(context || "").toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((keyword) => lowerHref.includes(keyword) || lowerContext.includes(keyword));

  if (url.protocol !== "https:") reasons.push({ text: "未使用 HTTPS 加密連線", weight: 25 });
  if (url.href.length > 120) reasons.push({ text: "URL 長度過長，可能用於混淆真實目的地", weight: 20 });
  if (isIpAddress(hostname)) reasons.push({ text: "使用 IP 位址作為網域，風險較高", weight: 30 });
  if (SHORTENER_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) reasons.push({ text: "使用短網址服務，目的地不透明", weight: 25 });
  if (matchedKeywords.length >= 2) reasons.push({ text: `包含多個敏感關鍵字：${matchedKeywords.slice(0, 4).join(", ")}`, weight: 25 });
  else if (matchedKeywords.length === 1) reasons.push({ text: `包含敏感關鍵字：${matchedKeywords[0]}`, weight: 12 });
  if (hostname.includes("xn--")) reasons.push({ text: "網域含 Punycode，可能偽裝相似字元", weight: 25 });
  if (hasExcessiveSubdomains(hostname)) reasons.push({ text: "子網域層級過多，可能用於偽裝品牌網域", weight: 15 });

  const score = Math.min(100, reasons.reduce((total, item) => total + item.weight, 0));
  return { input: rawUrl, normalizedUrl: url.href, riskLevel: scoreToRiskLevel(score), score, reasons: reasons.map((reason) => reason.text) };
}
