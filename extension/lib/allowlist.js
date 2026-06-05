// Built-in allowlist of widely-trusted registrable domains.
// Tier 1 of the cascade: if a host matches one of these we skip all network
// checks entirely (no privacy exposure, no latency, no cost).
//
// This is intentionally small and hand-curated. The user's own allowlist
// (added via the popup) is stored separately in chrome.storage and merged in.
//
// Brands here double as the reference set for typosquatting detection
// (see lib/heuristics.js), so keep recognizable login-bearing brands present.
export const ALLOWLIST = [
  // Search / portals
  "google.com",
  "bing.com",
  "yahoo.com",
  "duckduckgo.com",
  // Big tech / accounts
  "apple.com",
  "icloud.com",
  "microsoft.com",
  "live.com",
  "office.com",
  "amazon.com",
  "aws.amazon.com",
  // Social
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "twitter.com",
  "x.com",
  "linkedin.com",
  "reddit.com",
  "tiktok.com",
  "youtube.com",
  // Dev / work
  "github.com",
  "gitlab.com",
  "stackoverflow.com",
  "atlassian.com",
  "slack.com",
  "zoom.us",
  "notion.so",
  "dropbox.com",
  "cloudflare.com",
  // Payments / finance (common phishing targets — trusted only on exact domain)
  "paypal.com",
  "stripe.com",
  "chase.com",
  "bankofamerica.com",
  "wellsfargo.com",
  // Media / shopping
  "netflix.com",
  "spotify.com",
  "wikipedia.org",
  "ebay.com",
  // Taiwan-relevant
  "gov.tw",
  "edu.tw",
  "nycu.edu.tw",
  "104.com.tw",
  "pchome.com.tw",
  "momoshop.com.tw",
  "ctbcbank.com",
  "esunbank.com.tw",
  "cathaybk.com.tw",
];

// Brands used as the typosquatting reference set (registrable domain, label).
export const BRANDS = [
  "google",
  "facebook",
  "apple",
  "icloud",
  "amazon",
  "paypal",
  "microsoft",
  "office365",
  "netflix",
  "instagram",
  "whatsapp",
  "linkedin",
  "youtube",
  "dropbox",
  "github",
  "binance",
  "coinbase",
  "chase",
  "wellsfargo",
  "bankofamerica",
];
