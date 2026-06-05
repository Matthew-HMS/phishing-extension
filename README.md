# Phishing Guard

A Chrome (Manifest V3) extension that detects phishing sites while you browse,
backed by a thin proxy server that holds your API keys.

It uses a **tiered cascade** so the expensive LLM tier is rarely hit:

| Tier | Where | Cost | What |
| --- | --- | --- | --- |
| 1. Allowlist | extension | free, instant | Skip checks for top/trusted domains |
| 2a. Blocklist | extension | free, instant, offline | OpenPhish + URLhaus feeds synced locally, enforced via declarativeNetRequest |
| 2b. Heuristics | extension | free, instant | Punycode, typosquatting, IP hosts, suspicious TLDs, deep subdomains, entropy (PSL-aware) |
| 3. Reputation | backend | free | Google Safe Browsing lookup (known-bad URLs) |
| 4. LLM verdict | backend | paid | OpenAI judges unknown pages that show credential-collection signals |

Verdicts are cached per-page (origin + path), so repeat visits cost nothing.

---

## Quick start

**1. Backend** — needed for the reputation + AI tiers (local heuristics and the
blocklist still work without it).
- *Using the deployed cloud backend:* nothing to do — [extension/config.js](extension/config.js)
  already points at it (the `https://…run.app` URL + token).
- *Running locally:* `cd backend && npm install && cp .env.example .env` (add your
  keys), then `npm start`. Set `BACKEND_URL` to `http://localhost:8787` in
  [extension/config.js](extension/config.js).

**2. Load the extension**
1. Open `chrome://extensions`, turn on **Developer mode** (top-right).
2. Click **Load unpacked** and choose the [extension/](extension/) folder.
3. Accept the permission prompt — the 🛡️ shield appears in your toolbar (pin it).

Protection is now on.

## Using the extension

### While you browse (automatic)
You don't have to do anything — every page is checked in the background:
- **Dangerous site → a full red warning page** *before* it loads ("Deceptive
  site blocked" for phishing, ☣️ "Dangerous site blocked" for malware). Choose
  **Back to safety** (closes the tab) or, at your own risk, **Proceed anyway**.
- **Suspicious login page → a red overlay** after it loads, with the reasons.
- The toolbar badge shows **!** on suspicious/dangerous pages.

### The popup (click the 🛡️ icon)
A snapshot of the current tab:
- **Risk** — ✅ Safe · ⚠️ Suspicious · ⛔ Dangerous — with the reasons and the
  **detection source** (allowlist / blocklist / heuristics / safe-browsing / llm).
- **Trust this site** — adds it to your personal allowlist (skips all future
  checks for that site).
- **Enable toggle** — turn protection on/off.
- **Blocklist: N URLs** — how many known-bad URLs are synced, with a **Refresh**.

### Scan the links on a page
Opening the popup **automatically scans every link** on the page and shows
**found / unique / risky** counts, then lists the full URLs of any risky links —
useful on search results, webmail, forums, etc.

### 🤖 AI Diagnosis
Click it to have the AI inspect the page's links and flag lookalikes the rules
might miss (typosquats, brand-impersonation domains, raw-IP hosts), each with a
confidence and reason. (Requires the backend's OpenAI key with active billing.)

### Try it safely
- **Heuristic block:** type `https://login.secure.account.paypa1.xyz/signin` — it
  won't resolve, but you'll still get the warning (proof it blocks before load).
- **Real reputation block** (needs a Safe Browsing key): Google's test pages
  `https://testsafebrowsing.appspot.com/s/phishing.html` and `…/s/malware.html`.

### If something looks wrong
- Popup source shows **`heuristics-offline`** → the backend isn't reachable
  (start it, or check `BACKEND_URL`). Local tiers still protect you.
- Wrongly blocked a site you trust → open the popup and click **Trust this site**.

---

## How it works (under the hood)

### Offline blocklist

[extension/lib/blocklist.js](extension/lib/blocklist.js) syncs two free,
key-less feeds into `chrome.storage.local` and refreshes them every 6 hours via
`chrome.alarms`:

- **OpenPhish** community feed → phishing
- **URLhaus** (abuse.ch) online feed → malware

Entries are normalized to `host + path` (scheme/query/fragment stripped) so a
known phishing URL matches even with tracking params, without over-blocking an
entire shared host. Known-bad sites are blocked even if the backend is down.
See the count + force a refresh from the **popup** (the "Blocklist: N URLs"
row), or from the service-worker console:

```js
chrome.storage.local.get("blocklist", d =>
  console.log(Object.keys(d.blocklist?.entries || {}).length, "entries"));
```

### Network-layer blocking (declarativeNetRequest)

[extension/lib/dnr.js](extension/lib/dnr.js) compiles the synced blocklist into
`declarativeNetRequest` dynamic rules that **redirect known-bad main-frame
requests to the warning page at the network layer** — before the request is
sent, and even while the service worker is asleep (the `onBeforeNavigate` check
is a JS fallback). "Proceed anyway" adds a higher-priority `allow` rule so the
host isn't immediately re-blocked. Rules are rebuilt only on each feed refresh
(they persist in Chrome across restarts).

## Architecture

```
Extension (MV3)
  background.js   Phase 1 on navigation: allowlist → cache → heuristics → /scan
                  Redirects known-bad URLs to a warning page before they load.
  content.js      Phase 2 after load: extracts page signals → /analyze.
                  Shows a blocking overlay if the page is judged phishing.
  popup/          Current-tab verdict, enable toggle, "trust this site".
  warning/        Full-page interstitial for blocked navigations.

Backend (Node/Express proxy — holds the keys)
  POST /scan        URL-only: Safe Browsing + heuristic score → risk level.
  POST /scan-batch     Many URLs in one Safe Browsing call (auto page-link scan).
  POST /diagnose-links LLM judges a list of URLs from their strings (AI Diagnosis).
  POST /analyze        URL + page signals → escalates to OpenAI when warranted.
```

> **Why a backend?** A browser extension can't safely store API keys — anyone
> can unzip it. The proxy keeps keys server-side, caches verdicts, and
> rate-limits clients.

## Setup

### 1. Backend

```bash
cd backend
npm install
cp .env.example .env       # then edit .env
npm start
```

Edit `.env`:

- `OPENAI_API_KEY` — your key (powers Tier 4). Without it, Tier 4 is skipped
  and the system falls back to heuristics + reputation.
- `GOOGLE_SAFE_BROWSING_KEY` — free key from
  [Google](https://developers.google.com/safe-browsing/v4/get-started)
  (powers Tier 3). Optional but strongly recommended.

Check it's up: `curl localhost:8787/health`

> **Deploying to the cloud** (so you don't run it locally): see
> [DEPLOY.md](DEPLOY.md). It covers Google Cloud Run (recommended — free HTTPS),
> the `API_TOKEN` lock-down, and a VM alternative.

### 2. Extension

1. If your backend runs somewhere other than `http://localhost:8787`, update
   `BACKEND_URL` in [extension/config.js](extension/config.js).
2. Open `chrome://extensions`, enable **Developer mode**.
3. Click **Load unpacked** and select the [extension/](extension/) folder.
4. Browse. Click the toolbar icon to see the current site's verdict.

## Testing it

- A blatant typosquat like `https://paypa1.com/login` trips the heuristic tier.
- With a Safe Browsing key, you can test against Google's
  [test URLs](https://testsafebrowsing.appspot.com/).
- Pages with password fields or cross-origin form targets trigger the Phase 2
  deep analysis (and the LLM, if a key is set).

## Where the allowlist lives

- **Built-in trusted domains:** [extension/lib/allowlist.js](extension/lib/allowlist.js)
  (edit and reload the extension to change them).
- **Sites you "Trust this site" on:** saved to `chrome.storage.local` under the
  key `userAllowlist` — persistent per Chrome profile, not a file on disk.
  Inspect or clear it from the service-worker console (`chrome://extensions` →
  Phishing Guard → *service worker*):
  ```js
  chrome.storage.local.get("userAllowlist", console.log);
  chrome.storage.local.set({ userAllowlist: [] }); // clear
  ```

## Privacy notes

- Allowlisted sites never leave the browser (no network call).
- Only the URL and **lightweight** page signals (title, a text snippet, form
  *hostnames*, field counts) are sent — never field values, tokens, or cookies.
- The LLM tier is only invoked for unknown pages that look like they collect
  credentials.

## Regenerating bundled data

- **Icons:** `python3 extension/icons/generate_icons.py`
- **Public Suffix List:** `python3 extension/lib/generate_psl.py` (downloads the
  list from publicsuffix.org and rewrites `extension/lib/psl-data.js`). The
  heuristics use this for correct registrable-domain ("eTLD+1") parsing —
  essential for multi-part suffixes like `com.tw` / `co.uk` and private
  suffixes like `github.io`.

## Page-link scanning + AI Diagnosis

When the popup opens it **automatically** scans every link on the page. It
injects a collector (`chrome.scripting`) to gather each `<a href>`,
de-duplicates by `host + path`, and runs them through the **URL-level** cascade
(allowlist → blocklist → cache → heuristics → reputation). Unknown links go to
`/scan-batch`, so the whole page costs a single Safe Browsing call. The popup
shows live **found / unique / risky** counts and lists the risky links (full
URLs).

The **🤖 AI Diagnosis** button sends the page's links to the LLM
(`/diagnose-links`), which judges each one **from the URL string alone** — brand
impersonation, typosquatting, deceptive subdomains, raw-IP hosts, etc. (no page
fetch). It lists the links the AI flags, with a confidence and reason.
Allowlisted hosts are skipped and the request is capped (40 links) to bound
cost. Requires active OpenAI billing.

## Tests

Pure logic (PSL parsing, heuristics, blocklist normalization, DNR rule
generation, backend risk/category mapping) is covered by Node's built-in test
runner:

```bash
npm test        # from the repo root — 25 tests
```

## Limitations / next steps (MVP)

- **Taiwan 165 anti-fraud feed** — adding it is just one entry in the `FEEDS`
  array in [blocklist.js](extension/lib/blocklist.js), pending a stable plain-
  text source.
- **Scale-out** — the backend's in-memory verdict cache and rate-limiter are
  single-instance; swap [cache.js](backend/src/cache.js) for Redis to run
  multiple instances.
- Brand-in-host matching still uses substring search, so a brand word inside an
  unrelated label (e.g. "pineapple") can mildly raise suspicion (never blocks).
- The DNR redirect shows the warning page but doesn't populate the popup's
  per-tab status (the `onBeforeNavigate` path does); minor cosmetic gap.
