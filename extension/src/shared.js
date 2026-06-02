export const DEFAULT_SETTINGS = {
  apiBaseUrl: 'http://localhost:8000',
  riskThreshold: 75,
  warningThreshold: 45,
  whitelist: [],
  enabled: true
};

export function normalizeHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function isWhitelisted(url, whitelist = []) {
  const host = normalizeHost(url);
  return whitelist.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

export async function getSettings() {
  const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...stored };
}

export async function saveSettings(nextSettings) {
  await chrome.storage.sync.set({ ...DEFAULT_SETTINGS, ...nextSettings });
}

export function riskBadgeClass(level) {
  if (level === 'HIGH') return 'badge high';
  if (level === 'MEDIUM') return 'badge medium';
  return 'badge low';
}
