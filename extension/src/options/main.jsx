import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { DEFAULT_SETTINGS, getSettings, saveSettings } from '../shared.js';
import './style.css';

function App() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);

  useEffect(() => { getSettings().then(setSettings); }, []);

  function update(field, value) {
    setSettings((current) => ({ ...current, [field]: value }));
    setSaved(false);
  }

  async function onSubmit(event) {
    event.preventDefault();
    const whitelist = String(settings.whitelistText || settings.whitelist.join('\n'))
      .split('\n').map((item) => item.trim().toLowerCase()).filter(Boolean);
    const next = { ...settings, whitelist };
    delete next.whitelistText;
    await saveSettings(next);
    setSettings(next);
    setSaved(true);
  }

  return (
    <main>
      <h1>Phishing Guard 設定</h1>
      <form onSubmit={onSubmit}>
        <label>
          <span>啟用防護</span>
          <input type="checkbox" checked={settings.enabled} onChange={(e) => update('enabled', e.target.checked)} />
        </label>
        <label>
          <span>後端 API URL</span>
          <input value={settings.apiBaseUrl} onChange={(e) => update('apiBaseUrl', e.target.value)} placeholder="http://localhost:8000" />
        </label>
        <label>
          <span>高風險阻擋閾值</span>
          <input type="number" min="1" max="100" value={settings.riskThreshold} onChange={(e) => update('riskThreshold', Number(e.target.value))} />
        </label>
        <label>
          <span>自訂白名單，每行一個網域</span>
          <textarea value={settings.whitelistText ?? settings.whitelist.join('\n')} onChange={(e) => update('whitelistText', e.target.value)} rows="8" placeholder="internal.example.com" />
        </label>
        <button type="submit">儲存設定</button>
        {saved && <p className="saved">設定已儲存。</p>}
      </form>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
