import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ShieldCheck, ShieldAlert, Settings } from 'lucide-react';
import './style.css';

function App() {
  const [status, setStatus] = useState({ lastScan: null, blockedCount: 0 });

  useEffect(() => {
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => setStatus(response || {}));
  }, []);

  const last = status.lastScan;
  const level = last?.risk_level || 'LOW';
  const Icon = level === 'HIGH' ? ShieldAlert : ShieldCheck;

  return (
    <main className="popup">
      <header>
        <Icon size={28} />
        <div>
          <h1>Phishing Guard</h1>
          <p>即時網址風險防護</p>
        </div>
      </header>

      <section className={`score ${level.toLowerCase()}`}>
        <span>目前狀態</span>
        <strong>{level === 'HIGH' ? '嚴重危險' : level === 'MEDIUM' ? '警告' : '安全'}</strong>
        <small>最近分數：{last?.risk_score ?? 0}/100</small>
      </section>

      <section className="card">
        <h2>阻擋報告</h2>
        <p>累計阻擋：{status.blockedCount || 0}</p>
        {last?.reasons?.length ? (
          <ul>{last.reasons.slice(0, 4).map((reason) => <li key={reason}>{reason}</li>)}</ul>
        ) : <p>尚無可疑事件。</p>}
      </section>

      <button onClick={() => chrome.runtime.openOptionsPage()}>
        <Settings size={16} /> 設定白名單與 API
      </button>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
