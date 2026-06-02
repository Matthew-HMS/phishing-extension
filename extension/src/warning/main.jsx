import React from 'react';
import { createRoot } from 'react-dom/client';
import { TriangleAlert } from 'lucide-react';
import './style.css';

function parseReasons() {
  const params = new URLSearchParams(location.search);
  try { return JSON.parse(params.get('reasons') || '[]'); } catch { return []; }
}

function App() {
  const params = new URLSearchParams(location.search);
  const target = params.get('target') || '';
  const score = params.get('score') || '未知';
  const reasons = parseReasons();

  return (
    <main>
      <TriangleAlert size={56} />
      <h1>已阻擋高風險網站</h1>
      <p className="target">{target}</p>
      <section>
        <strong>風險分數：{score}/100</strong>
        <ul>{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
      </section>
      <div className="actions">
        <button onClick={() => history.back()}>返回上一頁</button>
        <a href={target}>仍要前往</a>
      </div>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
