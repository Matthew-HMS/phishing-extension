# Phishing Guard Project - Phase 2

此版本包含：

1. 階段一：瀏覽器插件主動防禦
2. 階段二：FastAPI 後端與 OpenAI Responses API 手動 AI 分析

## 專案結構

```txt
phishing-guard-project/
├── extension/                 # Chrome / Edge 插件
│   ├── manifest.json
│   └── src/
│       ├── background.js      # 本地規則 + 呼叫後端
│       ├── content.js         # 主動 DOM 擷取 + 提供頁面上下文
│       ├── rules/localRules.js
│       └── popup/             # Popup UI + AI 按鈕
├── backend-api/               # FastAPI 後端
│   ├── app/
│   │   ├── main.py
│   │   ├── routers/scan.py
│   │   ├── services/rule_checker.py
│   │   ├── services/ai_checker.py
│   │   ├── schemas/scan.py
│   │   └── utils/url_features.py
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
└── docker-compose.yml
```

## 運作流程

### 插件簡單防禦

```txt
content.js 自動監聽網頁 DOM
→ 擷取頁面中的 URL
→ 傳給 background.js
→ background.js 呼叫 localRules.js
→ 可疑連結直接在網頁上標記
```

此流程不會呼叫後端，也不會呼叫 OpenAI。

### 手動 AI 分析流程

```txt
使用者點擊 Popup 的「使用 AI 深度分析」
→ popup/main.js 傳送 REQUEST_AI_ANALYSIS 給 background.js
→ background.js 要求 content.js 回傳目前頁面上下文
→ content.js 回傳頁面標題、目前 URL、可見文字、頁面連結
→ background.js 把資料 POST 到 FastAPI /api/v1/scan
→ FastAPI 的 ai_checker.py 使用 .env 內的 OPENAI_API_KEY
→ 呼叫 OpenAI Responses API
→ 回傳 riskLevel、score、reasons、aiSummary
→ Popup 顯示 AI 分析結果
```

## 啟動
### Anaconda 後端環境

```bash
cd backend-api
conda create -n phishing-guard python=3.11 -y
conda activate phishing-guard
pip install -r requirements.txt
```

接著編輯 `backend-api/.env`：

```txt
OPENAI_API_KEY=你的 OpenAI API Key
OPENAI_MODEL=gpt-4o-mini
CORS_ORIGINS=*
```

啟動後端：

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 載入插件

1. 開啟 Chrome / Edge
2. 進入 `chrome://extensions`
3. 開啟「開發人員模式」
4. 點選「載入未封裝項目」
5. 選擇：

```txt
phishing-guard-project/extension
```

## 測試方法
在後端內啟動後端 `uvicorn`
```txt
cd \phishing-guard-project\backend-api
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
此時 terminal 會出現 Uvicorn running on http://127.0.0.1:8000
打開瀏覽器輸入 http://127.0.0.1:8000/api/v1/health
應該會出現
```json
{
  "status": "ok",
  "service": "phishing-guard-backend"
}
```
輸入 http://127.0.0.1:8000/docs
會出現 FastAPI 的 Swagger UI，可測試 API

## 使用方法

1. 在後端內啟動後端 `uvicorn`
```txt
cd \phishing-guard-project\backend-api
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
```
2. 載入插件
3. 開啟任意測試網頁
4. 插件會自動執行本地防禦
5. 點擊插件 Popup 的「使用 AI 深度分析」
6. Popup 會顯示後端與 AI 的分析結果

## API

### `POST /api/v1/scan`

插件 AI 按鈕使用此 API。

Request：

```json
{
  "url": "https://example.com/login",
  "pageTitle": "Example Login",
  "context": "頁面可見文字",
  "links": ["https://example.com/login"],
  "localFindings": []
}
```

Response：

```json
{
  "riskLevel": "LOW",
  "score": 20,
  "reasons": [],
  "aiSummary": "此頁面目前未發現明顯釣魚特徵。",
  "source": "openai-responses-api"
}
```

### `POST /api/v1/scan/rules`

只跑後端本地規則，不呼叫 OpenAI，方便測試。

## Docker 啟動

```bash
cp backend-api/.env.example backend-api/.env
# 編輯 backend-api/.env 填入 OPENAI_API_KEY
docker compose up --build
```
