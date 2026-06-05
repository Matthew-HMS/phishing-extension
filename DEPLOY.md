# Deploying the backend

The backend is a small Node/Express service. It needs to be reachable over
**HTTPS** (a browser extension can't call a plain-HTTP remote) and should be
locked down with `API_TOKEN` so strangers can't spend your OpenAI credits.

Recommended: **Google Cloud Run** (free HTTPS, scales to zero, no server admin).
A VM works too (always-on, but you set up HTTPS yourself — see the end).

---

## 0. Generate a shared token

```bash
openssl rand -hex 32
```
Use this same value for `API_TOKEN` in the cloud **and** in
[extension/config.js](extension/config.js).

---

## One-time GCP setup

1. **Create a project** at <https://console.cloud.google.com> (note its
   *Project ID*) and make sure **billing is enabled** (Cloud Run has a free
   tier, but a billing account must be attached).
2. **Install the gcloud CLI** (<https://cloud.google.com/sdk/docs/install>), or
   just use **Cloud Shell** (the `>_` icon in the console — gcloud is preinstalled).
3. Authenticate and select the project:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```
4. **Enable the APIs** Cloud Run needs:
   ```bash
   gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
     artifactregistry.googleapis.com
   ```

## Option A — Google Cloud Run (recommended)

Deploy straight from the `backend/` source (uses the bundled `Dockerfile`):

```bash
gcloud run deploy phishing-guard \
  --source backend \
  --region asia-east1 \
  --allow-unauthenticated \
  --max-instances 1 \
  --set-env-vars "OPENAI_API_KEY=sk-...,OPENAI_MODEL=gpt-4o-mini,GOOGLE_SAFE_BROWSING_KEY=...,API_TOKEN=<token from step 0>"
```

Notes:
- `asia-east1` is Taiwan — lowest latency for you; pick any region you like.
- `--allow-unauthenticated` lets the extension reach it; **our `API_TOKEN` is
  what actually gates access** (Cloud Run's own auth would require a Google
  identity the extension doesn't have).
- `--max-instances 1` keeps the in-memory cache/rate-limiter coherent and caps
  cost. Cold start (scale-to-zero) is fine — the extension falls back to local
  heuristics if the first request is slow.
- Hardening (optional): put the secrets in **Secret Manager** and reference them
  with `--set-secrets` instead of `--set-env-vars` so they're not visible in the
  console.

The command prints a **Service URL** like `https://phishing-guard-xxxx.a.run.app`.

Verify:
```bash
curl https://phishing-guard-xxxx.a.run.app/health
# {"ok":true,"safeBrowsing":true,"llm":true}
```

---

## Point the extension at the cloud

Edit [extension/config.js](extension/config.js):

```js
export const BACKEND_URL = "https://phishing-guard-xxxx.a.run.app"; // no trailing slash
export const API_TOKEN = "<token from step 0>";
```

Then reload the extension at `chrome://extensions`. That's it — you no longer
need to run anything locally.

---

## Auto-deploy with GitHub Actions

The workflow [.github/workflows/deploy-backend.yml](.github/workflows/deploy-backend.yml)
redeploys to Cloud Run whenever `backend/**` changes on `main` (or when run
manually from the Actions tab). Set it up once:

### 1. Create a deployer service account
```bash
PROJECT_ID=$(gcloud config get-value project)
gcloud iam service-accounts create gh-deployer \
  --display-name="GitHub Actions deployer"
SA=gh-deployer@$PROJECT_ID.iam.gserviceaccount.com

for role in roles/run.admin roles/iam.serviceAccountUser \
            roles/cloudbuild.builds.editor roles/artifactregistry.admin \
            roles/storage.admin; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA" --role="$role"
done
```
(If a deploy ever fails with a permissions error, the quick fallback is to grant
`roles/owner` to this SA — less tidy, but unblocks you.)

### 2. Create a key for it
```bash
gcloud iam service-accounts keys create gh-key.json --iam-account=$SA
cat gh-key.json   # copy the whole JSON
```
> Treat `gh-key.json` as a secret: don't commit it. Delete it locally after you
> paste it into GitHub (`rm gh-key.json`).

### 3. Add GitHub repo secrets
In your repo: **Settings → Secrets and variables → Actions → New repository
secret**. Add:

| Secret | Value |
| --- | --- |
| `GCP_SA_KEY` | the entire contents of `gh-key.json` |
| `GCP_PROJECT_ID` | your project ID |
| `OPENAI_API_KEY` | your OpenAI key |
| `GOOGLE_SAFE_BROWSING_KEY` | your Safe Browsing key |
| `API_TOKEN` | the token from step 0 |

### 4. Trigger it
Push a change under `backend/`, or run it manually: **Actions → Deploy backend
(Cloud Run) → Run workflow**. The job logs print the service URL. Put that URL +
`API_TOKEN` into [extension/config.js](extension/config.js) and reload the
extension.

> **More secure alternative (no long-lived key): Workload Identity Federation.**
> Replace the `auth` step's `credentials_json` with
> `workload_identity_provider` + `service_account`, and create a pool/provider:
> ```bash
> gcloud iam workload-identity-pools create github-pool --location=global
> gcloud iam workload-identity-pools providers create-oidc github-provider \
>   --location=global --workload-identity-pool=github-pool \
>   --issuer-uri="https://token.actions.githubusercontent.com" \
>   --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
>   --attribute-condition="assertion.repository=='OWNER/REPO'"
> POOL=$(gcloud iam workload-identity-pools describe github-pool --location=global --format='value(name)')
> gcloud iam service-accounts add-iam-policy-binding $SA \
>   --role=roles/iam.workloadIdentityUser \
>   --member="principalSet://iam.googleapis.com/$POOL/attribute.repository/OWNER/REPO"
> ```
> Then store the provider resource name as a secret and reference it in the
> workflow. WIF avoids storing a key in GitHub.

## Option B — your Google Cloud VM

Works, but you must provide HTTPS yourself (Cloud Run gives it for free).

1. **Install Docker** on the VM, then build & run:
   ```bash
   docker build -t phishing-guard ./backend
   docker run -d --restart unless-stopped -p 8787:8787 \
     -e OPENAI_API_KEY=sk-... \
     -e GOOGLE_SAFE_BROWSING_KEY=... \
     -e API_TOKEN=<token> \
     -e OPENAI_MODEL=gpt-4o-mini \
     phishing-guard
   ```
2. **HTTPS** — you need a domain (Let's Encrypt won't issue for a bare IP). Point
   a domain (or a free one, e.g. DuckDNS) at the VM's external IP, open ports
   80/443 in the GCP firewall, and run [Caddy](https://caddyserver.com) in front
   for automatic TLS:
   ```
   # /etc/caddy/Caddyfile
   your-domain.example {
     reverse_proxy localhost:8787
   }
   ```
3. Set `BACKEND_URL = "https://your-domain.example"` in config.js.

This is more setup and ongoing maintenance (OS patching, cert renewal is
automatic with Caddy, process restarts via `--restart`). Cloud Run avoids all of
it — prefer it unless you specifically want the VM.

---

## Keeping local dev working

Leave `API_TOKEN` empty in `backend/.env` and `extension/config.js` to run
locally with the gate open (`npm start` in `backend/`). Set both to the same
value only for the deployed setup.
