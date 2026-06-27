# Deploying QuantumSafe

This guide takes you from the repo to a live, clickable demo:

- **Backend API** → Render (Flask + Postgres)
- **Frontend dashboard** → Vercel (static)
- **Payments** → Stripe (optional; test mode is fine)
- **Demo data** → a seed script so the dashboard looks populated

Estimated time: ~30–45 minutes. You need free accounts on Render, Vercel, and
(optionally) Stripe.

---

## 1. Backend → Render

1. Push this repo to GitHub (already done if you're reading this there).
2. On [Render](https://render.com): **New → Blueprint**, pick this repo. Render
   reads [`render.yaml`](render.yaml) and provisions a **web service** +
   **Postgres database** automatically.
3. `SECRET_KEY` and `JWT_SECRET_KEY` are generated for you; `DATABASE_URL` is
   wired automatically. Fill in the `sync: false` variables in the Render
   dashboard once the service exists:
   - `FRONTEND_ORIGIN` and `DASHBOARD_URL` → your Vercel URL (see step 2; you can
     come back and set these after Vercel is live)
   - `API_URL` → this Render service's URL (e.g. `https://quantumsafe-api.onrender.com`)
   - Stripe + Mail vars → optional, see steps 3–4
4. Wait for the first deploy, then check `https://<your-api>.onrender.com/health`
   → should return `{"status":"ok"}`.

> Note: Render's free tier sleeps when idle, so the first request after a while
> is slow. The dashboard pre-warms the API on page load to hide this.

## 2. Frontend → Vercel

1. On [Vercel](https://vercel.com): **Add New → Project**, import this repo.
   [`vercel.json`](vercel.json) serves the `frontend/` directory statically.
2. Deploy. Note your URL (e.g. `https://quantumsafe.vercel.app`).
3. Point the dashboard at your API. Two options:
   - **Quick:** edit the top of `frontend/app.js` and set the default
     `API_BASE` to your Render URL, then redeploy; **or**
   - add this line to the top of each HTML file's `<head>` before `app.js`:
     ```html
     <script>window.QUANTUMSAFE_API = "https://quantumsafe-api.onrender.com";</script>
     ```
4. Go back to Render and set `FRONTEND_ORIGIN` and `DASHBOARD_URL` to your Vercel
   URL (this is what the API's CORS allows). Redeploy the API.

## 3. Stripe (optional — only to take payments)

1. In the [Stripe Dashboard](https://dashboard.stripe.com) (Test mode):
   - **Products** → create **Pro** ($19/mo recurring) and **Team** ($49/mo
     recurring). Copy each **price ID** (`price_…`).
   - **Developers → API keys** → copy the **Secret key** (`sk_test_…`).
   - **Developers → Webhooks** → **Add endpoint**:
     `https://<your-api>.onrender.com/api/v1/billing/webhook`, subscribe to
     `checkout.session.completed`, `customer.subscription.updated`,
     `customer.subscription.deleted`. Copy the **signing secret** (`whsec_…`).
2. Set on Render: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`,
   `STRIPE_PRO_PRICE_ID`, `STRIPE_TEAM_PRICE_ID`. Redeploy.

Without these, billing endpoints return a clean "not configured" (503) and the
rest of the app works fine.

## 4. Email (optional — verification + alerts)

Set `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`,
`MAIL_DEFAULT_SENDER` on Render (e.g. Gmail with an App Password). Without these,
verification/reset/alert emails are logged instead of sent — fine for a demo.

## 5. Seed the demo account (recommended for a portfolio demo)

So visitors see a populated dashboard without signing up:

```bash
# Render: Shell tab on the web service, or locally pointed at the prod DB
cd backend && python seed_demo.py
```

This creates:

```
demo@quantumsafe.dev  /  demodemo123   (Pro plan, 5 scans, descending risk trend)
```

Add the demo credentials to your landing page or README so reviewers can log in.

---

## Local quickstart (for development)

```bash
pip install -e .
pip install -r backend/requirements.txt
cp .env.example .env            # set SECRET_KEY + JWT_SECRET_KEY
cd backend && python seed_demo.py   # optional demo data
python app.py                   # API at http://localhost:5000
# in another shell:
cd frontend && python -m http.server 3000   # dashboard at http://localhost:3000
```

Run tests: `pytest -q`
