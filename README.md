# ThreatScope — Threat Intelligence Dashboard

A full-stack security tool that aggregates threat data from **VirusTotal**, **AbuseIPDB**, and **Shodan** for any IP address or URL.

Built with **FastAPI** (Python) + **React** (Vite). Deployable to Railway for free.

---

## Project Structure

```
threat-intel-dashboard/
├── backend/
│   ├── main.py              # FastAPI app with all API routes
│   ├── requirements.txt     # Python dependencies
│   ├── .env.example         # Copy to .env and add your keys
│   └── railway.toml         # Railway deployment config
└── frontend/
    ├── src/
│   │   ├── App.jsx          # Main React component
│   │   └── main.jsx         # Entry point
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── .env.example         # Copy to .env and set API URL
```

---

## Step 1 — Get Your Free API Keys

| Service | Free Tier | Where to get it |
|---|---|---|
| VirusTotal | 4 req/min | virustotal.com → Profile → API Key |
| AbuseIPDB | 1,000 req/day | abuseipdb.com → Account → API |
| Shodan | Limited free | shodan.io → Account → API Key |

---

## Step 2 — Run Locally

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your API keys

uvicorn main:app --reload
# API now running at http://localhost:8000
# Docs at http://localhost:8000/docs
```

### Frontend

```bash
cd frontend
npm install

cp .env.example .env
# .env should have: VITE_API_URL=http://localhost:8000

npm run dev
# App now running at http://localhost:5173
```

---

## Step 3 — Deploy to Railway

### Backend

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub repo
3. Select the repo, set the **Root Directory** to `backend`
4. Add environment variables in Railway dashboard:
   - `VIRUSTOTAL_API_KEY`
   - `ABUSEIPDB_API_KEY`
   - `SHODAN_API_KEY`
5. Railway auto-detects Python and uses `railway.toml` for the start command
6. Copy your deployed backend URL (e.g. `https://your-app.railway.app`)

### Frontend

1. Create another Railway service → Deploy from same repo
2. Set **Root Directory** to `frontend`
3. Add environment variable:
   - `VITE_API_URL=https://your-backend.railway.app`
4. Railway builds with `npm run build` and serves the static files

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/analyze/{target}` | Full analysis from all 3 sources |
| `GET /api/virustotal/{resource}` | VirusTotal lookup only |
| `GET /api/abuseipdb/{ip}` | AbuseIPDB lookup only |
| `GET /api/shodan/{ip}` | Shodan lookup only |

Interactive docs available at `/docs` (FastAPI's built-in Swagger UI).

---

## What This Demonstrates (for your resume)

- **REST API integration** — authenticated requests to 3 external APIs
- **Async Python** — FastAPI with `httpx` for concurrent requests
- **React frontend** — component-based UI consuming a REST API
- **Security domain knowledge** — threat intelligence, IP reputation, CVE awareness
- **Full-stack deployment** — separate frontend/backend services on Railway

---

## Ideas to Extend This Project

- [ ] Add URL scanning (VirusTotal URL endpoint)
- [ ] Add file hash lookup
- [ ] Store search history in a database (PostgreSQL on Railway)
- [ ] Add email alerts for high-risk scores (SendGrid API)
- [ ] Export reports as PDF
- [ ] Add bulk IP scanning via CSV upload
- [ ] Add user authentication (JWT)
