# PhishGuard — Explainable Hybrid Phishing Detection System

A college-level, professionally engineered **cybersecurity + Machine Learning** application that detects phishing websites using a hybrid approach combining structural URL analysis, brand impersonation detection, HTML content analysis, and an explainable ML ensemble.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Next.js 14 Frontend (TypeScript + Tailwind CSS)        │
│  ─ Scanner · History · Benchmark · Documentation        │
└───────────────────┬─────────────────────────────────────┘
                    │ REST API
┌───────────────────▼─────────────────────────────────────┐
│  FastAPI Backend (Python 3.11)                           │
│  ─ URL Sanitizer → Feature Extractor (37 features)      │
│  ─ Brand Similarity Engine (combosquat/typosquat/IDN)   │
│  ─ HTML Analyzer (BeautifulSoup4, SSRF-protected)       │
│  ─ ML Ensemble (Random Forest, GBT, LR — pure NumPy)   │
│  ─ Risk Scorer (0–100) → Explainability Engine          │
│  ─ Threat Intel stub (Google Safe Browsing / VT ready)  │
└───────────────────┬─────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────┐
│  Database: Supabase (PostgreSQL) / SQLite fallback       │
└─────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

| Feature | Detail |
|---|---|
| **37-feature URL extractor** | Length ratios, digit content, entropy, TLD risk, special char counts |
| **Brand similarity engine** | Combosquatting, typosquatting, homoglyphs, subdomain deception, IDN/Punycode |
| **Pure-NumPy ML models** | Random Forest, Gradient Boosting, Logistic Regression (no scikit-learn DLLs) |
| **SSRF protection** | Blocks loopback, RFC 1918, link-local, AWS metadata before any HTTP fetch |
| **HTML analysis** | Detects login forms, external form actions, hidden iframes, script density |
| **Explainability** | Human-readable reason strings with severity tiers (CRITICAL → LOW) |
| **Risk scoring** | Calibrated 0–100 score combining ML + rules + brand + HTML + threat intel |
| **Threat intel ready** | Google Safe Browsing + VirusTotal wired in — just add API keys |
| **Scan history** | Persisted to Supabase (cloud) or SQLite (fallback), paginated REST API |
| **Full test suite** | 28/28 tests passing (pytest) |

---

## 📊 ML Performance

| Model | Accuracy | F1 | ROC-AUC | FNR |
|---|---|---|---|---|
| Random Forest ⭐ | 100% | 1.000 | 1.000 | 0% |
| Gradient Boosting | 100% | 1.000 | 1.000 | 0% |
| Logistic Regression | 100% | 1.000 | 1.000 | 0% |

**Generalization:** 14/14 unseen obfuscation techniques correctly classified (never seen during training).

**Top features:** `is_https` · `tld_is_risky` · `hostname_length` · `is_suspicious_brand_use` · `script_count`

Training set: **2,300 samples** (1,150 legitimate + 1,150 phishing), 80/20 stratified split.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+

### Backend
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env          # fill in API keys (optional)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# → http://localhost:3000
```

### API Docs
```
http://localhost:8000/docs       # Swagger UI
http://localhost:8000/redoc      # ReDoc
```

---

## 🔑 External APIs (Optional — Unlock P1 Features)

| API | Free Tier | Env Var | What it Unlocks |
|---|---|---|---|
| [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started) | 10k QPS | `GOOGLE_SAFE_BROWSING_API_KEY` | Real-time phishing URL check |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | 4 req/min | `VIRUSTOTAL_API_KEY` | 70+ vendor verdict |
| [Supabase](https://supabase.com) | 500MB free | `SUPABASE_URL` + `SUPABASE_KEY` | Cloud PostgreSQL history |

Without keys, the system runs fully in **offline mode** using rule-based detection + ML only.

---

## 🗂️ Project Structure

```
website/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/       # analyze, history, health, benchmark
│   │   ├── ml/
│   │   │   ├── models.py           # Pure-NumPy RF, GBT, LR
│   │   │   ├── model_loader.py     # Singleton loader
│   │   │   ├── training/           # Dataset builder + training script
│   │   │   └── trained_models/     # model_metadata.json, benchmark_results.json
│   │   ├── security/               # SSRF protection, URL sanitizer
│   │   ├── services/               # Feature extractor, brand similarity,
│   │   │                           # HTML analyzer, risk scorer, explainability,
│   │   │                           # threat intel, database
│   │   ├── schemas/                # Pydantic request/response models
│   │   ├── config.py
│   │   └── main.py
│   ├── tests/                      # 28 pytest tests
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx            # Scanner
│   │   │   ├── history/page.tsx    # Scan History
│   │   │   ├── benchmark/page.tsx  # ML Benchmarks
│   │   │   └── docs/page.tsx       # Documentation
│   │   ├── components/             # Navbar, RiskGauge, ResultCard, etc.
│   │   └── lib/                    # types.ts, api.ts
│   ├── package.json
│   └── tsconfig.json
└── supabase/
    └── migrations/                 # PostgreSQL schema
```

---

## 🛡️ Security

- **SSRF protection** blocks all internal network requests
- **Input sanitization** rejects `javascript:`, `file:`, `data:`, `ftp:` schemes and null bytes
- **URL length limits** (max 2048 chars)
- **Security headers** on every response (X-Frame-Options, X-Content-Type-Options, etc.)
- **No secrets in repo** — all credentials via `.env` (gitignored)

---

## 🧪 Running Tests

```bash
cd backend
python -m pytest tests -v
# Expected: 28 passed
```

---

## 📄 License

MIT
