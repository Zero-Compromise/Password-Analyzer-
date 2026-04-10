# PassGuard — Password Strength Analyzer

A full-stack password analysis tool with real-time strength scoring, breach detection via HaveIBeenPwned, and AI-powered improvement tips.

---

## 🏗️ Project Structure

```
passguard-app/
├── frontend/
│   ├── index.html          ← Dev 1: UI markup & layout
│   ├── style.css           ← Dev 1: All styles
│   └── app.js              ← Dev 2: Client-side logic
├── backend/
│   ├── server.py           ← Dev 3: FastAPI routes & CORS
│   ├── analyzer.py         ← Dev 4: Strength scoring engine
│   ├── breach_check.py     ← Dev 4: HaveIBeenPwned integration
│   └── requirements.txt    ← Dev 3: Python dependencies
├── docs/
│   └── API.md              ← Dev 3: API documentation
└── README.md               ← Team Lead: This file
```

---

## 👥 Team & Branch Assignments

| Contributor | Branch | Files to Commit |
|-------------|--------|-----------------|
| Team Lead | `main` | `README.md`, merge PRs |
| Dev 1 | `feature/frontend-ui` | `frontend/index.html`, `frontend/style.css` |
| Dev 2 | `feature/frontend-logic` | `frontend/app.js` |
| Dev 3 | `feature/backend-api` | `backend/server.py`, `backend/requirements.txt`, `docs/API.md` |
| Dev 4 | `feature/backend-security` | `backend/analyzer.py`, `backend/breach_check.py` |

---

## 🚀 Getting Started

### Clone the repo
```bash
git clone https://github.com/YOUR-ORG/passguard-app.git
cd passguard-app
```

### Each contributor: create your branch
```bash
git checkout -b feature/YOUR-BRANCH-NAME
```

### Run the backend
```bash
cd backend
pip install -r requirements.txt
uvicorn server:app --reload --port 8000
```

### Run the frontend
Open `frontend/index.html` in a browser, or serve it:
```bash
cd frontend
npx serve .
```

---

## 🔄 Git Workflow

```bash
# 1. Pull latest main before starting
git pull origin main

# 2. Work on your branch
git add .
git commit -m "feat: your description"
git push origin feature/YOUR-BRANCH-NAME

# 3. Open a Pull Request on GitHub → request review → merge to main
```

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| POST | `/analyze` | Full password analysis |

See `docs/API.md` for full request/response schemas.
