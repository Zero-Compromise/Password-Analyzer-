# ====================================================
# PassGuard — server.py
# Branch: feature/backend-api
# Contributor: Dev 3
# ====================================================
#
# Run: uvicorn server:app --reload --port 8000

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import time
import logging
from analyzer import PasswordAnalyzer
from breach_check import BreachChecker

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("passguard")

# ─── App Setup ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="PassGuard API",
    description="Password strength analysis and breach detection service",
    version="2.0.0",
)

# Allow frontend origin — tighten this in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # TODO: restrict to your domain in production
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ─── Singletons ──────────────────────────────────────────────────────────────

analyzer = PasswordAnalyzer()
breach_checker = BreachChecker()

# ─── Request/Response Models ──────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    password: str

    @validator('password')
    def validate_password(cls, v):
        if len(v) > 256:
            raise ValueError("Password too long (max 256 chars)")
        return v

class AnalyzeResponse(BaseModel):
    score:       int
    label:       str
    breached:    bool
    breach_count: int
    tips:        list[str]
    entropy:     float
    crack_time:  str

# ─── Middleware: Request timing ──────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 2)
    logger.info(f"{request.method} {request.url.path} → {response.status_code} ({duration}ms)")
    return response

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check — frontend polls this every 5 seconds."""
    return {"status": "ok", "version": "2.0.0"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest):
    """
    Full password analysis:
    - Strength score (0–100)
    - Breach database check via HaveIBeenPwned k-anonymity API
    - Entropy calculation
    - Estimated crack time
    - Improvement tips
    """
    pwd = body.password

    # Strength analysis (from analyzer.py — Dev 4)
    analysis = analyzer.analyze(pwd)

    # Breach check (from breach_check.py — Dev 4)
    # NOTE: sends only first 5 chars of SHA-1 hash — password is never transmitted
    is_breached, breach_count = await breach_checker.check(pwd)

    # Build tips list
    tips = analyzer.generate_tips(pwd, analysis)

    return {
        "score":        analysis["score"],
        "label":        analysis["label"],
        "breached":     is_breached,
        "breach_count": breach_count,
        "tips":         tips,
        "entropy":      analysis["entropy"],
        "crack_time":   analysis["crack_time"],
    }


@app.exception_handler(422)
async def validation_error_handler(request: Request, exc):
    return JSONResponse(
        status_code=422,
        content={"error": "Invalid request", "detail": str(exc)},
    )
