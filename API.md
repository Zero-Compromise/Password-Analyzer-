# PassGuard API Documentation

Base URL: `http://localhost:8000` (development)

---

## GET /health

Health check endpoint. Polled by the frontend every 5 seconds.

**Response:**
```json
{ "status": "ok", "version": "2.0.0" }
```

---

## POST /analyze

Performs full password analysis.

**Request body:**
```json
{ "password": "MyP@ssw0rd!" }
```

| Field    | Type   | Required | Max length |
|----------|--------|----------|------------|
| password | string | ✓        | 256 chars  |

**Response:**
```json
{
  "score":        85,
  "label":        "Strong",
  "breached":     false,
  "breach_count": 0,
  "tips":         ["Use 16+ characters for near-uncrackable protection"],
  "entropy":      72.3,
  "crack_time":   "14,532 years"
}
```

| Field        | Type    | Description                                      |
|--------------|---------|--------------------------------------------------|
| score        | integer | 0–100 strength score                             |
| label        | string  | Weak / Fair / Good / Strong                      |
| breached     | boolean | Found in HaveIBeenPwned database                 |
| breach_count | integer | Number of times seen in data breaches            |
| tips         | array   | Up to 4 actionable improvement suggestions       |
| entropy      | float   | Estimated bits of entropy                        |
| crack_time   | string  | Human-readable estimated time to brute-force     |

**Error responses:**
| Code | Meaning                             |
|------|-------------------------------------|
| 422  | Validation error (e.g. too long)    |
| 500  | Internal server error               |

---

## Security Notes

- Passwords are **never logged** or stored
- Breach check uses **k-anonymity** — only first 5 chars of SHA-1 hash sent to HaveIBeenPwned
- CORS is open in dev; restrict `allow_origins` in production
