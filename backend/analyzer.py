# ====================================================
# PassGuard — analyzer.py
# Branch: feature/backend-security
# Contributor: Dev 4
# ====================================================

import re
import math


class PasswordAnalyzer:
    """
    Analyses password strength: score, entropy, crack time, tips.
    No passwords are stored or logged.
    """

    # Patterns that indicate a weak or predictable password
    COMMON_PATTERNS = [
        (re.compile(r'(.)\1{2,}'),                     "Avoid repeating characters (e.g. 'aaa')"),
        (re.compile(r'(012|123|234|345|456|567|678|789|890)', re.I), "Avoid sequential numbers"),
        (re.compile(r'(abc|bcd|cde|def|efg|fgh|ghi|hij)', re.I),     "Avoid sequential letters"),
        (re.compile(r'^(password|pass|admin|login|user|qwerty|letmein|welcome)', re.I), "Avoid common words"),
    ]

    # Rough estimate of pool sizes per character type
    POOL = {
        'lower':   26,
        'upper':   26,
        'digit':   10,
        'symbol':  32,
    }

    def analyze(self, pwd: str) -> dict:
        """Return full analysis dict for a given password string."""
        checks = self._run_checks(pwd)
        score  = self._calculate_score(pwd, checks)
        label  = self._score_to_label(score)
        pool   = self._pool_size(checks)
        entropy = self._entropy(pwd, pool)
        crack  = self._crack_time(entropy)

        return {
            "score":      score,
            "label":      label,
            "entropy":    round(entropy, 1),
            "crack_time": crack,
            "checks":     checks,
        }

    # ─── Internal helpers ────────────────────────────────────────────────────

    def _run_checks(self, pwd: str) -> dict:
        return {
            "has_lower":   bool(re.search(r'[a-z]', pwd)),
            "has_upper":   bool(re.search(r'[A-Z]', pwd)),
            "has_digit":   bool(re.search(r'\d', pwd)),
            "has_symbol":  bool(re.search(r'[^A-Za-z0-9]', pwd)),
            "length_ok":   len(pwd) >= 8,
            "length_great": len(pwd) >= 12,
            "length_excellent": len(pwd) >= 16,
            "no_common_pattern": not any(p.search(pwd) for p, _ in self.COMMON_PATTERNS),
        }

    def _calculate_score(self, pwd: str, checks: dict) -> int:
        """
        Weighted scoring out of 100.
        Each criterion contributes proportionally.
        """
        weights = {
            "length_ok":          10,
            "length_great":       15,
            "length_excellent":   10,
            "has_lower":          10,
            "has_upper":          15,
            "has_digit":          15,
            "has_symbol":         20,
            "no_common_pattern":   5,
        }
        raw = sum(w for k, w in weights.items() if checks.get(k))

        # Bonus for very long passwords
        bonus = min(10, max(0, (len(pwd) - 16) // 2))
        return min(100, raw + bonus)

    def _score_to_label(self, score: int) -> str:
        if score <= 30: return "Weak"
        if score <= 55: return "Fair"
        if score <= 80: return "Good"
        return "Strong"

    def _pool_size(self, checks: dict) -> int:
        return sum(
            self.POOL.get(k.replace("has_", ""), 0)
            for k in ["has_lower", "has_upper", "has_digit", "has_symbol"]
            if checks.get(k)
        )

    def _entropy(self, pwd: str, pool: int) -> float:
        if pool == 0 or len(pwd) == 0:
            return 0.0
        return len(pwd) * math.log2(pool)

    def _crack_time(self, entropy: float) -> str:
        """
        Estimate crack time assuming 10 billion guesses/sec (modern GPU cluster).
        """
        if entropy == 0:
            return "instant"
        guesses = 2 ** entropy
        seconds = guesses / 1e10

        if seconds < 1:          return "< 1 second"
        if seconds < 60:         return f"{int(seconds)} seconds"
        if seconds < 3600:       return f"{int(seconds / 60)} minutes"
        if seconds < 86400:      return f"{int(seconds / 3600)} hours"
        if seconds < 2_592_000:  return f"{int(seconds / 86400)} days"
        if seconds < 31_536_000: return f"{int(seconds / 2_592_000)} months"
        years = seconds / 31_536_000
        if years < 1_000:        return f"{int(years):,} years"
        if years < 1_000_000:    return f"{int(years/1000):,}k years"
        return "centuries+"

    def generate_tips(self, pwd: str, analysis: dict) -> list[str]:
        """Return a list of actionable improvement tips (max 4)."""
        tips = []
        checks = analysis["checks"]

        if not checks["has_upper"]:
            tips.append("Add uppercase letters (A–Z)")
        if not checks["has_digit"]:
            tips.append("Include at least one number")
        if not checks["has_symbol"]:
            tips.append("Add symbols like !@#$ for big entropy gains")
        if not checks["length_great"]:
            tips.append("Use 12+ characters for much better protection")
        elif not checks["length_excellent"]:
            tips.append("16+ characters makes your password near-uncrackable")
        if not checks["no_common_pattern"]:
            # Find which pattern triggered
            for pattern, msg in self.COMMON_PATTERNS:
                if pattern.search(pwd):
                    tips.append(msg)
                    break

        return tips[:4]
