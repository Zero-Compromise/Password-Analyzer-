# ====================================================
# PassGuard — breach_check.py
# Branch: feature/backend-security
# Contributor: Dev 4
# ====================================================
#
# Uses HaveIBeenPwned k-anonymity API:
# https://haveibeenpwned.com/API/v3#PwnedPasswords
#
# HOW IT WORKS (k-anonymity model):
#   1. SHA-1 hash the password client-side (here: server-side before sending)
#   2. Send only the FIRST 5 characters of the hash to HIBP
#   3. HIBP returns all hashes with that prefix
#   4. We check locally whether our full hash is in the list
#   ⇒ The real password is NEVER sent to any third-party service

import hashlib
import httpx
import logging

logger = logging.getLogger("passguard.breach")

HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_TIMEOUT = 5.0  # seconds


class BreachChecker:
    """
    Checks a password against the HaveIBeenPwned Pwned Passwords database
    using the k-anonymity model. The raw password is never transmitted.
    """

    async def check(self, password: str) -> tuple[bool, int]:
        """
        Returns:
            (is_breached: bool, breach_count: int)
        """
        sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            hashes = await self._fetch_range(prefix)
            return self._search(hashes, suffix)
        except Exception as exc:
            logger.warning(f"HIBP check failed: {exc} — defaulting to not breached")
            # Fail open: don't block the user if HIBP is unreachable
            return False, 0

    # ─── Private helpers ────────────────────────────────────────────────────

    async def _fetch_range(self, prefix: str) -> str:
        """
        Fetches the list of SHA-1 hash suffixes from HIBP for a given 5-char prefix.
        Raises httpx.HTTPError on network failure.
        """
        async with httpx.AsyncClient(timeout=HIBP_TIMEOUT) as client:
            response = await client.get(
                HIBP_URL.format(prefix=prefix),
                headers={"Add-Padding": "true"},   # padding prevents traffic analysis
            )
            response.raise_for_status()
            return response.text

    def _search(self, hashes_text: str, target_suffix: str) -> tuple[bool, int]:
        """
        Parses the HIBP response (each line: SUFFIX:COUNT) and looks for target_suffix.
        """
        for line in hashes_text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            hash_suffix, count_str = parts
            if hash_suffix.strip().upper() == target_suffix.upper():
                count = int(count_str.strip()) if count_str.strip().isdigit() else 0
                logger.info(f"Password found in breach database ({count:,} occurrences)")
                return True, count

        return False, 0
