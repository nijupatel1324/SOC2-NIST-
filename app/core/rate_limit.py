import time
from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import Request, HTTPException, status
from app.core.config import settings
from app.core.logging import log_security_event


class InMemoryRateLimiter:
    """
    Sliding-window in-memory rate limiter for sensitive endpoints (e.g. login).
    Tracks timestamps of requests per client key.
    """
    def __init__(self, requests_per_minute: int = 5):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60
        self.records: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(self, key: str, client_ip: str = "unknown") -> None:
        """
        Validates whether key has exceeded the allowed rate limit.
        Cleans expired timestamps older than window_seconds.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune timestamps older than 60 seconds
        self.records[key] = [t for t in self.records[key] if t > cutoff]

        if len(self.records[key]) >= self.requests_per_minute:
            log_security_event(
                event_type="RATE_LIMIT_EXCEEDED",
                status="BLOCKED",
                client_ip=client_ip,
                resource=f"RateLimitKey:{key}",
                details={"window_seconds": self.window_seconds, "attempts": len(self.records[key])},
                severity="HIGH"
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Rate limit is {self.requests_per_minute} attempts per minute."
            )

        self.records[key].append(now)

    def reset(self, key: Optional[str] = None) -> None:
        """Resets rate limit counter (useful for tests)."""
        if key:
            self.records.pop(key, None)
        else:
            self.records.clear()


login_rate_limiter = InMemoryRateLimiter(
    requests_per_minute=settings.RATE_LIMIT_LOGIN_PER_MINUTE
)
