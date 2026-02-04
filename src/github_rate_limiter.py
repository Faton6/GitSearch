"""
GitHub API Rate Limiter
Manages rate limits for multiple GitHub tokens with automatic quota tracking.

This module provides intelligent rate limiting for GitHub API requests:
- Tracks quotas for multiple tokens with SEPARATE limits for different resource types
- Automatic token rotation
- Handles rate limit errors gracefully
- Enforces Search API specific limits

GitHub Rate Limits (authenticated):
- Core REST API: 5000 requests/hour
- Search API (repos, issues, commits, etc.): 30 requests/minute
- Search Code API: 10 requests/minute
- GraphQL API: 5000 points/hour

Usage:
    from src.github_rate_limiter import initialize_rate_limiter, get_rate_limiter

    # Initialize with tokens
    initialize_rate_limiter(('token1', 'token2', 'token3'))

    # Get rate limiter instance
    rate_limiter = get_rate_limiter()

    # Before making a code search request
    rate_limiter.wait_for_search_rate_limit(is_code_search=True)
    token = rate_limiter.get_best_token(resource='search_code')

    # After receiving response - specify resource type!
    rate_limiter.update_quota_from_headers(token, response.headers, resource='search_code')

Author: GitSearch Team
Date: 2025-10-03
"""

import time
import threading
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from src.logger import logger


# GitHub API Resource Types and their limits
RESOURCE_LIMITS = {
    "core": {"limit": 5000, "window": 3600},  # 5000/hour
    "search": {"limit": 30, "window": 60},  # 30/minute (repos, issues, commits, users, topics)
    "search_code": {"limit": 10, "window": 60},  # 10/minute (code search only)
    "graphql": {"limit": 5000, "window": 3600},  # 5000 points/hour
}


@dataclass
class ResourceQuota:
    """Stores quota information for a specific API resource type."""

    resource: str
    remaining: int = field(default=0)
    limit: int = field(default=0)
    reset_time: float = 0.0
    last_check: float = field(default_factory=time.time)

    def __post_init__(self):
        """Initialize with default limits from RESOURCE_LIMITS."""
        if self.limit == 0 and self.resource in RESOURCE_LIMITS:
            self.limit = RESOURCE_LIMITS[self.resource]["limit"]
            self.remaining = self.limit

    @property
    def seconds_until_reset(self) -> float:
        """Calculate seconds until quota reset."""
        return max(0, self.reset_time - time.time())

    def is_available(self, min_remaining: int = 1) -> bool:
        """Check if resource has enough quota remaining."""
        # If reset time passed, quota should be available
        if self.reset_time > 0 and time.time() >= self.reset_time:
            return True
        return self.remaining >= min_remaining


@dataclass
class TokenQuota:
    """Stores quota information for a single GitHub token with multiple resources."""

    token: str
    # Separate quotas for each resource type
    resources: Dict[str, ResourceQuota] = field(default_factory=dict)
    consecutive_errors: int = 0
    is_blocked: bool = False
    block_until: float = 0.0
    last_check: float = field(default_factory=time.time)

    def __post_init__(self):
        """Initialize resource quotas."""
        for resource in RESOURCE_LIMITS:
            if resource not in self.resources:
                self.resources[resource] = ResourceQuota(resource=resource)

    def get_resource_quota(self, resource: str) -> ResourceQuota:
        """Get quota for specific resource, creating if needed."""
        if resource not in self.resources:
            self.resources[resource] = ResourceQuota(resource=resource)
        return self.resources[resource]

    @property
    def core_remaining(self) -> int:
        """Get remaining core API quota."""
        return self.resources.get("core", ResourceQuota(resource="core")).remaining

    @property
    def search_remaining(self) -> int:
        """Get remaining search API quota."""
        return self.resources.get("search", ResourceQuota(resource="search")).remaining

    @property
    def search_code_remaining(self) -> int:
        """Get remaining search code API quota."""
        return self.resources.get("search_code", ResourceQuota(resource="search_code")).remaining

    def is_available_for(self, resource: str = "core", min_remaining: int = 1) -> bool:
        """
        Check if token is available for specific resource type.

        Args:
            resource: Resource type ('core', 'search', 'search_code', 'graphql')
            min_remaining: Minimum quota required
        """
        if self.is_blocked:
            if time.time() >= self.block_until:
                self.is_blocked = False
                self.consecutive_errors = 0
                logger.info(f"Token unblocked: {self.token[:12]}...")
            else:
                return False

        quota = self.get_resource_quota(resource)
        return quota.is_available(min_remaining)


class GitHubRateLimiter:
    """
    Manages GitHub API rate limits for multiple tokens with resource-specific tracking.

    Features:
    - Separate quota tracking for core, search, search_code, graphql resources
    - Automatic token rotation based on remaining quotas
    - Backoff strategies for rate limit errors
    - Per-minute tracking for search APIs

    GitHub Rate Limits (authenticated):
    - Core: 5000 requests/hour
    - Search: 30 requests/minute
    - Search Code: 10 requests/minute
    """

    # Reserve quotas for different resources
    MIN_REMAINING = {
        "core": 100,  # Reserve 100 for core API
        "search": 2,  # Reserve 2 for search
        "search_code": 1,  # Reserve 1 for code search
        "graphql": 100,  # Reserve 100 for graphql
    }

    def __init__(self, tokens: Tuple[str, ...]):
        """
        Initialize rate limiter with GitHub tokens.

        Args:
            tokens: Tuple of GitHub personal access tokens
        """
        # Initialize token quotas (filter out invalid tokens)
        self.tokens: Dict[str, TokenQuota] = {
            token: TokenQuota(token=token) for token in tokens if token and token.strip() and token != "-"
        }

        # Thread safety
        self._lock = threading.Lock()

        # Per-minute tracking for search APIs (separate from header-based tracking)
        self._search_requests_this_minute = 0
        self._search_code_requests_this_minute = 0
        self._minute_start = time.time()

        # Statistics
        self._total_requests = 0
        self._rate_limit_hits = 0

        if not self.tokens:
            logger.warning("GitHubRateLimiter initialized without valid tokens!")
        else:
            logger.info(f"GitHubRateLimiter initialized with {len(self.tokens)} tokens")

    def get_best_token(self, resource: str = "core") -> Optional[str]:
        """
        Select the best available token for a specific resource type.

        Args:
            resource: Resource type ('core', 'search', 'search_code', 'graphql')

        Returns:
            Token string or None if no tokens available
        """
        min_remaining = self.MIN_REMAINING.get(resource, 1)

        with self._lock:
            if not self.tokens:
                logger.error("No tokens configured!")
                return None

            # Filter available tokens for this resource
            available_tokens = [
                quota for quota in self.tokens.values() if quota.is_available_for(resource, min_remaining)
            ]

            if not available_tokens:
                # All tokens exhausted for this resource
                # Find token with earliest reset for this resource
                def get_reset_time(tq: TokenQuota) -> float:
                    rq = tq.get_resource_quota(resource)
                    return rq.reset_time if rq.reset_time > 0 else float("inf")

                earliest_reset = min(self.tokens.values(), key=get_reset_time)
                rq = earliest_reset.get_resource_quota(resource)
                wait_time = rq.seconds_until_reset

                logger.warning(
                    f"All tokens exhausted for '{resource}'. "
                    f"Next reset in {wait_time:.0f}s. "
                    f"Total tokens: {len(self.tokens)}"
                )

                return earliest_reset.token

            # Select token with highest remaining quota for this resource
            def get_remaining(tq: TokenQuota) -> int:
                return tq.get_resource_quota(resource).remaining

            best_token = max(available_tokens, key=get_remaining)

            logger.debug(
                f"Selected token {best_token.token[:12]}... for '{resource}' "
                f"(remaining: {get_remaining(best_token)})"
            )

            return best_token.token

    def wait_if_rate_limited(self, resource: str = "core", max_wait: int = 3600) -> bool:
        """
        Check if all tokens are rate limited and wait until reset if needed.

        Args:
            resource: Resource type to check
            max_wait: Maximum seconds to wait (default 1 hour)

        Returns:
            True if ready to proceed, False if should not wait
        """
        min_remaining = self.MIN_REMAINING.get(resource, 1)

        with self._lock:
            if not self.tokens:
                return False

            # Check if any token is available
            available_tokens = [
                quota for quota in self.tokens.values() if quota.is_available_for(resource, min_remaining)
            ]

            if available_tokens:
                return True  # At least one token available

            # All tokens exhausted - find earliest reset
            def get_reset_time(tq: TokenQuota) -> float:
                rq = tq.get_resource_quota(resource)
                return rq.reset_time if rq.reset_time > 0 else float("inf")

            earliest_reset = min(self.tokens.values(), key=get_reset_time)
            rq = earliest_reset.get_resource_quota(resource)
            wait_time = rq.seconds_until_reset

            if wait_time > max_wait:
                logger.error(
                    f"Rate limit wait time ({wait_time:.0f}s) exceeds max ({max_wait}s). "
                    f"Consider adding more tokens or increasing max_wait."
                )
                return False

            if wait_time > 0:
                logger.info(
                    f"All {len(self.tokens)} tokens rate limited for '{resource}'. "
                    f"Waiting {wait_time:.0f}s until reset at {time.strftime('%H:%M:%S', time.localtime(rq.reset_time))}"
                )
                time.sleep(wait_time + 1)  # +1 second buffer
                logger.info(f"Rate limit reset complete for '{resource}'. Resuming...")

            return True

    def _detect_resource_from_headers(self, headers: Dict[str, str]) -> str:
        """
        Detect resource type from rate limit headers.

        GitHub returns X-RateLimit-Resource header (if available) or we can
        infer from the limit value.
        """
        # Check for explicit resource header (newer GitHub API)
        resource = headers.get("X-RateLimit-Resource", "").lower()
        if resource in RESOURCE_LIMITS:
            return resource

        # Also check lowercase version
        resource = headers.get("x-ratelimit-resource", "").lower()
        if resource in RESOURCE_LIMITS:
            return resource

        # Infer from limit value
        try:
            limit = int(headers.get("X-RateLimit-Limit", headers.get("x-ratelimit-limit", 0)))
            if limit == 10:
                return "search_code"
            elif limit == 30:
                return "search"
            elif limit >= 5000:
                return "core"
        except (ValueError, TypeError):
            pass

        return "core"  # Default to core

    def update_quota_from_headers(self, token: str, headers: Dict[str, str], resource: Optional[str] = None):
        """
        Update token quota from GitHub API response headers.

        IMPORTANT: Specify the resource type to avoid mixing quotas!

        Headers processed:
        - X-RateLimit-Limit: Maximum quota
        - X-RateLimit-Remaining: Remaining quota
        - X-RateLimit-Reset: Unix timestamp when quota resets
        - X-RateLimit-Resource: Resource type (if available)

        Args:
            token: GitHub token used for the request
            headers: Response headers from GitHub API
            resource: Resource type ('core', 'search', 'search_code').
                     If None, will try to detect from headers.
        """
        try:
            # Support both cases for headers
            new_limit = None
            new_remaining = None
            new_reset = None

            for key in headers:
                key_lower = key.lower()
                if key_lower == "x-ratelimit-limit":
                    new_limit = int(headers[key])
                elif key_lower == "x-ratelimit-remaining":
                    new_remaining = int(headers[key])
                elif key_lower == "x-ratelimit-reset":
                    new_reset = float(headers[key])

            if new_limit is None and new_remaining is None and new_reset is None:
                return

            # Detect or use specified resource
            if resource is None:
                resource = self._detect_resource_from_headers(headers)

        except (ValueError, KeyError) as e:
            logger.error(f"Error parsing rate limit headers: {e}")
            return

        with self._lock:
            if token not in self.tokens:
                logger.warning(f"Unknown token: {token[:12]}...")
                return

            token_quota = self.tokens[token]
            resource_quota = token_quota.get_resource_quota(resource)

            if new_limit is not None:
                resource_quota.limit = new_limit
            if new_remaining is not None:
                resource_quota.remaining = new_remaining
            if new_reset is not None:
                resource_quota.reset_time = new_reset

            resource_quota.last_check = time.time()
            token_quota.last_check = time.time()
            token_quota.consecutive_errors = 0

        # Log warnings outside lock
        if new_remaining is not None:
            min_reserve = self.MIN_REMAINING.get(resource, 1)
            if new_remaining < min_reserve:
                reset_in = max(0, new_reset - time.time()) if new_reset else 0
                logger.warning(
                    f"Token {token[:12]}... '{resource}' quota low: "
                    f"{new_remaining}/{new_limit or '?'} "
                    f"(resets in {reset_in:.0f}s)"
                )

    def handle_rate_limit_error(self, token: str, retry_after: Optional[int] = None, resource: str = "core"):
        """
        Handle rate limit exceeded error for a token.

        Args:
            token: GitHub token that hit rate limit
            retry_after: Retry-After header value (seconds)
            resource: Resource type that was rate limited
        """
        with self._lock:
            if token not in self.tokens:
                return

            token_quota = self.tokens[token]
            token_quota.consecutive_errors += 1
            self._rate_limit_hits += 1

            # Update resource quota
            resource_quota = token_quota.get_resource_quota(resource)
            resource_quota.remaining = 0

            if retry_after:
                resource_quota.reset_time = time.time() + retry_after
                logger.warning(f"Token {token[:12]}... '{resource}' rate limited. " f"Retry after {retry_after}s")
            else:
                # Default wait times based on resource
                default_wait = RESOURCE_LIMITS.get(resource, {}).get("window", 60)
                resource_quota.reset_time = time.time() + default_wait
                logger.warning(f"Token {token[:12]}... '{resource}' rate limited. " f"Default wait: {default_wait}s")

            # Block token if too many errors
            if token_quota.consecutive_errors >= 3:
                token_quota.is_blocked = True
                token_quota.block_until = resource_quota.reset_time
                logger.error(f"Token {token[:12]}... BLOCKED due to repeated errors")

    def wait_for_search_rate_limit(self, is_code_search: bool = False):
        """
        Enforce Search API rate limit.

        Args:
            is_code_search: True for code search (10/min), False for other search (30/min)
        """
        current_time = time.time()
        limit = 10 if is_code_search else 30
        counter_attr = "_search_code_requests_this_minute" if is_code_search else "_search_requests_this_minute"

        with self._lock:
            # Reset counter if we're in a new minute
            if current_time - self._minute_start >= 60:
                self._minute_start = current_time
                self._search_requests_this_minute = 0
                self._search_code_requests_this_minute = 0
                logger.debug("Search rate limit counters reset")

            counter = getattr(self, counter_attr)

            if counter >= limit:
                time_to_wait = 60 - (current_time - self._minute_start)

                if time_to_wait > 0:
                    search_type = "code search" if is_code_search else "search"
                    logger.info(
                        f"{search_type.title()} rate limit reached ({limit}/min). " f"Waiting {time_to_wait:.1f}s..."
                    )

                    self._lock.release()
                    try:
                        time.sleep(time_to_wait + 0.5)  # Small buffer
                    finally:
                        self._lock.acquire()

                    self._minute_start = time.time()
                    self._search_requests_this_minute = 0
                    self._search_code_requests_this_minute = 0

            # Increment appropriate counter
            setattr(self, counter_attr, getattr(self, counter_attr) + 1)
            self._total_requests += 1

    def get_status_report(self) -> Dict:
        """Generate comprehensive status report."""
        with self._lock:
            return {
                "total_tokens": len(self.tokens),
                "total_requests": self._total_requests,
                "rate_limit_hits": self._rate_limit_hits,
                "search_this_minute": self._search_requests_this_minute,
                "search_code_this_minute": self._search_code_requests_this_minute,
                "tokens": [
                    {
                        "token": f"{tq.token[:12]}...",
                        "is_blocked": tq.is_blocked,
                        "consecutive_errors": tq.consecutive_errors,
                        "resources": {
                            name: {
                                "remaining": rq.remaining,
                                "limit": rq.limit,
                                "reset_in": f"{rq.seconds_until_reset:.0f}s",
                            }
                            for name, rq in tq.resources.items()
                        },
                    }
                    for tq in self.tokens.values()
                ],
            }

    def print_status(self):
        """Print formatted status report to logger."""
        status = self.get_status_report()

        logger.info("=" * 80)
        logger.info("GitHub Rate Limiter Status")
        logger.info(
            f"Tokens: {status['total_tokens']} | "
            f"Requests: {status['total_requests']} | "
            f"Rate limit hits: {status['rate_limit_hits']}"
        )
        logger.info(
            f"Search this minute: {status['search_this_minute']}/30 | "
            f"Code search: {status['search_code_this_minute']}/10"
        )

        for token_info in status["tokens"]:
            blocked = " [BLOCKED]" if token_info["is_blocked"] else ""
            logger.info(f"\nToken {token_info['token']}{blocked}")
            for res_name, res_info in token_info["resources"].items():
                logger.info(
                    f"  {res_name}: {res_info['remaining']}/{res_info['limit']} " f"(reset in {res_info['reset_in']})"
                )
        logger.info("=" * 80)


# Global rate limiter instance
_rate_limiter: Optional[GitHubRateLimiter] = None


def initialize_rate_limiter(tokens: Tuple[str, ...]):
    """Initialize the global rate limiter instance."""
    global _rate_limiter
    _rate_limiter = GitHubRateLimiter(tokens)
    logger.info("Global rate limiter initialized")


def get_rate_limiter() -> GitHubRateLimiter:
    """Get the global rate limiter instance."""
    if _rate_limiter is None:
        raise RuntimeError("Rate limiter not initialized. Call initialize_rate_limiter() first.")
    return _rate_limiter


def is_initialized() -> bool:
    """Check if rate limiter is initialized."""
    return _rate_limiter is not None
