"""
GitHub API Rate Limiter
Manages rate limits for multiple GitHub tokens with automatic quota tracking.

This module provides intelligent rate limiting for GitHub API requests:
- Tracks quotas for multiple tokens
- Automatic token rotation
- Handles rate limit errors gracefully
- Enforces Search API specific limits (30 requests/minute)

Usage:
    from src.github_rate_limiter import initialize_rate_limiter, get_rate_limiter
    
    # Initialize with tokens
    initialize_rate_limiter(('token1', 'token2', 'token3'))
    
    # Get rate limiter instance
    rate_limiter = get_rate_limiter()
    
    # Before making a search request
    rate_limiter.wait_for_search_rate_limit()
    token = rate_limiter.get_best_token()
    
    # After receiving response
    rate_limiter.update_quota_from_headers(token, response.headers)

Author: GitSearch Team  
Date: 2025-10-03
"""

import time
import threading
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from datetime import datetime
from src.logger import logger


@dataclass
class TokenQuota:
    """Stores quota information for a single GitHub token."""
    token: str
    remaining: int = 5000
    limit: int = 5000
    reset_time: float = 0.0
    last_check: float = field(default_factory=time.time)
    consecutive_errors: int = 0
    is_blocked: bool = False
    
    @property
    def usage_percentage(self) -> float:
        """Calculate percentage of quota used."""
        if self.limit == 0:
            return 100.0
        return ((self.limit - self.remaining) / self.limit) * 100
    
    @property
    def seconds_until_reset(self) -> float:
        """Calculate seconds until quota reset."""
        return max(0, self.reset_time - time.time())
    
    def is_available(self, min_remaining: int = 100) -> bool:
        """
        Check if token has enough quota remaining.
        
        Args:
            min_remaining: Minimum quota required
            
        Returns:
            True if token is available and has sufficient quota
        """
        if self.is_blocked:
            # Check if block should be lifted
            if time.time() >= self.reset_time:
                self.is_blocked = False
                self.consecutive_errors = 0
                logger.info(f"Token unblocked: {self.token[:8]}...")
                return True
            return False
        return self.remaining >= min_remaining


class GitHubRateLimiter:
    """
    Manages GitHub API rate limits for multiple tokens.
    
    Features:
    - Automatic quota tracking from response headers
    - Smart token rotation based on remaining quotas
    - Backoff strategies for rate limit errors
    - Health monitoring for all tokens
    - Search API specific rate limiting (30 requests/minute)
    
    Attributes:
        SEARCH_LIMIT_PER_MINUTE: GitHub Search API limit (30 requests/minute)
        REST_LIMIT_PER_HOUR: GitHub REST API limit (5000 requests/hour for authenticated)
        MIN_REMAINING_QUOTA: Reserve quota for critical requests
    """
    
    # GitHub API rate limits (from official documentation)
    SEARCH_LIMIT_PER_MINUTE = 30  # Special limit for Search API
    REST_LIMIT_PER_HOUR = 5000  # For authenticated requests
    MIN_REMAINING_QUOTA = 100  # Reserve quota for critical requests
    
    def __init__(self, tokens: Tuple[str, ...]):
        """
        Initialize rate limiter with GitHub tokens.
        
        Args:
            tokens: Tuple of GitHub personal access tokens
        """
        # Initialize token quotas (filter out invalid tokens)
        self.tokens: Dict[str, TokenQuota] = {
            token: TokenQuota(token=token) 
            for token in tokens if token and token != '-'
        }
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Search API rate limiting
        self._last_search_time = 0.0
        self._search_requests_this_minute = 0
        self._minute_start = time.time()
        
        # Statistics
        self._total_requests = 0
        self._rate_limit_hits = 0
        
        if not self.tokens:
            logger.warning("GitHubRateLimiter initialized without valid tokens!")
        else:
            logger.info(f"GitHubRateLimiter initialized with {len(self.tokens)} tokens")
    
    def get_best_token(self) -> Optional[str]:
        """
        Select the best available token based on remaining quota.
        
        Selection strategy:
        1. Filter out blocked tokens
        2. Filter tokens with insufficient quota
        3. Select token with highest remaining quota
        
        Returns:
            Token string or None if no tokens available
        """
        with self._lock:
            if not self.tokens:
                logger.error("No tokens configured!")
                return None
            
            # Filter available tokens
            available_tokens = [
                quota for quota in self.tokens.values() 
                if quota.is_available(self.MIN_REMAINING_QUOTA)
            ]
            
            if not available_tokens:
                # All tokens exhausted, find one with earliest reset
                earliest_reset = min(
                    self.tokens.values(), 
                    key=lambda q: q.reset_time
                )
                wait_time = earliest_reset.seconds_until_reset
                
                logger.warning(
                    f"All tokens exhausted. Next reset in {wait_time:.0f} seconds. "
                    f"Total tokens: {len(self.tokens)}"
                )
                
                # Return the token that resets earliest (caller should wait)
                return earliest_reset.token
            
            # Select token with highest remaining quota
            best_token = max(available_tokens, key=lambda q: q.remaining)
            
            logger.debug(
                f"Selected token {best_token.token[:8]}... "
                f"(remaining: {best_token.remaining}/{best_token.limit}, "
                f"usage: {best_token.usage_percentage:.1f}%)"
            )
            
            return best_token.token
    
    def update_quota_from_headers(self, token: str, headers: Dict[str, str]):
        """
        Update token quota from GitHub API response headers.
        
        Headers processed:
        - X-RateLimit-Limit: Maximum quota per hour
        - X-RateLimit-Remaining: Remaining quota
        - X-RateLimit-Reset: Unix timestamp when quota resets
        - X-RateLimit-Used: Number of requests used
        
        Args:
            token: GitHub token used for the request
            headers: Response headers from GitHub API
        """
        with self._lock:
            if token not in self.tokens:
                logger.warning(f"Attempting to update quota for unknown token: {token[:8]}...")
                return
            
            quota = self.tokens[token]
            
            try:
                # Parse rate limit headers
                updated = False
                
                if 'X-RateLimit-Limit' in headers:
                    quota.limit = int(headers['X-RateLimit-Limit'])
                    updated = True
                    
                if 'X-RateLimit-Remaining' in headers:
                    quota.remaining = int(headers['X-RateLimit-Remaining'])
                    updated = True
                    
                if 'X-RateLimit-Reset' in headers:
                    quota.reset_time = float(headers['X-RateLimit-Reset'])
                    updated = True
                
                if updated:
                    quota.last_check = time.time()
                    quota.consecutive_errors = 0  # Reset error counter on successful update
                    
                    # Log warning if quota is low
                    if quota.remaining < self.MIN_REMAINING_QUOTA:
                        logger.warning(
                            f"Token {token[:8]}... quota low: "
                            f"{quota.remaining}/{quota.limit} "
                            f"(resets in {quota.seconds_until_reset:.0f}s)"
                        )
                    
                    # Log info for very low quota
                    if quota.remaining < 50:
                        logger.error(
                            f"Token {token[:8]}... quota critical: "
                            f"{quota.remaining}/{quota.limit} "
                            f"(resets at {datetime.fromtimestamp(quota.reset_time).strftime('%H:%M:%S')})"
                        )
                
            except (ValueError, KeyError) as e:
                logger.error(f"Error parsing rate limit headers: {e}")
            except Exception as e:
                logger.error(f"Unexpected error updating quota: {e}", exc_info=True)
    
    def handle_rate_limit_error(self, token: str, retry_after: Optional[int] = None):
        """
        Handle rate limit exceeded error for a token.
        
        Actions taken:
        1. Increment consecutive error counter
        2. Update reset time if Retry-After header present
        3. Block token if too many consecutive errors
        4. Log detailed error information
        
        Args:
            token: GitHub token that hit rate limit
            retry_after: Retry-After header value (seconds)
        """
        with self._lock:
            if token not in self.tokens:
                return
            
            quota = self.tokens[token]
            quota.consecutive_errors += 1
            self._rate_limit_hits += 1
            
            # Update reset time if provided
            if retry_after:
                quota.reset_time = time.time() + retry_after
                logger.warning(
                    f"Token {token[:8]}... rate limited. "
                    f"Retry after {retry_after}s (error #{quota.consecutive_errors})"
                )
            else:
                logger.warning(
                    f"Token {token[:8]}... rate limited (error #{quota.consecutive_errors})"
                )
            
            # Block token temporarily if repeated errors
            if quota.consecutive_errors >= 3:
                quota.is_blocked = True
                quota.remaining = 0  # Mark as exhausted
                logger.error(
                    f"Token {token[:8]}... BLOCKED due to repeated rate limit errors. "
                    f"Will retry after {quota.seconds_until_reset:.0f}s"
                )
    
    def wait_for_search_rate_limit(self):
        """
        Enforce Search API rate limit (30 requests/minute).
        
        GitHub Search API has a special limit of 30 requests per minute,
        separate from the general REST API limit.
        
        This method ensures we don't exceed this limit by:
        1. Tracking requests per minute
        2. Waiting if limit is reached
        3. Resetting counter each minute
        """
        current_time = time.time()
        
        with self._lock:
            # Reset counter if we're in a new minute
            if current_time - self._minute_start >= 60:
                self._minute_start = current_time
                self._search_requests_this_minute = 0
                logger.debug("Search API rate limit counter reset")
            
            # Check if we've hit the per-minute limit
            if self._search_requests_this_minute >= self.SEARCH_LIMIT_PER_MINUTE:
                time_to_wait = 60 - (current_time - self._minute_start)
                
                if time_to_wait > 0:
                    logger.info(
                        f"Search API rate limit reached "
                        f"({self.SEARCH_LIMIT_PER_MINUTE} requests/minute). "
                        f"Waiting {time_to_wait:.1f}s for reset..."
                    )
                    
                    # Release lock while sleeping
                    self._lock.release()
                    try:
                        time.sleep(time_to_wait)
                    finally:
                        self._lock.acquire()
                    
                    # Reset counters after waiting
                    self._minute_start = time.time()
                    self._search_requests_this_minute = 0
            
            # Increment counter
            self._search_requests_this_minute += 1
            self._total_requests += 1
            self._last_search_time = time.time()
    
    def wait_for_token_reset(self, token: str, timeout: int = 3600):
        """
        Wait for a specific token's quota to reset.
        
        Args:
            token: Token to wait for
            timeout: Maximum time to wait (seconds)
        """
        if token not in self.tokens:
            return
        
        quota = self.tokens[token]
        wait_time = min(quota.seconds_until_reset, timeout)
        
        if wait_time > 0:
            logger.info(
                f"Waiting {wait_time:.0f}s for token {token[:8]}... quota reset"
            )
            time.sleep(wait_time)
            
            # Unblock token after reset
            with self._lock:
                quota.is_blocked = False
                quota.consecutive_errors = 0
    
    def get_status_report(self) -> Dict[str, any]:
        """
        Generate comprehensive status report for all tokens.
        
        Returns:
            Dictionary with detailed status information:
            - total_tokens: Number of configured tokens
            - available_tokens: Tokens with sufficient quota
            - blocked_tokens: Tokens currently blocked
            - total_remaining_quota: Sum of all remaining quotas
            - total_requests: Total requests made this session
            - rate_limit_hits: Number of rate limit errors
            - tokens: Detailed info for each token
        """
        with self._lock:
            available_count = sum(
                1 for q in self.tokens.values() 
                if q.is_available()
            )
            blocked_count = sum(
                1 for q in self.tokens.values() 
                if q.is_blocked
            )
            total_remaining = sum(
                q.remaining for q in self.tokens.values()
            )
            
            return {
                'total_tokens': len(self.tokens),
                'available_tokens': available_count,
                'blocked_tokens': blocked_count,
                'total_remaining_quota': total_remaining,
                'total_requests': self._total_requests,
                'rate_limit_hits': self._rate_limit_hits,
                'search_requests_this_minute': self._search_requests_this_minute,
                'tokens': [
                    {
                        'token': f"{q.token[:8]}...",
                        'remaining': q.remaining,
                        'limit': q.limit,
                        'usage': f"{q.usage_percentage:.1f}%",
                        'reset_in': f"{q.seconds_until_reset:.0f}s",
                        'reset_at': datetime.fromtimestamp(q.reset_time).strftime('%Y-%m-%d %H:%M:%S'),
                        'is_blocked': q.is_blocked,
                        'consecutive_errors': q.consecutive_errors,
                        'last_check': datetime.fromtimestamp(q.last_check).strftime('%Y-%m-%d %H:%M:%S')
                    }
                    for q in self.tokens.values()
                ]
            }
    
    def print_status(self):
        """Print formatted status report to logger."""
        status = self.get_status_report()
        
        logger.info("=" * 80)
        logger.info("GitHub Rate Limiter Status")
        logger.info("=" * 80)
        logger.info(f"Total tokens: {status['total_tokens']}")
        logger.info(f"Available tokens: {status['available_tokens']}")
        logger.info(f"Blocked tokens: {status['blocked_tokens']}")
        logger.info(f"Total remaining quota: {status['total_remaining_quota']}")
        logger.info(f"Total requests (session): {status['total_requests']}")
        logger.info(f"Rate limit hits: {status['rate_limit_hits']}")
        logger.info(f"Search requests this minute: {status['search_requests_this_minute']}/{self.SEARCH_LIMIT_PER_MINUTE}")
        logger.info("-" * 80)
        
        for token_info in status['tokens']:
            status_icon = "✓" if not token_info['is_blocked'] else "✗"
            logger.info(
                f"{status_icon} Token {token_info['token']}: "
                f"{token_info['remaining']}/{token_info['limit']} "
                f"({token_info['usage']}) - "
                f"resets in {token_info['reset_in']}"
            )
        
        logger.info("=" * 80)


# Global rate limiter instance
_rate_limiter: Optional[GitHubRateLimiter] = None


def initialize_rate_limiter(tokens: Tuple[str, ...]):
    """
    Initialize the global rate limiter instance.
    
    Args:
        tokens: Tuple of GitHub personal access tokens
    """
    global _rate_limiter
    _rate_limiter = GitHubRateLimiter(tokens)
    logger.info("Global rate limiter initialized")


def get_rate_limiter() -> GitHubRateLimiter:
    """
    Get the global rate limiter instance.
    
    Returns:
        GitHubRateLimiter instance
        
    Raises:
        RuntimeError: If rate limiter not initialized
    """
    if _rate_limiter is None:
        raise RuntimeError(
            "Rate limiter not initialized. "
            "Call initialize_rate_limiter() first."
        )
    return _rate_limiter


def is_initialized() -> bool:
    """Check if rate limiter is initialized."""
    return _rate_limiter is not None
