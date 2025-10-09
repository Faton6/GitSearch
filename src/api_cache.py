"""
Cache Manager for GitHub API Responses.

Reduces redundant API calls by caching frequently accessed data:
- Repository statistics
- User information
- Search results (with TTL)
- Rate limit status

Features:
- Time-based expiration (TTL)
- LRU eviction when cache is full
- Thread-safe operations
- Persistent cache to disk (optional)
- Statistics tracking
"""

import time
import json
import threading
import pickle
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from collections import OrderedDict

from src.logger import logger


@dataclass
class CacheEntry:
    """Single cache entry with metadata."""
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl: float = 3600.0  # 1 hour default
    
    @property
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        return (time.time() - self.created_at) > self.ttl
    
    @property
    def age(self) -> float:
        """Get age of entry in seconds."""
        return time.time() - self.created_at
    
    def access(self) -> Any:
        """Access entry and update metadata."""
        self.last_accessed = time.time()
        self.access_count += 1
        return self.value


@dataclass
class CacheStats:
    """Statistics for cache usage."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    total_size: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0


class APICache:
    """
    LRU cache with TTL for API responses.
    
    Features:
    - Time-based expiration
    - Size-based LRU eviction
    - Thread-safe operations
    - Optional disk persistence
    
    Attributes:
        max_size: Maximum number of entries (default: 1000)
        default_ttl: Default time-to-live in seconds (default: 3600)
        cleanup_interval: Seconds between cleanup runs (default: 300)
    """
    
    def __init__(self, 
                 max_size: int = 1000,
                 default_ttl: float = 3600.0,
                 cleanup_interval: float = 300.0,
                 persist_path: Optional[Path] = None):
        """
        Initialize cache.
        
        Args:
            max_size: Maximum cache entries
            default_ttl: Default entry lifetime (seconds)
            cleanup_interval: Time between cleanup runs (seconds)
            persist_path: Path to persist cache to disk
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        self.persist_path = persist_path
        
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = CacheStats()
        
        self._should_stop = False
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="CacheCleanup"
        )
        self._cleanup_thread.start()
        
        # Load persisted cache if exists
        if persist_path:
            self._load_from_disk()
        
        logger.info(
            f"API Cache initialized: max_size={max_size}, "
            f"default_ttl={default_ttl}s, persist={persist_path is not None}"
        )
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            if key not in self._cache:
                self._stats.misses += 1
                return None
            
            entry = self._cache[key]
            
            # Check expiration
            if entry.is_expired:
                self._remove_entry(key, reason="expired")
                self._stats.misses += 1
                self._stats.expirations += 1
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            
            self._stats.hits += 1
            return entry.access()
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None):
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        with self._lock:
            # Check if we need to evict
            if key not in self._cache and len(self._cache) >= self.max_size:
                self._evict_lru()
            
            # Create or update entry
            if key in self._cache:
                # Update existing
                self._cache[key].value = value
                self._cache[key].created_at = time.time()
                self._cache[key].ttl = ttl or self.default_ttl
                self._cache.move_to_end(key)
            else:
                # Create new
                entry = CacheEntry(
                    key=key,
                    value=value,
                    ttl=ttl or self.default_ttl
                )
                self._cache[key] = entry
            
            self._stats.total_size = len(self._cache)
    
    def delete(self, key: str) -> bool:
        """
        Delete entry from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            if key in self._cache:
                self._remove_entry(key, reason="manual delete")
                return True
            return False
    
    def clear(self):
        """Clear all entries from cache."""
        with self._lock:
            self._cache.clear()
            self._stats.total_size = 0
            logger.info("Cache cleared")
    
    def _remove_entry(self, key: str, reason: str = ""):
        """Remove entry and log."""
        if key in self._cache:
            entry = self._cache.pop(key)
            self._stats.total_size = len(self._cache)
            logger.debug(f"Cache entry removed: {key[:50]} ({reason})")
    
    def _evict_lru(self):
        """Evict least recently used entry."""
        if not self._cache:
            return
        
        # First item is least recently used (in OrderedDict)
        lru_key = next(iter(self._cache))
        self._remove_entry(lru_key, reason="LRU eviction")
        self._stats.evictions += 1
    
    def _cleanup_expired(self):
        """Remove all expired entries."""
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired
            ]
            
            for key in expired_keys:
                self._remove_entry(key, reason="cleanup expired")
                self._stats.expirations += 1
            
            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def _cleanup_loop(self):
        """Background cleanup thread."""
        while not self._should_stop:
            try:
                time.sleep(self.cleanup_interval)
                self._cleanup_expired()
                
                # Persist to disk if configured
                if self.persist_path:
                    self._save_to_disk()
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
    
    def _save_to_disk(self):
        """Save cache to disk."""
        if not self.persist_path:
            return
        
        try:
            with self._lock:
                # Only save non-expired entries
                valid_entries = {
                    k: v for k, v in self._cache.items()
                    if not v.is_expired
                }
                
                self.persist_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(self.persist_path, 'wb') as f:
                    pickle.dump(valid_entries, f)
                
                logger.debug(f"Cache persisted: {len(valid_entries)} entries")
        except Exception as e:
            logger.error(f"Failed to save cache to disk: {e}")
    
    def _load_from_disk(self):
        """Load cache from disk."""
        if not self.persist_path or not self.persist_path.exists():
            return
        
        try:
            with open(self.persist_path, 'rb') as f:
                loaded_cache = pickle.load(f)
            
            with self._lock:
                # Only load non-expired entries
                for key, entry in loaded_cache.items():
                    if not entry.is_expired:
                        self._cache[key] = entry
                
                self._stats.total_size = len(self._cache)
            
            logger.info(f"Cache loaded from disk: {len(self._cache)} entries")
        except Exception as e:
            logger.error(f"Failed to load cache from disk: {e}")
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                expirations=self._stats.expirations,
                total_size=self._stats.total_size
            )
    
    def shutdown(self):
        """Shutdown cache and cleanup thread."""
        logger.info("Shutting down cache")
        self._should_stop = True
        
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)
        
        # Final save to disk
        if self.persist_path:
            self._save_to_disk()
        
        stats = self.get_stats()
        logger.info(
            f"Cache statistics:\n"
            f"  Total entries: {stats.total_size}\n"
            f"  Hits: {stats.hits}\n"
            f"  Misses: {stats.misses}\n"
            f"  Hit rate: {stats.hit_rate:.1f}%\n"
            f"  Evictions: {stats.evictions}\n"
            f"  Expirations: {stats.expirations}"
        )
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
        return False


class GitHubAPICache:
    """
    Specialized cache for GitHub API responses.
    
    Provides separate caches for different data types with appropriate TTLs:
    - Repository stats: 1 hour
    - User info: 24 hours
    - Search results: 5 minutes
    - Rate limit status: 10 seconds
    """
    
    def __init__(self, base_path: Optional[Path] = None):
        """
        Initialize GitHub API cache.
        
        Args:
            base_path: Base directory for persistent caches
        """
        self.base_path = base_path
        
        # Repository statistics cache (1 hour TTL)
        self.repo_stats = APICache(
            max_size=5000,
            default_ttl=3600.0,
            persist_path=base_path / "repo_stats.cache" if base_path else None
        )
        
        # User information cache (24 hours TTL)
        self.user_info = APICache(
            max_size=10000,
            default_ttl=86400.0,
            persist_path=base_path / "user_info.cache" if base_path else None
        )
        
        # Search results cache (5 minutes TTL, volatile)
        self.search_results = APICache(
            max_size=1000,
            default_ttl=300.0,
            persist_path=None  # Don't persist search results
        )
        
        # Rate limit status cache (10 seconds TTL, volatile)
        self.rate_limits = APICache(
            max_size=100,
            default_ttl=10.0,
            persist_path=None
        )
        
        logger.info("GitHub API cache initialized")
    
    def get_repo_stats(self, repo_full_name: str) -> Optional[Dict]:
        """Get cached repository statistics."""
        return self.repo_stats.get(f"repo_stats:{repo_full_name}")
    
    def set_repo_stats(self, repo_full_name: str, stats: Dict):
        """Cache repository statistics."""
        self.repo_stats.set(f"repo_stats:{repo_full_name}", stats)
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """Get cached user information."""
        return self.user_info.get(f"user_info:{username}")
    
    def set_user_info(self, username: str, info: Dict):
        """Cache user information."""
        self.user_info.set(f"user_info:{username}", info)
    
    def get_search_results(self, query: str, search_type: str) -> Optional[list]:
        """Get cached search results."""
        return self.search_results.get(f"search:{search_type}:{query}")
    
    def set_search_results(self, query: str, search_type: str, results: list):
        """Cache search results."""
        self.search_results.set(f"search:{search_type}:{query}", results)
    
    def get_rate_limit(self, token: str) -> Optional[Dict]:
        """Get cached rate limit status."""
        token_hash = token[:8] if token else "anonymous"
        return self.rate_limits.get(f"rate_limit:{token_hash}")
    
    def set_rate_limit(self, token: str, status: Dict):
        """Cache rate limit status."""
        token_hash = token[:8] if token else "anonymous"
        self.rate_limits.set(f"rate_limit:{token_hash}", status)
    
    def get_all_stats(self) -> Dict[str, CacheStats]:
        """Get statistics for all caches."""
        return {
            'repo_stats': self.repo_stats.get_stats(),
            'user_info': self.user_info.get_stats(),
            'search_results': self.search_results.get_stats(),
            'rate_limits': self.rate_limits.get_stats()
        }
    
    def shutdown(self):
        """Shutdown all caches."""
        logger.info("Shutting down GitHub API cache")
        self.repo_stats.shutdown()
        self.user_info.shutdown()
        self.search_results.shutdown()
        self.rate_limits.shutdown()


# Global cache instance
_api_cache: Optional[GitHubAPICache] = None


def get_api_cache(base_path: Optional[Path] = None) -> GitHubAPICache:
    """
    Get or create global API cache.
    
    Args:
        base_path: Base directory for cache files
        
    Returns:
        GitHubAPICache instance
    """
    global _api_cache
    if _api_cache is None:
        _api_cache = GitHubAPICache(base_path=base_path)
    return _api_cache


def shutdown_cache():
    """Shutdown global API cache."""
    global _api_cache
    if _api_cache is not None:
        _api_cache.shutdown()
        _api_cache = None
