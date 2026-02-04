# -*- coding: utf-8 -*-
"""
Temp Folder Manager Module

Provides intelligent temporary folder management with:
- Size-based cleanup (LRU eviction)
- Repository caching
- Automatic cleanup when size exceeded
- Statistics and monitoring
"""

import shutil
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from threading import Lock

from src.logger import logger


@dataclass
class RepoCache:
    """Cached repository metadata."""

    path: str
    size_bytes: int
    last_access: float
    repo_url: str = ""
    clone_time: float = 0.0


@dataclass
class TempFolderStats:
    """Statistics for temp folder management."""

    total_size_bytes: int = 0
    repo_count: int = 0
    cleanups_performed: int = 0
    bytes_cleaned: int = 0
    last_cleanup_time: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0


class TempFolderManager:
    """
    Manages temporary folder with LRU eviction and size limits.

    Features:
    - Automatic cleanup when size limit exceeded
    - LRU (Least Recently Used) eviction strategy
    - Repository caching to avoid re-cloning
    - Thread-safe operations
    - Statistics tracking

    Usage:
        manager = TempFolderManager(
            temp_folder='/app/temp',
            max_size_gb=10.0,
            max_repos=50
        )

        # Check if repo is cached
        if manager.is_cached(repo_url):
            path = manager.get_cached_path(repo_url)

        # Register new clone
        manager.register_repo(repo_path, repo_url)

        # Cleanup if needed
        manager.cleanup_if_needed()
    """

    # Files/folders to never delete
    PROTECTED_ITEMS = {"command_file", "list_to_scan.txt", ".gitkeep"}

    def __init__(self, temp_folder: str, max_size_gb: float = 10.0, max_repos: int = 50, cleanup_keep_newest: int = 20):
        """
        Initialize temp folder manager.

        Args:
            temp_folder: Path to temp directory
            max_size_gb: Maximum folder size in GB before cleanup
            max_repos: Maximum number of repos to keep
            cleanup_keep_newest: Number of newest repos to keep during cleanup
        """
        self.temp_folder = Path(temp_folder)
        self.max_size_bytes = int(max_size_gb * 1024 * 1024 * 1024)
        self.max_repos = max_repos
        self.cleanup_keep_newest = cleanup_keep_newest

        self._cache: Dict[str, RepoCache] = {}  # repo_url -> RepoCache
        self._path_to_url: Dict[str, str] = {}  # path -> repo_url
        self._lock = Lock()
        self._stats = TempFolderStats()

        # Ensure temp folder exists
        self.temp_folder.mkdir(parents=True, exist_ok=True)

        # Load existing repos into cache
        self._scan_existing_repos()

        logger.info(
            f"TempFolderManager initialized: max_size={max_size_gb}GB, "
            f"max_repos={max_repos}, current_size={self._stats.total_size_bytes / (1024**3):.2f}GB, "
            f"repos={self._stats.repo_count}"
        )

    def _scan_existing_repos(self):
        """Scan temp folder and populate cache with existing repos."""
        try:
            for item in self.temp_folder.iterdir():
                if item.name in self.PROTECTED_ITEMS:
                    continue
                if item.is_dir():
                    size = self._get_dir_size(item)
                    mtime = item.stat().st_mtime

                    # Try to determine repo URL from path
                    repo_url = self._extract_url_from_path(item)

                    cache_entry = RepoCache(path=str(item), size_bytes=size, last_access=mtime, repo_url=repo_url)

                    if repo_url:
                        self._cache[repo_url] = cache_entry
                    self._path_to_url[str(item)] = repo_url
                    self._stats.total_size_bytes += size
                    self._stats.repo_count += 1

        except Exception as e:
            logger.warning(f"Error scanning temp folder: {e}")

    def _extract_url_from_path(self, path: Path) -> str:
        """Try to extract repo URL from directory name."""
        # Directory name format is usually: owner_repo or similar
        name = path.name
        # Could be improved with a metadata file
        return f"https://github.com/{name.replace('_', '/')}" if "_" in name else ""

    @staticmethod
    def _get_dir_size(path: Path) -> int:
        """Calculate total size of directory in bytes."""
        total = 0
        try:
            for entry in path.rglob("*"):
                if entry.is_file():
                    try:
                        total += entry.stat().st_size
                    except (OSError, PermissionError):
                        pass
        except Exception:
            pass
        return total

    def is_cached(self, repo_url: str) -> bool:
        """Check if repository is in cache."""
        with self._lock:
            if repo_url in self._cache:
                cache_entry = self._cache[repo_url]
                # Verify path still exists
                if Path(cache_entry.path).exists():
                    self._stats.cache_hits += 1
                    return True
                else:
                    # Path no longer exists, remove from cache
                    del self._cache[repo_url]
            self._stats.cache_misses += 1
            return False

    def get_cached_path(self, repo_url: str) -> Optional[str]:
        """Get cached repository path and update access time."""
        with self._lock:
            if repo_url in self._cache:
                cache_entry = self._cache[repo_url]
                if Path(cache_entry.path).exists():
                    cache_entry.last_access = time.time()
                    # Touch directory to update mtime
                    try:
                        Path(cache_entry.path).touch()
                    except Exception:
                        pass
                    return cache_entry.path
                else:
                    del self._cache[repo_url]
            return None

    def register_repo(self, repo_path: str, repo_url: str, clone_time: float = 0.0):
        """
        Register a newly cloned repository.

        Args:
            repo_path: Path to cloned repository
            repo_url: Repository URL
            clone_time: Time taken to clone (seconds)
        """
        path = Path(repo_path)
        if not path.exists():
            return

        size = self._get_dir_size(path)

        with self._lock:
            cache_entry = RepoCache(
                path=str(path), size_bytes=size, last_access=time.time(), repo_url=repo_url, clone_time=clone_time
            )

            self._cache[repo_url] = cache_entry
            self._path_to_url[str(path)] = repo_url
            self._stats.total_size_bytes += size
            self._stats.repo_count += 1

            logger.debug(
                f"Registered repo: {repo_url}, size={size / (1024**2):.2f}MB, "
                f"total_size={self._stats.total_size_bytes / (1024**3):.2f}GB"
            )

    def unregister_repo(self, repo_path: str):
        """Remove repository from cache (called when manually deleting)."""
        with self._lock:
            repo_url = self._path_to_url.get(str(repo_path))
            if repo_url and repo_url in self._cache:
                self._stats.total_size_bytes -= self._cache[repo_url].size_bytes
                self._stats.repo_count -= 1
                del self._cache[repo_url]
            if str(repo_path) in self._path_to_url:
                del self._path_to_url[str(repo_path)]

    def should_cleanup(self) -> bool:
        """Check if cleanup is needed based on size or repo count."""
        return self._stats.total_size_bytes > self.max_size_bytes or self._stats.repo_count > self.max_repos

    def cleanup_if_needed(self, force: bool = False) -> Tuple[int, int]:
        """
        Perform cleanup if size limit exceeded.

        Args:
            force: Force cleanup even if under limit

        Returns:
            Tuple of (repos_removed, bytes_freed)
        """
        if not force and not self.should_cleanup():
            return 0, 0

        return self.cleanup_lru()

    def cleanup_lru(self) -> Tuple[int, int]:
        """
        Remove least recently used repos until under limits.

        Returns:
            Tuple of (repos_removed, bytes_freed)
        """
        repos_removed = 0
        bytes_freed = 0

        with self._lock:
            # Sort by last_access (oldest first)
            sorted_repos = sorted(self._cache.items(), key=lambda x: x[1].last_access)

            # Calculate how many to remove
            repos_to_remove = max(0, self._stats.repo_count - self.cleanup_keep_newest)

            # Also check if we need to free space
            target_size = self.max_size_bytes * 0.7  # Target 70% of max

            removed_urls = []

            for repo_url, cache_entry in sorted_repos:
                if repos_removed >= repos_to_remove and self._stats.total_size_bytes <= target_size:
                    break

                # Don't remove if it's one of the newest
                if repos_removed >= len(sorted_repos) - self.cleanup_keep_newest:
                    break

                try:
                    path = Path(cache_entry.path)
                    if path.exists():
                        shutil.rmtree(path)
                        bytes_freed += cache_entry.size_bytes
                        repos_removed += 1
                        self._stats.total_size_bytes -= cache_entry.size_bytes
                        self._stats.repo_count -= 1
                        removed_urls.append(repo_url)

                        logger.debug(
                            f"LRU cleanup: removed {repo_url}, " f"freed {cache_entry.size_bytes / (1024**2):.2f}MB"
                        )
                except Exception as e:
                    logger.warning(f"Failed to remove {cache_entry.path}: {e}")

            # Clean up cache entries
            for url in removed_urls:
                if url in self._cache:
                    path = self._cache[url].path
                    del self._cache[url]
                    if path in self._path_to_url:
                        del self._path_to_url[path]

            if repos_removed > 0:
                self._stats.cleanups_performed += 1
                self._stats.bytes_cleaned += bytes_freed
                self._stats.last_cleanup_time = time.time()

                logger.info(
                    f"LRU cleanup completed: removed {repos_removed} repos, "
                    f"freed {bytes_freed / (1024**3):.2f}GB, "
                    f"remaining: {self._stats.repo_count} repos, "
                    f"{self._stats.total_size_bytes / (1024**3):.2f}GB"
                )

        return repos_removed, bytes_freed

    def cleanup_all(self) -> Tuple[int, int]:
        """
        Remove all repos from temp folder (except protected items).

        Returns:
            Tuple of (repos_removed, bytes_freed)
        """
        repos_removed = 0
        bytes_freed = 0

        with self._lock:
            try:
                for item in self.temp_folder.iterdir():
                    if item.name in self.PROTECTED_ITEMS:
                        continue
                    if item.is_dir():
                        try:
                            size = self._get_dir_size(item)
                            shutil.rmtree(item)
                            bytes_freed += size
                            repos_removed += 1
                        except Exception as e:
                            logger.warning(f"Failed to remove {item}: {e}")
                    elif item.is_file():
                        try:
                            item.unlink()
                        except Exception:
                            pass

                # Clear cache
                self._cache.clear()
                self._path_to_url.clear()
                self._stats.total_size_bytes = 0
                self._stats.repo_count = 0
                self._stats.cleanups_performed += 1
                self._stats.bytes_cleaned += bytes_freed
                self._stats.last_cleanup_time = time.time()

                logger.info(f"Full cleanup: removed {repos_removed} repos, " f"freed {bytes_freed / (1024**3):.2f}GB")

            except Exception as e:
                logger.error(f"Error during full cleanup: {e}")

        return repos_removed, bytes_freed

    def get_stats(self) -> Dict:
        """Get current statistics."""
        return {
            "total_size_gb": self._stats.total_size_bytes / (1024**3),
            "total_size_bytes": self._stats.total_size_bytes,
            "max_size_gb": self.max_size_bytes / (1024**3),
            "repo_count": self._stats.repo_count,
            "max_repos": self.max_repos,
            "usage_percent": (self._stats.total_size_bytes / self.max_size_bytes * 100)
            if self.max_size_bytes > 0
            else 0,
            "cleanups_performed": self._stats.cleanups_performed,
            "total_bytes_cleaned": self._stats.bytes_cleaned,
            "cache_hits": self._stats.cache_hits,
            "cache_misses": self._stats.cache_misses,
            "cache_hit_rate": (
                self._stats.cache_hits / (self._stats.cache_hits + self._stats.cache_misses) * 100
                if (self._stats.cache_hits + self._stats.cache_misses) > 0
                else 0
            ),
            "last_cleanup": self._stats.last_cleanup_time,
        }

    def get_cached_repos(self) -> List[Dict]:
        """Get list of cached repositories with metadata."""
        with self._lock:
            return [
                {
                    "url": entry.repo_url,
                    "path": entry.path,
                    "size_mb": entry.size_bytes / (1024**2),
                    "last_access": entry.last_access,
                    "clone_time": entry.clone_time,
                }
                for entry in sorted(self._cache.values(), key=lambda x: x.last_access, reverse=True)
            ]


# Global instance (lazy initialization)
_temp_manager: Optional[TempFolderManager] = None
_temp_manager_lock = Lock()


def get_temp_manager() -> TempFolderManager:
    """Get or create global TempFolderManager instance."""
    global _temp_manager

    if _temp_manager is None:
        with _temp_manager_lock:
            if _temp_manager is None:
                from src import constants

                _temp_manager = TempFolderManager(
                    temp_folder=constants.TEMP_FOLDER,
                    max_size_gb=constants.MAX_TEMP_FOLDER_SIZE / (1024**3),
                    max_repos=50,
                    cleanup_keep_newest=20,
                )

    return _temp_manager


def check_temp_folder_size_smart() -> Tuple[int, int]:
    """
    Smart temp folder check with LRU cleanup.

    Replacement for the old check_temp_folder_size() function.

    Returns:
        Tuple of (repos_removed, bytes_freed)
    """
    manager = get_temp_manager()
    return manager.cleanup_if_needed()


# Backward compatibility alias
check_and_cleanup_temp = check_temp_folder_size_smart


__all__ = [
    "TempFolderManager",
    "TempFolderStats",
    "RepoCache",
    "get_temp_manager",
    "check_temp_folder_size_smart",
    "check_and_cleanup_temp",
]
