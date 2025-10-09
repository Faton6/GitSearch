"""
Adaptive Threading Manager for GitHub API Requests.

Automatically adjusts thread pool size based on available API quotas
to maximize throughput without hitting rate limits.

Features:
- Dynamic worker adjustment based on token quotas
- Automatic scaling when quotas are low
- Prevents aggressive threading when rate limited
- Monitors and logs thread pool statistics
"""

import threading
import time
from typing import Optional, Dict, List
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from src.logger import logger
from src import constants


@dataclass
class ThreadPoolStats:
    """Statistics for thread pool usage."""
    current_workers: int
    total_tasks_submitted: int = 0
    total_tasks_completed: int = 0
    total_wait_time: float = 0.0
    adjustments_made: int = 0
    last_adjustment_time: float = 0.0


class AdaptiveThreadPoolManager:
    """
    Manages ThreadPoolExecutor with dynamic worker adjustment.
    
    Adjusts worker count based on:
    - Available GitHub API quotas
    - Current rate limit status
    - Number of blocked tokens
    - Error rates
    
    Attributes:
        MIN_WORKERS: Minimum number of workers (default: 1)
        MAX_WORKERS: Maximum number of workers (default: 10)
        ADJUSTMENT_INTERVAL: Seconds between adjustments (default: 30)
    """
    
    MIN_WORKERS = 1
    MAX_WORKERS = 10
    ADJUSTMENT_INTERVAL = 30  # seconds
    
    def __init__(self, 
                 initial_workers: int = 5,
                 task_type: str = "scan",
                 min_workers: Optional[int] = None,
                 max_workers: Optional[int] = None):
        """
        Initialize adaptive thread pool.
        
        Args:
            initial_workers: Starting number of workers
            task_type: Type of tasks (for logging)
            min_workers: Override MIN_WORKERS
            max_workers: Override MAX_WORKERS
        """
        self.task_type = task_type
        self.MIN_WORKERS = min_workers or self.MIN_WORKERS
        self.MAX_WORKERS = max_workers or self.MAX_WORKERS
        
        self.current_workers = max(self.MIN_WORKERS, min(initial_workers, self.MAX_WORKERS))
        self.executor = ThreadPoolExecutor(max_workers=self.current_workers)
        
        self.stats = ThreadPoolStats(current_workers=self.current_workers)
        self.lock = threading.Lock()
        self.should_stop = False
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_and_adjust,
            daemon=True,
            name=f"AdaptiveThreadMonitor-{task_type}"
        )
        self.monitor_thread.start()
        
        logger.info(
            f"Adaptive thread pool '{task_type}' started with {self.current_workers} workers "
            f"(min={self.MIN_WORKERS}, max={self.MAX_WORKERS})"
        )
    
    def _get_quota_info(self) -> Dict[str, any]:
        """Get current quota information from rate limiter."""
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            
            if not is_initialized():
                return {
                    'available': True,
                    'total_remaining': 5000,
                    'avg_remaining_pct': 100.0,
                    'blocked_tokens': 0,
                    'total_tokens': len(constants.token_tuple) if hasattr(constants, 'token_tuple') else 0
                }
            
            rate_limiter = get_rate_limiter()
            status = rate_limiter.get_all_tokens_status()
            
            total_remaining = sum(s['remaining'] for s in status)
            avg_remaining_pct = sum(
                ((s['limit'] - s['remaining']) / s['limit'] * 100) if s['limit'] > 0 else 100
                for s in status
            ) / len(status) if status else 0
            
            blocked_tokens = sum(1 for s in status if s['is_blocked'])
            
            return {
                'available': total_remaining > 100,
                'total_remaining': total_remaining,
                'avg_remaining_pct': avg_remaining_pct,
                'blocked_tokens': blocked_tokens,
                'total_tokens': len(status)
            }
        except Exception as e:
            logger.debug(f"Could not get quota info: {e}")
            return {
                'available': True,
                'total_remaining': 5000,
                'avg_remaining_pct': 50.0,
                'blocked_tokens': 0,
                'total_tokens': 0
            }
    
    def _calculate_optimal_workers(self) -> int:
        """
        Calculate optimal number of workers based on current quotas.
        
        Strategy:
        - High quotas (>80% available): Use MAX_WORKERS
        - Medium quotas (40-80% available): Scale proportionally
        - Low quotas (<40% available): Use MIN_WORKERS
        - If tokens blocked: Reduce by 1 per blocked token
        """
        quota_info = self._get_quota_info()
        
        if not quota_info['available']:
            return self.MIN_WORKERS
        
        avg_remaining_pct = quota_info['avg_remaining_pct']
        blocked_tokens = quota_info['blocked_tokens']
        total_tokens = quota_info['total_tokens']
        
        # Calculate base workers from quota
        if avg_remaining_pct < 20:  # < 20% quota used = >80% available
            base_workers = self.MAX_WORKERS
        elif avg_remaining_pct < 60:  # 20-60% quota used
            # Scale between MIN and MAX
            ratio = (60 - avg_remaining_pct) / 40  # 0 to 1
            base_workers = int(self.MIN_WORKERS + ratio * (self.MAX_WORKERS - self.MIN_WORKERS))
        else:  # > 60% quota used
            base_workers = self.MIN_WORKERS
        
        # Reduce for blocked tokens
        if blocked_tokens > 0 and total_tokens > 0:
            blocked_ratio = blocked_tokens / total_tokens
            reduction = int(base_workers * blocked_ratio)
            base_workers = max(self.MIN_WORKERS, base_workers - reduction)
        
        return base_workers
    
    def _adjust_workers(self, new_worker_count: int):
        """
        Adjust thread pool worker count.
        
        Args:
            new_worker_count: Desired number of workers
        """
        if new_worker_count == self.current_workers:
            return
        
        with self.lock:
            old_count = self.current_workers
            self.current_workers = new_worker_count
            
            # Shutdown old executor
            self.executor.shutdown(wait=False)
            
            # Create new executor with adjusted workers
            self.executor = ThreadPoolExecutor(max_workers=self.current_workers)
            
            self.stats.adjustments_made += 1
            self.stats.last_adjustment_time = time.time()
            self.stats.current_workers = self.current_workers
            
            logger.info(
                f"Adjusted '{self.task_type}' thread pool: "
                f"{old_count} -> {self.current_workers} workers"
            )
    
    def _monitor_and_adjust(self):
        """Background thread that monitors and adjusts worker count."""
        while not self.should_stop:
            try:
                time.sleep(self.ADJUSTMENT_INTERVAL)
                
                if self.should_stop:
                    break
                
                optimal_workers = self._calculate_optimal_workers()
                
                if optimal_workers != self.current_workers:
                    quota_info = self._get_quota_info()
                    logger.debug(
                        f"Quota status: {quota_info['total_remaining']} remaining, "
                        f"{quota_info['avg_remaining_pct']:.1f}% used, "
                        f"{quota_info['blocked_tokens']} blocked"
                    )
                    self._adjust_workers(optimal_workers)
                
            except Exception as e:
                logger.error(f"Error in adaptive thread monitor: {e}")
    
    def submit(self, fn, *args, **kwargs):
        """
        Submit task to thread pool.
        
        Args:
            fn: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Future object
        """
        with self.lock:
            self.stats.total_tasks_submitted += 1
            future = self.executor.submit(fn, *args, **kwargs)
            
            # Add callback to track completion
            def on_done(f):
                with self.lock:
                    self.stats.total_tasks_completed += 1
            
            future.add_done_callback(on_done)
            return future
    
    def shutdown(self, wait: bool = True):
        """
        Shutdown thread pool.
        
        Args:
            wait: Wait for pending tasks to complete
        """
        logger.info(f"Shutting down adaptive thread pool '{self.task_type}'")
        self.should_stop = True
        
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
        
        self.executor.shutdown(wait=wait)
        
        logger.info(
            f"Thread pool '{self.task_type}' statistics:\n"
            f"  Total tasks: {self.stats.total_tasks_submitted}\n"
            f"  Completed: {self.stats.total_tasks_completed}\n"
            f"  Adjustments made: {self.stats.adjustments_made}\n"
            f"  Final workers: {self.stats.current_workers}"
        )
    
    def get_stats(self) -> ThreadPoolStats:
        """Get current thread pool statistics."""
        with self.lock:
            return ThreadPoolStats(
                current_workers=self.stats.current_workers,
                total_tasks_submitted=self.stats.total_tasks_submitted,
                total_tasks_completed=self.stats.total_tasks_completed,
                total_wait_time=self.stats.total_wait_time,
                adjustments_made=self.stats.adjustments_made,
                last_adjustment_time=self.stats.last_adjustment_time
            )
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown(wait=True)
        return False


# Global adaptive thread pools
_scan_pool: Optional[AdaptiveThreadPoolManager] = None
_clone_pool: Optional[AdaptiveThreadPoolManager] = None


def get_scan_pool(initial_workers: int = 5) -> AdaptiveThreadPoolManager:
    """
    Get or create adaptive scan thread pool.
    
    Args:
        initial_workers: Initial worker count (if creating new pool)
        
    Returns:
        AdaptiveThreadPoolManager instance
    """
    global _scan_pool
    if _scan_pool is None:
        _scan_pool = AdaptiveThreadPoolManager(
            initial_workers=initial_workers,
            task_type="scan",
            min_workers=1,
            max_workers=10
        )
    return _scan_pool


def get_clone_pool(initial_workers: int = 1) -> AdaptiveThreadPoolManager:
    """
    Get or create adaptive clone thread pool.
    
    Args:
        initial_workers: Initial worker count (if creating new pool)
        
    Returns:
        AdaptiveThreadPoolManager instance
    """
    global _clone_pool
    if _clone_pool is None:
        _clone_pool = AdaptiveThreadPoolManager(
            initial_workers=initial_workers,
            task_type="clone",
            min_workers=1,
            max_workers=3  # Cloning is I/O heavy, keep lower
        )
    return _clone_pool


def shutdown_all_pools(wait: bool = True):
    """Shutdown all adaptive thread pools."""
    global _scan_pool, _clone_pool
    
    if _scan_pool is not None:
        _scan_pool.shutdown(wait=wait)
        _scan_pool = None
    
    if _clone_pool is not None:
        _clone_pool.shutdown(wait=wait)
        _clone_pool = None
