"""
Asynchronous AI Analysis Worker

This module provides a background worker pool for AI-powered leak analysis.
AI analysis runs in parallel with main scanning operations, improving throughput.

Features:
- Non-blocking AI analysis queue
- Configurable worker pool size
- Priority-based processing
- Graceful shutdown handling
- Result callbacks for completed analyses

Usage:
    from src.ai_worker import AIWorkerPool, get_ai_worker_pool
    
    # Initialize worker pool (usually at startup)
    pool = get_ai_worker_pool()
    
    # Submit leak for AI analysis (non-blocking)
    pool.submit_analysis(leak_obj, callback=on_analysis_complete)
    
    # Shutdown gracefully
    pool.shutdown()

Author: GitSearch Team
Date: 2025-11-26
"""

import threading
import queue
import time
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from src.logger import logger
from src import constants


@dataclass(order=True)
class AITask:
    """Task for AI analysis with priority support."""
    priority: int
    leak_obj: Any = field(compare=False)
    callback: Optional[Callable] = field(default=None, compare=False)
    submitted_at: float = field(default_factory=time.time, compare=False)
    
    # Priority levels
    HIGH = 0      # High severity leaks, corporate emails found
    NORMAL = 1    # Standard analysis
    LOW = 2       # Background/batch analysis


class AIWorkerPool:
    """
    Background worker pool for asynchronous AI leak analysis.
    
    This allows the main scanning process to continue while AI
    analysis happens in parallel, significantly improving throughput.
    
    Attributes:
        max_workers: Maximum number of concurrent AI analysis workers
        queue_size: Maximum number of pending tasks
        timeout: Timeout for AI analysis per leak (seconds)
    """
    
    def __init__(
        self,
        max_workers: int = 2,
        queue_size: int = 100,
        timeout: int = 60
    ):
        """
        Initialize AI worker pool.
        
        Args:
            max_workers: Number of parallel AI analysis threads
            queue_size: Maximum pending tasks in queue
            timeout: Timeout per analysis in seconds
        """
        self.max_workers = max_workers
        self.queue_size = queue_size
        self.timeout = timeout
        
        # Task queue with priority support
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=queue_size)
        
        # Worker threads
        self._workers: list[threading.Thread] = []
        self._shutdown_event = threading.Event()
        self._started = False
        
        # Statistics
        self._stats = {
            'submitted': 0,
            'completed': 0,
            'failed': 0,
            'timeout': 0,
            'queue_full_drops': 0,
        }
        self._stats_lock = threading.Lock()
        
        # Start workers
        self._start_workers()
        
        logger.info(f"AIWorkerPool initialized with {max_workers} workers")
    
    def _start_workers(self):
        """Start worker threads."""
        if self._started:
            return
        
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"AIWorker-{i}",
                daemon=True
            )
            worker.start()
            self._workers.append(worker)
        
        self._started = True
    
    def _worker_loop(self):
        """Main loop for worker threads."""
        while not self._shutdown_event.is_set():
            try:
                # Get task with timeout to allow shutdown check
                try:
                    task: AITask = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process task
                try:
                    self._process_task(task)
                except Exception as e:
                    logger.error(f"AI worker error processing task: {e}")
                    with self._stats_lock:
                        self._stats['failed'] += 1
                finally:
                    self._queue.task_done()
                    
            except Exception as e:
                logger.error(f"AI worker loop error: {e}")
    
    def _process_task(self, task: AITask):
        """Process a single AI analysis task."""
        leak_obj = task.leak_obj
        
        try:
            if not constants.AI_ANALYSIS_ENABLED:
                logger.debug("AI analysis disabled, skipping")
                return
            
            # Check if already analyzed
            if hasattr(leak_obj, 'ai_analysis') and leak_obj.ai_analysis:
                logger.debug(f"AI analysis already done for {getattr(leak_obj, 'repo_name', 'unknown')}")
                return
            
            repo_name = getattr(leak_obj, 'repo_name', 'unknown')
            logger.info(f"[AIWorker] Starting analysis for {repo_name}")
            
            start_time = time.time()
            
            # Run AI analysis with timeout protection
            if hasattr(leak_obj, 'run_ai_analysis_sync'):
                leak_obj.run_ai_analysis_sync(force=False)
            elif hasattr(leak_obj, '_create_ai_obj'):
                leak_obj._create_ai_obj()
                if hasattr(leak_obj, 'ai_obj') and leak_obj.ai_obj:
                    leak_obj.ai_analysis = leak_obj.ai_obj.analyze_leak_comprehensive()
            
            elapsed = time.time() - start_time
            logger.info(f"[AIWorker] Completed analysis for {repo_name} in {elapsed:.2f}s")
            
            with self._stats_lock:
                self._stats['completed'] += 1
            
            # Execute callback if provided
            if task.callback:
                try:
                    task.callback(leak_obj, leak_obj.ai_analysis if hasattr(leak_obj, 'ai_analysis') else None)
                except Exception as e:
                    logger.error(f"AI callback error: {e}")
                    
        except TimeoutError:
            logger.warning(f"AI analysis timeout for {getattr(leak_obj, 'repo_name', 'unknown')}")
            with self._stats_lock:
                self._stats['timeout'] += 1
                
        except Exception as e:
            logger.error(f"AI analysis failed for {getattr(leak_obj, 'repo_name', 'unknown')}: {e}")
            with self._stats_lock:
                self._stats['failed'] += 1
    
    def submit_analysis(
        self,
        leak_obj: Any,
        callback: Optional[Callable] = None,
        priority: int = AITask.NORMAL
    ) -> bool:
        """
        Submit a leak object for AI analysis.
        
        This is non-blocking - the analysis will happen in the background.
        
        Args:
            leak_obj: LeakObj instance to analyze
            callback: Optional callback function(leak_obj, ai_analysis) called when done
            priority: Task priority (AITask.HIGH, NORMAL, LOW)
            
        Returns:
            True if submitted successfully, False if queue is full
        """
        if not constants.AI_ANALYSIS_ENABLED:
            return False
        
        if self._shutdown_event.is_set():
            logger.warning("AI worker pool is shutting down, rejecting task")
            return False
        
        task = AITask(
            priority=priority,
            leak_obj=leak_obj,
            callback=callback
        )
        
        try:
            self._queue.put_nowait(task)
            with self._stats_lock:
                self._stats['submitted'] += 1
            
            repo_name = getattr(leak_obj, 'repo_name', 'unknown')
            logger.debug(f"[AIWorker] Queued analysis for {repo_name} (priority={priority})")
            return True
            
        except queue.Full:
            logger.warning("AI analysis queue full, dropping task")
            with self._stats_lock:
                self._stats['queue_full_drops'] += 1
            return False
    
    def submit_high_priority(self, leak_obj: Any, callback: Optional[Callable] = None) -> bool:
        """Submit high-priority analysis (e.g., corporate email found)."""
        return self.submit_analysis(leak_obj, callback, priority=AITask.HIGH)
    
    def get_queue_size(self) -> int:
        """Get current queue size."""
        return self._queue.qsize()
    
    def get_stats(self) -> Dict[str, int]:
        """Get worker pool statistics."""
        with self._stats_lock:
            return dict(self._stats)
    
    def wait_completion(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for all queued tasks to complete.
        
        Args:
            timeout: Maximum time to wait (None = wait forever)
            
        Returns:
            True if all tasks completed, False if timeout
        """
        try:
            self._queue.join()
            return True
        except Exception:
            return False
    
    def shutdown(self, wait: bool = True, timeout: float = 30.0):
        """
        Shutdown the worker pool.
        
        Args:
            wait: Whether to wait for pending tasks to complete
            timeout: Maximum time to wait for pending tasks
        """
        logger.info("Shutting down AI worker pool...")
        
        if wait:
            # Wait for queue to empty (with timeout)
            start = time.time()
            while not self._queue.empty() and (time.time() - start) < timeout:
                time.sleep(0.5)
        
        # Signal workers to stop
        self._shutdown_event.set()
        
        # Wait for workers to finish
        for worker in self._workers:
            worker.join(timeout=5.0)
        
        stats = self.get_stats()
        logger.info(f"AI worker pool shutdown complete. Stats: {stats}")


# Global worker pool instance
_ai_worker_pool: Optional[AIWorkerPool] = None
_pool_lock = threading.Lock()


def get_ai_worker_pool() -> AIWorkerPool:
    """
    Get or create the global AI worker pool.
    
    Returns:
        AIWorkerPool instance
    """
    global _ai_worker_pool
    
    if _ai_worker_pool is None:
        with _pool_lock:
            if _ai_worker_pool is None:
                # Get config from constants
                max_workers = getattr(constants, 'AI_WORKER_POOL_SIZE', 2)
                queue_size = getattr(constants, 'AI_WORKER_QUEUE_SIZE', 100)
                timeout = getattr(constants, 'AI_ANALYSIS_TIMEOUT', 60)
                
                _ai_worker_pool = AIWorkerPool(
                    max_workers=max_workers,
                    queue_size=queue_size,
                    timeout=timeout
                )
    
    return _ai_worker_pool


def shutdown_ai_worker_pool(wait: bool = True):
    """Shutdown the global AI worker pool."""
    global _ai_worker_pool
    
    if _ai_worker_pool is not None:
        _ai_worker_pool.shutdown(wait=wait)
        _ai_worker_pool = None


def submit_ai_analysis(
    leak_obj: Any,
    callback: Optional[Callable] = None,
    priority: int = AITask.NORMAL
) -> bool:
    """
    Convenience function to submit AI analysis.
    
    Args:
        leak_obj: LeakObj instance to analyze
        callback: Optional callback when analysis completes
        priority: Task priority
        
    Returns:
        True if submitted, False otherwise
    """
    pool = get_ai_worker_pool()
    return pool.submit_analysis(leak_obj, callback, priority)
