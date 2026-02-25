# -*- coding: utf-8 -*-
"""
Tests for new GitSearch modules:
- github_rate_limiter
- ai_worker (now in AIObj)
- temp_manager
- metrics

Run with: pytest test_new_modules.py -v
"""

import pytest
import time
import tempfile
import shutil
import os
from unittest.mock import patch

# Mark all tests in this module as slow due to threading/locking in tested modules
pytestmark = pytest.mark.slow


# ====================
# Rate Limiter Tests
# ====================


class TestResourceQuota:
    """Tests for ResourceQuota dataclass."""

    def test_resource_quota_creation(self):
        """Test ResourceQuota creation with defaults."""
        from src.github_rate_limiter import ResourceQuota

        quota = ResourceQuota(resource="core")

        # Should initialize with RESOURCE_LIMITS defaults
        assert quota.resource == "core"
        assert quota.limit == 5000  # Default core limit
        assert quota.remaining == 5000

    def test_resource_quota_search_code(self):
        """Test ResourceQuota for search_code resource."""
        from src.github_rate_limiter import ResourceQuota

        quota = ResourceQuota(resource="search_code")

        assert quota.limit == 10  # 10/minute for code search
        assert quota.remaining == 10

    def test_resource_quota_is_available(self):
        """Test is_available method."""
        from src.github_rate_limiter import ResourceQuota

        quota = ResourceQuota(resource="core")
        quota.remaining = 100

        assert quota.is_available(min_remaining=50) is True
        assert quota.is_available(min_remaining=150) is False


class TestTokenQuota:
    """Tests for TokenQuota class."""

    def test_token_quota_initialization(self):
        """Test TokenQuota initializes with all resource quotas."""
        from src.github_rate_limiter import TokenQuota

        token_quota = TokenQuota(token="test_token")

        assert "core" in token_quota.resources
        assert "search" in token_quota.resources
        assert "search_code" in token_quota.resources
        assert "graphql" in token_quota.resources

    def test_token_quota_default_limits(self):
        """Test TokenQuota has correct default limits."""
        from src.github_rate_limiter import TokenQuota

        token_quota = TokenQuota(token="test_token")

        assert token_quota.resources["core"].limit == 5000
        assert token_quota.resources["search"].limit == 30
        assert token_quota.resources["search_code"].limit == 10
        assert token_quota.resources["graphql"].limit == 5000

    def test_is_available_for_resource(self):
        """Test is_available_for method."""
        from src.github_rate_limiter import TokenQuota

        token_quota = TokenQuota(token="test_token")
        token_quota.resources["core"].remaining = 100

        assert token_quota.is_available_for("core", min_remaining=50) is True

    def test_is_available_when_blocked(self):
        """Test is_available_for returns False when blocked."""
        from src.github_rate_limiter import TokenQuota

        token_quota = TokenQuota(token="test_token")
        token_quota.is_blocked = True
        token_quota.block_until = time.time() + 3600  # Blocked for 1 hour

        assert token_quota.is_available_for("core") is False

    def test_get_resource_quota(self):
        """Test get_resource_quota creates quota if missing."""
        from src.github_rate_limiter import TokenQuota

        token_quota = TokenQuota(token="test_token")
        quota = token_quota.get_resource_quota("core")

        assert quota is not None
        assert quota.resource == "core"


class TestGitHubRateLimiter:
    """Tests for GitHubRateLimiter class."""

    def test_initialization_with_tokens(self):
        """Test initializing limiter with tokens."""
        from src.github_rate_limiter import GitHubRateLimiter

        limiter = GitHubRateLimiter(tokens=("token_1", "token_2", "token_3"))

        assert len(limiter.tokens) == 3

    def test_initialization_filters_invalid_tokens(self):
        """Test that invalid tokens are filtered."""
        from src.github_rate_limiter import GitHubRateLimiter

        limiter = GitHubRateLimiter(tokens=("valid_token", "", "-", "  ", "another_valid"))

        assert len(limiter.tokens) == 2

    def test_get_best_token(self):
        """Test getting best available token."""
        from src.github_rate_limiter import GitHubRateLimiter

        limiter = GitHubRateLimiter(tokens=("token_1", "token_2"))

        token = limiter.get_best_token(resource="core")

        assert token in ("token_1", "token_2")

    def test_update_quota_from_headers(self):
        """Test updating quota from GitHub response headers."""
        from src.github_rate_limiter import GitHubRateLimiter

        limiter = GitHubRateLimiter(tokens=("test_token",))

        headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4500",
            "X-RateLimit-Reset": str(time.time() + 3600),
        }

        limiter.update_quota_from_headers("test_token", headers, resource="core")

        token_quota = limiter.tokens["test_token"]
        assert token_quota.resources["core"].remaining == 4500

    def test_handle_rate_limit_error(self):
        """Test handling rate limit error."""
        from src.github_rate_limiter import GitHubRateLimiter

        limiter = GitHubRateLimiter(tokens=("test_token",))

        limiter.handle_rate_limit_error("test_token", retry_after=60, resource="search_code")

        token_quota = limiter.tokens["test_token"]
        assert token_quota.resources["search_code"].remaining == 0
        assert token_quota.consecutive_errors == 1


# ====================
# Temp Manager Tests
# ====================


class TestTempFolderManager:
    """Tests for TempFolderManager class."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        dirpath = tempfile.mkdtemp()
        yield dirpath
        shutil.rmtree(dirpath, ignore_errors=True)

    def test_manager_creation(self, temp_dir):
        """Test TempFolderManager creation."""
        from src.temp_manager import TempFolderManager

        manager = TempFolderManager(temp_folder=temp_dir, max_size_gb=1.0, max_repos=10)

        assert str(manager.temp_folder) == temp_dir
        assert manager.max_size_bytes == int(1.0 * 1024 * 1024 * 1024)
        assert manager.max_repos == 10

    def test_get_stats_empty(self, temp_dir):
        """Test get_stats on empty directory."""
        from src.temp_manager import TempFolderManager

        manager = TempFolderManager(temp_folder=temp_dir)
        stats = manager.get_stats()

        assert stats["repo_count"] == 0
        assert stats["total_size_bytes"] == 0

    def test_get_stats_with_folders(self, temp_dir):
        """Test get_stats with folders."""
        from src.temp_manager import TempFolderManager

        # Create test folders that look like repos
        os.makedirs(os.path.join(temp_dir, "owner_repo1"))
        os.makedirs(os.path.join(temp_dir, "owner_repo2"))

        manager = TempFolderManager(temp_folder=temp_dir)
        stats = manager.get_stats()

        assert stats["repo_count"] == 2

    def test_is_cached_false_for_uncached(self, temp_dir):
        """Test is_cached returns False for uncached repo."""
        from src.temp_manager import TempFolderManager

        manager = TempFolderManager(temp_folder=temp_dir)

        assert manager.is_cached("https://github.com/test/repo") is False

    def test_register_and_check_cache(self, temp_dir):
        """Test registering a repo and checking cache."""
        from src.temp_manager import TempFolderManager

        manager = TempFolderManager(temp_folder=temp_dir)

        # Create a repo folder
        repo_path = os.path.join(temp_dir, "test_repo")
        os.makedirs(repo_path)
        repo_url = "https://github.com/test/repo"

        manager.register_repo(repo_path, repo_url)

        assert manager.is_cached(repo_url) is True
        assert manager.get_cached_path(repo_url) == repo_path


# ====================
# Metrics Tests
# ====================


class TestMetricsCollector:
    """Tests for MetricsCollector class."""

    @pytest.fixture
    def metrics(self):
        """Create fresh MetricsCollector for each test."""
        from src.metrics import MetricsCollector

        return MetricsCollector()

    def test_increment_counter(self, metrics):
        """Test incrementing a counter."""
        metrics.increment("test_counter")
        metrics.increment("test_counter")
        metrics.increment("test_counter", 5)

        all_metrics = metrics.get_all_metrics()
        assert all_metrics["counters"]["test_counter"] == 7

    def test_set_gauge(self, metrics):
        """Test setting a gauge."""
        metrics.set_gauge("test_gauge", 42.5)

        all_metrics = metrics.get_all_metrics()
        assert all_metrics["gauges"]["test_gauge"] == 42.5

    def test_timer_context_manager(self, metrics):
        """Test timer context manager."""
        with patch("time.time", side_effect=[0, 0.01]):
            with metrics.timer("test_operation"):
                pass

        all_metrics = metrics.get_all_metrics()
        assert "test_operation" in all_metrics["timers"]

        timer_data = all_metrics["timers"]["test_operation"]
        assert timer_data["count"] == 1
        assert timer_data["sum"] >= 0.01

    def test_timer_with_labels(self, metrics):
        """Test timer with labels."""
        with patch("time.time", side_effect=[0, 0.005]):
            with metrics.timer("api_call", labels={"method": "GET", "endpoint": "/test"}):
                pass

        all_metrics = metrics.get_all_metrics()
        # Label-based timers should be recorded
        assert len(all_metrics["timers"]) > 0

    def test_prometheus_format(self, metrics):
        """Test Prometheus export format."""
        metrics.increment("requests_total", 10)
        metrics.set_gauge("active_connections", 5)

        prometheus = metrics.to_prometheus()

        assert "gitsearch_requests_total" in prometheus
        assert "gitsearch_active_connections" in prometheus
        assert "10" in prometheus
        assert "5" in prometheus

    def test_json_format(self, metrics):
        """Test JSON export format."""
        metrics.increment("test_counter", 3)

        json_output = metrics.to_json()

        assert '"counters"' in json_output
        assert '"test_counter"' in json_output
        assert '"3"' in json_output or "3" in json_output

    def test_reset(self, metrics):
        """Test metrics reset."""
        metrics.increment("counter", 100)
        metrics.set_gauge("gauge", 50)

        metrics.reset()

        all_metrics = metrics.get_all_metrics()
        assert all_metrics["counters"].get("counter", 0) == 0
        assert all_metrics["gauges"].get("gauge", 0) == 0


# ====================
# AI Worker Tests
# ====================


class TestAIWorkerPool:
    """Tests for AIWorkerPool class."""

    @pytest.mark.slow
    def test_worker_pool_creation(self):
        """Test AIWorkerPool creation."""
        from src.AIObj import AIWorkerPool

        pool = AIWorkerPool(max_workers=2, queue_size=10)

        try:
            assert pool.max_workers == 2
            assert pool.queue_size == 10
        finally:
            pool.shutdown()

    def test_task_creation(self):
        """Test AITask creation."""
        from src.AIObj import AITask

        task = AITask(priority=1, leak_obj={"file": "test.py", "secret": "xxx"}, callback=None)

        assert task.priority == 1
        assert task.leak_obj["file"] == "test.py"

    def test_task_priority_ordering(self):
        """Test AITask priority comparison."""
        from src.AIObj import AITask

        task_high = AITask(priority=0, leak_obj={})  # HIGH priority
        task_normal = AITask(priority=1, leak_obj={})  # NORMAL priority
        task_low = AITask(priority=2, leak_obj={})  # LOW priority

        # Lower number = higher priority
        assert task_high < task_normal < task_low

    def test_task_priority_constants(self):
        """Test AITask has priority constants."""
        from src.AIObj import AITask

        assert AITask.HIGH == 0
        assert AITask.NORMAL == 1
        assert AITask.LOW == 2


# ====================
# Integration Tests
# ====================


class TestModulesIntegration:
    """Integration tests between modules."""

    def test_rate_limiter_with_metrics(self):
        """Test rate limiter with metrics."""
        from src.github_rate_limiter import GitHubRateLimiter
        from src.metrics import MetricsCollector

        metrics = MetricsCollector()
        limiter = GitHubRateLimiter()

        limiter.add_token("test_token")
        token = limiter.get_available_token("core")

        if token:
            metrics.increment("api_calls")

        all_metrics = metrics.get_all_metrics()
        assert all_metrics["counters"]["api_calls"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
