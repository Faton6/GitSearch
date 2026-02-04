"""
Unit tests for the api_client module.

This module contains comprehensive tests for GitSearchAPIClient
to ensure proper database operations and error handling.
"""

import pytest
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pymysql

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.api_client import GitSearchAPIClient  # noqa: E402


@pytest.fixture
def api_client():
    """Create an API client instance for testing."""
    with patch.dict(os.environ, {"DB_USER": "test_user", "DB_PASSWORD": "test_pass"}):
        client = GitSearchAPIClient()
        yield client
        # Cleanup
        client.close()


class TestGitSearchAPIClientInit:
    """Tests for GitSearchAPIClient initialization."""

    def test_init_with_env_vars(self):
        """Test initialization reads environment variables."""
        with patch.dict(os.environ, {"DB_USER": "test_user", "DB_PASSWORD": "test_pass"}):
            client = GitSearchAPIClient()
            assert client.db_config["user"] == "test_user"
            assert client.db_config["password"] == "test_pass"
            client.close()

    def test_init_with_defaults(self):
        """Test initialization uses defaults when env vars missing."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear env vars that might interfere
            env = os.environ.copy()
            if "DB_USER" in env:
                del env["DB_USER"]
            if "DB_PASSWORD" in env:
                del env["DB_PASSWORD"]

            with patch.dict(os.environ, env, clear=True):
                client = GitSearchAPIClient()
                assert client.db_config["user"] == "root"
                assert client.db_config["password"] == "changeme"
                client.close()


class TestDatabaseConnection:
    """Tests for database connection handling."""

    def test_get_connection_success(self, api_client):
        """Test successful database connection."""
        with patch("pymysql.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_connect.return_value = mock_conn
            mock_conn.ping.return_value = None

            conn = api_client._get_connection()

            mock_connect.assert_called_once()
            assert conn is not None

    def test_get_connection_failure(self, api_client):
        """Test database connection failure with retry."""
        with patch("pymysql.connect") as mock_connect:
            mock_connect.side_effect = pymysql.Error("Connection failed")

            conn = api_client._get_connection()

            # Should have retried MAX_RETRIES times
            assert mock_connect.call_count == GitSearchAPIClient.MAX_RETRIES
            assert conn is None

    def test_get_connection_reuses_existing(self, api_client):
        """Test that existing connection is reused."""
        with patch("pymysql.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_connect.return_value = mock_conn
            mock_conn.ping.return_value = None

            # First call creates connection
            conn1 = api_client._get_connection()
            # Second call should reuse
            conn2 = api_client._get_connection()

            # connect should only be called once (second uses ping)
            assert mock_connect.call_count == 1
            assert conn1 == conn2

    def test_close_connection(self, api_client):
        """Test closing database connection."""
        with patch("pymysql.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_connect.return_value = mock_conn
            mock_conn.ping.return_value = None

            api_client._get_connection()
            api_client.close()

            mock_conn.close.assert_called_once()
            assert api_client._connection is None


class TestDataOperations:
    """Tests for data CRUD operations."""

    def test_get_data_success(self, api_client):
        """Test successful data retrieval."""
        with patch.object(api_client, "_get_connection") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_get_conn.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchall.return_value = [{"id": 1, "url": "test_url", "result": 4}]

            result = api_client.get_data("leak", {})

            assert len(result) == 1
            assert result[0]["url"] == "test_url"

    def test_get_data_empty(self, api_client):
        """Test data retrieval with no results."""
        with patch.object(api_client, "_get_connection") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_get_conn.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchall.return_value = []

            result = api_client.get_data("leak", {})

            assert result == []

    def test_add_data_success(self, api_client):
        """Test successful data insertion."""
        with patch.object(api_client, "_get_connection") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_get_conn.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.lastrowid = 42

            result = api_client.add_data("leak", {"url": "new_url", "result": 4})

            assert result == 42
            mock_conn.commit.assert_called()

    def test_upd_data_success(self, api_client):
        """Test successful data update."""
        with patch.object(api_client, "_get_connection") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_get_conn.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.rowcount = 1

            result = api_client.upd_data("leak", {"id": 1, "result": 5})

            assert result == 1
            mock_conn.commit.assert_called()


class TestMakeRequest:
    """Tests for _make_request compatibility method."""

    def test_make_request_get(self, api_client):
        """Test make_request with get action."""
        with patch.object(api_client, "get_data") as mock_get:
            mock_get.return_value = [{"id": 1}]

            result = api_client._make_request(
                {"tname": "leak", "dname": "GitSearch", "action": "get", "content": {"id": 1}}
            )

            assert "auth" in result
            assert result["auth"] is True
            mock_get.assert_called()

    def test_make_request_add(self, api_client):
        """Test make_request with add action."""
        with patch.object(api_client, "add_data") as mock_add:
            mock_add.return_value = 42

            result = api_client._make_request(
                {"tname": "leak", "dname": "GitSearch", "action": "add", "content": {"url": "test", "result": 4}}
            )

            assert "content" in result
            mock_add.assert_called()


class TestRetryLogic:
    """Tests for retry logic on connection errors."""

    def test_retry_on_operational_error(self, api_client):
        """Test that OperationalError triggers retry."""
        call_count = 0

        def side_effect_func(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise pymysql.OperationalError("Connection lost")
            return [{"id": 1}]

        with patch.object(api_client, "_get_connection") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_get_conn.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchall.side_effect = side_effect_func

            # Should succeed after retries
            _ = api_client.get_data("leak", {})

            assert call_count == 3  # Failed twice, succeeded on third


class TestTableMapping:
    """Tests for table name mapping."""

    def test_table_mapping_exists(self):
        """Test that TABLE_MAPPING is properly defined."""
        assert "company" in GitSearchAPIClient.TABLE_MAPPING
        assert GitSearchAPIClient.TABLE_MAPPING["company"] == "companies"

    def test_field_mapping_exists(self):
        """Test that FIELD_MAPPING is properly defined."""
        assert "accounts" in GitSearchAPIClient.FIELD_MAPPING
        assert "company_id" in GitSearchAPIClient.FIELD_MAPPING["accounts"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
