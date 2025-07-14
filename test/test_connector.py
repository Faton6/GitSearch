import pytest
from unittest.mock import patch, MagicMock
import pymysql # Changed from mariadb
import os
import sys
from pathlib import Path
import json
import base64
import bz2
import time # Import time for mocking

from src import Connector
from src import constants
from src import logger

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Mock environment variables for database connection
@pytest.fixture(autouse=True)
def mock_env_vars():
    with patch.dict(os.environ, {"DB_USER": "test_user", "DB_PASSWORD": "test_pass"}):
        yield

# Test connect_to_database function
def test_connect_to_database_success():
    with patch("pymysql.connect") as mock_connect: # Changed from mariadb
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        conn, cursor = Connector.connect_to_database()

        mock_connect.assert_called_once_with(
            user="test_user",
            password="test_pass",
            host=constants.url_DB,
            port=3306,
            database="Gitsearch"
        )
        assert conn == mock_conn
        assert cursor == mock_cursor

def test_connect_to_database_failure():
    with patch("pymysql.connect", side_effect=pymysql.Error("Connection failed")) as mock_connect: # Changed from mariadb
        conn, cursor = Connector.connect_to_database()

        mock_connect.assert_called_once()
        assert conn is None
        assert cursor is None

# Test dump_target_from_DB function
def test_dump_target_from_DB_success():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        # Mocking the bytes after base64 decode, as the actual code handles the decode
        # The data returned by fetchall should be base64 encoded bytes
        mock_cursor.fetchall.return_value = [
            (base64.b64encode(b"dork1, dork2"), 1), # Added space here
            (base64.b64encode(b"dork3"), 2)
        ]

        result = Connector.dump_target_from_DB()

        mock_cursor.execute.assert_called_once_with("SELECT dork, company_id FROM dorks")
        # SELECT operations don't require commit
        mock_conn.close.assert_called_once()
        assert result == {
            1: ["dork1", "dork2"],
            2: ["dork3"]
        }

def test_dump_target_from_DB_no_connection():
    with patch("src.Connector.connect_to_database", return_value=(None, None)):
        result = Connector.dump_target_from_DB()
        assert result == {}

def test_dump_target_from_DB_db_error():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)
        mock_cursor.execute.side_effect = pymysql.Error("DB error") # Changed from mariadb

        result = Connector.dump_target_from_DB()

        mock_conn.close.assert_called_once()
        assert result == {}

# Test dump_from_DB function
def test_dump_from_DB_success_mode_0():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        mock_cursor.fetchall.return_value = [
            (1, "url1", "status1"),
            (2, "url2", "status2")
        ]

        result = Connector.dump_from_DB(mode=0)

        mock_cursor.execute.assert_called_once_with("SELECT id, url, result FROM leak")
        # SELECT operations don't require commit
        mock_conn.close.assert_called_once()
        assert result == {"url1": "status1", "url2": "status2"}

def test_dump_from_DB_success_mode_1():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        mock_cursor.fetchall.return_value = [
            (1, "url1", "status1"),
            (2, "url2", "status2")
        ]

        result = Connector.dump_from_DB(mode=1)

        mock_cursor.execute.assert_called_once_with("SELECT id, url, result FROM leak")
        # SELECT operations don't require commit
        mock_conn.close.assert_called_once()
        assert result == {"url1": ["status1", 1], "url2": ["status2", 2]}

def test_dump_from_DB_no_connection():
    with patch("src.Connector.connect_to_database", return_value=(None, None)):
        result = Connector.dump_from_DB()
        assert result == {}

def test_dump_from_DB_db_error():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)
        mock_cursor.execute.side_effect = pymysql.Error("DB error") # Changed from mariadb

        result = Connector.dump_from_DB()

        mock_conn.close.assert_called_once()
        assert result == {}

# Test get_company_name function
def test_get_company_name_success():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        mock_cursor.fetchone.return_value = ("Acme",)

        result = Connector.get_company_name(7)

        mock_cursor.execute.assert_called_once_with("SELECT company_name FROM companies WHERE id=%s", (7,))
        # SELECT operations don't require commit
        mock_conn.close.assert_called_once()
        assert result == "Acme"


def test_get_company_name_no_connection():
    with patch("src.Connector.connect_to_database", return_value=(None, None)):
        assert Connector.get_company_name(1) == ""


def test_get_company_name_db_error():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)
        mock_cursor.execute.side_effect = pymysql.Error("DB error")

        result = Connector.get_company_name(1)

        mock_conn.close.assert_called_once()
        assert result == ""


# Test dump_account_from_DB function
def test_dump_account_from_DB_success():
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [("account1",), ("account2",)]

    result = Connector.dump_account_from_DB(mock_cursor)

    mock_cursor.execute.assert_called_once_with("SELECT account FROM accounts")
    assert result == ["account1", "account2"]

def test_dump_account_from_DB_no_connection():
    # This test doesn't really make sense anymore since dump_account_from_DB requires cursor
    # But we can test it with None cursor to see if it handles gracefully
    mock_cursor = MagicMock()
    mock_cursor.execute.side_effect = pymysql.Error("DB error")
    
    result = Connector.dump_account_from_DB(mock_cursor)
    assert result == []

def test_dump_account_from_DB_db_error():
    mock_cursor = MagicMock()
    mock_cursor.execute.side_effect = pymysql.Error("DB error") # Changed from mariadb

    result = Connector.dump_account_from_DB(mock_cursor)

    assert result == []

# Test dump_row_data_from_DB function
def test_dump_row_data_from_DB_success():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        test_data = {"key": "value"}
        compressed_data = bz2.compress(json.dumps(test_data).encode("utf-8"))
        encoded_data = base64.b64encode(compressed_data)

        mock_cursor.fetchone.return_value = (encoded_data,)

        result = Connector.dump_row_data_from_DB(123)

        mock_cursor.execute.assert_called_once_with("SELECT raw_data FROM raw_report WHERE leak_id=%s", (123,)) # Changed to %s
        # SELECT operations don't require commit
        mock_conn.close.assert_called_once()
        assert result == test_data

def test_dump_row_data_from_DB_no_data():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        mock_cursor.fetchone.return_value = None

        result = Connector.dump_row_data_from_DB(123)

        assert result is None

def test_dump_row_data_from_DB_decoding_error():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        mock_cursor.fetchone.return_value = (b"invalid_base64",)

        # Catch a more general exception as bz2.DecompressorError might not be available
        result = Connector.dump_row_data_from_DB(123)

        assert result is None

# Test dump_ai_report_from_DB function (similar to dump_row_data_from_DB)
def test_dump_ai_report_from_DB_success():
    with patch("src.Connector.connect_to_database") as mock_connect_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect_db.return_value = (mock_conn, mock_cursor)

        test_data = {"ai_response": "good"}
        compressed_data = bz2.compress(json.dumps(test_data).encode("utf-8"))
        encoded_data = base64.b64encode(compressed_data)

        mock_cursor.fetchone.return_value = (encoded_data,)

        result = Connector.dump_ai_report_from_DB(456)

        mock_cursor.execute.assert_called_once_with("SELECT ai_report FROM raw_report WHERE leak_id=%s", (456,)) # Changed to %s
        # SELECT operations don't require commit
        mock_conn.close.assert_called_once()
        assert result == test_data

# Test dump_to_DB_req function (requires more complex mocking for file operations and multiple inserts)
# This test will focus on the flow and calls, not exhaustive data validation.
@patch("src.Connector.connect_to_database")
@patch("builtins.open", new_callable=MagicMock)
@patch("json.load")
def test_dump_to_DB_req_mode_0_success(mock_json_load, mock_open, mock_connect_db):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect_db.return_value = (mock_conn, mock_cursor)

    # Mock the content of the JSON file that dump_to_DB_req reads
    mock_json_load.return_value = {
        "scan": {
            "1": [
                {"tname": "leak", "dname": "GitLeak", "action": "add", "content": {
                    "url": "repo_url_1", "level": 1, "author_info": "author1", "found_at": "now",
                    "created_at": "then", "updated_at": "later", "approval": 0, "leak_type": "type1",
                    "result": 4, "company_id": 1, "profitability_scores": {}}},
                {"tname": "raw_report", "dname": "GitLeak", "action": "add", "content": {
                    "leak_id": 1, "report_name": "repo_url_1", "raw_data": "raw_data_1", "ai_report": "ai_report_1"}},
                {"size": 100, "stargazers_count": 10, "has_issues": True, "has_projects": True, "has_downloads": True,
                 "has_wiki": True, "has_pages": True, "forks_count": 5, "open_issues_count": 2, "subscribers_count": 3,
                 "topics": "topic1", "contributors_count": 4, "commits_count": 20, "commiters_count": 3, "ai_result": 1,
                 "description": "desc1"},
                [{"account": "acc1", "need_monitor": 0, "related_company_id": 1}],
                [{"commiter_name": "comm1", "commiter_email": "email1", "need_monitor": 0, "related_account_id": 0}]
            ]
        }
    }

    # Mock lastrowid for INSERT statements
    mock_cursor.lastrowid = 101

    # Mock dump_account_from_DB to return an empty list, simulating no existing accounts
    with patch("src.Connector.dump_account_from_DB", return_value=[]):
        Connector.dump_to_DB_req("dummy_filename.json", mock_conn, mock_cursor)

        # Assertions for execute calls (simplified)
        assert mock_cursor.execute.call_count >= 4 # At least for leak, raw_report, leak_stats, commiters
        # dump_to_DB_req doesn't call commit/close - that's done at higher level

# Test dump_to_DB function (high-level, as it orchestrates other functions)
@patch("src.Connector.dump_to_DB_req")
@patch("src.Connector.logger")
@patch("builtins.open", new_callable=MagicMock)
@patch("json.dump")
@patch("time.strftime") # Mock time.strftime
@patch("src.Connector.load_existing_leak_urls") # Mock to return empty dict for new leaks
def test_dump_to_DB_mode_0_success(mock_load_urls, mock_strftime, mock_json_dump, mock_open, mock_logger, mock_dump_to_DB_req):
    mock_strftime.return_value = "2025-06-17-12-00" # Consistent timestamp
    mock_load_urls.return_value = {}  # Empty dict means all leaks are new

    # Mock constants.RESULT_MASS with a dummy LeakObj
    mock_leak_obj = MagicMock()
    mock_leak_obj.write_obj.return_value = {
        "url": "test_url", "leak_type": "test_type", "level": 1, "author_info": "test_author",
        "found_at": "test_found", "created_at": "test_created", "updated_at": "test_updated",
        "approval": 0, "result": 4, "company_id": 1, "profitability_scores": {}}
    mock_leak_obj.repo_url = "test_repo_url"
    mock_leak_obj.secrets = {"scanner1": {"leak1": "data"}}
    mock_leak_obj.ai_analysis = {"ai": "report"}
    mock_leak_obj.get_stats.return_value = ({}, [], []) # Mock empty stats

    # Setup constants for the test
    original_result_mass = constants.RESULT_MASS
    original_url_db = constants.url_DB
    
    constants.RESULT_MASS = constants.AutoVivification()
    constants.RESULT_MASS["key1"]["obj1"] = mock_leak_obj
    constants.url_DB = "some_db_url"

    with patch("src.Connector.connect_to_database") as mock_connect:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = (mock_conn, mock_cursor)
        
        Connector.dump_to_DB(mode=0)

        mock_json_dump.assert_called_once()
        mock_dump_to_DB_req.assert_called_once()

    # Clean up constants.RESULT_MASS for other tests
    constants.RESULT_MASS = original_result_mass
    constants.url_DB = original_url_db
    
    
def test_load_existing_leak_urls():
    with patch("src.Connector.connect_to_database") as mock_connect:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = (mock_conn, mock_cursor)
        mock_cursor.fetchall.return_value = [(1, "url1"), (2, "url2")]

        res = Connector.load_existing_leak_urls()

        mock_cursor.execute.assert_called_once_with("SELECT id, url FROM leak")
        assert res == {"url1": 1, "url2": 2}


def test_merge_reports_deduplication():
    old = {"gitleaks": {"Leak #1": {"Match": "foo", "File": "f"}}}
    new = {"gitleaks": {"0": {"Match": "foo", "File": "f"}, "1": {"Match": "bar", "File": "f2"}}}
    merged = Connector.merge_reports(old, new)
    logger.info(f"Merged report: {merged}")
    assert len(merged["gitleaks"]) == 2


@patch("src.Connector.dump_account_from_DB", return_value=["acc0"])
@patch("src.Connector.get_accounts_from_DB", return_value=["acc0"])
@patch("src.Connector.get_commiters_from_DB", return_value=[("Old", "o@x.com")])
@patch("src.Connector.connect_to_database")
def test_update_existing_leak(mock_connect, mock_get_comm, mock_get_acc, mock_dump_acc):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value = (mock_conn, mock_cursor)
    mock_cursor.fetchone.side_effect = [None]

    class DummyStats:
        def __init__(self):
            self.commits_stats_commiters_table = [
                {"commiter_name": "Alice", "commiter_email": "alice@ex.com"}
            ]
            self.contributors_stats_accounts_table = [
                {"account": "acc1", "need_monitor": 0, "related_company_id": 1}
            ]
            self.repo_stats_leak_stats_table = {"contributors_count": 1, "commits_count": 1}

    leak_obj = MagicMock()
    leak_obj.stats = DummyStats()
    leak_obj.repo_url = "url1"
    leak_obj.secrets = {}
    leak_obj.ai_report = {}
    leak_obj.write_obj.return_value = {
        "level": 1,
        "author_info": "bob",
        "leak_type": "t",
        "result": 4,
        "updated_at": "2024-01-02",
    }

    Connector.update_existing_leak(5, leak_obj, mock_conn, mock_cursor)

    assert mock_cursor.execute.call_count > 0

