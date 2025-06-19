import sqlite3
import os
from src import reports

# Setup in-memory SQLite database with minimal schema
import pytest

@pytest.fixture
def db_connection(tmp_path):
    conn = sqlite3.connect(':memory:')
    cur = conn.cursor()
    cur.executescript('''
        CREATE TABLE leak (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            level INTEGER,
            author_info TEXT,
            found_at TEXT,
            created_at TEXT,
            updated_at TEXT,
            approval INTEGER,
            leak_type TEXT,
            result INTEGER,
            done_by INTEGER,
            company_id INTEGER
        );
        CREATE TABLE leak_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            leak_id INTEGER,
            size INTEGER,
            stargazers_count INTEGER,
            forks_count INTEGER,
            open_issues_count INTEGER,
            ai_result INTEGER
        );
        CREATE TABLE raw_report (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            leak_id INTEGER,
            report_name TEXT,
            raw_data TEXT,
            ai_report TEXT
        );
    ''')
    # Insert sample data
    cur.execute("INSERT INTO leak (url, level, author_info, found_at, created_at, approval, leak_type, result, done_by, company_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ('repo1', 0, 'auth', '2024-05-01', '2024-05-01', 1, 'typeA', 0, 0, 1))
    cur.execute("INSERT INTO leak (url, level, author_info, found_at, created_at, approval, leak_type, result, done_by, company_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ('repo2', 2, 'auth', '2024-05-02', '2024-05-02', 1, 'typeB', 1, 0, 1))

    cur.execute("INSERT INTO leak_stats (leak_id, size, stargazers_count, forks_count, open_issues_count, ai_result) VALUES (?,?,?,?,?,?)",
                (1, 100, 5, 1, 0, 0))
    cur.execute("INSERT INTO leak_stats (leak_id, size, stargazers_count, forks_count, open_issues_count, ai_result) VALUES (?,?,?,?,?,?)",
                (2, 200, 10, 2, 1, 1))

    cur.execute("INSERT INTO raw_report (leak_id, report_name, raw_data, ai_report) VALUES (?,?,?,?)",
                (1, 'repo1', 'ok', 'ok'))
    cur.execute("INSERT INTO raw_report (leak_id, report_name, raw_data, ai_report) VALUES (?,?,?,?)",
                (2, 'repo2', 'error: too large', 'ai'))
    conn.commit()
    yield conn
    conn.close()


def test_generate_business_report(tmp_path, db_connection):
    data = reports.generate_report('2024-05-01', '2024-05-03', 'business', conn=db_connection, output_dir=tmp_path)
    assert data['total_leaks'] == 2
    assert isinstance(data['status_breakdown'], list)
    assert isinstance(data['daily_counts'], list)
    # ensure file created
    assert os.path.exists(data['path'])


def test_generate_empty_period(tmp_path, db_connection):
    data = reports.generate_report('2023-01-01', '2023-01-02', 'business', conn=db_connection, output_dir=tmp_path)
    assert data['total_leaks'] == 0
    assert data['status_breakdown'] == []
    assert data['daily_counts'] == []


def test_generate_technical_report(tmp_path, db_connection):
    data = reports.generate_report('2024-05-01', '2024-05-03', 'technical', conn=db_connection, output_dir=tmp_path)
    assert 'level_breakdown' in data
    assert 'serious_leaks' in data
    assert any(l[2] >= 1 for l in data['serious_leaks'])