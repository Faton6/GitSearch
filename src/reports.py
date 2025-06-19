# coding: utf-8
"""Report generation module for GitSearch.

This module provides a ``generate_report`` function that collects
statistics from the database and writes an HTML report. Two report
flavours are supported: ``business`` and ``technical``. Business reports
contain aggregated numbers suitable for non-technical audiences. The
technical report extends it with additional metrics from ``leak_stats``
and ``raw_report`` tables and a table of serious leaks (level >= 1).

The function can operate with the real MariaDB connection or any DB-API
compatible connection (used in tests with SQLite).
"""
from __future__ import annotations

import os
import argparse
from typing import Any, Dict, List, Tuple

from src import Connector, constants


def _execute(cursor, query: str, params: Tuple[Any, Any]):
    """Helper that tries ``%s`` placeholders first and falls back to ``?``.

    SQLite uses ``?`` as parameter placeholder while PyMySQL uses ``%s``.
    This helper allows using the same queries for both backends."""
    try:
        cursor.execute(query, params)
    except Exception:
        cursor.execute(query.replace("%s", "?"), params)


def generate_report(
    start_date: str,
    end_date: str,
    report_type: str = "business",
    output_dir: str | None = None,
) -> Dict[str, Any]:
    """Generate leak report.

    Parameters
    ----------
    start_date, end_date: str
        Report period in ``YYYY-MM-DD`` format.
    report_type: str
        ``"business"`` or ``"technical"``.
    conn:
        Optional DB connection. If ``None`` the function will connect
        using :func:`Connector.connect_to_database`.
    output_dir: str
        Directory where HTML report will be written. Defaults to
        ``<project>/reports``.

    Returns
    -------
    Dict with collected statistics and path to the created HTML file
    under ``key 'path'``.
    """
    if report_type not in {"business", "technical"}:
        raise ValueError("report_type must be 'business' or 'technical'")

    print(f"Generating {report_type} report for period {start_date} ... {end_date}")
    conn, cursor = Connector.connect_to_database()
    if not conn or not cursor:
        raise RuntimeError("Database connection failed")

    output_dir = output_dir or os.path.join(constants.MAIN_FOLDER_PATH, "reports")

    data: Dict[str, Any] = {}

    # --- Business level statistics -----------------------------------------
    cursor.execute(
        "SELECT COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s",
        (start_date, end_date),
    )
    data["total_leaks"] = cursor.fetchone()[0]

    cursor.execute(
        "SELECT result, COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s GROUP BY result",
        (start_date, end_date),
    )
    data["status_breakdown"] = cursor.fetchall()

    cursor.execute(
        "SELECT AVG(level) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s",
        (start_date, end_date),
    )
    avg = cursor.fetchone()[0]
    data["average_severity"] = float(avg) if avg is not None else 0.0

    cursor.execute(
        "SELECT DATE(created_at) AS day, COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s GROUP BY day ORDER BY day",
        (start_date, end_date),
    )
    data["daily_counts"] = cursor.fetchall()

    # --- Technical additions ----------------------------------------------
    if report_type == "technical":
        cursor.execute(
            "SELECT level, COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s GROUP BY level",
            (start_date, end_date),
        )
        data["level_breakdown"] = cursor.fetchall()

        cursor.execute(
            """
            SELECT COUNT(*), AVG(ls.size), AVG(ls.forks_count), AVG(ls.stargazers_count)
            FROM leak_stats ls JOIN leak l ON ls.leak_id = l.id
            WHERE DATE(l.created_at) BETWEEN %s AND %s
            """,
            (start_date, end_date),
        )
        stats_row = cursor.fetchone()
        data["leak_stats_summary"] = {
            "count": stats_row[0] or 0,
            "avg_size": float(stats_row[1] or 0),
            "avg_forks": float(stats_row[2] or 0),
            "avg_stars": float(stats_row[3] or 0),
        }

        cursor.execute( # TODO check if "error" or "not state" in raw_report 
            """
            SELECT COUNT(*) FROM raw_report rr
            JOIN leak l ON rr.leak_id = l.id
            WHERE DATE(l.created_at) BETWEEN %s AND %s
            """,
            (start_date, end_date),
        )
        data["error_reports"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT url, leak_type, level, found_at FROM leak WHERE level >= 0 AND DATE(created_at) BETWEEN %s AND %s",
            (start_date, end_date),
        )
        data["serious_leaks"] = cursor.fetchall()

    # -- Generate HTML ------------------------------------------------------
    report_title = f"{report_type.capitalize()} report"
    html_lines: List[str] = [
        "<html>",
        "<head><meta charset='utf-8'><title>%s</title>" % report_title,
        "<style>table{border-collapse:collapse;}th,td{border:1px solid #ccc;padding:4px;}</style>",
        "</head><body>",
        f"<h1>{report_title}</h1>",
        f"<p>Period: {start_date} .. {end_date}</p>",
        f"<p>Total leaks: {data['total_leaks']}</p>",
        f"<p>Average severity: {data['average_severity']:.2f}</p>",
        "<h2>Status breakdown</h2>",
        "<table><tr><th>Status</th><th>Count</th></tr>",
    ]
    for status, count in data["status_breakdown"]:
        html_lines.append(f"<tr><td>{status}</td><td>{count}</td></tr>")
    html_lines.append("</table>")

    html_lines.extend([
        "<h2>Daily counts</h2>",
        "<table><tr><th>Day</th><th>Leaks</th></tr>",
    ])
    for day, count in data["daily_counts"]:
        html_lines.append(f"<tr><td>{day}</td><td>{count}</td></tr>")
    html_lines.append("</table>")

    if report_type == "technical":
        html_lines.extend([
            "<h2>Level breakdown</h2>",
            "<table><tr><th>Level</th><th>Count</th></tr>",
        ])
        for lvl, cnt in data["level_breakdown"]:
            html_lines.append(f"<tr><td>{lvl}</td><td>{cnt}</td></tr>")
        html_lines.append("</table>")

        ls = data["leak_stats_summary"]
        html_lines.append(
            f"<p>Stats records: {ls['count']}, avg size: {ls['avg_size']:.1f}, avg forks: {ls['avg_forks']:.1f}, avg stars: {ls['avg_stars']:.1f}</p>"
        )
        html_lines.append(f"<p>Error reports: {data['error_reports']}</p>")

        html_lines.extend([
            "<h2>Medium or high leaks (level ≥ 1)</h2>",
            "<table><tr><th>Found at</th><th>URL</th><th>Type</th><th>Level</th></tr>",
        ])
        for url, ltype, lvl, found in data["serious_leaks"]:
            html_lines.append(
                f"<tr><td>{found}</td><td>{url}</td><td>{ltype}</td><td>{lvl}</td></tr>"
            )
        html_lines.append("</table>")

    html_lines.extend(["</body>", "</html>"])

    report_path = os.path.join(
        output_dir,
        f"leak_report_{report_type}_{start_date}_to_{end_date}.html",
    )
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_lines))
    data["path"] = report_path

    if conn is not None:
        conn.commit()
    else:
        conn.close()

    return data


def generate_report_from_config():
    start_date = constants.CONFIG_FILE['start_date']
    end_date = constants.CONFIG_FILE['end_date']
    typ = constants.CONFIG_FILE['report_type']
    path_to_save = os.path.join(constants.MAIN_FOLDER_PATH, "reports")
    if typ not in {"business", "technical"}:
        raise ValueError("report_type must be 'business' or 'technical'")

    result = generate_report(start_date, end_date, typ, path_to_save)
    print(f"Report saved to {result['path']}")