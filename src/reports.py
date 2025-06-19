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
    conn: Any = None,
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

    print(f"Generating {report_type} report for period {start_date} - {end_date}")
    
    close_conn = False
    if conn is None:
        conn, cursor = Connector.connect_to_database()
        close_conn = True
        if not conn or not cursor:
            raise RuntimeError("Database connection failed")
    else:
        cursor = conn.cursor()
    


    output_dir = output_dir or os.path.join(constants.MAIN_FOLDER_PATH, "reports")

    data: Dict[str, Any] = {}
    logo_path = os.path.join(constants.MAIN_FOLDER_PATH, "media", "logo_gitsearch.png")

    # --- Business level statistics -----------------------------------------
    _execute(
        cursor,
        "SELECT COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s",
        (start_date, end_date),
    )
    data["total_leaks"] = cursor.fetchone()[0]

    _execute(
        cursor,
        "SELECT result, COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s GROUP BY result",
        (start_date, end_date),
    )
    data["status_breakdown"] = cursor.fetchall()

    _execute(
        cursor,
        "SELECT AVG(level) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s",
        (start_date, end_date),
    )
    avg = cursor.fetchone()[0]
    data["average_severity"] = float(avg) if avg is not None else 0.0

    _execute(
        cursor,
        "SELECT DATE(created_at) AS day, COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s GROUP BY day ORDER BY day",
        (start_date, end_date),
    )
    data["daily_counts"] = cursor.fetchall()
    _execute(
        cursor,
        "SELECT leak_type, COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s GROUP BY leak_type ORDER BY COUNT(*) DESC LIMIT 5",
        (start_date, end_date),
    )
    data["top_leak_types"] = cursor.fetchall()

    _execute(
        cursor,
        "SELECT url, leak_type, level, found_at FROM leak WHERE DATE(created_at) BETWEEN %s AND %s ORDER BY level DESC, found_at DESC LIMIT 5",
        (start_date, end_date),
    )
    data["top_leaks"] = cursor.fetchall()

    _execute(
        cursor,
        "SELECT COUNT(DISTINCT company_id) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s",
        (start_date, end_date),
    )
    data["unique_companies"] = cursor.fetchone()[0]

    _execute(
        cursor,
        "SELECT COALESCE(c.company_name, l.company_id) AS name, COUNT(*) FROM leak l LEFT JOIN companies c ON l.company_id=c.id WHERE DATE(l.created_at) BETWEEN %s AND %s GROUP BY l.company_id ORDER BY COUNT(*) DESC LIMIT 5",
        (start_date, end_date),
    )
    data["top_companies"] = cursor.fetchall()

    # --- Technical additions ----------------------------------------------
    if report_type == "technical":
        _execute(
        cursor,
            "SELECT level, COUNT(*) FROM leak WHERE DATE(created_at) BETWEEN %s AND %s GROUP BY level",
            (start_date, end_date),
        )
        data["level_breakdown"] = cursor.fetchall()

        _execute(
        cursor,
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

        _execute(
        cursor, # TODO check if "error" or "not state" in raw_report 
            """
            SELECT COUNT(*) FROM raw_report rr
            JOIN leak l ON rr.leak_id = l.id
            WHERE DATE(l.created_at) BETWEEN %s AND %s
            """,
            (start_date, end_date),
        )
        data["error_reports"] = cursor.fetchone()[0]

        _execute(
        cursor,
            "SELECT url, leak_type, level, found_at FROM leak WHERE level >= 0 AND DATE(created_at) BETWEEN %s AND %s",
            (start_date, end_date),
        )
        data["serious_leaks"] = cursor.fetchall()

    # -- Generate HTML ------------------------------------------------------
    report_title = f"{report_type.capitalize()} report"
    html_lines: List[str] = [
        "<html>",
        "<head><meta charset='utf-8'><title>%s</title>" % report_title,
        "<style>body{font-family:Arial,sans-serif;background:#f0f6ff;color:#333;}"
        "header{background:#004c99;color:#fff;padding:10px;}"
        "h1,h2{color:#004c99;}table{border-collapse:collapse;width:100%;margin-bottom:20px;}"
        "th{background:#1a75d1;color:#fff;}th,td{border:1px solid #a0c4ff;padding:6px;}"
        "</style>",
        "</head><body>",
        f"<header><img src='{logo_path}' alt='logo' style='height:40px;vertical-align:middle;'>"
        f" <span style='font-size:24px;margin-left:10px;'>{report_title}</span></header>",
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

    dates = [d for d, _ in data["daily_counts"]]
    counts = [c for _, c in data["daily_counts"]]
    html_lines.extend([
        "<canvas id='dailyChart' width='600' height='300'></canvas>",
        "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>",
        f"<script>new Chart(document.getElementById('dailyChart').getContext('2d'),{{type:'line',data:{{labels:{dates},datasets:[{{label:'Leaks',data:{counts},borderColor:'#004c99',backgroundColor:'#1a75d1',fill:false}}]}},options:{{scales:{{y:{{beginAtZero:true}}}}}}}});</script>",
    ])

    html_lines.extend([
        f"<p>Unique companies affected: {data['unique_companies']}</p>",
        "<h2>Top companies</h2>",
        "<table><tr><th>Company</th><th>Count</th></tr>",
    ])
    for name, cnt in data["top_companies"]:
        html_lines.append(f"<tr><td>{name}</td><td>{cnt}</td></tr>")
    html_lines.append("</table>")

    html_lines.extend([
        "<h2>Top leak types</h2>",
        "<table><tr><th>Type</th><th>Count</th></tr>",
    ])
    for ltype, cnt in data["top_leak_types"]:
        html_lines.append(f"<tr><td>{ltype}</td><td>{cnt}</td></tr>")
    html_lines.append("</table>")

    html_lines.extend([
        "<h2>Top leaks</h2>",
        "<table><tr><th>Found at</th><th>URL</th><th>Type</th><th>Level</th></tr>",
    ])
    for url, ltype, lvl, found in data["top_leaks"]:
        html_lines.append(f"<tr><td>{found}</td><td>{url}</td><td>{ltype}</td><td>{lvl}</td></tr>")
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

    if close_conn:
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