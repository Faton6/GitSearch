# coding: utf-8
"""API client for GitSearch database operations.

This module provides a centralized way to interact with the GitSearch database,
replacing direct database connections scattered throughout the application.
Unlike the external API version, this client directly connects to MariaDB.
"""

import os
import pymysql
import json
import base64
import bz2
from typing import Dict, List, Any, Optional
from src import constants
from src.logger import logger


class GitSearchAPIClient:
    """Client for interacting with GitSearch database."""
    
    def __init__(self):
        self.db_config = {
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', 'changeme'),
            'host': constants.url_DB,
            'port': 3306,
            'database': 'Gitsearch'
        }
    
    def _get_connection(self):
        """Get database connection."""
        try:
            conn = pymysql.connect(**self.db_config)
            return conn
        except pymysql.Error as e:
            logger.error(f"Error connecting to MariaDB: {e}")
            return None
    
    def get_data(self, table_name: str, filters: Optional[Dict[str, Any]] = None, 
                 limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get data from specified table with filters.
        
        Parameters
        ----------
        table_name : str
            Name of the table to query
        filters : dict, optional
            Dictionary of column:value pairs for WHERE clause
        limit : int
            Maximum number of records to return per query
        offset : int
            Starting offset for pagination
            
        Returns
        -------
        List[Dict[str, Any]]
            List of records as dictionaries
        """
        results = []
        conn = self._get_connection()
        if not conn:
            return results
        
        try:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            # Build query
            query = f"SELECT * FROM {table_name}"
            params = []
            
            if filters:
                where_clauses = []
                for key, value in filters.items():
                    where_clauses.append(f"{key}=%s")
                    params.append(value)
                query += " WHERE " + " AND ".join(where_clauses)
            
            query += f" LIMIT {limit} OFFSET {offset}"
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_data for table {table_name}: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def add_data(self, table_name: str, data: Dict[str, Any]) -> Optional[int]:
        """Add data to specified table.
        
        Parameters
        ----------
        table_name : str
            Name of the table
        data : dict
            Dictionary of column:value pairs to insert
            
        Returns
        -------
        int or None
            ID of inserted record, or None on failure
        """
        conn = self._get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # Build INSERT query
            columns = list(data.keys())
            placeholders = ', '.join(['%s'] * len(columns))
            column_names = ', '.join(columns)
            
            query = f"INSERT INTO {table_name} ({column_names}) VALUES ({placeholders})"
            values = [data[col] for col in columns]
            
            cursor.execute(query, values)
            conn.commit()
            
            return cursor.lastrowid
        except pymysql.Error as e:
            logger.error(f"Error in add_data for table {table_name}: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
    
    def upd_data(self, table_name: str, data: Dict[str, Any]) -> Optional[int]:
        """Update data in specified table.
        
        Parameters
        ----------
        table_name : str
            Name of the table
        data : dict
            Dictionary containing 'id' key and column:value pairs to update
            
        Returns
        -------
        int or None
            Number of affected rows, or None on failure
        """
        if 'id' not in data:
            logger.error(f"upd_data requires 'id' in data for table {table_name}")
            return None
        
        conn = self._get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # Build UPDATE query
            record_id = data['id']
            update_data = {k: v for k, v in data.items() if k != 'id'}
            
            set_clauses = ', '.join([f"{col}=%s" for col in update_data.keys()])
            query = f"UPDATE {table_name} SET {set_clauses} WHERE id=%s"
            values = list(update_data.values()) + [record_id]
            
            cursor.execute(query, values)
            conn.commit()
            
            affected = cursor.rowcount
            if affected == 0:
                logger.warning(f"No rows affected in upd_data for {table_name} with id={record_id}")
            
            return affected
        except pymysql.Error as e:
            logger.error(f"Error in upd_data for table {table_name}: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
    
    def get_leaks_in_period(self, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Get all leaks in specified date range.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        List[Dict[str, Any]]
            List of leak records
        """
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            query = """
                SELECT * FROM leak 
                WHERE found_at BETWEEN %s AND %s
                ORDER BY found_at DESC
            """
            cursor.execute(query, (start_date, end_date))
            results = cursor.fetchall()
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_leaks_in_period: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_leak_stats_for_leaks(self, leak_ids: List[int]) -> List[Dict[str, Any]]:
        """Get leak statistics for specified leak IDs.
        
        Parameters
        ----------
        leak_ids : List[int]
            List of leak IDs
            
        Returns
        -------
        List[Dict[str, Any]]
            List of leak_stats records
        """
        if not leak_ids:
            return []
        
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            placeholders = ', '.join(['%s'] * len(leak_ids))
            query = f"SELECT * FROM leak_stats WHERE leak_id IN ({placeholders})"
            cursor.execute(query, leak_ids)
            results = cursor.fetchall()
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_leak_stats_for_leaks: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_raw_reports_for_leaks(self, leak_ids: List[int]) -> List[Dict[str, Any]]:
        """Get raw reports for specified leak IDs.
        
        Parameters
        ----------
        leak_ids : List[int]
            List of leak IDs
            
        Returns
        -------
        List[Dict[str, Any]]
            List of raw_report records
        """
        if not leak_ids:
            return []
        
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            placeholders = ', '.join(['%s'] * len(leak_ids))
            query = f"SELECT * FROM raw_report WHERE leak_id IN ({placeholders})"
            cursor.execute(query, leak_ids)
            results = cursor.fetchall()
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_raw_reports_for_leaks: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def count_leaks_in_period(self, start_date: str, end_date: str) -> int:
        """Count total leaks in period.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        int
            Count of leaks
        """
        conn = self._get_connection()
        if not conn:
            return 0
        
        try:
            cursor = conn.cursor()
            query = "SELECT COUNT(*) FROM leak WHERE found_at BETWEEN %s AND %s"
            cursor.execute(query, (start_date, end_date))
            result = cursor.fetchone()
            return result[0] if result else 0
        except pymysql.Error as e:
            logger.error(f"Error in count_leaks_in_period: {e}")
            return 0
        finally:
            if conn:
                conn.close()
    
    def get_leaks_by_result(self, start_date: str, end_date: str) -> Dict[str, int]:
        """Get leak counts grouped by result status.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        Dict[str, int]
            Dictionary mapping result status to count
        """
        conn = self._get_connection()
        if not conn:
            return {}
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT result, COUNT(*) as count 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s
                GROUP BY result
            """
            cursor.execute(query, (start_date, end_date))
            results = cursor.fetchall()
            return {str(row[0]): row[1] for row in results}
        except pymysql.Error as e:
            logger.error(f"Error in get_leaks_by_result: {e}")
            return {}
        finally:
            if conn:
                conn.close()
    
    def get_leaks_by_type(self, start_date: str, end_date: str, limit: int = 10) -> List[tuple]:
        """Get top leak types in period.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
        limit : int
            Maximum number of types to return
            
        Returns
        -------
        List[tuple]
            List of (leak_type, count) tuples
        """
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT leak_type, COUNT(*) as count 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s
                GROUP BY leak_type
                ORDER BY count DESC
                LIMIT %s
            """
            cursor.execute(query, (start_date, end_date, limit))
            results = cursor.fetchall()
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_leaks_by_type: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_leaks_by_level(self, start_date: str, end_date: str) -> List[tuple]:
        """Get leak counts grouped by severity level.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        List[tuple]
            List of (level, count) tuples
        """
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT level, COUNT(*) as count 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s
                GROUP BY level
            """
            cursor.execute(query, (start_date, end_date))
            results = cursor.fetchall()
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_leaks_by_level: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_average_severity(self, start_date: str, end_date: str) -> float:
        """Calculate average severity level in period.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        float
            Average severity level
        """
        conn = self._get_connection()
        if not conn:
            return 0.0
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT AVG(level) 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s
            """
            cursor.execute(query, (start_date, end_date))
            result = cursor.fetchone()
            return float(result[0]) if result and result[0] is not None else 0.0
        except pymysql.Error as e:
            logger.error(f"Error in get_average_severity: {e}")
            return 0.0
        finally:
            if conn:
                conn.close()
    
    def get_serious_leaks(self, start_date: str, end_date: str, min_level: int = 1) -> List[tuple]:
        """Get serious leaks (level >= min_level) in period.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
        min_level : int
            Minimum severity level
            
        Returns
        -------
        List[tuple]
            List of (url, leak_type, level, found_at) tuples
        """
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT url, leak_type, level, found_at 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s AND level >= %s
                ORDER BY level DESC, found_at DESC
            """
            cursor.execute(query, (start_date, end_date, min_level))
            results = cursor.fetchall()
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_serious_leaks: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_unique_companies_count(self, start_date: str, end_date: str) -> int:
        """Get count of unique companies affected in period.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        int
            Count of unique companies
        """
        conn = self._get_connection()
        if not conn:
            return 0
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT COUNT(DISTINCT company_id) 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s AND company_id IS NOT NULL AND company_id != 0
            """
            cursor.execute(query, (start_date, end_date))
            result = cursor.fetchone()
            return result[0] if result else 0
        except pymysql.Error as e:
            logger.error(f"Error in get_unique_companies_count: {e}")
            return 0
        finally:
            if conn:
                conn.close()
    
    def get_unique_repositories_count(self, start_date: str, end_date: str) -> int:
        """Get count of unique repositories scanned in period.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        int
            Count of unique repositories
        """
        conn = self._get_connection()
        if not conn:
            return 0
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT COUNT(DISTINCT url) 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s
            """
            cursor.execute(query, (start_date, end_date))
            result = cursor.fetchone()
            return result[0] if result else 0
        except pymysql.Error as e:
            logger.error(f"Error in get_unique_repositories_count: {e}")
            return 0
        finally:
            if conn:
                conn.close()
    
    def get_daily_leak_counts(self, start_date: str, end_date: str) -> List[tuple]:
        """Get daily leak counts in period.
        
        Parameters
        ----------
        start_date, end_date : str
            Date range in YYYY-MM-DD format
            
        Returns
        -------
        List[tuple]
            List of (date, count) tuples sorted by date
        """
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            query = """
                SELECT DATE(found_at) as date, COUNT(*) as count 
                FROM leak 
                WHERE found_at BETWEEN %s AND %s
                GROUP BY DATE(found_at)
                ORDER BY date
            """
            cursor.execute(query, (start_date, end_date))
            results = cursor.fetchall()
            return results
        except pymysql.Error as e:
            logger.error(f"Error in get_daily_leak_counts: {e}")
            return []
        finally:
            if conn:
                conn.close()
