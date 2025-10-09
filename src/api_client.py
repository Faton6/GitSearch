# coding: utf-8
"""API client for GitSearch database operations.

This module provides a centralized way to interact with the GitSearch database,
replacing direct database connections scattered throughout the application.
Unlike the external API version, this client directly connects to MariaDB.

Field Mapping:
--------------
This client implements automatic field name mapping to ensure compatibility
between different project versions with different database schemas:

- accounts table: 'company_id' -> 'related_company_id'
  This allows Connector.py to remain synchronized with other projects that
  use 'company_id', while this database uses 'related_company_id'.

To add new field mappings, update the FIELD_MAPPING dictionary in GitSearchAPIClient class.
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
    
    # Маппинг таблиц для совместимости с ver2 API
    TABLE_MAPPING = {
        'company': 'companies',
        'dork': 'dorks',
        'leak': 'leak',
        'raw_report': 'raw_report',
        'leak_stats': 'leak_stats',
        'account': 'account',
        'related_accounts_leaks': 'related_accounts_leaks'
    }
    
    # Маппинг полей для совместимости между проектами
    # Формат: {'table_name': {'source_field': 'target_field'}}
    FIELD_MAPPING = {
        'accounts': {
            'company_id': 'related_company_id'
        }
    }
    
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
    
    def _make_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compatibility method for ver2 API-style requests.
        
        Emulates API interface but works with local database.
        Expected data format:
        {
            'tname': table_name,
            'dname': database_name,
            'action': 'get'|'add'|'upd',
            'content': {...},
            'limit': int,
            'offset': int
        }
        """
        try:
            table_name = data.get('tname')
            dname = data.get('dname', '')
            action = data.get('action')
            content = data.get('content', {})
            limit = data.get('limit', 100)
            offset = data.get('offset', 0)
            
            # Маппинг полей для companies
            field_mapping = {
                'companies': {
                    'name': 'company_name'  # name в ver2 -> company_name в локальной БД
                }
            }
            
            # Конвертируем имя таблицы используя маппинг класса
            actual_table = self.TABLE_MAPPING.get(table_name, table_name)
            
            if action == 'get':
                results = self.get_data(actual_table, content, limit, offset)
                
                # Конвертируем поля обратно для совместимости с ver2
                if actual_table in field_mapping:
                    converted_results = []
                    for row in results:
                        converted_row = dict(row)
                        for old_field, new_field in field_mapping[actual_table].items():
                            if new_field in converted_row:
                                converted_row[old_field] = converted_row[new_field]
                        converted_results.append(converted_row)
                    results = converted_results
                
                return {
                    'auth': True,
                    'content': results if results else [0]
                }
            elif action == 'add':
                result_id = self.add_data(actual_table, content)
                return {
                    'auth': True,
                    'content': {'id': result_id} if result_id else 'ERROR: Failed to add data'
                }
            elif action == 'upd':
                affected = self.upd_data(actual_table, content)
                return {
                    'auth': True,
                    'content': {'affected': affected if affected is not None else 0}
                }
            else:
                return {
                    'auth': False,
                    'content': f'ERROR: Unknown action {action}'
                }
        except Exception as e:
            logger.error(f"Error in _make_request: {e}")
            return {
                'auth': False,
                'content': f'ERROR: {str(e)}'
            }
    
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
        # Применяем маппинг таблиц для совместимости с ver2 API
        actual_table = self.TABLE_MAPPING.get(table_name, table_name)
        
        results = []
        conn = self._get_connection()
        if not conn:
            return results
        
        try:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            # Build query
            query = f"SELECT * FROM {actual_table}"
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
    
    def _map_fields(self, table_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map field names for compatibility between projects.
        
        Parameters
        ----------
        table_name : str
            Name of the table
        data : dict
            Original data dictionary
            
        Returns
        -------
        dict
            Data with mapped field names
        """
        if table_name not in self.FIELD_MAPPING:
            return data
        
        mapped_data = {}
        field_map = self.FIELD_MAPPING[table_name]
        
        for key, value in data.items():
            # Если есть маппинг для этого поля, используем целевое имя
            mapped_key = field_map.get(key, key)
            mapped_data[mapped_key] = value
        
        return mapped_data
    
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
        # Применяем маппинг таблиц для совместимости с ver2 API
        actual_table = self.TABLE_MAPPING.get(table_name, table_name)
        
        # Применяем маппинг полей для совместимости между проектами
        mapped_data = self._map_fields(actual_table, data)
        
        conn = self._get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # Build INSERT query
            columns = list(mapped_data.keys())
            placeholders = ', '.join(['%s'] * len(columns))
            column_names = ', '.join(columns)
            
            query = f"INSERT INTO {actual_table} ({column_names}) VALUES ({placeholders})"
            values = [mapped_data[col] for col in columns]
            
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
        
        # Применяем маппинг таблиц для совместимости с ver2 API
        actual_table = self.TABLE_MAPPING.get(table_name, table_name)
        
        # Применяем маппинг полей для совместимости между проектами
        mapped_data = self._map_fields(actual_table, data)
        
        conn = self._get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # Build UPDATE query
            record_id = mapped_data['id']
            update_data = {k: v for k, v in mapped_data.items() if k != 'id'}
            
            set_clauses = ', '.join([f"{col}=%s" for col in update_data.keys()])
            query = f"UPDATE {actual_table} SET {set_clauses} WHERE id=%s"
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
