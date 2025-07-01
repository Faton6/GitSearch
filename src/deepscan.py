"""
Deep Scanning Module for GitSearch

This module provides functionality for performing deep scans on repositories
and scanning repositories from provided URL lists.

Classes:
    DeepScanManager: Manages comprehensive deep scanning of repositories marked in database
    ListScanManager: Handles scanning of repositories from URL lists

Functions:
    deep_scan(): Legacy wrapper for deep scanning functionality  
    list_search(): Scans repositories from a file containing URLs
    _list_scan(): Deprecated legacy function for list scanning

Usage:
    # Deep scan repositories marked in database
    deep_scan()
    
    # Scan repositories from URL list file  
    list_search("/path/to/urls.txt")
    
    # Or use default file location
    list_search()  # Uses temp/list_to_scan.txt

Author: GitSearch Team
Date: 2025-01-14
"""

import os
from typing import Dict, List, Optional, Tuple, Any

from src.logger import logger
from src import Connector
from src import constants
from src.LeakObj import RepoObj
from src import filters
from src.searcher.scanner import Scanner

# Deep scan configuration constants
DEEP_SCAN_CONFIG = {
    'max_retries': 3,
    'timeout_multiplier': 3.0,
    'batch_size': 5,
    'enable_ai_analysis': True,
    'required_scanners': ['gitleaks', 'gitsecrets', 'grepscan', 'deepsecrets', 'ioc_finder']
}

LIST_SCAN_CONFIG = {
    'max_urls_per_batch': 10,
    'url_validation_enabled': True,
    'auto_mark_processed': True,
    'supported_hosts': ['github.com', 'gist.github.com']
}


class DeepScanManager:
    """
    Manages deep scanning operations for repositories.
    
    This class handles the process of performing comprehensive scans on repositories
    that have been marked for deep scanning in the database.
    """
    
    def __init__(self):
        self.urls_to_scan: constants.AutoVivification = constants.AutoVivification()
        
    def _get_urls_for_deep_scan(self) -> Dict[str, List[Any]]:
        """
        Retrieve URLs from database that are marked for deep scanning.
        
        Returns:
            Dict containing URLs and their associated data for deep scanning
        """
        urls_to_scan = constants.AutoVivification()
        url_dump = constants.dork_dict_from_DB
        
        for url_from_db in url_dump.keys():
            url_data = url_dump[url_from_db]
            if (isinstance(url_data[0], str) and 
                int(url_data[0]) == constants.RESULT_CODE_TO_DEEPSCAN):
                urls_to_scan[url_from_db] = [url_data[1], None, None]
                
        logger.info(f"Found {len(urls_to_scan)} URLs marked for deep scanning")
        return urls_to_scan
    
    def _perform_deep_scan(self, url: str, database_id: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Perform deep scan on a single repository URL.
        
        Args:
            url: Repository URL to scan
            database_id: Database identifier for the repository
            
        Returns:
            Tuple of (scan_results, ai_report)
        """
        try:
            # Create a mock RepoObj for the checker
            mock_repo_data = {
                'full_name': '/'.join(url.split('/')[-2:]),
                'owner': {'login': url.split('/')[-2]},
                'size': 0  # Will be updated during scanning
            }
            repo_obj = RepoObj(url, mock_repo_data, 'deep_scan_dork')
            
            # Initialize checker with deep scan mode (mode=3)
            checker = filters.Checker(
                url=url,
                dork='deep_scan',
                obj=repo_obj,
                mode=3  # Deep scan mode
            )
            
            # Perform the scanning process
            checker.clone()
            scan_results, ai_report = checker.run()
            
            return scan_results, ai_report
            
        except Exception as e:
            logger.error(f"Error during deep scan of {url}: {e}")
            return None, None
    
    def _compare_scan_results(self, url: str, database_id: str, new_results: Dict) -> bool:
        """
        Compare new scan results with existing database results.
        
        Args:
            url: Repository URL
            database_id: Database identifier
            new_results: New scan results to compare
            
        Returns:
            True if results are different (need update), False if same
        """
        try:
            raw_report = Connector.dump_row_data_from_DB(database_id)
            
            # Compare key scanner results using configured scanners
            scanner_types = ['grepscan', 'trufflehog', 'deepsecrets', 'gitleaks', 'gitsecrets']
            
            differences_found = 0
            for scanner_type in scanner_types:
                old_count = len(raw_report.get(scanner_type, {}))
                new_count = len(new_results.get(scanner_type, {}))
                
                if old_count != new_count:
                    differences_found += 1
                    logger.info(f"Difference found in {scanner_type}: {old_count} vs {new_count}")
            
            # Consider results different if we found any differences
            if differences_found > 0:
                logger.info(f"Found {differences_found} differences for {url}")
                return True
            else:
                logger.info(f"No significant changes found for {url}")
                return False
                    
        except Exception as e:
            logger.error(f"Error comparing results for {url}: {e}")
            return True  # Assume difference if comparison fails
    
    def run(self) -> None:
        """
        Execute the complete deep scanning process.
        """
        logger.info("Starting deep scan process")
        
        # Step 1: Get URLs marked for deep scanning
        self.urls_to_scan = self._get_urls_for_deep_scan()
        
        if not self.urls_to_scan:
            logger.info("No URLs found for deep scanning")
            return
        
        # Step 2: Process URLs in batches
        url_list = list(self.urls_to_scan.keys())
        batch_size = DEEP_SCAN_CONFIG['batch_size']
        
        for i in range(0, len(url_list), batch_size):
            batch_urls = url_list[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}: {len(batch_urls)} URLs")
            
            self._process_batch(batch_urls)
        
        # Step 3: Filter out URLs with unchanged results and update database
        self._finalize_results()
        
        logger.info("Deep scan process completed")
    
    def _process_batch(self, batch_urls: List[str]) -> None:
        """
        Process a batch of URLs for deep scanning.
        
        Args:
            batch_urls: List of URLs to process in this batch
        """
        for url in batch_urls:
            database_id = self.urls_to_scan[url][0]
            logger.info(f"Deep scanning: {url}")
            
            # Retry logic for failed scans
            for attempt in range(DEEP_SCAN_CONFIG['max_retries']):
                try:
                    scan_result, ai_report = self._perform_deep_scan(url, database_id)
                    if scan_result is not None:
                        self.urls_to_scan[url][1] = scan_result
                        self.urls_to_scan[url][2] = ai_report
                        break
                    else:
                        logger.warning(f"Scan attempt {attempt + 1} failed for {url}")
                        
                except Exception as e:
                    logger.error(f"Error in scan attempt {attempt + 1} for {url}: {e}")
                    
            else:
                logger.error(f"All scan attempts failed for {url}, removing from update list")
                del self.urls_to_scan[url]
    
    def _finalize_results(self) -> None:
        """
        Compare results and update database with changed repositories.
        """
        urls_to_update = {}
        
        for url in list(self.urls_to_scan.keys()):
            database_id = self.urls_to_scan[url][0]
            new_results = self.urls_to_scan[url][1]
            
            if new_results and self._compare_scan_results(url, database_id, new_results):
                urls_to_update[url] = self.urls_to_scan[url]
            else:
                del self.urls_to_scan[url]
        
        # Update database with new results
        if urls_to_update:
            logger.info(f"Updating database with results for {len(urls_to_update)} repositories")
            Connector.dump_to_DB(mode=1, result_deepscan=urls_to_update)
        else:
            logger.info("No repositories require database updates")


def deep_scan():
    """
    Legacy function wrapper for deep scanning.
    
    This function maintains backward compatibility while using the new
    DeepScanManager class for improved code organization.
    """
    try:
        deep_scan_manager = DeepScanManager()
        deep_scan_manager.run()
    except Exception as e:
        logger.error(f"Error in deep scan process: {e}")
        raise


class ListScanManager:
    """
    Manages scanning of repositories from a provided list of URLs.
    
    This class handles the process of scanning GitHub repositories
    from a list provided in a text file.
    """
    
    def __init__(self, input_file_path: Optional[str] = None):
        """
        Initialize the ListScanManager.
        
        Args:
            input_file_path: Path to file containing URLs to scan.
                           Defaults to temp/list_to_scan.txt if not provided.
        """
        self.input_file_path = (input_file_path if input_file_path 
                               else str(constants.MAIN_FOLDER_PATH / "temp" / "list_to_scan.txt"))
    
    def _read_urls_from_file(self) -> List[str]:
        """
        Read and validate URLs from the input file.
        
        Returns:
            List of valid URLs to scan
        """
        if not os.path.exists(self.input_file_path):
            logger.info(f"List scan file not found: {self.input_file_path}")
            return []
        
        try:
            with open(self.input_file_path, 'r', encoding='utf-8') as file:
                url_list = [
                    line.strip() for line in file 
                    if line.strip() and not line.strip().startswith('//')
                ]
            
            if not url_list:
                logger.info("No valid URLs found in the list scan file.")
                return []
            
            # Validate URLs
            valid_urls = []
            for url in url_list:
                if self._is_valid_github_url(url):
                    valid_urls.append(url)
                else:
                    logger.warning(f"Skipping invalid URL: {url}")
            
            logger.info(f"Found {len(valid_urls)} valid URLs to scan")
            return valid_urls
            
        except Exception as e:
            logger.error(f"Error reading URLs from file {self.input_file_path}: {e}")
            return []
    
    def _is_valid_github_url(self, url: str) -> bool:
        """
        Validate if the URL is a valid GitHub repository URL.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid GitHub URL, False otherwise
        """
        if not LIST_SCAN_CONFIG['url_validation_enabled']:
            return True
            
        # Check if URL contains supported hosts
        for host in LIST_SCAN_CONFIG['supported_hosts']:
            if host in url and url.startswith(('https://', 'http://')):
                try:
                    parts = url.split('/')
                    return len(parts) >= 5 and parts[2] in LIST_SCAN_CONFIG['supported_hosts']
                except (IndexError, AttributeError):
                    return False
        return False
    
    def _create_repo_objects(self, url_list: List[str]) -> List[RepoObj]:
        """
        Convert URLs to RepoObj instances for scanning.
        
        Args:
            url_list: List of repository URLs
            
        Returns:
            List of RepoObj instances
        """
        repo_objs = []
        
        for url in url_list:
            try:
                parts = url.split('/')
                if len(parts) >= 5:
                    owner = parts[3]
                    repo_name = parts[4]
                    owner_repo = f"{owner}/{repo_name}"
                    
                    mock_repo_data = {
                        'full_name': owner_repo,
                        'owner': {'login': owner}
                    }
                    
                    repo_obj = RepoObj(url, mock_repo_data, 'list_scan_dork')
                    repo_objs.append(repo_obj)
                    
            except (IndexError, ValueError) as e:
                logger.warning(f"Could not parse URL for RepoObj: {url} - {e}")
                continue
        
        return repo_objs
    
    def _mark_urls_as_processed(self, url_list: List[str]) -> None:
        """
        Mark processed URLs by prefixing them with '//' in the file.
        
        Args:
            url_list: List of URLs that were processed
        """
        try:
            with open(self.input_file_path, 'w', encoding='utf-8') as file:
                for url in url_list:
                    file.write(f"//{url}\n")
            logger.info(f"Marked {len(url_list)} URLs as processed")
        except Exception as e:
            logger.error(f"Error marking URLs as processed: {e}")
    
    def _scan_repositories(self, repo_objs: List[RepoObj]) -> None:
        """
        Scan the repository objects using the Scanner.
        
        Args:
            repo_objs: List of repository objects to scan
        """
        if not repo_objs:
            logger.info("No repository objects to scan")
            return
        
        try:
            # Create a temporary entry in dork_dict for the scanner
            temp_key = 'list_scan_temp'
            if temp_key not in constants.dork_dict:
                constants.dork_dict[temp_key] = []
            
            # Add repository URLs to the temporary dork_dict entry
            repo_urls = [obj.repo_url for obj in repo_objs]
            constants.dork_dict[temp_key].extend(repo_urls)
            
            # Use the existing Scanner to process the repositories
            scanner = Scanner(temp_key)
            scanner.gitscan()
            
            # Clean up temporary entry
            if temp_key in constants.dork_dict:
                del constants.dork_dict[temp_key]
                
            logger.info(f"Successfully processed {len(repo_objs)} repositories")
            
        except Exception as e:
            logger.error(f"Error during repository scanning: {e}")
            raise
    
    def run(self) -> None:
        """
        Execute the complete list scanning process.
        """
        logger.info(f"Starting list scan from file: {self.input_file_path}")
        
        # Step 1: Read URLs from file
        url_list = self._read_urls_from_file()
        if not url_list:
            return
        
        # Step 2: Create repository objects
        repo_objs = self._create_repo_objects(url_list)
        if not repo_objs:
            logger.warning("No valid repository objects created")
            return
        
        # Step 3: Scan repositories
        self._scan_repositories(repo_objs)
        
        # Step 4: Dump results and mark URLs as processed
        filters.dumping_data()
        self._mark_urls_as_processed(url_list)
        
        logger.info("List scan process completed")


def list_search(input_file_path: Optional[str] = None) -> None:
    """
    Scans GitHub repositories from a list of URLs provided in a file.
    
    Args:
        input_file_path: Path to file containing URLs to scan.
                        If not provided, defaults to temp/list_to_scan.txt.
    """
    try:
        list_scan_manager = ListScanManager(input_file_path)
        list_scan_manager.run()
    except Exception as e:
        logger.error(f"Error in list search process: {e}")
        raise


def _list_scan(url_list: List[str]) -> None:
    """
    Legacy function for backward compatibility.
    
    Args:
        url_list: List of URLs to scan
        
    Deprecated: Use ListScanManager.run() instead
    """
    logger.warning("_list_scan is deprecated. Use ListScanManager instead.")
    
    try:
        # Create temporary file with URLs
        temp_file = str(constants.MAIN_FOLDER_PATH / "temp" / "temp_list_scan.txt")
        with open(temp_file, 'w', encoding='utf-8') as f:
            for url in url_list:
                f.write(f"{url}\n")
        
        # Use ListScanManager
        list_scan_manager = ListScanManager(temp_file)
        list_scan_manager.run()
        
        # Clean up temporary file
        if os.path.exists(temp_file):
            os.remove(temp_file)
            
    except Exception as e:
        logger.error(f"Error in legacy _list_scan: {e}")
        raise
