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
from typing import Dict, List, Optional, Any, Tuple

from src.logger import logger
from src import Connector
from src import constants
from src.LeakObj import RepoObj, GlistObj
from src import filters
from src import utils
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
        url_dump = Connector.dump_from_DB(mode=1)
        
        for url_from_db in url_dump.keys():
            url_data = url_dump[url_from_db]
            if (isinstance(url_data, str) and 
                int(url_data[0]) == constants.RESULT_CODE_TO_DEEPSCAN) or (isinstance(url_data[0], int) and 
                url_data[0] == constants.RESULT_CODE_TO_DEEPSCAN):
                urls_to_scan[url_from_db] = [url_data[1], None]
                
        logger.info(f"Found {len(urls_to_scan)} URLs marked for deep scanning")
        return urls_to_scan
 
 
    def _get_urls_for_deep_scan_with_no_results(self):
        """
        Retrieve URLs from database that are marked as not research yet (4).
        
        Returns:
            Dict containing URLs and their associated data for deep rescanning
        """
        
        urls_to_scan = constants.AutoVivification()
        url_dump = Connector.dump_from_DB(mode=1)
        
        for url_from_db in url_dump.keys():
            url_data = url_dump[url_from_db]
            if (isinstance(url_data[0], str) and 
                int(url_data[0]) == constants.RESULT_CODE_TO_SEND) or (isinstance(url_data[0], int) and 
                url_data[0] == constants.RESULT_CODE_TO_SEND):
                urls_to_scan[url_from_db] = [url_data[1], None]
                
        logger.info(f"Found {len(urls_to_scan)} URLs not analysed yet")
        return urls_to_scan
    
    def _perform_gistobj_deep_scan(self, url: str, leak_id: str, company_id: int) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Perform deep scan on a single Gist URL.
        
        Args:
            url: Gist URL to scan
            leak_id: Database identifier for the Gist
            
        Returns:
            Tuple of (scan_results, ai_report)
        """
        try:
            # Create a mock GlistObj for the checker
            mock_repo_data = {
                'full_name': '/'.join(url.split('/')[-2:]),
                'owner': {'login': url.split('/')[-2]},
                'size': 0  # Will be updated during scanning
            }
            
            
            company_name = Connector.get_company_name(company_id=company_id)
            glist_obj = GlistObj(url, company_name, company_id)
            glist_obj.stats.get_repo_stats()
            checker = filters.Checker(url=url, dork=company_name, obj=glist_obj, mode=2)
            checker.clone()
            checker.run()
                       
            return glist_obj
            
        except Exception as e:
            logger.error(f"Error during deep scan of {url}: {e}")
            return None
    def _perform_leakobj_deep_scan(self, url: str, leak_id: str, company_id: int) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Perform deep scan on a single repository URL.
        
        Args:
            url: Repository URL to scan
            leak_id: Database identifier for the repository
            
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
            company_name = Connector.get_company_name(company_id=company_id)
            repo_obj = RepoObj(url, mock_repo_data, company_id)
            
            # Initialize checker with deep scan mode (mode=3)
            checker = filters.Checker(url=url, dork=company_name, obj=repo_obj, mode=3)
            
            # Perform the scanning process
            checker.clone()
            checker.run()
            
            return repo_obj
            
        except Exception as e:
            logger.error(f"Error during deep scan of {url}: {e}")
            return None
    
 
    def run(self, mode=0) -> None:
        """
        Execute the complete deep scanning process.
        """
        logger.info("Starting deep scan process")
        
        if mode == 0:
            self.urls_to_scan = self._get_urls_for_deep_scan()
        elif mode == 1:
            self.urls_to_scan = self._get_urls_for_deep_scan_with_no_results()
        else:
            logger.error('Incorrect mode of deepscan, use standart mode = 0')
            self.urls_to_scan = self._get_urls_for_deep_scan()
        
        if not self.urls_to_scan:
            logger.info("No URLs found for deep scanning")
            return
        
        # Step 2: Process URLs in batches
        url_list = list(self.urls_to_scan.keys())
        batch_size = DEEP_SCAN_CONFIG['batch_size']
        counter = 0
        for i in range(0, len(url_list), batch_size):
            batch_urls = url_list[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}: {len(batch_urls)} URLs")
            
            self._process_batch(batch_urls)

            if counter > constants.MAX_OBJ_BEFORE_SEND:
                self.send_objs()
                counter = 0
            counter += 1
    
    def send_objs(self):
        for url, data in list(self.urls_to_scan.items()):
            leak_obj = data[1]
            if leak_obj:
                constants.RESULT_MASS["deep_scan"][leak_obj.repo_name] = leak_obj
            else:
                del self.urls_to_scan[url]

        if constants.RESULT_MASS.get("deep_scan"):
            Connector.dump_to_DB()
            constants.RESULT_MASS.pop("deep_scan", None)
        else:
            logger.info("No repositories require database updates")
        
        logger.info("Deep scan process completed")
    
    def _process_batch(self, batch_urls: List[str]) -> None:
        """
        Process a batch of URLs for deep scanning.
        
        Args:
            batch_urls: List of URLs to process in this batch
        """
        for url in batch_urls:
            leak_id = self.urls_to_scan[url][0]
            logger.info(f"Deep scanning: {url}")

            for attempt in range(DEEP_SCAN_CONFIG["max_retries"]):
                try:
                    company_id = Connector.get_compnay_id(leak_id)
                    
                    if 'gist.github.com' in url:
                        leak_obj = self._perform_gistobj_deep_scan(url, leak_id, company_id)
                    else:
                        leak_obj = self._perform_leakobj_deep_scan(url, leak_id, company_id)
                    if leak_obj:
                        self.urls_to_scan[url][1] = leak_obj
                        break
                    logger.warning(f"Scan attempt {attempt + 1} failed for {url}")
                except Exception as e:
                    logger.error(f"Error in scan attempt {attempt + 1} for {url}: {e}")

            else:
                logger.error(f"All scan attempts failed for {url}, removing from update list")
                del self.urls_to_scan[url]
    


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
        utils.dumping_data()
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

