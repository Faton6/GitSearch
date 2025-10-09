import os
from typing import Dict, List, Optional, Any, Tuple

from src.logger import logger
from src import Connector
from src import constants
from src.LeakObj import RepoObj, GlistObj
from src import filters
from src import utils
from src.searcher.scanner import Scanner

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
    
    def __init__(self):
        self.urls_to_scan: constants.AutoVivification = constants.AutoVivification()
        
    def _get_urls_for_deep_scan(self) -> Dict[str, List[Any]]:
        urls_to_scan = constants.AutoVivification()
        url_dump = Connector.dump_from_DB(mode=1)
        
        for url_from_db in url_dump.keys():
            url_data = url_dump[url_from_db]
            if (isinstance(url_data[0], str) and 
                int(url_data[0]) == constants.RESULT_CODE_TO_DEEPSCAN) or (isinstance(url_data[0], int) and 
                url_data[0] == constants.RESULT_CODE_TO_DEEPSCAN):
                urls_to_scan[url_from_db] = [url_data[1], None]
                
        logger.info(f"Found {len(urls_to_scan)} URLs marked for deep scanning")
        return urls_to_scan
 
 
    def _get_urls_for_deep_scan_with_no_results(self):
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
    
    def _perform_gistobj_deep_scan(self, url: str, leak_id: int, company_id: int) -> Tuple[Optional[Dict], Optional[Dict]]:
        try:
            # Create a mock GlistObj for the checker
            mock_repo_data = {
                'full_name': '/'.join(url.split('/')[-2:]),
                'owner': {'login': url.split('/')[-2]},
                'size': 0  # Will be updated during scanning
            }
            
            
            company_name = Connector.get_company_name(company_id=company_id)
            glist_obj = GlistObj(url, company_name, company_id)
            glist_obj.stats.fetch_repository_stats()
            checker = filters.Checker(url=url, dork=company_name, obj=glist_obj, mode=2)
            checker.clone()
            checker.run()
                       
            return glist_obj
            
        except Exception as e:
            import traceback
            logger.error(f"Error during deep scan of {url}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
    def _perform_leakobj_deep_scan(self, url: str, leak_id: int, company_id: int) -> Tuple[Optional[Dict], Optional[Dict]]:
        try:
            # Create a mock RepoObj for the checker
            mock_repo_data = {
                'full_name': '/'.join(url.split('/')[-2:]),
                'owner': {'login': url.split('/')[-2]},
                'size': 0  # Will be updated during scanning
            }
            company_name = Connector.get_company_name(company_id=company_id)
            repo_obj = RepoObj(url, mock_repo_data, company_name, company_id)
            repo_obj.stats.fetch_repository_stats()
            # Initialize checker with deep scan mode (mode=3)
            checker = filters.Checker(url=url, dork=company_name, obj=repo_obj, mode=3)
            
            # Perform the scanning process
            checker.clone()
            checker.run()
            
            return repo_obj
            
        except Exception as e:
            import traceback
            logger.error(f"Error during deep scan of {url}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
    
 
    def run(self, mode=0) -> None:
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
        
        url_list = list(self.urls_to_scan.keys())
        batch_size = DEEP_SCAN_CONFIG['batch_size']
        counter = 0
        if len(url_list) > 500:
            url_list = url_list[:500]
        for i in range(0, len(url_list), batch_size):
            batch_urls = url_list[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}: {len(batch_urls)} URLs. I={i}")
            counter += self._process_batch(batch_urls)
            self.send_objs()
        self.send_objs()
    
    def send_objs(self):
        urls_to_remove = []
        for url, data in list(self.urls_to_scan.items()):
            leak_obj = data[1]
            if leak_obj and leak_obj.repo_name not in constants.RESULT_MASS["deep_scan"]:
                constants.RESULT_MASS["deep_scan"][leak_obj.repo_name] = leak_obj
                urls_to_remove.append(url)
        for url in urls_to_remove:
            del self.urls_to_scan[url]

        if constants.RESULT_MASS.get("deep_scan"):
            Connector.dump_to_DB()
            constants.RESULT_MASS.pop("deep_scan", None)
        else:
            logger.info("No repositories require database updates")
        logger.info("Deep scan process completed")
    
    def _process_batch(self, batch_urls: List[str]) -> None:
        counter = 0
        for url in batch_urls:
            if isinstance(self.urls_to_scan[url][0], (int, str)):
                leak_id = int(self.urls_to_scan[url][0])
            else:
                continue
            logger.info(f"Deep scanning: {url}")

            for attempt in range(DEEP_SCAN_CONFIG["max_retries"]):
                try:
                    company_id = Connector.get_company_id(int(leak_id))
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
            counter += 1
        return counter
    


class ListScanManager:
    
    def __init__(self, input_file_path: Optional[str] = None):
        self.input_file_path = (input_file_path if input_file_path 
                               else str(constants.MAIN_FOLDER_PATH / "temp" / "list_to_scan.txt"))
    
    def _read_urls_from_file(self) -> List[str]:
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
        if not LIST_SCAN_CONFIG['url_validation_enabled']:
            return True
            
        for host in LIST_SCAN_CONFIG['supported_hosts']:
            if host in url and url.startswith(('https://', 'http://')):
                try:
                    parts = url.split('/')
                    return len(parts) >= 5 and parts[2] in LIST_SCAN_CONFIG['supported_hosts']
                except (IndexError, AttributeError):
                    return False
        return False
    
    def _create_repo_objects(self, url_list: List[str]) -> List[RepoObj]:
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
        try:
            with open(self.input_file_path, 'w', encoding='utf-8') as file:
                for url in url_list:
                    file.write(f"//{url}\n")
            logger.info(f"Marked {len(url_list)} URLs as processed")
        except Exception as e:
            logger.error(f"Error marking URLs as processed: {e}")
    
    def _scan_repositories(self, repo_objs: List[RepoObj]) -> None:
        if not repo_objs:
            logger.info("No repository objects to scan")
            return
        
        try:
            temp_key = 'list_scan_temp'
            if temp_key not in constants.dork_dict:
                constants.dork_dict[temp_key] = []
            
            repo_urls = [obj.repo_url for obj in repo_objs]
            constants.dork_dict[temp_key].extend(repo_urls)
            
            scanner = Scanner(temp_key)
            scanner.gitscan()
            
            if temp_key in constants.dork_dict:
                del constants.dork_dict[temp_key]
                
            logger.info(f"Successfully processed {len(repo_objs)} repositories")
            
        except Exception as e:
            logger.error(f"Error during repository scanning: {e}")
            raise
    
    def run(self) -> None:
        logger.info(f"Starting list scan from file: {self.input_file_path}")
        
        url_list = self._read_urls_from_file()
        if not url_list:
            return
        
        repo_objs = self._create_repo_objects(url_list)
        if not repo_objs:
            logger.warning("No valid repository objects created")
            return
        
        self._scan_repositories(repo_objs)
        
        utils.dumping_data()
        self._mark_urls_as_processed(url_list)
        
        logger.info("List scan process completed")


def list_search(input_file_path: Optional[str] = None) -> None:
    try:
        list_scan_manager = ListScanManager(input_file_path)
        list_scan_manager.run()
    except Exception as e:
        logger.error(f"Error in list search process: {e}")
        raise

