import os
import gc
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Union

from src.logger import logger
from src import Connector
from src import constants
from src.LeakObj import RepoObj, GlistObj
from src import filters
from src import utils
from src.searcher.scanner import Scanner

DEEP_SCAN_CONFIG = {
    "max_retries": 3,
    "timeout_multiplier": 3.0,
    "batch_size": 5,
    "max_workers": 3,  # Number of parallel workers for deep scan
    "enable_ai_analysis": True,
    "required_scanners": ["gitleaks", "gitsecrets", "grepscan", "deepsecrets", "detect_secrets"],
    "max_urls_per_run": 0,  # 0 = no limit, process all URLs from DB
}

LIST_SCAN_CONFIG = {
    "max_urls_per_batch": 10,
    "url_validation_enabled": True,
    "auto_mark_processed": True,
    "supported_hosts": ["github.com", "gist.github.com"],
}


class DeepScanManager:
    def __init__(self, max_workers: int = None):
        """
        Initialize DeepScanManager with parallel processing support.

        Args:
            max_workers: Number of parallel workers (default: from DEEP_SCAN_CONFIG)
        """
        self.urls_to_scan: constants.AutoVivification = constants.AutoVivification()
        self.max_workers = max_workers or DEEP_SCAN_CONFIG["max_workers"]
        self._lock = threading.Lock()  # Thread-safe operations
        self._processed_count = 0  # Счетчик обработанных URL для периодической очистки
        self._gc_interval = 50  # Интервал сборки мусора
        logger.info(f"DeepScanManager initialized with {self.max_workers} parallel workers")

    def _cleanup_memory(self, force: bool = False):
        """
        Периодическая очистка памяти.

        Args:
            force: Принудительная очистка вне зависимости от счетчика
        """
        self._processed_count += 1
        if force or self._processed_count >= self._gc_interval:
            gc.collect()
            self._processed_count = 0
            logger.debug("🧹 Memory cleanup performed")

    def _clear_processed_urls(self, urls: List[str]):
        """
        Немедленно удаляет обработанные URL из памяти.

        Args:
            urls: Список URL для удаления
        """
        with self._lock:
            for url in urls:
                if url in self.urls_to_scan:
                    # Очищаем ссылку на объект перед удалением
                    self.urls_to_scan[url][1] = None
                    del self.urls_to_scan[url]

    def _is_valid_github_url(self, url: str) -> bool:
        """
        Проверяет, что URL относится к github.com или gist.github.com.

        Args:
            url: URL для проверки

        Returns:
            True если URL валидный (github.com или gist.github.com), иначе False
        """
        if not url or not isinstance(url, str):
            return False

        url_lower = url.lower()
        valid_hosts = ["github.com", "gist.github.com"]

        for host in valid_hosts:
            if host in url_lower:
                try:
                    if url_lower.startswith(("http://", "https://")):
                        parts = url_lower.split("/")
                        if len(parts) >= 3:
                            domain = parts[2]
                            if domain in valid_hosts or domain.endswith("." + host):
                                return True
                except (IndexError, AttributeError):
                    pass

        logger.warning(f"Invalid URL detected (not github.com): {url}")
        return False

    def _get_urls_for_deep_scan(self) -> Dict[str, List[Any]]:
        """
        Получает URL для глубокого сканирования из базы данных.
        Фильтрует только валидные GitHub URL.

        Returns:
            Словарь {url: [leak_id, leak_obj]} для сканирования
        """
        urls_to_scan = constants.AutoVivification()
        url_dump = Connector.dump_from_DB_by_result(constants.RESULT_CODE_TO_DEEPSCAN)

        skipped_count = 0
        for url_from_db, url_data in url_dump.items():
            if not self._is_valid_github_url(url_from_db):
                skipped_count += 1
                continue
            urls_to_scan[url_from_db] = [url_data[1], None]

        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} non-GitHub URLs")
        logger.info(f"Found {len(urls_to_scan)} valid GitHub URLs marked for deep scanning")
        return urls_to_scan

    def _get_urls_for_deep_scan_with_no_results(self) -> Dict[str, List[Any]]:
        """
        Получает URL для повторного сканирования (с незаполненными полями).
        Фильтрует только валидные GitHub URL.

        Returns:
            Словарь {url: [leak_id, leak_obj]} для повторного сканирования
        """
        urls_to_scan = constants.AutoVivification()
        url_dump = Connector.dump_from_DB_by_result(constants.RESULT_CODE_TO_SEND)

        skipped_count = 0
        for url_from_db, url_data in url_dump.items():
            if not self._is_valid_github_url(url_from_db):
                skipped_count += 1
                continue
            urls_to_scan[url_from_db] = [url_data[1], None]

        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} non-GitHub URLs during rescan")
        logger.info(f"Found {len(urls_to_scan)} valid GitHub URLs not analysed yet")
        return urls_to_scan

    def _perform_deep_scan(
        self, url: str, leak_id: int, company_id: int, is_gist: bool = False
    ) -> Optional[Union[RepoObj, GlistObj]]:
        """
        Perform deep scan on a repository or gist.

        Args:
            url: URL to scan
            leak_id: Database leak ID
            company_id: Company ID for context
            is_gist: True for gist URLs, False for repository URLs

        Returns:
            LeakObj (RepoObj or GlistObj) on success, None on failure
        """
        try:
            company_name = Connector.get_company_name(company_id=company_id)

            if is_gist:
                leak_obj = GlistObj(url, company_name, company_id)
                checker_mode = 2
            else:
                # Create mock repo data for RepoObj initialization
                mock_repo_data = {
                    "full_name": "/".join(url.split("/")[-2:]),
                    "owner": {"login": url.split("/")[-2]},
                    "size": 0,  # Will be updated during scanning
                }
                leak_obj = RepoObj(url, mock_repo_data, company_name, company_id)
                checker_mode = 3  # Deep scan mode

            leak_obj.stats.fetch_repository_stats()
            checker = filters.Checker(url=url, dork=company_name, obj=leak_obj, mode=checker_mode)
            checker.clone()
            checker.run()

            return leak_obj

        except Exception as e:
            logger.error(f"Error during deep scan of {url}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def _perform_gistobj_deep_scan(self, url: str, leak_id: int, company_id: int) -> Optional[GlistObj]:
        """Perform deep scan on a gist URL. Wrapper for backward compatibility."""
        return self._perform_deep_scan(url, leak_id, company_id, is_gist=True)

    def _perform_leakobj_deep_scan(self, url: str, leak_id: int, company_id: int) -> Optional[RepoObj]:
        """Perform deep scan on a repository URL. Wrapper for backward compatibility."""
        return self._perform_deep_scan(url, leak_id, company_id, is_gist=False)

    def run(self, mode=0) -> None:
        """Run deep scan.

        Args:
            mode: 0 = scan result=5 (TO_DEEPSCAN), 1 = rescan result=4 (TO_SEND / unchecked)
        """
        logger.info("Starting deep scan process (mode=%d)", mode)

        if mode == 0:
            self.urls_to_scan = self._get_urls_for_deep_scan()
        elif mode == 1:
            self.urls_to_scan = self._get_urls_for_deep_scan_with_no_results()
        else:
            logger.error("Incorrect mode of deepscan, use mode 0 or 1")
            self.urls_to_scan = self._get_urls_for_deep_scan()

        if not self.urls_to_scan:
            logger.info("No URLs found for deep scanning")
            return

        url_list = list(self.urls_to_scan.keys())
        batch_size = DEEP_SCAN_CONFIG["batch_size"]
        counter = 0
        max_urls = DEEP_SCAN_CONFIG.get("max_urls_per_run", 0)
        if max_urls > 0 and len(url_list) > max_urls:
            url_list = url_list[:max_urls]
        logger.info("Processing %d URLs (total in DB: %d)", len(url_list), len(self.urls_to_scan))
        for i in range(0, len(url_list), batch_size):
            batch_urls = url_list[i : i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}: {len(batch_urls)} URLs. I={i}")
            counter += self._process_batch(batch_urls)
            self.send_objs()
        self.send_objs()
        failed_count = len(url_list) - counter
        logger.info(
            "Deep scan run completed: %d/%d URLs processed successfully, %d failed",
            counter, len(url_list), failed_count,
        )

    def send_objs(self):
        """
        Отправляет обработанные объекты в базу данных и очищает память.

        Оптимизация: немедленное освобождение ссылок после обработки.
        """
        urls_to_remove = []
        with self._lock:
            for url, data in list(self.urls_to_scan.items()):
                leak_obj = data[1]
                if leak_obj and leak_obj.repo_name not in constants.RESULT_MASS.get("deep_scan", {}):
                    if "deep_scan" not in constants.RESULT_MASS:
                        constants.RESULT_MASS["deep_scan"] = {}
                    constants.RESULT_MASS["deep_scan"][leak_obj.repo_name] = leak_obj
                    urls_to_remove.append(url)

            # Немедленная очистка обработанных URL
            for url in urls_to_remove:
                del self.urls_to_scan[url]

        if constants.RESULT_MASS.get("deep_scan"):
            Connector.dump_to_DB()
            # Очищаем отправленные данные
            constants.RESULT_MASS.pop("deep_scan", None)
            # Принудительная сборка мусора после отправки
            self._cleanup_memory(force=True)
            logger.info(f"✅ Sent {len(urls_to_remove)} objects to database")
        else:
            logger.info("No repositories require database updates")
        logger.info("Deep scan batch completed")

    def _process_single_url(self, url: str) -> bool:
        """
        Process single URL with retries (called in parallel).

        Args:
            url: URL to scan

        Returns:
            True if successful, False otherwise
        """
        try:
            if url not in self.urls_to_scan:
                return False

            # Get leak_id safely
            with self._lock:
                if isinstance(self.urls_to_scan[url][0], (int, str)):
                    leak_id = int(self.urls_to_scan[url][0])
                else:
                    return False

            logger.info(f"🔍 Deep scanning: {url}")

            # Retry loop
            for attempt in range(DEEP_SCAN_CONFIG["max_retries"]):
                try:
                    company_id = Connector.get_company_id(leak_id)

                    # Perform scan based on URL type
                    if "gist.github.com" in url:
                        leak_obj = self._perform_gistobj_deep_scan(url, leak_id, company_id)
                    else:
                        leak_obj = self._perform_leakobj_deep_scan(url, leak_id, company_id)

                    if leak_obj:
                        # Thread-safe update
                        with self._lock:
                            self.urls_to_scan[url][1] = leak_obj
                        logger.info(f"✅ Successfully scanned: {url}")
                        return True

                    logger.warning(f"⚠️ Scan attempt {attempt + 1}/{DEEP_SCAN_CONFIG['max_retries']} failed for {url}")

                except Exception as e:
                    logger.error(
                        f"❌ Error in scan attempt {attempt + 1}/{DEEP_SCAN_CONFIG['max_retries']} for {url}: {e}"
                    )

            # All attempts failed
            logger.error(f"❌ All scan attempts failed for {url}, removing from update list")
            with self._lock:
                if url in self.urls_to_scan:
                    del self.urls_to_scan[url]
            # Периодическая очистка памяти
            self._cleanup_memory()
            return False

        except Exception as e:
            logger.error(f"💥 Fatal error processing {url}: {e}")
            self._cleanup_memory()
            return False

    def _process_batch(self, batch_urls: List[str]) -> int:
        """
        Process batch URLs in parallel using ThreadPoolExecutor.

        Args:
            batch_urls: List of URLs to process

        Returns:
            Number of successfully processed URLs
        """
        counter = 0

        # Filter valid URLs
        valid_urls = []
        with self._lock:
            for url in batch_urls:
                if url in self.urls_to_scan and isinstance(self.urls_to_scan[url][0], (int, str)):
                    valid_urls.append(url)

        if not valid_urls:
            logger.warning("No valid URLs in batch")
            return 0

        logger.info(f"⚡ Processing {len(valid_urls)} URLs with {self.max_workers} parallel workers")

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_url = {executor.submit(self._process_single_url, url): url for url in valid_urls}

            # Process completed tasks as they finish
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    success = future.result(timeout=600)  # 10 min timeout per URL
                    if success:
                        counter += 1
                except TimeoutError:
                    logger.error(f"⏱️ Timeout processing {url} (10 minutes)")
                except Exception as e:
                    logger.error(f"💥 Exception processing {url}: {e}")

        logger.info(f"📊 Batch completed: {counter}/{len(valid_urls)} URLs processed successfully")
        return counter


class ListScanManager:
    def __init__(self, input_file_path: Optional[str] = None):
        self.input_file_path = input_file_path or str(constants.MAIN_FOLDER_PATH / "temp" / "list_to_scan.txt")

    def _read_urls_from_file(self) -> List[str]:
        if not os.path.exists(self.input_file_path):
            logger.info(f"List scan file not found: {self.input_file_path}")
            return []

        try:
            with open(self.input_file_path, "r", encoding="utf-8") as file:
                url_list = [line.strip() for line in file if line.strip() and not line.strip().startswith("//")]

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
        if not LIST_SCAN_CONFIG["url_validation_enabled"]:
            return True

        for host in LIST_SCAN_CONFIG["supported_hosts"]:
            if host in url and url.startswith(("https://", "http://")):
                try:
                    parts = url.split("/")
                    return len(parts) >= 5 and parts[2] in LIST_SCAN_CONFIG["supported_hosts"]
                except (IndexError, AttributeError):
                    return False
        return False

    def _create_repo_objects(self, url_list: List[str]) -> List[RepoObj]:
        repo_objs = []

        for url in url_list:
            try:
                parts = url.split("/")
                if len(parts) >= 5:
                    owner = parts[3]
                    repo_name = parts[4]
                    owner_repo = f"{owner}/{repo_name}"

                    mock_repo_data = {"full_name": owner_repo, "owner": {"login": owner}}

                    repo_obj = RepoObj(url, mock_repo_data, "list_scan_dork")
                    repo_objs.append(repo_obj)

            except (IndexError, ValueError) as e:
                logger.warning(f"Could not parse URL for RepoObj: {url} - {e}")
                continue

        return repo_objs

    def _mark_urls_as_processed(self, url_list: List[str]) -> None:
        try:
            with open(self.input_file_path, "w", encoding="utf-8") as file:
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
            temp_key = "list_scan_temp"
            if temp_key not in constants.dork_dict_from_DB:
                constants.dork_dict_from_DB[temp_key] = []

            repo_urls = [obj.repo_url for obj in repo_objs]
            constants.dork_dict_from_DB[temp_key].extend(repo_urls)

            scanner = Scanner(temp_key)
            scanner.gitscan()

            if temp_key in constants.dork_dict_from_DB:
                del constants.dork_dict_from_DB[temp_key]

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
