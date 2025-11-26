# Standard libs import
import sys
import functools
from random import choice
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import shutil
import subprocess
from pathlib import Path
import re
import time
import hashlib
import git
import ast
import threading
from typing import Optional, Dict, Any, FrozenSet, List

# Third-party imports
from github import Github, GithubException, RateLimitExceededException

# Project lib's import
from src import Connector, constants
from src.logger import logger, CLR
from src import utils
from src.exceptions import (
    ScanError, TimeoutScanError, RepositoryNotFoundError, 
    RepositoryAccessDeniedError, RepositoryOversizeError, CloneError,
    ScannerNotInstalledError
)

exclusions: tuple[str]
with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", 'r') as fd:
    exclusions = tuple(line.rstrip() for line in fd)

def _exc_catcher(func):
    """Decorator for catching exceptions in scan methods with typed exceptions."""
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except subprocess.TimeoutExpired as e:
            scanner_name = func.__name__.replace('_scan', '').replace('_', '-')
            url = args[0].url if args and hasattr(args[0], 'url') else ''
            logger.error("TimeoutExpired exception in %s", func.__name__)
            raise TimeoutScanError(scanner_name, url, timeout_seconds=getattr(e, 'timeout', 0))
        except RepositoryNotFoundError:
            raise  # Re-raise typed exceptions
        except RepositoryAccessDeniedError:
            raise
        except CloneError:
            raise
        except ScanError:
            raise
        except Exception as exc:
            logger.error("Exception in %s: %s", func.__name__, exc)
            return 2
    return wrapper


class CheckerException(ScanError):
    """Legacy exception for backward compatibility."""
    pass


INITED = 0x0001
CLONED = 0x0002
SCANNED = 0x0004
NOT_CLONED = 0x0008


class Checker:
    # Используем константы из constants.py для единообразия
    file_ignore = tuple(constants.BINARY_FILE_EXTENSIONS)
    
    # Кеш скомпилированных regex паттернов на уровне класса
    _search_pattern_cache: Dict[FrozenSet[str], re.Pattern] = {}
    _compiled_regex_cache: Dict[str, re.Pattern] = {}
    
    @classmethod
    def _get_search_pattern(cls, terms: List[str]) -> re.Pattern:
        """
        Возвращает скомпилированный паттерн поиска из кеша.
        
        Args:
            terms: Список терминов для поиска
            
        Returns:
            Скомпилированный re.Pattern
        """
        key = frozenset(terms)
        if key not in cls._search_pattern_cache:
            escaped = [re.escape(t) for t in terms]
            cls._search_pattern_cache[key] = re.compile(
                r'\b(?:' + '|'.join(escaped) + r')\b',
                re.IGNORECASE
            )
        return cls._search_pattern_cache[key]
    
    @classmethod
    def _get_compiled_regex(cls, pattern: str, flags: int = 0) -> re.Pattern:
        """
        Возвращает скомпилированное regex из кеша.
        
        Args:
            pattern: Строка регулярного выражения
            flags: Флаги компиляции
            
        Returns:
            Скомпилированный re.Pattern
        """
        cache_key = f"{pattern}:{flags}"
        if cache_key not in cls._compiled_regex_cache:
            cls._compiled_regex_cache[cache_key] = re.compile(pattern, flags)
        return cls._compiled_regex_cache[cache_key]
    
    @classmethod
    def clear_pattern_cache(cls):
        """Очистка кеша паттернов."""
        cls._search_pattern_cache.clear()
        cls._compiled_regex_cache.clear()

    def __init__(self, url: str, dork: str, obj: any, mode: int = 1, token: str = '') -> None:
        self.url = url
        self.obj = obj
        self.dork = dork
        self.mode = mode
        scan_type = 'None'
        
        # Ensure temp folder exists before creating paths
        if not os.path.exists(constants.TEMP_FOLDER):
            try:
                os.makedirs(constants.TEMP_FOLDER, exist_ok=True)
                logger.info(f'Created temp folder: {constants.TEMP_FOLDER}')
            except Exception as e:
                logger.error(f'Cannot create temp folder {constants.TEMP_FOLDER}: {e}')
                raise
        
        self.repos_dir = constants.TEMP_FOLDER + '/' + url.split('/')[-2] + '---' + url.split('/')[-1]
        self.report_dir = self.repos_dir + '---reports/'
        self.secrets = constants.AutoVivification()
        self.repo: git.Repo
        self.status = INITED
        self.company_name = Connector.get_company_name(self.obj.company_id)
        self.company_terms = utils.generate_company_search_terms(self.company_name)
        self.safe_company_name = utils.sanitize_company_name(self.company_name)
        self.scan_time_limit = constants.MAX_TIME_TO_SCAN_BY_UTIL_DEEP if self.mode == 3 else constants.MAX_TIME_TO_SCAN_BY_UTIL_DEFAULT
        self.log_color = choice(tuple(CLR.values()))
        # Блокировка для безопасного удаления директории при мультипоточности
        self._cleanup_lock = threading.Lock()
        self._cleaned = False  # Флаг для предотвращения повторного удаления
        self.scans = {
            'gitleaks': self.gitleaks_scan,
            'trufflehog': self.trufflehog_scan,
            'detect_secrets': self.detect_secrets_scan,
            'kingfisher': self.kingfisher_scan,
            'grepscan': self.grep_scan
        }

        self.deep_scans = {
            'gitleaks': self.gitleaks_scan,
            'gitsecrets': self.gitsecrets_scan,
            'grepscan': self.grep_scan,
            'deepsecrets': self.deepsecrets_scan,
            'detect_secrets': self.detect_secrets_scan,
            'kingfisher': self.kingfisher_scan,
            'ai_deep_scan': self.ai_deep_scan,
            # ,'ioc_extractor': self._ioc_extractor
        }

    def _clean_repo_dirs(self):
        """
        Safely remove repository directory with race condition protection.
        
        This method ensures:
        - Only one cleanup happens at a time (thread-safe)
        - Working directory is preserved
        - Proper error handling
        """
        with self._cleanup_lock:
            if self._cleaned:
                logger.debug(f'Repository {self.repos_dir} already cleaned, skipping')
                return
            
            # Save current working directory
            original_cwd = None
            try:
                original_cwd = os.getcwd()
            except (OSError, FileNotFoundError) as e:
                logger.warning(f'Cannot get current working directory: {e}')
                # If we can't get CWD, try to change to a safe location
                try:
                    os.chdir(constants.MAIN_FOLDER_PATH)
                    original_cwd = str(constants.MAIN_FOLDER_PATH)
                except Exception as e2:
                    logger.error(f'Cannot change to safe directory: {e2}')
            
            # Clean repository directory
            try:
                if os.path.exists(self.repos_dir):
                    # Ensure we're not inside the directory we're trying to delete
                    if original_cwd and self.repos_dir in original_cwd:
                        try:
                            os.chdir(constants.MAIN_FOLDER_PATH)
                        except Exception as e:
                            logger.warning(f'Cannot change directory before cleanup: {e}')
                    
                    shutil.rmtree(self.repos_dir, ignore_errors=True)
                    logger.debug(f'Cleaned repository directory: {self.repos_dir}')
            except Exception as e:
                logger.error(f'Error cleaning repository directory {self.repos_dir}: {e}')
            
            # Clean report directory
            try:
                if os.path.exists(self.report_dir):
                    shutil.rmtree(self.report_dir, ignore_errors=True)
                    logger.debug(f'Cleaned report directory: {self.report_dir}')
            except Exception as e:
                logger.error(f'Error cleaning report directory {self.report_dir}: {e}')
            
            # Restore working directory
            if original_cwd:
                try:
                    os.chdir(original_cwd)
                except (OSError, FileNotFoundError) as e:
                    logger.warning(f'Cannot restore working directory to {original_cwd}: {e}')
                    # Try to change to safe location as fallback
                    try:
                        os.chdir(constants.MAIN_FOLDER_PATH)
                    except Exception as e2:
                        logger.error(f'Cannot change to safe directory: {e2}')
            
            self._cleaned = True

    def _pywhat_analyze_names(self, match):
        all_names = []
        res_analyze = utils.pywhat_analyze(match, self.repos_dir)
        for i in res_analyze:
            all_names.append(i['Name'])
        if len(all_names) < 1:
            all_names.append('None')
        return all_names

    def _clone_with_pygithub(self) -> bool:
        """
        Clone repository using PyGithub API instead of git subprocess.
        
        Benefits:
        - No filesystem complexity or directory management issues
        - Direct API access through existing rate limiter
        - Downloads only needed files
        - Reduced disk space usage
        
        Returns:
            bool: True if cloning was successful, False otherwise
        """
        try:
            # Extract owner and repo name from URL
            # URL format: https://github.com/owner/repo
            parts = self.url.rstrip('/').split('/')
            if len(parts) < 2:
                logger.error(f'Invalid GitHub URL format: {self.url}')
                return False
            
            owner, repo_name = parts[-2], parts[-1]
            logger.info(f'Cloning {owner}/{repo_name} using PyGithub API')
            
            # Use rate limiter to get best available token for core API
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            
            if is_initialized():
                rate_limiter = get_rate_limiter()
                # Get token for core API (not search!)
                token = rate_limiter.get_best_token(resource='core')
                if not token:
                    logger.error(f'No GitHub tokens available for PyGithub clone')
                    return False
                
                # Check if token has enough core quota (need at least 50 for typical repo)
                token_quota = rate_limiter.tokens.get(token)
                if token_quota:
                    core_quota = token_quota.get_resource_quota('core')
                    if core_quota.remaining < 50:
                        wait_time = core_quota.seconds_until_reset
                        if wait_time > 0 and wait_time < 120:  # Wait max 2 minutes
                            logger.info(f'Core API quota low ({core_quota.remaining}), waiting {wait_time:.0f}s for reset...')
                            time.sleep(wait_time + 1)
                        elif wait_time >= 120:
                            logger.warning(f'Core API quota low ({core_quota.remaining}), reset in {wait_time:.0f}s - falling back to git clone')
                            return False
            else:
                token = constants.GITHUB_CLONE_TOKEN
                if not token:
                    logger.error(f'No GitHub token configured for PyGithub clone')
                    return False
            
            # Initialize GitHub client with best available token
            # Disable retry (retry=None with Retry object) to handle rate limits ourselves
            # Set timeout to prevent long waits
            g = Github(token, retry=None, timeout=30)
            
            try:
                # Get repository
                repo = g.get_repo(f'{owner}/{repo_name}')
                
                # Create repos directory
                os.makedirs(self.repos_dir, exist_ok=True)
                
                # Track API calls for rate limiting
                api_calls = [0]  # Use list to allow modification in nested function
                max_api_calls = 500  # Safety limit
                
                # Download all contents recursively
                def download_contents(contents, path=""):
                    """Recursively download repository contents"""
                    for content_file in contents:
                        # Check API call limit
                        api_calls[0] += 1
                        if api_calls[0] > max_api_calls:
                            logger.warning(f'API call limit reached ({max_api_calls}), stopping download')
                            return
                        
                        file_path = os.path.join(self.repos_dir, path, content_file.name)
                        
                        if content_file.type == "dir":
                            # Create directory and recurse
                            os.makedirs(file_path, exist_ok=True)
                            try:
                                download_contents(
                                    repo.get_contents(content_file.path),
                                    os.path.join(path, content_file.name)
                                )
                            except RateLimitExceededException as e:
                                logger.warning(f'Rate limit hit while accessing directory {content_file.path}')
                                raise  # Re-raise to stop clone
                            except GithubException as e:
                                if e.status == 403:
                                    logger.warning(f'Access forbidden for directory {content_file.path}: rate limit likely')
                                    raise  # Re-raise to stop clone and trigger fallback
                                logger.warning(f'Cannot access directory {content_file.path}: {e}')
                        else:
                            # Download file
                            try:
                                # Check if file should be excluded
                                skip_file = False
                                for ext in self.file_ignore:
                                    if content_file.name.endswith(ext):
                                        skip_file = True
                                        break
                                
                                if not skip_file:
                                    # Skip symlinks and special files
                                    if content_file.type not in ["file", "blob"]:
                                        logger.debug(f'Skipping non-file content: {content_file.path} (type: {content_file.type})')
                                        continue
                                    
                                    # Try decoded_content first, fall back to raw content for binary/unknown encoding files
                                    file_content = None
                                    try:
                                        file_content = content_file.decoded_content
                                    except RateLimitExceededException:
                                        raise  # Re-raise to stop clone
                                    except GithubException as e:
                                        if e.status == 403:
                                            raise  # Re-raise 403 to stop clone
                                        # For files with unsupported encoding (binary files, etc.)
                                        try:
                                            file_content = content_file.content
                                        except Exception:
                                            logger.debug(f'Cannot get content for {content_file.path}, skipping')
                                            continue
                                    except Exception:
                                        # For files with unsupported encoding (binary files, etc.)
                                        try:
                                            file_content = content_file.content
                                        except Exception:
                                            logger.debug(f'Cannot get content for {content_file.path}, skipping')
                                            continue
                                    
                                    # Verify we have valid bytes content
                                    if file_content is None:
                                        logger.debug(f'File content is None for {content_file.path}, skipping')
                                        continue
                                    
                                    # Convert to bytes if needed
                                    if isinstance(file_content, str):
                                        file_content = file_content.encode('utf-8')
                                    
                                    if not isinstance(file_content, bytes):
                                        logger.warning(f'Invalid content type for {content_file.path}: {type(file_content)}, skipping')
                                        continue
                                    
                                    with open(file_path, 'wb') as f:
                                        f.write(file_content)
                            except Exception as e:
                                logger.warning(f'Cannot download file {content_file.path}: {e}')
                
                # Start downloading from root
                root_contents = repo.get_contents("")
                download_contents(root_contents)
                
                logger.info(f'Successfully cloned {owner}/{repo_name} via API')
                
                # Create report directory
                os.makedirs(self.report_dir, exist_ok=True)
                
                # Note: We don't initialize git.Repo here since we didn't use git clone
                # If git operations are needed later, we can initialize it separately
                self.repo = None
                
                return True
                
            except RateLimitExceededException as e:
                logger.warning(f'Rate limit exceeded during PyGithub clone for {self.url}')
                # Update rate limiter about this error (core API)
                if is_initialized():
                    rate_limiter = get_rate_limiter()
                    retry_after = getattr(e, 'headers', {}).get('Retry-After')
                    rate_limiter.handle_rate_limit_error(token, int(retry_after) if retry_after else None, resource='core')
                self.secrets = {'Scan_error': f'Rate limit exceeded: {self.url}'}
                return False
                
            except GithubException as e:
                if e.status == 404:
                    logger.warning(f'Repository not found: {self.url}')
                    self.secrets = {'Scan_error': f'Repository not found: {self.url}'}
                elif e.status == 403:
                    logger.warning(f'Access forbidden (likely rate limit) for {self.url}: {e.data.get("message", str(e)) if hasattr(e, "data") else str(e)}')
                    # Update rate limiter about this error (core API)
                    if is_initialized():
                        rate_limiter = get_rate_limiter()
                        retry_after = getattr(e, 'headers', {}).get('Retry-After')
                        rate_limiter.handle_rate_limit_error(token, int(retry_after) if retry_after else 60, resource='core')
                    self.secrets = {'Scan_error': f'Access forbidden (rate limit): {self.url}'}
                else:
                    logger.error(f'GitHub API error for {self.url}: {e}')
                    self.secrets = {'Scan_error': f'GitHub API error: {str(e)}'}
                return False
            
        except Exception as exc:
            logger.error(f'PyGithub clone failed for {self.url}: {exc}')
            self.secrets = {'Scan_error': f'PyGithub clone failed: {str(exc)}'}
            return False

    def clone(self):
        """Clone repository with proper error handling and cleanup"""
        
        logger.info(f'Repository %s %s %s size: %s %s %s', self.log_color, self.url, CLR["RESET"],
                    self.log_color, self.obj.stats.repo_stats_leak_stats_table["size"], CLR["RESET"])
        
        if self.obj.stats.repo_stats_leak_stats_table['size'] > constants.REPO_MAX_SIZE:
            logger.info(
                f'Repository %s %s %s oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]} > {constants.REPO_MAX_SIZE} limit), code not analyze',
                self.log_color, self.url, CLR["RESET"])
            self.obj.status.append(
                f'Repository {self.url} is oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]}), code not analyze')
            # Report oversize status instead of generic "not state"
            self.secrets = {
                'Scan_status': 'oversize',
                'Scan_error': f'Repository {self.url} is oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]} bytes > {constants.REPO_MAX_SIZE} bytes limit)',
                'Size_bytes': self.obj.stats.repo_stats_leak_stats_table["size"],
                'Size_limit': constants.REPO_MAX_SIZE
            }
            self._clean_repo_dirs()
            self.status |= NOT_CLONED
        else:
            logger.info('Cloning %s %s %s', self.log_color, self.url, CLR["RESET"])

            clone_success = False
            
            # Try PyGithub first if configured
            if constants.CLONE_METHOD == 'pygithub':
                logger.info('Attempting clone via PyGithub API for %s', self.url)
                
                # Clean before attempt
                self._clean_repo_dirs()
                
                # Reset cleanup flag to allow directory creation
                with self._cleanup_lock:
                    self._cleaned = False
                
                clone_success = self._clone_with_pygithub()
                
                if clone_success:
                    # Get contributor stats if needed
                    try:
                        self.obj.stats.fetch_contributors_stats()
                    except Exception as e:
                        logger.warning(f'Cannot fetch contributor stats via API: {e}')
                    
                    logger.info(f'Successfully cloned {self.url} via PyGithub')
                    self.status |= CLONED
                    return
                elif not constants.CLONE_FALLBACK_TO_GIT:
                    # PyGithub failed and no fallback
                    logger.error(f'PyGithub clone failed for {self.url}, no fallback enabled')
                    self._clean_repo_dirs()
                    self.status |= NOT_CLONED
                    return
                else:
                    logger.warning(f'PyGithub clone failed for {self.url}, falling back to git clone')
            
            # Use traditional git clone (either as primary method or fallback)
            for try_clone in range(constants.MAX_TRY_TO_CLONE):
                try:
                    # Clean before attempt
                    self._clean_repo_dirs()
                    
                    # Reset cleanup flag to allow directory creation
                    with self._cleanup_lock:
                        self._cleaned = False
                    
                    # Ensure parent directory exists and we can access it
                    parent_dir = os.path.dirname(self.repos_dir)
                    if not os.path.exists(parent_dir):
                        os.makedirs(parent_dir, exist_ok=True)
                    
                    # Save current working directory
                    original_cwd = os.getcwd()
                    
                    # Change to parent directory before cloning
                    try:
                        os.chdir(parent_dir)
                    except OSError as e:
                        logger.error(f'Cannot change to parent directory {parent_dir}: {e}')
                        raise
                    
                    repo_url = self.url
                    authenticated_url = repo_url.replace(
                        "https://",
                        f"https://{constants.GITHUB_CLONE_TOKEN}@"
                    )   
                    
                    # Clone with subprocess and timeout
                    import subprocess
                    clone_timeout = getattr(constants, 'MAX_TIME_TO_CLONE', 500)
                    
                    try:
                        result = subprocess.run([
                            'git', 'clone', '--depth=1', authenticated_url, self.repos_dir
                        ], timeout=clone_timeout, capture_output=True, text=True, cwd=parent_dir)
                        
                        if result.returncode != 0:
                            if 'not found' in result.stderr.lower() or 'not found' in result.stdout.lower():
                                logger.warning(f'Repository not found: {self.url}')
                                self.secrets = {'Scan error': f'Repository not found: {self.url}'}
                                break
                            logger.error(f'git clone failed (attempt {try_clone + 1}/{constants.MAX_TRY_TO_CLONE}): {result.stderr}')
                            continue
                            
                        self.repo = git.Repo(self.repos_dir)
                        clone_success = True
                        
                    except subprocess.TimeoutExpired:
                        logger.error(f'git clone timeout ({clone_timeout}s) for {self.url} (attempt {try_clone + 1}/{constants.MAX_TRY_TO_CLONE})')
                        continue
                    finally:
                        # Always restore working directory
                        try:
                            os.chdir(original_cwd)
                        except OSError as e:
                            logger.error(f'Cannot restore working directory to {original_cwd}: {e}')
                    
                    if clone_success:
                        # Remove token from .git/config after successful clone
                        utils.remove_token_from_git_config(self.repos_dir, self.url)
                        
                        # Create report directory
                        os.makedirs(self.report_dir, exist_ok=True)
                        
                        # Clean excluded files
                        self.clean_excluded_files()
                        
                        # Get contributor stats
                        self.obj.stats.fetch_contributors_stats()
                        
                        logger.info(f'Successfully cloned {self.url}')
                        break
                        
                except Exception as exc:
                    logger.error(f'Clone attempt {try_clone + 1}/{constants.MAX_TRY_TO_CLONE} failed for {self.url}: {exc}')
                    if try_clone < constants.MAX_TRY_TO_CLONE - 1:
                        time.sleep(5)
                    continue
            
            if not clone_success:
                logger.error(f'Failed to clone repo {self.url} after {constants.MAX_TRY_TO_CLONE} attempts')
                self.secrets = {'Scan error': f'Failed to clone repo {self.url} after {constants.MAX_TRY_TO_CLONE} attempts'}
                self._clean_repo_dirs()
                self.status |= NOT_CLONED
            else:
                self.status |= CLONED

    def clean_excluded_files(self):
        """Очищает исключенные файлы из репозитория"""
        repo_path = Path(self.repos_dir)  # DEBUG

        for file_path in repo_path.iterdir():
            if file_path.is_file():
                for ext in self.file_ignore:
                    if file_path.name.endswith(ext):
                        self.obj.status.append(f'File extension: {ext}')
                        file_path.unlink()
                        break

    def scan(self):
        logger.info('Started scan: %s | %s %s %s ', self.dork, self.log_color,
                    self.url, CLR["RESET"])
        
        # Проверка существования директории перед началом сканирования
        if not os.path.isdir(self.repos_dir):
            logger.error('Repository directory %s does not exist or was removed before scan', self.repos_dir)
            self.secrets = {'Scan error': f'Repository directory removed before scan'}
            return self.secrets
        
        cur_dir = os.getcwd()
        try:
            os.chdir(self.repos_dir)
        except (FileNotFoundError, NotADirectoryError) as e:
            logger.error('Failed to change to repository directory %s: %s', self.repos_dir, e)
            self.secrets = {'Scan error': f'Failed to access repository directory'}
            return self.secrets
        
        if self.mode == 3:
            self.scans = self.deep_scans
        scan_results = {}
        try:
            with ThreadPoolExecutor(max_workers=len(self.scans)) as executor:
                futures = {executor.submit(method): name for name, method in self.scans.items()}
                for future in as_completed(futures):
                    res, method = future.result(), futures[future]
                    scan_results[method] = res
                    if res == 1:
                        return 1
                    if res == 2:
                        logger.error('Excepted error in scan, check privious log!')
                    elif res == 3:
                        logger.info(f'Canceling {method} scan in repo: {"/".join(self.url.split("/")[-2:])}')
        finally:
            # Всегда возвращаемся в исходную директорию, даже при ошибках
            try:
                os.chdir(cur_dir)
            except Exception as e:
                logger.error(f'Failed to return to original directory {cur_dir}: {e}')
        
        # Проверяем, есть ли хотя бы один сканер с результатами
        has_results = any(
            scan_type in self.secrets and 
            len(self.secrets[scan_type]) > 0
            for scan_type in self.secrets
        )
        
        if not has_results:
            logger.info(f'No meaningful results found in {self.url} by any scanner')
            # Добавляем информативную запись вместо пустого результата
            self.secrets['message'] = f'No leaks found for dork "{self.dork}" in repository'
        
        logger.info('Scanned: %s | %s %s %s ', self.dork, self.log_color, self.url,
                    CLR["RESET"])

        return self.secrets

    @_exc_catcher
    def grep_scan(self):
        """
        Улучшенный поиск по ключевым словам в репозитории.
        Ищет как по основному dork, так и по названию компании.
        Использует более качественный поиск слов с учетом границ слов.
        """
        scan_type = 'grepscan'
        self.secrets[scan_type] = constants.AutoVivification()
        
        try:
            if not os.path.isdir(self.repos_dir):
                logger.info('Repository directory %s removed before grep_scan', self.repos_dir)
                return 3
            # Создаем список поисковых терминов
            search_terms = [self.dork]
            if self.company_name:
                # Добавляем название компании и его части
                search_terms.extend(self.company_terms)
            search_terms = list(set(search_terms))
            # Используем Python для более качественного поиска
            found_matches = self._enhanced_file_search(search_terms)
            
            # Обрабатываем найденные совпадения
            meaningful_count = 0
            for index, match_info in enumerate(found_matches[:constants.MAX_UTIL_RES_LINES]):
                leak_text = match_info['text']
                file_path = match_info['file']
                search_term = match_info['term']
                
                # Проверяем семантическую осмысленность
                meaningfulness = self._enhanced_semantic_check(leak_text, search_term)
                
                if meaningfulness > 0:
                    meaningful_count += 1
                
                # Обрезаем слишком длинные строки
                if len(leak_text) > constants.MAX_LINE_LEAK_LEN:
                    leak_text = self._get_context(leak_text, search_term, constants.MAX_LINE_LEAK_LEN)
                
                self.secrets[scan_type][f'Leak #{index}']['meaningfull'] = meaningfulness
                self.secrets[scan_type][f'Leak #{index}']['Match'] = leak_text
                self.secrets[scan_type][f'Leak #{index}']['File'] = file_path
                # Дополнительная информация для анализа (не влияет на совместимость)
                self.secrets[scan_type][f'Leak #{index}']['SearchTerm'] = search_term
            
            logger.debug(f'Meaningful matches: {meaningful_count}/{len(found_matches)} for {self.url}')
            
            # Если не найдено ни одного совпадения, добавляем информативную запись
            if len(found_matches) == 0:
                logger.info(f'No matches found in {self.url} for terms: {", ".join(search_terms)}')
            elif meaningful_count == 0:
                logger.info(f'Found {len(found_matches)} matches in {self.url} but none were meaningful')
                
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2
            
        logger.info(f'\t- {scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
        return 0

    

    def _enhanced_file_search(self, search_terms):
        """Улучшенный поиск в файлах с учетом размера файлов"""
            
        found_matches = []
                
        # Размер файла в байтах (2 МБ)
        MAX_FILE_SIZE_FOR_PYTHON = 2 * 1024 * 1024  # 2 MB
        
        try:
            for root, dirs, files in os.walk('.'):
                # Исключаем системные папки
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d not in {'node_modules', '__pycache__', 'venv', 'env'}]
                
                for file in files:
                    # Проверяем расширение или известные файлы без расширений
                    _, ext = os.path.splitext(file.lower())
                    filename_lower = file.lower()
                    
                    # Проверяем расширение или известные файлы без расширений
                    is_text_file = (
                        ext in constants.TEXT_FILE_EXTS or 
                        filename_lower in {
                            'readme', 'license', 'changelog', 'authors', 'contributors',
                            'gemfile', 'rakefile', 'gruntfile', 'gulpfile',
                            'package', 'requirements'
                        } or
                        filename_lower.startswith(('license.', 'changelog.', 'install.')) or
                        filename_lower.endswith(('.example', '.sample', '.template', '.dist'))
                    )
                    
                    if not is_text_file:
                        continue
                    
                    file_path = os.path.join(root, file)
                    
                    # Проверяем, что файл существует и это не симлинк на несуществующий файл
                    if not os.path.exists(file_path):
                        logger.debug(f'Skipping non-existent file: {file_path}')
                        continue
                    
                    # Пропускаем симлинки
                    if os.path.islink(file_path):
                        logger.debug(f'Skipping symlink: {file_path}')
                        continue
                    
                    try:
                        # Проверяем размер файла
                        file_size = os.path.getsize(file_path)
                        
                        if file_size > MAX_FILE_SIZE_FOR_PYTHON:
                            # Для больших файлов используем grep
                            matches = self._search_large_file_with_grep(file_path, search_terms)
                            found_matches.extend(matches)
                        else:
                            # Для маленьких файлов используем Python
                            matches = self._search_small_file_with_python(file_path, search_terms)
                            found_matches.extend(matches)
                        
                        # Ограничиваем количество результатов
                        if len(found_matches) >= constants.MAX_UTIL_RES_LINES * 2:
                            return found_matches[:constants.MAX_UTIL_RES_LINES]
                            
                    except FileNotFoundError as fnf_error:
                        # Файл был удален между os.walk и обработкой
                        logger.debug(f'File disappeared during processing: {file_path}')
                        continue
                    except PermissionError as perm_error:
                        # Нет прав доступа к файлу
                        logger.debug(f'Permission denied for file: {file_path}')
                        continue
                    except OSError as os_error:
                        # Другие системные ошибки (broken symlinks, etc)
                        logger.debug(f'OS error processing file {file_path}: {os_error}')
                        continue
                    except Exception as ex:
                        # Неожиданные ошибки
                        logger.warning(f'Unexpected error processing file {file_path}: {ex}')
                        continue
        except FileNotFoundError:
            logger.info(f'Error in file search: {ex}')
            raise                
        
        except Exception as ex:
            logger.error(f'Error in file search: {ex}')
        
        return found_matches


    def _search_small_file_with_python(self, file_path, search_terms):
        """Поиск в небольших файлах с помощью Python с кешированием паттернов."""
        matches = []
        
        if not search_terms:
            return matches
        
        # Оптимизация: используем кешированный паттерн
        pattern = self._get_search_pattern(search_terms)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_stripped = line.strip()
                    if not line_stripped or len(line_stripped) > 1000:  # Пропускаем слишком длинные строки
                        continue
                    
                    # Single regex search instead of nested loop
                    match = pattern.search(line_stripped)
                    if match:
                        found_term = match.group(0)
                        context = self._get_context(line_stripped, found_term, 100)
                        matches.append({
                            'text': context,
                            'file': file_path,
                            'term': found_term,
                            'line_num': line_num
                        })
                        
                        # Ограничиваем количество находок на файл
                        if len(matches) >= 50:
                            return matches
        except FileNotFoundError:
            # Файл был удален между проверкой и открытием
            logger.debug(f'File not found during search: {file_path}')
        except PermissionError:
            # Нет прав доступа
            logger.debug(f'Permission denied during search: {file_path}')
        except UnicodeDecodeError:
            # Бинарный файл или некорректная кодировка (но errors='ignore' должен это предотвратить)
            logger.debug(f'Encoding error in file: {file_path}')
        except Exception as ex:
            # Другие неожиданные ошибки
            logger.debug(f'Unexpected error searching file {file_path}: {ex}')
            
        return matches

    def _search_large_file_with_grep(self, file_path, search_terms):
        """Поиск в больших файлах с помощью grep"""
        matches = []
        
        try:
            for term in search_terms:
                # Используем grep с ограничением количества результатов
                grep_command = [
                    'grep', '-n', '-i', '--text', '--max-count=20',
                    term, file_path
                ]
                
                try:
                    result = subprocess.run(
                        grep_command, 
                        capture_output=True, 
                        text=True, 
                        timeout=10  # Таймаут для больших файлов
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if not line.strip():
                                continue
                                
                            # Разбираем вывод grep: номер_строки:содержимое
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                line_num = parts[0]
                                content = parts[1]
                                
                                # Обрезаем контекст
                                context = self._get_context(content, term, 100)
                                
                                matches.append({
                                    'text': context,
                                    'file': file_path,
                                    'term': term,
                                    'line_num': int(line_num) if line_num.isdigit() else 0
                                })
                                
                except subprocess.TimeoutExpired:
                    logger.debug(f'Grep timeout for file {file_path} with term {term}')
                    continue
                except Exception as ex:
                    logger.debug(f'Grep error for file {file_path}: {ex}')
                    continue
                    
        except Exception as ex:
            logger.debug(f'Error in grep search for {file_path}: {ex}')
            
        return matches

    def _find_term_in_line(self, line, term):
        """Проверяет наличие термина в строке с учетом границ слов (оптимизировано)."""
        # Используем кешированный паттерн для точного совпадения
        word_boundary_pattern = rf'\b{re.escape(term)}\b'
        if self._get_compiled_regex(word_boundary_pattern, re.IGNORECASE).search(line):
            return True
        
        # Термин как часть слова (для названий компаний)
        if len(term) > 2 and self._get_compiled_regex(re.escape(term), re.IGNORECASE).search(line):
            # Проверяем, что это не длинная случайная строка
            # Исключаем только очевидные хеши/случайные строки
            hash_pattern = r'[a-f0-9]{30,}|[A-Za-z0-9+/]{25,}={0,2}'
            if self._get_compiled_regex(hash_pattern).search(line):
                return False
            
            # Проверяем, что строка содержит осмысленные символы
            if self._get_compiled_regex(r'[a-zA-Z]{2,}').search(line):
                return True
                
        return False

    def _get_context(self, line, term, max_length):
        """Получает контекст вокруг найденного термина"""
        if len(line) <= max_length:
            return line
        
        term_pos = line.lower().find(term.lower())
        if term_pos == -1:
            return line[:max_length] + '...'
        
        half_length = max_length // 2
        start = max(0, term_pos - half_length)
        end = min(len(line), term_pos + len(term) + half_length)
        
        result = line[start:end]
        if start > 0:
            result = '...' + result
        if end < len(line):
            result = result + '...'
        
        return result

    def _enhanced_semantic_check(self, text, term):
        """Улучшенная семантическая проверка"""
        if not text or not term or term.lower() not in text.lower():
            return 0
        
        # Сначала используем оригинальную проверку для совместимости
        original_check = utils.semantic_check_dork(text, term)
        if original_check:
            return original_check
        
        # Проверяем на очевидные хеши/случайные строки (более мягко)
        # Только длинные хеши считаем подозрительными
        if re.search(r'[a-f0-9]{40,}|[A-Za-z0-9+/]{30,}={0,2}', text):
            return 0
        
        # Проверяем, что строка не состоит только из случайных символов
        if len(text) > 50 and not re.search(r'[a-zA-Z]{3,}', text):
            return 0
        
        # Проверяем наличие контекстных слов в тексте
        context_score = sum(1 for word in constants.CONTEXT_WORDS if word in text.lower())
        
        # Если термин длинный (вероятно, название компании), то менее строгая проверка
        if len(term) > 4:
            # Для длинных терминов достаточно быть в осмысленном контексте
            if context_score > 0 or re.search(r'[a-zA-Z]{3,}', text):
                return 1
        
        # Для коротких терминов требуем контекст
        return min(context_score, 1)

    def _truncate_around_match(self, text, term, max_length):
        """Обрезает текст вокруг найденного термина"""
        return self._get_context(text, term, max_length)

    #    @_exc_catcher
    def gitleaks_scan(self):
        scan_type = 'gitleaks'
        
        # Проверка существования директории перед сканированием
        if not os.path.isdir(self.repos_dir):
            logger.warning('Repository directory %s removed before gitleaks_scan', self.repos_dir)
            return 3
        
        try:
            gitleaks_com = (
                '/usr/local/bin/gitleaks detect --no-banner --no-color --report-format json --exit-code 0 --report-path "'
                + self.report_dir + scan_type + '_rep.json"')
            
            ll = os.curdir
            os.chdir(self.repos_dir)
            gitleaks_proc = subprocess.run(gitleaks_com, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           shell=True, timeout=self.scan_time_limit, text=True, cwd=self.repos_dir)
            os.chdir(ll)
        except subprocess.TimeoutExpired:
            logger.error('\t- ' + scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2

        if os.path.exists(self.report_dir + scan_type + '_rep.json'):
            with open(self.report_dir + scan_type + '_rep.json', 'r') as file:
                js = json.load(file)
                
                def process_gitleaks_result(elem, index):
                    # Создаем позиционную информацию
                    position = f"V:{elem['StartColumn']}-{elem['EndColumn']};H:{elem['StartLine']}-{elem['EndLine']};"
                    
                    # Очищаем данные и создаем результат
                    match_str = elem.get('Match') or elem.get('Secret', '')
                    file_path = elem.get('File', '')
                    self._clean_result_data(elem)
                    elem['Position'] = position
                    elem['Match'] = match_str
                    elem['File'] = file_path
                    
                    return elem
                
                processed_count = self._process_scan_results(scan_type, js, process_gitleaks_result)
                logger.info(f'\t- {scan_type} scan %s %s %s success, processed {processed_count} results', 
                           self.log_color, self.url, CLR["RESET"])
        
        return 0

    @_exc_catcher
    def gitsecrets_scan(self):
        scan_type = 'gitsecrets'
        self.secrets[scan_type] = constants.AutoVivification()
        
        # Проверка существования директории перед сканированием
        if not os.path.isdir(self.repos_dir):
            logger.warning('Repository directory %s removed before gitsecrets_scan', self.repos_dir)
            return 3
        
        # Инициализация git secrets
        subprocess.run(['git', 'secrets', '--install', '-f'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit, shell=True)
        subprocess.run(['git', 'secrets', '--register-aws'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit, shell=True)
        subprocess.run(['git', 'secrets', '--aws-provider'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit, shell=True)
        
        gitsecret_com = 'git secrets --scan -r ' + self.repos_dir
        try:
            old_dir = os.curdir
            os.chdir(constants.TEMP_FOLDER)
            gitsecret_proc = subprocess.run(gitsecret_com, capture_output=True,
                                            shell=True, timeout=self.scan_time_limit, text=True, check=False)
            os.chdir(old_dir)
        except subprocess.TimeoutExpired:
            logger.error(f'\t- {scan_type} timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2

        # git-secrets выводит результаты в stderr, это нормальное поведение
        stderr_output = gitsecret_proc.stderr.strip()
        
        # Проверяем, есть ли найденные утечки
        if not stderr_output or len(stderr_output) == 0:
            logger.info(f'\t- {scan_type} scan %s %s %s success, no secrets found', 
                       self.log_color, self.url, CLR["RESET"])
            return 0
        
        # Сохраняем результаты в текстовый файл
        with open(self.report_dir + scan_type + '_rep.txt', 'w') as file:
            file.write(stderr_output)
        
        # Обрабатываем результаты построчно
        lines = stderr_output.split('\n')
        
        def process_gitsecrets_result(line, index):
            line = line.strip()
            if not line:
                return None
            
            # Пропускаем служебные сообщения
            if any(skip_phrase in line for skip_phrase in [
                '[ERROR] Matched one or more prohibited patterns',
                'Syntax error:', 'newline unexpected', 'Usage:', 'git-secrets'
            ]):
                return None
            
            # git-secrets выводит в формате: file:line:match или file:match
            if ':' in line:
                parts = line.split(':', 2)
                if len(parts) >= 2:
                    if len(parts) == 3:
                        # Формат: файл:строка:содержимое
                        file_path = parts[0].strip()
                        line_num = parts[1].strip()
                        match_str = parts[2].strip()
                        full_file_path = f"{file_path}:{line_num}"
                    else:
                        # Формат: файл:содержимое
                        file_path = parts[0].strip()
                        match_str = parts[1].strip()
                        full_file_path = file_path
                    
                    # Фильтруем пустые и слишком короткие совпадения
                    if len(match_str) < 3:
                        return None
                    
                    return self._create_standard_result(match_str, full_file_path)
            else:
                # Строка без разделителей - возможно, это найденный секрет
                if len(line) >= 6:  # Минимальная длина для секрета
                    return self._create_standard_result(line, "unknown")
                
            return None
        
        processed_count = self._process_scan_results(scan_type, lines, process_gitsecrets_result)
        
        logger.info(f'\t- {scan_type} scan %s %s %s success, processed {processed_count} results', 
                   self.log_color, self.url, CLR["RESET"])
        
        return 0
    
    @_exc_catcher
    def detect_secrets_scan(self):
        scan_type = 'detect_secrets'
        self.secrets[scan_type] = constants.AutoVivification()

        # Проверка существования директории перед сканированием
        if not os.path.isdir(self.repos_dir):
            logger.warning('Repository directory %s removed before detect_secrets_scan', self.repos_dir)
            return 3

        ds_bin = shutil.which('detect-secrets')
        if not ds_bin:
            self.secrets[scan_type]['Info'] = 'detect-secrets not installed'
            logger.info(f'\t- {scan_type} scan %s %s %s success (tool not available)',
                        self.log_color, self.url, CLR["RESET"])
            return 0

        cmd = [ds_bin, 'scan', '--all-files']
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.repos_dir,
                timeout=self.scan_time_limit
            )
        except subprocess.TimeoutExpired:
            logger.error(f'\t- {scan_type} timeout occured in repository %s %s %s',
                         self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s',
                         self.log_color, self.url, CLR["RESET"], ex)
            return 2

        try:
            output = json.loads(result.stdout)
        except Exception as ex:
            logger.error(f'Failed to parse detect-secrets output: {ex}')
            return 2

        # Проверяем структуру output
        if not isinstance(output, dict):
            logger.error(f'detect-secrets output is not a dict: {type(output)}')
            return 2
        
        results_data = output.get('results', {})
        if not isinstance(results_data, dict):
            logger.error(f'detect-secrets results is not a dict: {type(results_data)}')
            return 2

        results = []
        for file_path, secrets in results_data.items():
            if not isinstance(secrets, list):
                logger.warning(f'detect-secrets secrets for {file_path} is not a list: {type(secrets)}, skipping')
                continue
                
            for sec in secrets:
                if not isinstance(sec, dict):
                    logger.warning(f'detect-secrets secret is not a dict: {type(sec)}, skipping')
                    continue
                line_num = sec.get('line_number')
                line_text = ''
                abs_path = os.path.join(self.repos_dir, file_path)
                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as fh:
                        lines = fh.readlines()
                        if line_num and 0 < line_num <= len(lines):
                            line_text = lines[line_num - 1].strip()
                except Exception:
                    pass
                result_entry = self._create_standard_result(
                    match=line_text,
                    file_path=f"{file_path}:{line_num}",
                    extra_data={'SecretType': sec.get('type'),
                                'Verified': sec.get('is_verified')}
                )
                results.append(result_entry)

        processed_count = self._process_scan_results(scan_type, results, lambda x, _: x)

        logger.info(f'\t- {scan_type} scan %s %s %s success, processed {processed_count} results',
                    self.log_color, self.url, CLR["RESET"])

        return 0

    def kingfisher_scan(self):
        """Запускает kingfisher, парсит stdout‑массив и обрабатывает находки."""
        scan_type = 'kingfisher'
        self.secrets[scan_type] = constants.AutoVivification()

        # Проверка существования директории перед сканированием
        if not os.path.isdir(self.repos_dir):
            logger.warning('Repository directory %s removed before kingfisher_scan', self.repos_dir)
            return 3

        kf_bin = shutil.which('kingfisher')
        if not kf_bin:
            self.secrets[scan_type]['Info'] = 'kingfisher not installed'
            logger.info('\t- %s scan %s %s %s success (tool not available)',
                        scan_type, self.log_color, self.url, CLR["RESET"])
            return 0

        cmd = [
            kf_bin, 'scan', self.repos_dir,
            '--format', 'json', '--no-update-check', '--confidence', 'low', '-q'
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=self.scan_time_limit)
        except subprocess.TimeoutExpired:
            logger.error('\t- %s timeout in %s %s %s', scan_type,
                        self.log_color, self.url, CLR["RESET"])
            return 2
        except subprocess.CalledProcessError as ex:
            logger.error('\t- %s returned non‑zero: %s', scan_type, ex)
            return 2

        raw = res.stdout.lstrip()           # stderr содержит статистику/лог

        # --- извлекаем один внешний [...] ---
        start = raw.find('[')
        if start == -1:
            self.secrets[scan_type]['Info'] = 'No findings'
            logger.info('\t- %s scan %s %s %s success, no findings',
                        scan_type, self.log_color, self.url, CLR["RESET"])
            return 0

        depth = 0
        in_str = False
        esc = False
        end = -1
        for i, ch in enumerate(raw[start:], start):
            if in_str:
                esc = not esc if ch == '\\' and not esc else False
                if ch == '"' and not esc:
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end == -1:
            logger.error('Cannot find end of JSON array in Kingfisher output')
            return 2

        try:
            findings = json.loads(raw[start:end])
        except json.JSONDecodeError as e:
            logger.error('Kingfisher JSON decode error: %s', e)
            return 2

        # Проверяем структуру findings
        if not isinstance(findings, list):
            logger.error(f'Kingfisher findings is not a list: {type(findings)}')
            return 2

        results = []
        for item in findings:
            # Проверяем, что item является словарем
            if not isinstance(item, dict):
                logger.warning(f'Kingfisher item is not a dict: {type(item)}, skipping')
                continue
                
            rule_id = item.get('id', '')
            matches = item.get('matches', [])
            
            # Проверяем, что matches является списком
            if not isinstance(matches, list):
                logger.warning(f'Kingfisher matches is not a list: {type(matches)}, skipping')
                continue
            
            for match in matches:
                # Проверяем, что match является словарем
                if not isinstance(match, dict):
                    logger.warning(f'Kingfisher match is not a dict: {type(match)}, skipping')
                    continue
                    
                f = match.get('finding', {})
                if not isinstance(f, dict):
                    logger.warning(f'Kingfisher finding is not a dict: {type(f)}, skipping')
                    continue
                
                loc = f'{f.get("path","")}:{f.get("line")}' if f.get('line') else f.get('path','')
                
                # Безопасное извлечение validation status
                validation_data = f.get('validation', {})
                validation_status = validation_data.get('status') if isinstance(validation_data, dict) else None
                
                extra = {
                    'Rule':        rule_id,
                    'Confidence':  f.get('confidence'),
                    'Entropy':     f.get('entropy'),
                    'Fingerprint': f.get('fingerprint'),
                    'Validation':  validation_status
                }
                results.append(
                    self._create_standard_result(match=f.get('snippet','').strip(),
                                                file_path=loc,
                                                extra_data=extra)
                )

        processed = self._process_scan_results(scan_type, results, lambda x, _: x)
        if processed == 0:
            self.secrets[scan_type]['Info'] = 'Kingfisher completed but no meaningful results found'

        logger.info('\t- %s scan %s %s %s success, processed %d results',
                    scan_type, self.log_color, self.url, CLR["RESET"], processed)
        return 0
    
    @_exc_catcher
    def deepsecrets_scan(self):
        scan_type = 'deepsecrets'
        self.secrets[scan_type] = constants.AutoVivification()
        
        # Проверка существования директории перед сканированием
        if not os.path.isdir(self.repos_dir):
            logger.warning('Repository directory %s removed before deepsecrets_scan', self.repos_dir)
            return 3
        
        try:
            deep_com = 'deepsecrets --target-dir ' + self.repos_dir + ' --outfile ' + self.report_dir + scan_type + '_rep.json'
            deepsecrets_proc = subprocess.run(deep_com, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                              shell=True, timeout=self.scan_time_limit, text=True)
        except subprocess.TimeoutExpired:
            logger.error(scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url,
                         CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"],
                         ex)
            return 2

        if os.path.exists(self.report_dir + scan_type + '_rep.json'):
            with open(self.report_dir + scan_type + '_rep.json', 'r') as file:
                js = json.load(file)
                is_first = True
                counter = 1

                for i in js:
                    for j in js[i]:
                        a = True
                        if not is_first:
                            for _, v in self.secrets['deepsecrets'].items():
                                if str(j['line'][:constants.MAX_LINE_LEAK_LEN]) == v['Match']:
                                    a = False
                                    break
                                a = True
                        if a:
                            is_first = False

                            if len(j['line']) > constants.MAX_LINE_LEAK_LEN:
                                j['line'] = j['line'][:constants.MAX_LINE_LEAK_LEN]
                            self.secrets['deepsecrets'][f'Leak #{counter}']['Match'] = str(j['line'])

                            self.secrets['deepsecrets'][f'Leak #{counter}']['File'] = str(i)
                            counter += 1
            logger.info(f'{scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
            return 0
        else:
            logger.error('File deepsecrets_rep.json not founded\n')
            return 2

    @_exc_catcher
    def ai_deep_scan(self):
        """AI глубокое сканирование"""
        scan_type = 'ai_deep_scan'
        # Заглушка для AI сканирования - можно реализовать позже
        self.secrets[scan_type] = constants.AutoVivification()
        self.secrets[scan_type]['Info'] = 'AI deep scan not implemented'
        logger.info(f'\t- {scan_type} scan %s %s %s success (not implemented)', self.log_color, self.url, CLR["RESET"])
        return 0
    
    @_exc_catcher
    def trufflehog_scan(self):
        scan_type = 'trufflehog'
        self.secrets[scan_type] = constants.AutoVivification()
        
        # Проверка существования директории перед сканированием
        if not os.path.isdir(self.repos_dir):
            logger.warning('Repository directory %s removed before trufflehog_scan', self.repos_dir)
            return 3
        
        try:
            # Создаем кастомный конфиг для TruffleHog
            config_path = self._create_trufflehog_config()
            
            # Улучшенная команда TruffleHog с учетом компании
            truf_com = self._build_trufflehog_command(config_path)
            
            trufflehog_proc = subprocess.run(truf_com, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             shell=True, timeout=self.scan_time_limit, text=True)
        except subprocess.TimeoutExpired:
            logger.error('\t- ' + scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2

        # Обработка результатов
        return self._process_trufflehog_results(trufflehog_proc.stdout, scan_type)

    def _create_trufflehog_config(self):
        """Создает конфигурационный файл для TruffleHog с кастомными детекторами"""
        config_path = os.path.join(self.report_dir, 'trufflehog_config.json')
        
        # Получаем название компании для кастомных детекторов
        company_name = Connector.get_company_name(self.obj.company_id)
        
        # Создаем кастомные детекторы
        custom_detectors = self._generate_company_detectors(self.company_name, self.company_terms, self.safe_company_name)
        
        config_content = {
            'detectors': custom_detectors
        }
        
        # Сохраняем конфигурацию в JSON формате
        try:
            with open(config_path, 'w') as f:
                json.dump(config_content, f, indent=2)
            logger.debug(f'Created TruffleHog JSON config: {config_path}')
        except Exception as ex:
            logger.error(f'Failed to create TruffleHog config: {ex}')
            return None
            
        return config_path

    def _generate_company_detectors(self, company_name, company_terms, safe_name):
        """Генерирует кастомные детекторы на основе названия компании"""
        detectors = []
        
        # Всегда добавляем универсальный детектор для общих утечек
        detectors.append(self._create_universal_detector())
        detectors.append(self._create_config_detector())
        
        # Если есть название компании, добавляем специфичные детекторы
        if company_name: 
            # Создаем детекторы для компании
            detectors.extend([
                self._create_company_credentials_detector(safe_name, company_terms),
                self._create_company_api_detector(safe_name, company_terms),
                self._create_company_login_detector(safe_name, company_terms),
                self._create_company_email_detector(safe_name, company_terms)
            ])
        
        return detectors
    
    def _create_universal_detector(self):
        """Создает универсальный детектор для общих утечек"""
        return {
            'name': 'universal-secrets',
            'keywords': [
                'password', 'pwd', 'pass', 'secret', 'key', 'token', 'auth', 'api',
                'credential', 'cred', 'access', 'private', 'confidential', 'sensitive'
            ],
            'regex': {
                'secret': r'(?i)(?:password|pwd|pass|secret|key|token|auth|api|credential|cred|access|private)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9@#$%^&*()_+\-=\[\]{};:,.<>?/~`|\\!]{6,})\1',
                'base64_secret': r'(?i)(?:password|pwd|pass|secret|key|token|auth|api)[_\-\s]*[:=]\s*(["\']?)([A-Za-z0-9+/]{20,}={0,2})\1',
                'hex_secret': r'(?i)(?:password|pwd|pass|secret|key|token|auth|api)[_\-\s]*[:=]\s*(["\']?)([a-fA-F0-9]{16,})\1'
            },
            'entropy': 2.0,
            'exclude_words': [
                'example', 'test', 'demo', 'sample', 'placeholder', 'dummy', 'fake',
                'password', 'secret', 'key', 'token',
                '123456', 'password123', 'admin123', 'root123', 'test123'
            ]
        }
    
    def _create_config_detector(self):
        """Создает детектор для конфигурационных файлов"""
        return {
            'name': 'config-files-secrets',
            'keywords': [
                'config', 'env', 'settings', 'database', 'db', 'server', 'host',
                'url', 'uri', 'endpoint', 'connection', 'dsn'
            ],
            'regex': {
                'config_value': r'(?i)(?:database|db|server|host|url|uri|endpoint|connection|dsn)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9@._\-:\/]{5,})\1',
                'env_var': r'(?i)[A-Z_]{2,}[_]?(?:PASSWORD|PWD|PASS|SECRET|KEY|TOKEN|AUTH|API)[_A-Z0-9]*\s*[:=]\s*(["\']?)([a-zA-Z0-9@#$%^&*()_+\-=\[\]{};:,.<>?/~`|\\!]{6,})\1'
            },
            'entropy': 1.5,
            'exclude_words': [
                'localhost', '127.0.0.1', 'example.com', 'test.com', 'demo.com',
                'your_host_here', 'your_database_here'
            ]
        }
    
    def _create_company_credentials_detector(self, safe_name, company_terms):
        """Создает детектор для паролей, связанных с компанией"""
        return {
            'name': f'company-credentials-{safe_name}',
            'keywords': company_terms + ['password', 'pwd', 'pass', 'secret', 'key', 'token', 'auth', 'api'],
            'regex': {
                'credential': r'(?i)(?:' + '|'.join(re.escape(term) for term in company_terms) + r')[_\-\s]*(?:password|pwd|pass|secret|key|token|auth|api)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9@#$%^&*()_+\-=\[\]{};:,.<>?/~`|\\!]{6,})\1'
            },
            'entropy': 2.0,
            'exclude_words': [
                'example', 'test', 'demo', 'sample', 'placeholder', 'your_password_here',
                'change_me', 'replace_me', 'password123', 'admin123', 'root123'
            ]
        }
    
    def _create_company_api_detector(self, safe_name, company_terms):
        """Создает детектор для API ключей компании"""
        return {
            'name': f'company-api-keys-{safe_name}',
            'keywords': company_terms + ['api', 'key', 'token', 'access', 'secret'],
            'regex': {
                'api_key': r'(?i)(?:' + '|'.join(re.escape(term) for term in company_terms) + r')[_\-\s]*(?:api[_\-\s]*key|access[_\-\s]*token|secret[_\-\s]*key)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9]{15,})\1'
            },
            'entropy': 2.5,
            'exclude_words': [
                'example', 'test', 'demo', 'sample', 'placeholder', 'your_api_key_here'
            ]
        }
    
    def _create_company_login_detector(self, safe_name, company_terms):
        """Создает детектор для логинов компании"""
        company_terms_filtered = [term for term in company_terms if '\\d+' not in term]
        
        return {
            'name': f'company-login-pattern-{safe_name}',
            'keywords': company_terms + ['login', 'user', 'username', 'account'],
            'regex': {
                'company_login': r'(?i)(?:' + '|'.join(re.escape(term) for term in company_terms_filtered) + r')\d{1,8}',
                'company_login_config': r'(?i)(?:login|user|username|account)[_\-\s]*[:=]\s*(["\']?)(' + '|'.join(re.escape(term) for term in company_terms_filtered) + r')\d{1,8}\1'
            },
            'entropy': 1.0,
            'exclude_words': ['example', 'test', 'demo', 'sample']
        }
    
    def _create_company_email_detector(self, safe_name, company_terms):
        """Создает детектор для email доменов компании"""
        email_terms = [term for term in company_terms if '@' in term]
        if not email_terms:
            # Если нет явных email доменов, создаем на основе названия компании
            email_terms = [f"{term}.com" for term in company_terms[:3] if len(term) > 2]
        
        if email_terms:
            email_terms_clean = [term.replace('@', '') for term in email_terms]
            return {
                'name': f'company-email-pattern-{safe_name}',
                'keywords': company_terms + ['email', 'mail', 'address'],
                'regex': {
                    'company_email': r'(?i)\b([a-zA-Z0-9._-]+@(?:' + '|'.join(re.escape(term) for term in email_terms_clean) + r'))\b',
                    'company_email_config': r'(?i)(?:email|mail|address)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9._-]+@(?:' + '|'.join(re.escape(term) for term in email_terms_clean) + r'))\1'
                },
                'entropy': 1.0,
                'exclude_words': ['example@', 'test@', 'demo@']
            }
        else:
            return {
                'name': f'company-email-pattern-{safe_name}',
                'keywords': company_terms + ['email', 'mail', 'address'],
                'regex': {
                    'company_email': r'(?i)\b([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
                },
                'entropy': 1.0,
                'exclude_words': ['example@', 'test@', 'demo@']
            }
    
    def _build_trufflehog_command(self, config_path):
        """Строит улучшенную команду TruffleHog"""
        base_command = [
            'trufflehog', 'git',
            '--json',
            '--no-update',
            '--results=verified,unknown,unverified',  # Включаем все типы результатов для максимального покрытия
            '--concurrency=3',  # Уменьшаем для стабильности
            '--archive-max-size=100MB',  # Увеличиваем лимит архивов
            '--archive-max-depth=5',  # Увеличиваем глубину архивов
            '--no-verification',  # Отключаем верификацию для ускорения и полноты покрытия
            f'file://{self.repos_dir}'
        ]
        
        # Добавляем кастомную конфигурацию если она создана
        if config_path and os.path.exists(config_path):
            base_command.extend(['--config', config_path])
        
        # Минимальный набор исключений - только действительно ненужные файлы
        exclude_patterns = [
            '*.ipynb', '*.jpg', '*.png', '*.gif', '*.zip'
        ]
        
        for pattern in exclude_patterns:
            base_command.extend(['--exclude-globs', pattern])
        
        return ' '.join(base_command)

    def _process_trufflehog_results(self, stdout_data, scan_type):
        """Обрабатывает результаты TruffleHog с улучшенной фильтрацией"""
        # Сохраняем результаты в файл
        with open(self.report_dir + scan_type + '_rep.txt', 'w') as file:
            file.write(stdout_data)

        # Обрабатываем результаты
        trufflehog_list = []
        try:
            with open(self.report_dir + scan_type + '_rep.txt', 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        try:
                            result = json.loads(line)
                            # Проверяем, что result является словарем
                            if isinstance(result, dict):
                                trufflehog_list.append(result)
                            else:
                                logger.warning(f'TruffleHog result is not a dict: {type(result)}, skipping')
                        except json.JSONDecodeError:
                            continue
        except Exception as ex:
            logger.error(f'Error reading TruffleHog results: {ex}')
            return 2

        # Фильтруем и обрабатываем результаты
        processed_results = self._filter_and_enhance_results(trufflehog_list)
        
        def process_trufflehog_result(elem, index):
            # Создаем уникальный хеш для дедупликации
            source_data = elem.get('SourceMetadata', {})
            md5_dict_hash = hashlib.md5(json.dumps(source_data, sort_keys=True).encode('utf-8')).hexdigest()
            
            # Очищаем данные для экономии места
            self._clean_result_data(elem)
            
            # Добавляем данные о совпадении для совместимости
            raw_match = elem.get('RawV2') or elem.get('Raw', '')
            elem['Match'] = raw_match
            elem['meaningfull'] = self._evaluate_meaningfulness(elem)
            elem['dedup_hash'] = md5_dict_hash
            
            return elem
        
        # Дедупликация результатов
        processed_results_dedup = []
        seen_hashes = set()
        
        for result in processed_results:
            source_data = result.get('SourceMetadata', {})
            md5_dict_hash = hashlib.md5(json.dumps(source_data, sort_keys=True).encode('utf-8')).hexdigest()
            
            if md5_dict_hash not in seen_hashes:
                seen_hashes.add(md5_dict_hash)
                processed_results_dedup.append(result)
        
        # Обрабатываем финальные результаты
        processed_count = self._process_scan_results(scan_type, processed_results_dedup, process_trufflehog_result)
        
        logger.info(f'\t- {scan_type} scan %s %s %s success, processed {processed_count} results', 
                   self.log_color, self.url, CLR["RESET"])
        return 0

    def _filter_and_enhance_results(self, results):
        """Фильтрует и улучшает результаты TruffleHog"""
        enhanced_results = []
        
        for result in results:
            # Проверяем релевантность результата
            if self._is_result_relevant(result, self.company_name):
                # Добавляем дополнительную информацию
                result['CompanyRelevance'] = self._calculate_company_relevance(result, self.company_name)
                result['ContextualScore'] = self._calculate_contextual_score(result)
                enhanced_results.append(result)
        
        # Сортируем по релевантности
        enhanced_results.sort(key=lambda x: (
            x.get('Verified', False),
            x.get('CompanyRelevance', 0),
            x.get('ContextualScore', 0)
        ), reverse=True)
        
        return enhanced_results
    def _is_company_specific_pattern(self, text, company_name=None):
        """Проверяет наличие специфических паттернов компании в тексте"""
        if company_name is None:
            company_name = self.company_name

        if not company_name:
            return False

        company_terms = self.company_terms if company_name == self.company_name else utils.generate_company_search_terms(company_name)
        
        # Проверяем логины с цифрами (например, vtb123, company456)
        for term in company_terms:
            if len(term) > 2:
                # Логин паттерн: название_компании + цифры
                if re.search(rf'(?i)\b{re.escape(term)}\d{{1,8}}\b', text):
                    return True
                
                # Email паттерн: любой_email@компания.домен
                if re.search(rf'(?i)\b[a-zA-Z0-9._-]+@{re.escape(term)}\.[a-zA-Z]{{2,}}\b', text):
                    return True
                
                # Паттерн в кириллице (если применимо)
                if re.search(rf'(?i)\b{re.escape(term)}\d{{1,8}}\b', text):
                    return True
        
        return False

    def _calculate_company_relevance(self, result, company_name=None):
        """Вычисляет релевантность результата для компании"""
        if company_name is None:
            company_name = self.company_name
        if not company_name:
            return 0.0
        
        score = 0.0
        raw_data = result.get('RawV2') or result.get('Raw', '')
        source_metadata = result.get('SourceMetadata', {})
        
        # Безопасное извлечение вложенных значений с проверкой типов
        def safe_nested_get(data, *keys, default=''):
            """Безопасно получить значение из вложенной структуры словарей"""
            current = data
            for key in keys:
                if isinstance(current, dict):
                    current = current.get(key)
                else:
                    return default
                if current is None:
                    return default
            return current if current is not None else default
        
        # Анализируем различные части результата
        text_sources = [
            raw_data,
            safe_nested_get(source_metadata, 'Data', 'Git', 'file'),
            safe_nested_get(source_metadata, 'Data', 'Git', 'commit'),
        ]
        
        full_text = ' '.join(str(source) for source in text_sources if source).lower()
        
        # Проверяем наличие компанейских терминов
        company_terms = self.company_terms if company_name == self.company_name else utils.generate_company_search_terms(company_name)
        for term in company_terms:
            if term.lower() in full_text:
                # Вес зависит от длины термина (длинные термины более специфичны)
                weight = min(len(term) / 10.0, 1.0)
                score += weight
        
        return min(score, 1.0)

    def _calculate_contextual_score(self, result):
        """Вычисляет контекстуальный скор результата"""
        score = 0.0
        raw_data = result.get('RawV2') or result.get('Raw', '')
        
        # Бонусы за проверенные результаты
        if result.get('Verified', False):
            score += 1.0
        
        # Бонусы за определенные типы детекторов
        detector_name = result.get('DetectorName', '').lower()
        high_value_detectors = ['aws', 'google', 'azure', 'github', 'gitlab', 'database']
        
        for detector in high_value_detectors:
            if detector in detector_name:
                score += 0.5
                break
        
        # Штрафы за тестовые данные
        test_indicators = ['test', 'demo', 'example', 'sample', 'dummy']
        for indicator in test_indicators:
            if indicator in raw_data.lower():
                score -= 0.3
        
        return max(score, 0.0)

    def _evaluate_meaningfulness(self, result):
        """Оценивает осмысленность результата для совместимости с существующим кодом"""
        # Проверенные результаты всегда считаются осмысленными
        if result.get('Verified', False):
            return 1
        
        # Проверяем детектор - компанейские детекторы получают максимальный приоритет
        detector_name = result.get('DetectorName', '').lower()
        
        # Компанейские детекторы - максимальный приоритет
        company_detectors = [
            'company-credentials-', 'company-api-keys-', 'company-login-pattern-',
            'company-email-pattern-'
        ]
        
        for detector in company_detectors:
            if detector in detector_name:
                return 1
        
        # Высокое значение релевантности к компании
        company_relevance = result.get('CompanyRelevance', 0)
        if company_relevance > 0.2:
            return 1
        
        # Высокий контекстуальный скор
        contextual_score = result.get('ContextualScore', 0)
        if contextual_score > 0.3:
            return 1
        
        # Проверяем детектор - для важных детекторов снижаем требования
        important_detectors = [
            'aws', 'google', 'azure', 'github', 'gitlab', 'slack', 'discord',
            'stripe', 'paypal', 'twilio', 'sendgrid', 'mailgun', 'custom'
        ]
        
        for detector in important_detectors:
            if detector in detector_name:
                return 1
        
        # Анализируем сам секрет
        raw_data = result.get('RawV2') or result.get('Raw', '')
        if raw_data:
            # Получаем название компании для универсальных проверок
            company_name = Connector.get_company_name(self.obj.company_id)
            
            # Проверяем специфические паттерны компании
            if self._is_company_specific_pattern(raw_data, self.company_name):
                return 1
            
            # Длинные секреты более вероятно реальные
            if len(raw_data) > 20:
                return 1
            
            # Секреты с хорошей энтропией
            if self._calculate_entropy(raw_data) > 3.0:
                return 1
            
            # Секреты в base64 формате
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', raw_data):
                return 1
            
            # Hex секреты
            if re.match(r'^[a-fA-F0-9]{16,}$', raw_data):
                return 1
        
        # Проверяем контекст на наличие компанейских паттернов
        source_metadata = result.get('SourceMetadata', {})
        if isinstance(source_metadata, dict):
            data_text = str(source_metadata.get('Data', ''))
            if self._is_company_specific_pattern(data_text, self.company_name):
                return 1
        
        # По умолчанию считаем осмысленным (лучше ложное срабатывание, чем пропуск)
        return 1

    def _calculate_entropy(self, data):
        """Вычисляет энтропию строки. Делегирует в LeakAnalyzer."""
        from src.LeakAnalyzer import LeakAnalyzer
        return LeakAnalyzer.calculate_entropy(data)

    def _is_result_relevant(self, result, company_name=None):
        """Проверяет релевантность результата"""
        if company_name is None:
            company_name = self.company_name
        # Всегда включаем проверенные результаты
        if result.get('Verified', False):
            return True
        
        # Проверяем контекст на наличие компанейских терминов
        raw_data = result.get('RawV2') or result.get('Raw', '')
        source_metadata = result.get('SourceMetadata', {})
        
        # Безопасное извлечение вложенных значений с проверкой типов
        def safe_nested_get(data, *keys, default=''):
            """Безопасно получить значение из вложенной структуры словарей"""
            current = data
            for key in keys:
                if isinstance(current, dict):
                    current = current.get(key)
                else:
                    return default
                if current is None:
                    return default
            return current if current is not None else default
        
        # Собираем весь контекст для анализа
        context_data = [
            raw_data,
            safe_nested_get(source_metadata, 'Data', 'Git', 'file'),
            safe_nested_get(source_metadata, 'Data', 'Git', 'commit'),
        ]
        
        context_text = ' '.join(str(data) for data in context_data if data).lower()
        
        # Проверяем наличие компанейских терминов
        if company_name:
            company_terms = self.company_terms if company_name == self.company_name else utils.generate_company_search_terms(company_name)
            for term in company_terms:
                if term.lower() in context_text:
                    return True
            
            # Проверяем специфические паттерны компании
            if self._is_company_specific_pattern(context_text, company_name):
                return True
        
        # Проверяем наличие основного dork
        if self.dork.lower() in context_text:
            return True
        
        # Исключаем явно тестовые/демонстрационные данные
        exclude_patterns = [
            'test', 'demo', 'example', 'sample', 'placeholder',
            'lorem', 'ipsum', 'dummy', 'fake', 'mock'
        ]
        
        for pattern in exclude_patterns:
            if pattern in context_text:
                return False
        
        return True

    def run(self):
        """
        скачивает репозиторий по ссылке из url и проверяет с помощью сканеров TODO
        в конце, скаченный репозиторий удаляется,
        а обнаруженные секреты добавляются в словарь secrets
        """

        # logger.info(': ' + str(datetime.now()) + '\n')
        # Commented because logger shows time and date as well
        if self.status & NOT_CLONED:
            self.status |= SCANNED
        elif self.status & CLONED == 0:
            raise CheckerException(
                "You forgot call checker.clone() before scan()!")
        else:
            # self._pydriller_scan() TODO repair dependities
            self.scan()
            self.status |= SCANNED
            time.sleep(2)  # for MultiThread control
            self._clean_repo_dirs()

        self.obj.stats.fetch_commits_stats()  # get stats this to optimize token usage
        self.obj.secrets = self.secrets
        # AI анализ теперь выполняется автоматически в LeakObj._check_status()
        return self.secrets

    def _process_scan_results(self, scan_type, results, process_func):
        """Универсальная функция для обработки результатов сканирования"""
        self.secrets[scan_type] = constants.AutoVivification()
        
        processed_count = 0
        seen_matches = set()
        
        for index, result in enumerate(results[:constants.MAX_UTIL_RES_LINES]):
            # Обрабатываем результат через переданную функцию
            processed_result = process_func(result, index)
            
            if processed_result is None:
                continue
                
            # Проверяем на дублирование
            match_key = processed_result.get('Match', '')
            file_key = processed_result.get('File', '')
            dedup_key = f"{match_key}|{file_key}"
            if dedup_key in seen_matches:
                continue
            seen_matches.add(dedup_key)
            
            # Обрезаем слишком длинные строки
            if len(match_key) > constants.MAX_LINE_LEAK_LEN:
                processed_result['Match'] = match_key[:constants.MAX_LINE_LEAK_LEN] + '...'
            
            # Добавляем семантическую проверку
            processed_result['meaningfull'] = utils.semantic_check_dork(processed_result['Match'], self.dork)
            
            # Сохраняем результат
            self.secrets[scan_type][f'Leak #{processed_count}'] = processed_result
            processed_count += 1
        
        return processed_count

    def _create_standard_result(self, match, file_path="", extra_data=None):
        """Создает стандартную структуру результата"""
        result = {
            'Match': match,
            'File': file_path
        }
        
        if extra_data:
            result.update(extra_data)
            
        return result

    def _clean_result_data(self, result, fields_to_remove=None):
        """Очищает данные результата, удаляя ненужные поля"""
        if fields_to_remove is None:
            fields_to_remove = [
                'Fingerprint', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn', 
                'SymlinkFile', 'Secret', 'Entropy', 'Message', 'SourceID', 
                'SourceType', 'SourceName', 'DetectorType', 'DecoderName', 
                'Redacted', 'ExtraData', 'StructuredData', 'Raw', 'RawV2'
            ]
        
        for field in fields_to_remove:
            result.pop(field, None)
            
        return result

    

    def _collect_repo_text(self):
        """Собирает текст из всех файлов репозитория"""
        repo_text = ""
        
        try:
            for root, dirs, files in os.walk(self.repos_dir):
                for file in files:
                    _, ext = os.path.splitext(file.lower())
                    if ext in constants.TEXT_FILE_EXTS:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                repo_text += f.read()[:10000]  # Ограничиваем размер
                        except Exception:
                            continue
        except Exception:
            pass
        
        return repo_text
