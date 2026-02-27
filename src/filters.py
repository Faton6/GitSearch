# Standard libs import
from random import choice
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import shutil
import subprocess
from pathlib import Path
import re
import time
import git
import threading
from typing import Dict, FrozenSet, List

# Project lib's import
from src import Connector, constants
from src.logger import logger, CLR
from src import utils

exclusions: tuple[str]
with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", "r") as fd:
    exclusions = tuple(line.rstrip() for line in fd)


def _exc_catcher(func):
    """Decorator for catching exceptions in scan methods."""

    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except subprocess.TimeoutExpired as e:
            scanner_name = func.__name__.replace("_scan", "").replace("_", "-")
            url = args[0].url if args and hasattr(args[0], "url") else ""
            logger.error("TimeoutExpired in %s for %s", scanner_name, url)
            raise
        except Exception as exc:
            logger.error("Exception in %s: %s", func.__name__, exc)
            return 2

    return wrapper


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
            cls._search_pattern_cache[key] = re.compile(r"\b(?:" + "|".join(escaped) + r")\b", re.IGNORECASE)
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
        # Delegate to shared cache to avoid duplicating compilation logic
        return utils.get_compiled_regex(pattern, flags)

    @classmethod
    def clear_pattern_cache(cls):
        """Очистка кеша паттернов."""
        cls._search_pattern_cache.clear()
        cls._compiled_regex_cache.clear()
        utils.clear_regex_cache()

    def __init__(self, url: str, dork: str, obj: any, mode: int = 1, token: str = "") -> None:
        self.url = url
        self.obj = obj
        self.dork = dork
        self.mode = mode

        # Ensure temp folder exists before creating paths
        if not os.path.exists(constants.TEMP_FOLDER):
            try:
                os.makedirs(constants.TEMP_FOLDER, exist_ok=True)
                logger.info(f"Created temp folder: {constants.TEMP_FOLDER}")
            except Exception as e:
                logger.error(f"Cannot create temp folder {constants.TEMP_FOLDER}: {e}")
                raise

        self.repos_dir = constants.TEMP_FOLDER + "/" + url.split("/")[-2] + "---" + url.split("/")[-1]
        self.report_dir = self.repos_dir + "---reports/"
        self.secrets = constants.AutoVivification()
        self.repo: git.Repo
        self.status = INITED
        self.company_name = Connector.get_company_name(self.obj.company_id)
        self.company_terms = utils.generate_company_search_terms(self.company_name)
        self.safe_company_name = utils.sanitize_company_name(self.company_name)
        self.scan_time_limit = (
            constants.MAX_TIME_TO_SCAN_BY_UTIL_DEEP if self.mode == 3 else constants.MAX_TIME_TO_SCAN_BY_UTIL_DEFAULT
        )
        self.log_color = choice(tuple(CLR.values()))
        # Блокировка для безопасного удаления директории при мультипоточности
        self._cleanup_lock = threading.Lock()
        self._cleaned = False  # Флаг для предотвращения повторного удаления
        self.scans = {
            "gitleaks": self.gitleaks_scan,
            "trufflehog": self.trufflehog_scan,
            "detect_secrets": self.detect_secrets_scan,
            "kingfisher": self.kingfisher_scan,
            "grepscan": self.grep_scan,
        }

        self.deep_scans = {
            "gitleaks": self.gitleaks_scan,
            "gitsecrets": self.gitsecrets_scan,
            "grepscan": self.grep_scan,
            "deepsecrets": self.deepsecrets_scan,
            "detect_secrets": self.detect_secrets_scan,
            "kingfisher": self.kingfisher_scan,

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
                logger.debug(f"Repository {self.repos_dir} already cleaned, skipping")
                return

            # Save current working directory
            original_cwd = None
            try:
                original_cwd = os.getcwd()
            except (OSError, FileNotFoundError) as e:
                logger.warning(f"Cannot get current working directory: {e}")
                # If we can't get CWD, try to change to a safe location
                try:
                    os.chdir(constants.MAIN_FOLDER_PATH)
                    original_cwd = str(constants.MAIN_FOLDER_PATH)
                except Exception as e2:
                    logger.error(f"Cannot change to safe directory: {e2}")

            # Clean repository directory
            try:
                if os.path.exists(self.repos_dir):
                    # Ensure we're not inside the directory we're trying to delete
                    if original_cwd and self.repos_dir in original_cwd:
                        try:
                            os.chdir(constants.MAIN_FOLDER_PATH)
                        except Exception as e:
                            logger.warning(f"Cannot change directory before cleanup: {e}")

                    shutil.rmtree(self.repos_dir, ignore_errors=True)
                    logger.debug(f"Cleaned repository directory: {self.repos_dir}")
            except Exception as e:
                logger.error(f"Error cleaning repository directory {self.repos_dir}: {e}")

            # Clean report directory
            try:
                if os.path.exists(self.report_dir):
                    shutil.rmtree(self.report_dir, ignore_errors=True)
                    logger.debug(f"Cleaned report directory: {self.report_dir}")
            except Exception as e:
                logger.error(f"Error cleaning report directory {self.report_dir}: {e}")

            # Restore working directory
            if original_cwd:
                try:
                    os.chdir(original_cwd)
                except (OSError, FileNotFoundError) as e:
                    logger.warning(f"Cannot restore working directory to {original_cwd}: {e}")
                    # Try to change to safe location as fallback
                    try:
                        os.chdir(constants.MAIN_FOLDER_PATH)
                    except Exception as e2:
                        logger.error(f"Cannot change to safe directory: {e2}")

            self._cleaned = True

    def clone(self):
        """Clone repository with proper error handling and cleanup"""

        repo_size = self.obj.stats.repo_stats_leak_stats_table["size"]
        logger.info(
            f'Repository {self.log_color}{self.url}{CLR["RESET"]} size: {self.log_color}{repo_size}{CLR["RESET"]}'
        )

        if self.obj.stats.repo_stats_leak_stats_table["size"] > constants.REPO_MAX_SIZE:
            logger.info(
                f'Repository %s %s %s oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]} > {constants.REPO_MAX_SIZE} limit), code not analyze',
                self.log_color,
                self.url,
                CLR["RESET"],
            )
            self.obj.status.append(
                f'Repository {self.url} is oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]}), code not analyze'
            )
            # Report oversize status instead of generic "not state"
            self.secrets = {
                "Scan_status": "oversize",
                "Scan_error": f'Repository {self.url} is oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]} bytes > {constants.REPO_MAX_SIZE} bytes limit)',
                "Size_bytes": self.obj.stats.repo_stats_leak_stats_table["size"],
                "Size_limit": constants.REPO_MAX_SIZE,
            }
            self._clean_repo_dirs()
            self.status |= NOT_CLONED
        else:
            logger.info(f'Cloning {self.log_color}{self.url}{CLR["RESET"]}')

            clone_success = False

            
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
                        logger.error(f"Cannot change to parent directory {parent_dir}: {e}")
                        raise

                    repo_url = self.url
                    authenticated_url = repo_url.replace("https://", f"https://{constants.GITHUB_CLONE_TOKEN}@")

                    # Clone with subprocess and timeout
                    import subprocess

                    clone_timeout = getattr(constants, "MAX_TIME_TO_CLONE", 500)

                    try:
                        result = subprocess.run(
                            ["git", "clone", "--depth=1", authenticated_url, self.repos_dir],
                            timeout=clone_timeout,
                            capture_output=True,
                            text=True,
                            cwd=parent_dir,
                        )

                        if result.returncode != 0:
                            if "not found" in result.stderr.lower() or "not found" in result.stdout.lower():
                                logger.warning(f"Repository not found: {self.url}")
                                self.secrets = {"Scan error": f"Repository not found: {self.url}"}
                                break
                            logger.error(
                                f"git clone failed (attempt {try_clone + 1}/{constants.MAX_TRY_TO_CLONE}): {result.stderr}"
                            )
                            continue

                        self.repo = git.Repo(self.repos_dir)
                        clone_success = True

                    except subprocess.TimeoutExpired:
                        logger.error(
                            f"git clone timeout ({clone_timeout}s) for {self.url} (attempt {try_clone + 1}/{constants.MAX_TRY_TO_CLONE})"
                        )
                        continue
                    finally:
                        # Always restore working directory
                        try:
                            os.chdir(original_cwd)
                        except OSError as e:
                            logger.error(f"Cannot restore working directory to {original_cwd}: {e}")

                    if clone_success:
                        # Remove token from .git/config after successful clone
                        utils.remove_token_from_git_config(self.repos_dir, self.url)

                        # Create report directory
                        os.makedirs(self.report_dir, exist_ok=True)

                        # Clean excluded files
                        self.clean_excluded_files()

                        # Get contributor stats
                        self.obj.stats.fetch_contributors_stats()

                        logger.info(f"Successfully cloned {self.url}")
                        break

                except Exception as exc:
                    logger.error(
                        f"Clone attempt {try_clone + 1}/{constants.MAX_TRY_TO_CLONE} failed for {self.url}: {exc}"
                    )
                    if try_clone < constants.MAX_TRY_TO_CLONE - 1:
                        time.sleep(5)
                    continue

            if not clone_success:
                logger.error(f"Failed to clone repo {self.url} after {constants.MAX_TRY_TO_CLONE} attempts")
                self.secrets = {
                    "Scan error": f"Failed to clone repo {self.url} after {constants.MAX_TRY_TO_CLONE} attempts"
                }
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
                        self.obj.status.append(f"File extension: {ext}")
                        file_path.unlink()
                        break

    def scan(self):
        logger.info(f'Started scan: {self.dork} | {self.log_color}{self.url}{CLR["RESET"]} ')

        # Проверка существования директории перед началом сканирования
        if not os.path.isdir(self.repos_dir):
            logger.error("Repository directory %s does not exist or was removed before scan", self.repos_dir)
            self.secrets = {"Scan error": "Repository directory removed before scan"}
            return self.secrets

        cur_dir = os.getcwd()
        try:
            os.chdir(self.repos_dir)
        except (FileNotFoundError, NotADirectoryError) as e:
            logger.error("Failed to change to repository directory %s: %s", self.repos_dir, e)
            self.secrets = {"Scan error": "Failed to access repository directory"}
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
                        logger.error("Excepted error in scan, check privious log!")
                    elif res == 3:
                        logger.info(f'Canceling {method} scan in repo: {"/".join(self.url.split("/")[-2:])}')
        finally:
            # Всегда возвращаемся в исходную директорию, даже при ошибках
            try:
                os.chdir(cur_dir)
            except Exception as e:
                logger.error(f"Failed to return to original directory {cur_dir}: {e}")

        # Проверяем, есть ли хотя бы один сканер с результатами
        has_results = any(scan_type in self.secrets and len(self.secrets[scan_type]) > 0 for scan_type in self.secrets)

        if not has_results:
            logger.info(f"No meaningful results found in {self.url} by any scanner")
            # Добавляем информативную запись вместо пустого результата
            self.secrets["message"] = f'No leaks found for dork "{self.dork}" in repository'

        logger.info(f'Scanned: {self.dork} | {self.log_color}{self.url}{CLR["RESET"]}')

        return self.secrets

    @_exc_catcher
    def grep_scan(self):
        """
        Улучшенный поиск по ключевым словам в репозитории.
        Ищет как по основному dork, так и по названию компании.
        Использует более качественный поиск слов с учетом границ слов.
        """
        self.secrets["grepscan"] = constants.AutoVivification()

        try:
            # Создаем список поисковых терминов
            search_terms = [self.dork]
            if self.company_name:
                # Добавляем название компании и его части
                search_terms.extend(self.company_terms)
            search_terms = list(set(search_terms))
            # Используем Python для более качественного поиска
            found_matches = self._enhanced_file_search(search_terms)

            # Дедупликация результатов - убираем дублирующиеся совпадения
            deduped_matches = self._deduplicate_matches(found_matches)

            # Обрабатываем найденные совпадения
            meaningful_count = 0
            for index, match_info in enumerate(deduped_matches[: constants.MAX_UTIL_RES_LINES]):
                leak_text = match_info["text"]
                file_path = match_info["file"]
                search_term = match_info["term"]

                # Проверяем семантическую осмысленность
                meaningfulness = utils.semantic_check_dork(leak_text, search_term)

                if meaningfulness > 0:
                    meaningful_count += 1

                # Обрезаем слишком длинные строки (inline логика)
                if len(leak_text) > constants.MAX_LINE_LEAK_LEN:
                    term_pos = leak_text.lower().find(search_term.lower())
                    if term_pos != -1:
                        half_len = constants.MAX_LINE_LEAK_LEN // 2
                        start = max(0, term_pos - half_len)
                        end = min(len(leak_text), term_pos + len(search_term) + half_len)
                        leak_text = (
                            ("..." if start > 0 else "")
                            + leak_text[start:end]
                            + ("..." if end < len(leak_text) else "")
                        )
                    else:
                        leak_text = leak_text[: constants.MAX_LINE_LEAK_LEN] + "..."

                self.secrets["grepscan"][f"Leak #{index}"]["meaningfull"] = meaningfulness
                self.secrets["grepscan"][f"Leak #{index}"]["Match"] = leak_text
                self.secrets["grepscan"][f"Leak #{index}"]["File"] = file_path
                # Дополнительная информация для анализа (не влияет на совместимость)
                self.secrets["grepscan"][f"Leak #{index}"]["SearchTerm"] = search_term

            logger.debug(
                f"Meaningful matches: {meaningful_count}/{len(deduped_matches)} (deduped from {len(found_matches)}) for {self.url}"
            )

            # Если не найдено ни одного совпадения, добавляем информативную запись
            if not deduped_matches:
                logger.info(f'No matches found in {self.url} for terms: {", ".join(search_terms)}')
            elif meaningful_count == 0:
                logger.info(f"Found {len(deduped_matches)} unique matches in {self.url} but none were meaningful")

        except Exception as ex:
            logger.error("\t- Error in repository %s %s %s grepscan: %s", self.log_color, self.url, CLR["RESET"], ex)
            return 2

        logger.info("\t- grepscan scan %s %s %s success", self.log_color, self.url, CLR["RESET"])
        return 0

    def _deduplicate_matches(self, matches):
        """
        Дедупликация найденных совпадений.
        Удаляет дублирующиеся находки по (файл, текст совпадения).
        """
        seen = set()
        unique_matches = []

        for match in matches:
            # Создаем уникальный ключ из файла и текста совпадения
            key = (match["file"], match["text"].strip().lower())

            if key not in seen:
                seen.add(key)
                unique_matches.append(match)

        return unique_matches

    def _enhanced_file_search(self, search_terms):
        """Улучшенный поиск в файлах с учетом размера файлов"""

        found_matches = []

        # Размер файла в байтах (2 МБ)
        MAX_FILE_SIZE_FOR_PYTHON = 2 * 1024 * 1024  # 2 MB

        try:
            for root, dirs, files in os.walk("."):
                # Исключаем системные папки
                dirs[:] = [
                    d for d in dirs if not d.startswith(".") and d not in {"node_modules", "__pycache__", "venv", "env"}
                ]

                for file in files:
                    # Проверяем расширение или известные файлы без расширений
                    _, ext = os.path.splitext(file.lower())
                    filename_lower = file.lower()
                    is_text_file = (
                        ext in constants.TEXT_FILE_EXTS
                        or filename_lower
                        in {
                            "readme",
                            "license",
                            "changelog",
                            "authors",
                            "contributors",
                            "gemfile",
                            "rakefile",
                            "gruntfile",
                            "gulpfile",
                            "package",
                            "requirements",
                        }
                        or filename_lower.startswith(("license.", "changelog.", "install."))
                        or filename_lower.endswith((".example", ".sample", ".template", ".dist"))
                    )

                    if not is_text_file:
                        continue

                    file_path = os.path.join(root, file)

                    # Пропускаем симлинки
                    try:
                        if os.path.islink(file_path):
                            logger.debug(f"Skipping symlink: {file_path}")
                            continue
                    except OSError:
                        # Broken symlink or access issue
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
                            return found_matches[: constants.MAX_UTIL_RES_LINES]

                    except FileNotFoundError:
                        # Файл был удален между os.walk и обработкой
                        logger.debug(f"File disappeared during processing: {file_path}")
                        continue
                    except PermissionError:
                        # Нет прав доступа к файлу
                        logger.debug(f"Permission denied for file: {file_path}")
                        continue
                    except OSError as os_error:
                        # Другие системные ошибки (broken symlinks, etc)
                        logger.debug(f"OS error processing file {file_path}: {os_error}")
                        continue
                    except Exception as ex:
                        # Неожиданные ошибки
                        logger.warning(f"Unexpected error processing file {file_path}: {ex}")
                        continue
        except FileNotFoundError as ex:
            logger.info(f"Error in file search: {ex}")
            raise

        except Exception as ex:
            logger.error(f"Error in file search: {ex}")

        return found_matches

    def _search_small_file_with_python(self, file_path, search_terms):
        """Поиск в небольших файлах с помощью Python с кешированием паттернов."""
        matches = []

        if not search_terms:
            return matches

        # Оптимизация: используем кешированный паттерн
        pattern = self._get_search_pattern(search_terms)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line_stripped = line.strip()
                    if not line_stripped or len(line_stripped) > 1000:  # Пропускаем слишком длинные строки
                        continue

                    # Single regex search instead of nested loop
                    match = pattern.search(line_stripped)
                    if match:
                        found_term = match.group(0)
                        context = utils.extract_context_around_term(line_stripped, found_term)

                        matches.append({"text": context, "file": file_path, "term": found_term, "line_num": line_num})

                        # Ограничиваем количество находок на файл
                        if len(matches) >= 50:
                            return matches
        except FileNotFoundError:
            # Файл был удален между проверкой и открытием
            logger.debug(f"File not found during search: {file_path}")
        except PermissionError:
            # Нет прав доступа
            logger.debug(f"Permission denied during search: {file_path}")
        except UnicodeDecodeError:
            # Бинарный файл или некорректная кодировка (но errors='ignore' должен это предотвратить)
            logger.debug(f"Encoding error in file: {file_path}")
        except Exception as ex:
            # Другие неожиданные ошибки
            logger.debug(f"Unexpected error searching file {file_path}: {ex}")

        return matches

    def _search_large_file_with_grep(self, file_path, search_terms):
        """Поиск в больших файлах с помощью grep"""
        matches = []

        try:
            for term in search_terms:
                # Используем grep с ограничением количества результатов
                grep_command = ["grep", "-n", "-i", "--text", "--max-count=20", term, file_path]

                try:
                    result = subprocess.run(
                        grep_command, capture_output=True, text=True, timeout=10  # Таймаут для больших файлов
                    )

                    if result.returncode == 0:
                        for line in result.stdout.split("\n"):
                            if not line.strip():
                                continue

                            # Разбираем вывод grep: номер_строки:содержимое
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                line_num = parts[0]
                                content = parts[1]
                                context = utils.extract_context_around_term(content, term)

                                matches.append(
                                    {
                                        "text": context,
                                        "file": file_path,
                                        "term": term,
                                        "line_num": int(line_num) if line_num.isdigit() else 0,
                                    }
                                )

                except subprocess.TimeoutExpired:
                    logger.debug(f"Grep timeout for file {file_path} with term {term}")
                    continue
                except Exception as ex:
                    logger.debug(f"Grep error for file {file_path}: {ex}")
                    continue

        except Exception as ex:
            logger.debug(f"Error in grep search for {file_path}: {ex}")

        return matches

    #    @_exc_catcher
    def gitleaks_scan(self):
        scan_type = "gitleaks"
        if not os.path.isdir(self.repos_dir):
            return 3

        try:
            gitleaks_com = (
                '/usr/local/bin/gitleaks detect --no-banner --no-color --report-format json --exit-code 0 --report-path "'
                + self.report_dir
                + scan_type
                + '_rep.json"'
            )

            ll = os.curdir
            os.chdir(self.repos_dir)
            _ = subprocess.run(  # noqa: F841
                gitleaks_com,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                timeout=self.scan_time_limit,
                text=True,
                cwd=self.repos_dir,
            )
            os.chdir(ll)
        except (subprocess.TimeoutExpired, Exception) as ex:
            logger.error(
                f'\t- {scan_type} {"timeout" if isinstance(ex, subprocess.TimeoutExpired) else "error"} in repository %s %s %s: %s',
                self.log_color,
                self.url,
                CLR["RESET"],
                ex if not isinstance(ex, subprocess.TimeoutExpired) else "",
            )
            return 2

        if os.path.exists(self.report_dir + scan_type + "_rep.json"):
            with open(self.report_dir + scan_type + "_rep.json", "r") as file:
                js = json.load(file)

                def process_gitleaks_result(elem, index):
                    # Создаем позиционную информацию
                    position = f"V:{elem['StartColumn']}-{elem['EndColumn']};H:{elem['StartLine']}-{elem['EndLine']};"

                    # Очищаем данные и создаем результат
                    match_str = elem.get("Match") or elem.get("Secret", "")
                    file_path = elem.get("File", "")
                    self._clean_result_data(elem)
                    elem["Position"] = position
                    elem["Match"] = match_str
                    elem["File"] = file_path

                    return elem

                processed_count = self._process_scan_results(scan_type, js, process_gitleaks_result)
                logger.info(
                    f"\t- {scan_type} scan %s %s %s success, processed {processed_count} results",
                    self.log_color,
                    self.url,
                    CLR["RESET"],
                )

        return 0

    @_exc_catcher
    def gitsecrets_scan(self):
        scan_type = "gitsecrets"
        self.secrets[scan_type] = constants.AutoVivification()
        if not os.path.isdir(self.repos_dir):
            return 3

        # Инициализация git secrets
        subprocess.run(
            ["git", "secrets", "--install", "-f"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=self.scan_time_limit,
            shell=True,
        )
        subprocess.run(
            ["git", "secrets", "--register-aws"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=self.scan_time_limit,
            shell=True,
        )
        subprocess.run(
            ["git", "secrets", "--aws-provider"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=self.scan_time_limit,
            shell=True,
        )

        gitsecret_com = "git secrets --scan -r " + self.repos_dir  # pragma: allowlist secret
        try:
            old_dir = os.curdir
            os.chdir(constants.TEMP_FOLDER)
            gitsecret_proc = subprocess.run(
                gitsecret_com, capture_output=True, shell=True, timeout=self.scan_time_limit, text=True, check=False
            )
            os.chdir(old_dir)
        except (subprocess.TimeoutExpired, Exception) as ex:
            logger.error(
                f'\t- {scan_type} {"timeout" if isinstance(ex, subprocess.TimeoutExpired) else "error"} in repository %s %s %s',
                self.log_color,
                self.url,
                CLR["RESET"],
            )
            return 2

        # git-secrets выводит результаты в stderr, это нормальное поведение
        stderr_output = gitsecret_proc.stderr.strip()

        # Проверяем, есть ли найденные утечки
        if not stderr_output:
            logger.info(
                f"\t- {scan_type} scan %s %s %s success, no secrets found", self.log_color, self.url, CLR["RESET"]
            )
            return 0

        # Сохраняем результаты в текстовый файл
        with open(self.report_dir + scan_type + "_rep.txt", "w") as file:
            file.write(stderr_output)

        # Обрабатываем результаты построчно
        lines = stderr_output.split("\n")

        def process_gitsecrets_result(line, index):
            line = line.strip()
            if not line:
                return None

            # Пропускаем служебные сообщения
            if any(
                skip_phrase in line
                for skip_phrase in [
                    "[ERROR] Matched one or more prohibited patterns",
                    "Syntax error:",
                    "newline unexpected",
                    "Usage:",
                    "git-secrets",
                ]
            ):
                return None

            # git-secrets выводит в формате: file:line:match или file:match
            if ":" in line:
                parts = line.split(":", 2)
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

        logger.info(
            f"\t- {scan_type} scan %s %s %s success, processed {processed_count} results",
            self.log_color,
            self.url,
            CLR["RESET"],
        )

        return 0

    @_exc_catcher
    def detect_secrets_scan(self):
        scan_type = "detect_secrets"
        self.secrets[scan_type] = constants.AutoVivification()
        if not os.path.isdir(self.repos_dir):
            return 3

        ds_bin = shutil.which("detect-secrets")
        if not ds_bin:
            self.secrets[scan_type]["Info"] = "detect-secrets not installed"
            logger.info(
                f"\t- {scan_type} scan %s %s %s success (tool not available)", self.log_color, self.url, CLR["RESET"]
            )
            return 0

        cmd = [ds_bin, "scan", "--all-files"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, cwd=self.repos_dir, timeout=self.scan_time_limit
            )
        except (subprocess.TimeoutExpired, Exception) as ex:
            logger.error(
                f'\t- {scan_type} {"timeout" if isinstance(ex, subprocess.TimeoutExpired) else "error"} in repository %s %s %s',
                self.log_color,
                self.url,
                CLR["RESET"],
            )
            return 2

        try:
            output = json.loads(result.stdout)
        except Exception as ex:
            logger.error(f"Failed to parse detect-secrets output: {ex}")
            return 2

        # Проверяем структуру output
        if not isinstance(output, dict):
            logger.error(f"detect-secrets output is not a dict: {type(output)}")
            return 2

        results_data = output.get("results", {})
        if not isinstance(results_data, dict):
            logger.error(f"detect-secrets results is not a dict: {type(results_data)}")
            return 2

        results = []
        for file_path, secrets in results_data.items():
            if not isinstance(secrets, list):
                logger.warning(f"detect-secrets secrets for {file_path} is not a list: {type(secrets)}, skipping")
                continue

            for sec in secrets:
                if not isinstance(sec, dict):
                    logger.warning(f"detect-secrets secret is not a dict: {type(sec)}, skipping")
                    continue
                line_num = sec.get("line_number")
                line_text = ""
                abs_path = os.path.join(self.repos_dir, file_path)
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                        lines = fh.readlines()
                        if line_num and 0 < line_num <= len(lines):
                            line_text = lines[line_num - 1].strip()
                except Exception:
                    pass
                result_entry = self._create_standard_result(
                    match=line_text,
                    file_path=f"{file_path}:{line_num}",
                    extra_data={"SecretType": sec.get("type"), "Verified": sec.get("is_verified")},
                )
                results.append(result_entry)

        processed_count = self._process_scan_results(scan_type, results, lambda x, _: x)

        logger.info(
            f"\t- {scan_type} scan %s %s %s success, processed {processed_count} results",
            self.log_color,
            self.url,
            CLR["RESET"],
        )

        return 0

    def kingfisher_scan(self):
        """Запускает kingfisher и обрабатывает JSON вывод."""
        scan_type = "kingfisher"
        self.secrets[scan_type] = constants.AutoVivification()
        if not os.path.isdir(self.repos_dir):
            return 3

        kf_bin = shutil.which("kingfisher")
        if not kf_bin:
            self.secrets[scan_type]["Info"] = "kingfisher not installed"
            logger.info(
                "\t- %s scan %s %s %s success (tool not available)", scan_type, self.log_color, self.url, CLR["RESET"]
            )
            return 0

        cmd = [kf_bin, "scan", self.repos_dir, "--format", "json", "--no-update-check", "--rule", "all", "-q"]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.scan_time_limit)
        except subprocess.TimeoutExpired:
            logger.error("\t- %s timeout in %s %s %s", scan_type, self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error("\t- %s error: %s", scan_type, ex)
            return 2

        # Kingfisher выводит JSON построчно - парсим каждую строку отдельно
        output_lines = res.stdout.strip().split("\n")

        # Собираем все findings из всех JSON объектов
        all_findings = []

        for line in output_lines:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
                findings_by_rule = data.get("findings_by_rule", [])
                if findings_by_rule:
                    all_findings.extend(findings_by_rule)
            except json.JSONDecodeError:
                # Пропускаем строки с невалидным JSON
                continue

        findings_by_rule = all_findings

        if not findings_by_rule:
            self.secrets[scan_type]["Info"] = "No findings"
            logger.info("\t- %s scan %s %s %s success, no findings", scan_type, self.log_color, self.url, CLR["RESET"])
            return 0

        # Обрабатываем каждую находку
        results = []
        for rule_item in findings_by_rule:
            if not isinstance(rule_item, dict):
                continue

            rule_id = rule_item.get("id", "")
            matches = rule_item.get("matches", [])

            for match in matches:
                if not isinstance(match, dict):
                    continue

                finding = match.get("finding", {})
                if not isinstance(finding, dict):
                    continue

                # Формируем путь к файлу с номером строки
                file_path = finding.get("path", "")
                line_num = finding.get("line")
                location = f"{file_path}:{line_num}" if line_num else file_path

                # Извлекаем validation status безопасно
                validation_data = finding.get("validation", {})
                validation_status = validation_data.get("status") if isinstance(validation_data, dict) else None

                extra = {
                    "Rule": rule_id,
                    "Confidence": finding.get("confidence"),
                    "Entropy": finding.get("entropy"),
                    "Fingerprint": finding.get("fingerprint"),
                    "Validation": validation_status,
                }

                results.append(
                    self._create_standard_result(
                        match=finding.get("snippet", "").strip(), file_path=location, extra_data=extra
                    )
                )

        processed = self._process_scan_results(scan_type, results, lambda x, _: x)

        logger.info(
            "\t- %s scan %s %s %s success, processed %d results",
            scan_type,
            self.log_color,
            self.url,
            CLR["RESET"],
            processed,
        )
        return 0

    @_exc_catcher
    def deepsecrets_scan(self):
        scan_type = "deepsecrets"
        self.secrets[scan_type] = constants.AutoVivification()
        if not os.path.isdir(self.repos_dir):
            return 3

        try:
            deep_com = (
                "deepsecrets --target-dir " + self.repos_dir + " --outfile " + self.report_dir + scan_type + "_rep.json"
            )
            _ = subprocess.run(  # noqa: F841
                deep_com,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=True,
                timeout=self.scan_time_limit,
                text=True,
            )
        except (subprocess.TimeoutExpired, Exception) as ex:
            logger.error(
                f'\t- {scan_type} {"timeout" if isinstance(ex, subprocess.TimeoutExpired) else "error"} in repository %s %s %s',
                self.log_color,
                self.url,
                CLR["RESET"],
            )
            return 2

        if os.path.exists(self.report_dir + scan_type + "_rep.json"):
            with open(self.report_dir + scan_type + "_rep.json", "r") as file:
                js = json.load(file)
                is_first = True
                counter = 1

                for i in js:
                    for j in js[i]:
                        a = True
                        if not is_first:
                            for _, v in self.secrets["deepsecrets"].items():
                                if str(j["line"][: constants.MAX_LINE_LEAK_LEN]) == v["Match"]:
                                    a = False
                                    break
                                a = True
                        if a:
                            is_first = False

                            if len(j["line"]) > constants.MAX_LINE_LEAK_LEN:
                                j["line"] = j["line"][: constants.MAX_LINE_LEAK_LEN]
                            self.secrets["deepsecrets"][f"Leak #{counter}"]["Match"] = str(j["line"])

                            self.secrets["deepsecrets"][f"Leak #{counter}"]["File"] = str(i)
                            counter += 1
            logger.info(f"{scan_type} scan %s %s %s success", self.log_color, self.url, CLR["RESET"])
            return 0
        else:
            logger.error("File deepsecrets_rep.json not founded\n")
            return 2

    @_exc_catcher
    def trufflehog_scan(self):
        scan_type = "trufflehog"
        self.secrets[scan_type] = constants.AutoVivification()
        if not os.path.isdir(self.repos_dir):
            return 3

        try:
            # Команда TruffleHog
            truf_com = [
                "trufflehog",
                "git",
                "--json",
                "--no-update",
                "--results=verified,unknown,unverified",
                "--concurrency=4",
                "--no-verification",
                f"file://{self.repos_dir}",
            ]

            # Собираем команду через пробелы (ВАЖНО!)
            truf_cmd_str = " ".join(truf_com)

            trufflehog_proc = subprocess.run(
                truf_cmd_str,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                timeout=self.scan_time_limit,
                text=True,
            )

        except (subprocess.TimeoutExpired, Exception) as ex:
            logger.error(
                f'\t- {scan_type} {"timeout" if isinstance(ex, subprocess.TimeoutExpired) else "error"} in repository %s %s %s',
                self.log_color,
                self.url,
                CLR["RESET"],
            )
            return 2

        # Обработка результатов
        return self._process_trufflehog_results(trufflehog_proc.stdout, scan_type)

    def _process_trufflehog_results(self, stdout_data, scan_type):
        """Обрабатывает результаты TruffleHog"""
        logger.info(f"TruffleHog: Processing output ({len(stdout_data)} bytes)")

        with open(self.report_dir + scan_type + "_rep.txt", "w") as file:
            file.write(stdout_data)

        if not stdout_data.strip():
            logger.warning(f"TruffleHog: Empty output for {self.url}")
            return 0

        # Парсим слитные JSON (}{}{)
        trufflehog_list = []
        parse_errors = 0
        for line in stdout_data.replace("}{", "}\n{").split("\n"):
            if not line.strip():
                continue
            try:
                result = json.loads(line)
                if isinstance(result, dict):
                    trufflehog_list.append(result)
            except json.JSONDecodeError as e:
                parse_errors += 1
                if parse_errors <= 3:  # Show only first 3 errors
                    logger.warning(f"TruffleHog: JSON parse error - {str(e)[:100]}")
                continue

        if parse_errors > 0:
            logger.warning(f"TruffleHog: Total {parse_errors} JSON parse errors")
        logger.info(f"TruffleHog: Successfully parsed {len(trufflehog_list)} JSON results")

        # Фильтруем результаты
        filtered_results = self._filter_and_enhance_results(trufflehog_list)

        def process_result(elem, index):
            raw_match = elem.get("RawV2") or elem.get("Raw", "")
            source_metadata = elem.get("SourceMetadata", {})
            git_data = source_metadata.get("Data", {}).get("Git", {})

            self._clean_result_data(elem)
            elem["Match"] = raw_match
            elem["File"] = git_data.get("file", "")
            elem.pop("SourceMetadata", None)
            elem.pop("DetectorDescription", None)
            elem.pop("VerificationFromCache", None)

            return elem

        processed_count = self._process_scan_results(scan_type, filtered_results, process_result)
        logger.info(
            f"\t- {scan_type} scan %s %s %s success, {processed_count} results", self.log_color, self.url, CLR["RESET"]
        )
        return 0

    def _filter_and_enhance_results(self, results):
        """Фильтрует и улучшает результаты TruffleHog"""
        enhanced_results = []

        logger.info(f"TruffleHog: Filtering {len(results)} raw results")

        for result in results:
            detector_name = result.get("DetectorName", "unknown")
            verified = result.get("Verified", False)

            # Добавляем дополнительную информацию
            result["CompanyRelevance"] = self._calculate_company_relevance(result, self.company_name)
            result["ContextualScore"] = self._calculate_contextual_score(result)

            # Фильтруем только если есть явный негативный сигнал (тестовые данные и т.п.)
            if result["CompanyRelevance"] > 0 or result["ContextualScore"] >= 0 or verified:
                enhanced_results.append(result)
                
        # Сортируем по релевантности
        enhanced_results.sort(
            key=lambda x: (x.get("Verified", False), x.get("CompanyRelevance", 0), x.get("ContextualScore", 0)),
            reverse=True,
        )

        return enhanced_results

    def _is_company_specific_pattern(self, text, company_name=None):
        """Проверяет наличие специфических паттернов компании в тексте"""
        if company_name is None:
            company_name = self.company_name

        if not company_name:
            return False

        company_terms = (
            self.company_terms
            if company_name == self.company_name
            else utils.generate_company_search_terms(company_name)
        )

        # Используем обобщённую функцию из utils
        return utils.check_company_pattern_in_text(text, company_terms)

    def _calculate_company_relevance(self, result, company_name=None):
        """Вычисляет релевантность результата для компании"""
        if company_name is None:
            company_name = self.company_name
        if not company_name:
            return 0.0

        raw_data = result.get("RawV2") or result.get("Raw", "")
        source_metadata = result.get("SourceMetadata", {})

        # Анализируем различные части результата
        text_sources = [
            raw_data,
            utils.safe_get_nested(source_metadata, "Data", "Git", "file", default=""),
            utils.safe_get_nested(source_metadata, "Data", "Git", "commit", default=""),
        ]

        full_text = " ".join(str(source) for source in text_sources if source)

        # Используем обобщённую функцию расчёта релевантности
        company_terms = (
            self.company_terms
            if company_name == self.company_name
            else utils.generate_company_search_terms(company_name)
        )
        return utils.calculate_company_relevance_in_text(full_text, company_terms)

    def _calculate_contextual_score(self, result):
        """Вычисляет контекстуальный скор результата"""
        score = 0.0
        raw_data = result.get("RawV2") or result.get("Raw", "")

        # Бонусы за проверенные результаты
        if result.get("Verified", False):
            score += 1.0

        # Бонусы за определенные типы детекторов
        detector_name = result.get("DetectorName", "").lower()
        high_value_detectors = ["aws", "google", "azure", "github", "gitlab", "database"]

        for detector in high_value_detectors:
            if detector in detector_name:
                score += 0.5
                break

        # Штрафы за тестовые данные
        test_indicators = ["test", "demo", "example", "sample", "dummy"]
        for indicator in test_indicators:
            if indicator in raw_data.lower():
                score -= 0.3

        return score

    def _evaluate_meaningfulness(self, result):
        """Оценивает осмысленность результата для совместимости с существующим кодом"""
        # Проверенные результаты всегда считаются осмысленными
        if result.get("Verified", False):
            return 1

        # Проверяем детектор - компанейские детекторы получают максимальный приоритет
        detector_name = result.get("DetectorName", "").lower()

        # Компанейские детекторы - максимальный приоритет
        company_detectors = [
            "company-credentials-",
            "company-api-keys-",
            "company-login-pattern-",
            "company-email-pattern-",
        ]

        for detector in company_detectors:
            if detector in detector_name:
                return 1

        # Высокое значение релевантности к компании
        company_relevance = result.get("CompanyRelevance", 0)
        if company_relevance > 0.2:
            return 1

        # Высокий контекстуальный скор
        contextual_score = result.get("ContextualScore", 0)
        if contextual_score > 0.3:
            return 1

        # Проверяем детектор - для важных детекторов снижаем требования
        important_detectors = [
            "aws",
            "google",
            "azure",
            "github",
            "gitlab",
            "slack",
            "discord",
            "stripe",
            "paypal",
            "twilio",
            "sendgrid",
            "mailgun",
            "custom",
        ]

        for detector in important_detectors:
            if detector in detector_name:
                return 1

        # Анализируем сам секрет
        raw_data = result.get("RawV2") or result.get("Raw", "")
        if not raw_data:
            # Нет данных секрета — неосмысленный результат
            return 0

        # Получаем название компании для универсальных проверок
        _ = Connector.get_company_name(self.obj.company_id)  # noqa: F841  # pragma: allowlist secret

        # Проверяем специфические паттерны компании
        if self._is_company_specific_pattern(raw_data, self.company_name):
            return 1

        # Очень короткие секреты неинформативны
        if len(raw_data) < 8:
            return 0

        # Секреты с хорошей энтропией
        if utils.calculate_entropy(raw_data) > 3.5:
            return 1

        # Секреты в base64/hex формате
        if utils.looks_like_encoded_data(raw_data, min_hex_length=16, min_base64_length=20):
            return 1

        # Проверяем контекст на наличие компанейских паттернов
        source_metadata = result.get("SourceMetadata", {})
        if isinstance(source_metadata, dict):
            data_text = str(source_metadata.get("Data", ""))
            if self._is_company_specific_pattern(data_text, self.company_name):
                return 1

        # По умолчанию считаем неосмысленным — не прошёл ни одну проверку
        return 0

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
            logger.error("You forgot call checker.clone() before scan()!")
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

        logger.info(f"{scan_type}: Processing {len(results)} filtered results (limit: {constants.MAX_UTIL_RES_LINES})")

        processed_count = 0
        seen_matches = set()

        for index, result in enumerate(results[: constants.MAX_UTIL_RES_LINES]):
            # Обрабатываем результат через переданную функцию
            try:
                processed_result = process_func(result, index)
            except Exception as e:
                logger.error(f"{scan_type}: Error processing result #{index}: {e}")
                continue

            if processed_result is None:
                logger.info(f"{scan_type}: Skipped result #{index} (process_func returned None)")
                continue

            # Проверяем на дублирование
            match_key = processed_result.get("Match", "")
            file_key = processed_result.get("File", "")
            dedup_key = f"{match_key}|{file_key}"
            if dedup_key in seen_matches:
                continue
            seen_matches.add(dedup_key)

            # Обрезаем слишком длинные строки
            if len(match_key) > constants.MAX_LINE_LEAK_LEN:
                processed_result["Match"] = match_key[: constants.MAX_LINE_LEAK_LEN] + "..."

            # Добавляем осмысленность если ее еще нет
            if "meaningfull" not in processed_result:
                processed_result["meaningfull"] = self._evaluate_meaningfulness(processed_result)

            self.secrets[scan_type][f"Leak #{processed_count}"] = processed_result
            processed_count += 1

        logger.info(
            f"{scan_type}: Final count - {processed_count} results saved to secrets (from {len(results)} input)"
        )
        return processed_count

    def _create_standard_result(self, match, file_path="", extra_data=None):
        """Создает стандартную структуру результата"""
        result = {"Match": match, "File": file_path}

        if extra_data:
            result.update(extra_data)

        return result

    def _clean_result_data(self, result, fields_to_remove=None):
        """Очищает данные результата, удаляя ненужные поля"""
        if fields_to_remove is None:
            fields_to_remove = [
                "Fingerprint",
                "StartLine",
                "EndLine",
                "StartColumn",
                "EndColumn",
                "SymlinkFile",
                "Secret",
                "Entropy",
                "Message",
                "SourceID",
                "SourceType",
                "SourceName",
                "DetectorType",
                "DecoderName",
                "Redacted",
                "ExtraData",
                "StructuredData",
                "Raw",
                "RawV2",
            ]

        for field in fields_to_remove:
            result.pop(field, None)

        return result

