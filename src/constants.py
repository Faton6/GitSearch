# Standard library imports
from pathlib import Path
import os
import json
import tracemalloc
from typing import Dict, Tuple

# Project library imports
# from src.logger import logger, CLR

"""
GitSearch Constants Module

This module contains all global constants, configuration settings, and
application-wide variables used throughout the GitSearch application.

The module is divided into several sections:
- Application metadata
- File system paths
- Scanning parameters and timeouts
- GitHub API configuration
- AI analysis settings
- Database result codes
- Internationalization (i18n)
- Helper classes
"""

# =============================================================================
# Application Metadata
# =============================================================================

RUN_TESTS: bool = True  # DISABLED - Enable manually for testing
__VERSION__ = "1.0.0"
# =============================================================================
# File System Paths
# =============================================================================

MAIN_FOLDER_PATH = Path(Path(__file__).parent).parent  # Project root directory
SEARCH_FOLDER_PATH = f"{str(MAIN_FOLDER_PATH)}/src/searcher"  # Scanner modules
LOGS_PATH = str(MAIN_FOLDER_PATH) + "/logs"  # Application logs
TEMP_FOLDER = str(MAIN_FOLDER_PATH) + "/temp"  # Temporary files (cloned repos, etc.)
RESULTS = str(MAIN_FOLDER_PATH) + "/results"  # Scan results output

# Ensure required directories exist
if not os.path.exists(LOGS_PATH):
    os.makedirs(LOGS_PATH)
if not os.path.exists(TEMP_FOLDER):
    os.makedirs(TEMP_FOLDER)
if not os.path.exists(RESULTS):
    os.makedirs(RESULTS)
# =============================================================================
# Scanning Parameters and Timeouts (in seconds)
# =============================================================================

# Maximum size of temp folder before cleanup (10GB)
MAX_TEMP_FOLDER_SIZE = 10 * 1024 * 1024 * 1024
# Timeout for default scanning tools (detect-secrets, etc.)
MAX_TIME_TO_SCAN_BY_UTIL_DEFAULT = 100
# Timeout for deep scanning tools (trufflehog, deepsecrets, etc.)
MAX_TIME_TO_SCAN_BY_UTIL_DEEP = 3000
# Timeout for GitHub API search requests
MAX_TIME_TO_SEARCH_GITHUB_REQUEST = 500
# Timeout for git clone operations
MAX_TIME_TO_CLONE = 500

# =============================================================================
# GitHub API Configuration
# =============================================================================

# Cooldown between GitHub API requests (seconds)
GITHUB_REQUEST_COOLDOWN: float = 60.0
# Rate limit for GitHub requests per minute
GITHUB_REQUEST_RATE_LIMIT: float = 10.0
# Maximum results per search (GitHub API restriction)
# See: https://docs.github.com/rest/search/search#search-code
GITHUB_REPO_COUNT_AT_REQUEST_LIMIT: int = 1000
# Number of results per page in GitHub API requests
GITHUB_REQUEST_REPO_PER_PAGE: int = 100
# =============================================================================
# Database Result Codes
# =============================================================================

# Individual result code definitions:
RESULT_CODE_LEAK_NOT_FOUND = 0  # No leak found, added to exclude list
RESULT_CODE_STILL_ACCESS = 1  # Leak found, block request sent
RESULT_CODE_TO_SEND = 4  # Status not set, needs review
RESULT_CODE_TO_DEEPSCAN = 5  # Needs additional deep scanning

# =============================================================================
# Scanning Limits and Counters
# =============================================================================

# Dork counters (will be updated during runtime)
all_dork_counter = 0  # Total quantity of all dorks
dork_search_counter = 0  # Current number of searches in GitHub
all_dork_search_counter = 0  # Total stable quantity of searches

# Dump to database after this many searches (prevents memory overflow)
MAX_SEARCH_BEFORE_DUMP = 15

# Object sending limits
quantity_obj_before_send = 0  # Current count of objects before send
MAX_OBJ_BEFORE_SEND = 5  # Maximum objects before triggering send

# Repository and output limits
REPO_MAX_SIZE = 300000  # Maximum repo size in KB (300MB)
MAX_UTIL_RES_LINES = 200  # Max lines from each scanner in report
MAX_LINE_LEAK_LEN = 100  # Max length of leak line in characters
MAX_TRY_TO_CLONE = 3  # Number of retry attempts for git clone
MAX_COMMITERS_DISPLAY = 5  # Max committers to show in report
MAX_DESCRIPTION_LEN = 50  # Max description length in report

# Scanner names used across analyzers/reports
SCANNER_TYPES = (
    "gitsecrets",
    "trufflehog",
    "grepscan",
    "deepsecrets",
    "gitleaks",
    "kingfisher",
    "detect_secrets",
)

# =============================================================================
# Leak Severity Thresholds
# =============================================================================

AUTO_FALSE_POSITIVE_TRUE_POS_THRESHOLD = 0.2
AUTO_FALSE_POSITIVE_FALSE_POS_THRESHOLD = 0.8
AUTO_FALSE_POSITIVE_SENSITIVE_THRESHOLD = 0.2
AUTO_FALSE_POSITIVE_ORG_THRESHOLD = 0.25
AUTO_FALSE_POSITIVE_AI_NEGATIVE_CONFIDENCE = 0.6

# Hard auto-close: obvious FP with near-zero scores (bypasses 3-condition gate)
AUTO_HARD_CLOSE_UNIFIED_THRESHOLD = 0.1
AUTO_HARD_CLOSE_ORG_THRESHOLD = 0.1

LOW_CREDIBILITY_SCORE_THRESHOLD = 0.35
VERY_LOW_CREDIBILITY_SCORE_THRESHOLD = 0.3
LOW_CREDIBILITY_SCORE_PENALTY_FACTOR = 0.85
UNIFIED_PROBABILITY_MEDIUM_PRIORITY_THRESHOLD = 0.5

INSUFFICIENT_CONTEXT_MIN_SIGNALS = 1
COMMITTER_DOMAIN_MATCH_THRESHOLD = 0.7
# =============================================================================
# Internationalization
# =============================================================================

LANGUAGE = "ru"  # Default language for messages ('ru' or 'en')

# =============================================================================
# AI Analysis Configuration
# =============================================================================

AI_ANALYSIS_ENABLED = True  # Enable/disable AI-powered analysis
AI_ANALYSIS_TIMEOUT = 30  # Timeout for AI API requests (seconds)
AI_MAX_CONTEXT_LENGTH = 4000  # Maximum context length for AI (characters)
AI_COMPANY_RELEVANCE_THRESHOLD = 0.5  # Minimum confidence for company relevance (0.0-1.0)
AI_TRUE_POSITIVE_THRESHOLD = 0.6  # Minimum confidence for true positive (0.0-1.0)
AI_PROVIDER_CHECK_INTERVAL = 5  # Check provider availability every N requests
# (0 = check every time)

# AI Worker Pool Configuration (async analysis)
AI_WORKER_POOL_SIZE = 2  # Number of parallel AI analysis workers
AI_WORKER_QUEUE_SIZE = 100  # Maximum pending AI analysis tasks

# =============================================================================
# Country Profiling Configuration
# =============================================================================

COUNTRY_PROFILING: bool = True  # Enable geographic profiling
COMPANY_COUNTRY_MAP_DEFAULT: str = "ru"  # Default country for unmapped companies
COMPANY_COUNTRY_MAP: dict[str, str] = {
    # Russian companies
    "WILDBERRIES": "ru",
    "VTB": "ru",
    "INNO": "ru",
    "T1": "ru",
    "SBER": "ru",
    "GAZPROM": "ru",
    "YANDEX": "ru",
    "MAILRU": "ru",
    "OZON": "ru",
    "KASPERSKY": "ru",
    # International companies
    "GOOGLE": "en",
    "MICROSOFT": "en",
    "APPLE": "en",
    "AMAZON": "en",
    "META": "en",
    "TESLA": "en",
    "NVIDIA": "en",
    "IBM": "en",
    "ORACLE": "en",
    "ANDROID": "en",
    "LINUX": "en",
}
# Common public email domains for corporate domain detection
PUBLIC_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "yandex.ru",
    "mail.ru",
    "rambler.ru",
    "bk.ru",
    "list.ru",
    "protonmail.com",
    "tutanota.com",
    "temp-mail.org",
        # GitHub / GitLab noreply addresses — NOT corporate!
    "users.noreply.github.com",
    "noreply.github.com",
    "users.noreply.gitlab.com",
    "noreply.gitlab.com",
    # Common bot / CI domains
    "github.com",          # username@github.com in old commits
    "gitlab.com",
    "users.sourceforge.net",
}

# Substrings in email domain that indicate it is NOT corporate
NOREPLY_DOMAIN_KEYWORDS: tuple[str, ...] = ("noreply", "no-reply", "no_reply", "mailer-daemon", "donotreply")

# Patterns that might indicate dangerous content in repositories
DANGEROUS_PATTERNS = {
    "api_key",
    "secret",
    "password",
    "token",
    "credential",
    "private_key",
    "prod",
    "production",
    "admin",
    "root",
    "database",
    "db_password",
}

dork_dict_from_DB: dict = {}
company_name_to_id: dict = {}  # Mapping from company name to company_id
dork_list_from_file: list = []
url_from_DB: dict = {}


tracemalloc.start()
snap_backup = tracemalloc.take_snapshot()
# Load configuration from config.json
with open(f"{MAIN_FOLDER_PATH}/config.json") as config_file:
    CONFIG_FILE = json.load(config_file)


def load_env_variables(file_path=f"{MAIN_FOLDER_PATH}/.env"):
    """
    Load environment variables from .env file.
    Uses python-dotenv if available, otherwise falls back to simple parsing.

    Priority: os.environ > .env file > config.json defaults
    """
    env_variables = {}

    # Try using python-dotenv first (more robust)
    try:
        from dotenv import dotenv_values

        # Load values from .env without overwriting os.environ (we want to merge manually to respect priority)
        dotenv_vars = dotenv_values(file_path)
        if dotenv_vars:
            env_variables.update(dotenv_vars)
            # Also load into os.environ for compatibility with other libs
            from dotenv import load_dotenv

            load_dotenv(file_path)
    except ImportError:
        # Fallback to manual parsing if python-dotenv is not installed
        try:
            with open(file_path, "r") as f:
                for line in f.readlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip()
                        if value:
                            env_variables[key] = value
        except FileNotFoundError:
            pass
        except Exception as e:
            import logging

            logging.warning(f"Error reading .env file: {e}")

    # Then override with os.environ (Docker/system vars have priority)
    for key in [
        "URL_DB",
        "TOKEN_DB",
        "GITHUB_CLONE_TOKEN",
        "LOG_LEVEL",
        "AI_ANALYSIS_ENABLED",
        "AI_ANALYSIS_TIMEOUT",
        "AI_MAX_CONTEXT_LENGTH",
        "AI_COMPANY_RELEVANCE_THRESHOLD",
        "AI_TRUE_POSITIVE_THRESHOLD",
        "TOGETHER_API_KEY",
        "OPENROUTER_API_KEY",
        "FIREWORKS_API_KEY",
        "REPO_MAX_SIZE",
        "MAX_TIME_TO_CLONE",
    ]:
        if key in os.environ and os.environ[key]:
            env_variables[key] = os.environ[key]

    # GitHub tokens - check multiple env vars
    for i in range(1, 10):
        key = f"GITHUB_TOKEN_{i}"
        if key in os.environ and os.environ[key]:
            env_variables[key] = os.environ[key]
        elif key not in env_variables:
            break  # Stop at first missing token

    return env_variables


leak_check_list = CONFIG_FILE["leak_check_list"]

# Загрузка переменных окружения
env_variables = load_env_variables()

# Инициализация token_tuple - сначала из config.json, потом добавляем из .env
if CONFIG_FILE["token_list"] != ["-"]:
    token_tuple = tuple(CONFIG_FILE["token_list"])
else:
    token_tuple = tuple()

# Добавляем GitHub токены из .env / os.environ
github_tokens = [
    value for key, value in env_variables.items() if key.startswith("GITHUB_TOKEN") and value and value != "-"
]
if github_tokens:
    token_tuple = token_tuple + tuple(github_tokens)

# Database configuration
url_DB = env_variables.get("URL_DB", CONFIG_FILE.get("url_DB", "172.32.0.97"))
token_DB = env_variables.get("TOKEN_DB", CONFIG_FILE.get("token_DB", "-"))
GITHUB_CLONE_TOKEN = env_variables.get("GITHUB_CLONE_TOKEN", "")

# Override scanning limits from env if provided
if "REPO_MAX_SIZE" in env_variables:
    REPO_MAX_SIZE = int(env_variables["REPO_MAX_SIZE"])
if "MAX_TIME_TO_CLONE" in env_variables:
    MAX_TIME_TO_CLONE = int(env_variables["MAX_TIME_TO_CLONE"])


# Initialize GitHub Rate Limiter after token_tuple is ready
def _init_rate_limiter():
    """Initialize rate limiter after module load."""
    try:
        from src.github_rate_limiter import initialize_rate_limiter, is_initialized

        if token_tuple and not is_initialized():
            initialize_rate_limiter(token_tuple)
    except Exception:
        pass  # Rate limiter is optional


TEXT_FILE_EXTS = {
    ".txt",
    ".md",
    ".rst",
    ".py",
    ".js",
    ".ts",
    ".java",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".php",
    ".rb",
    ".go",
    ".rs",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".cmd",
    ".html",
    ".htm",
    ".xml",
    ".xhtml",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".sql",
    ".env",
    ".properties",
    ".gradle",
    ".maven",
    ".pom",
    ".dockerfile",
    ".r",
    ".R",
    ".scala",
    ".kt",
    ".swift",
    ".m",
    ".mm",
    ".pl",
    ".pm",
    ".lua",
    ".vim",
    ".emacs",
    ".gitignore",
    ".gitconfig",
    ".editorconfig",
    ".log",
    ".out",
    ".err",
    ".tmp",
    ".backup",
    ".bak",
    ".old",
    ".csv",
    ".tsv",
    ".dat",
    ".data",
}

LEAK_OBJ_MESSAGES = {
    "en": {
        "leak_found_in_section": "Leak detected in {obj_type} section for search {dork}",
        "leak_in_author_name": "Leak in author name, found by keyword: {leak_type}, leak: {author_name}",
        "leak_in_committers": "Leak in committer name/email, found by keyword: {leak_type}",
        "leak_in_repo_name": "Leak in repository name, found by keyword: {leak_type}, leak: {repo_name}",
        "repo_stats": "Repository statistics: Size: {size}, Forks: {forks}, Stars: {stars}, Downloaded: {has_downloads}, Issues: {issues}",
        "short_description": "Brief description: {description}",
        "no_description": "Brief description: none",
        "topics": "Topics: {topics}",
        "no_topics": "Topics: none",
        "committers_found": "Found the following committers: {committers}. There are {remaining} more committers",
        "committers_all": "Found the following committers: {committers}",
        "first_grepscan_line": "First line found by grepscan: {match}",
        "leaks_found_by_scanner": "Found {count} leaks by {scanner} scanner",
        "total_leaks_found": "Total leaks found: {total_count}",
        "full_report_length": "Full report length: {length}",
        "commit_description": "Commit description: {commit}",
        "profitability_scores": "Leak Profitability Scores: Org Relevance: {org_rel:.2f}, Sensitive Data: {sens_data:.2f}, True Positive: {tp:.2f}, False Positive: {fp:.2f}",
        "ai_analysis_company_related": "🤖 AI Analysis: Company-related leak detected (confidence: {confidence:.2f})",
        "ai_analysis_company_unrelated": "🤖 AI Analysis: Not company-related (confidence: {confidence:.2f})",
        "ai_analysis_high_severity": "🤖 AI Analysis: High severity leak detected (score: {score:.2f})",
        "ai_analysis_error": "🤖 AI Analysis: Error occurred during analysis",
        "ai_analysis_summary": "🤖 AI Summary: {summary}",
        "auto_false_positive": "✅ Auto-closed as false positive (very low leak likelihood)",
        "high_chance": "High chance of leak",
        "medium_chance": "Medium chance of leak",
        "low_chance": "Low chance of leak",
        "no_chance": "No chance of leak",
        "corporate_committer_target": "🎯 CRITICAL: Found committer with TARGET COMPANY email: {name} <{email}> - ALMOST CERTAIN relevance!",
        "corporate_committer_other": "🏢 Corporate email committer: {name} <{email}> (domain: {domain})",
        "repo_credibility_high": "✅ Repository credibility: HIGH ({score:.2f}) - likely real project",
        "repo_credibility_medium": "⚠️ Repository credibility: MEDIUM ({score:.2f})",
        "repo_credibility_low": "❌ Repository credibility: LOW ({score:.2f}) - likely test/example project",
        "repo_is_tiny": "📦 Tiny repository (<10KB) - possible test project",
        "repo_is_personal": "👤 Personal project (single contributor, few commits)",
        "repo_is_popular_oss": "🌟 Popular OSS repository - secrets may be examples",
        "gist_clone_error": "Failed to clone gist repository",
        "grepscan_parsing_error": "Error parsing grepscan results: {error}",
        "unified_results_header": "═══ UNIFIED RESULTS FROM ALL SCANNERS ═══ ({count} unique findings)",
        "unified_result_item": "  #{num} [{scanner}]: {match}",
        "unified_results_more": "  ... and {additional} more findings",
    },
    "ru": {
        "leak_found_in_section": "Обнаружена утечка в разделе {obj_type} по поиску {dork}",
        "leak_in_author_name": "Утечка в имени автора, найдена по слову: {leak_type}, утечка: {author_name}",
        "leak_in_committers": "Утечка в имени/почте коммитеров, найдена по слову: {leak_type}",
        "leak_in_repo_name": "Утечка в имени репозитория, найдена по слову: {leak_type}, утечка: {repo_name}",
        "repo_stats": "Статистика по репозиторию: Размер: {size}, форки: {forks}, звезды: {stars}, был ли скачен: {has_downloads}, кол-во issue: {issues}",
        "short_description": "Краткое описание: {description}",
        "no_description": "Краткое описание: отсутствует",
        "topics": "Топики: {topics}",
        "no_topics": "Топики: отсутствуют",
        "committers_found": "Обнаружены следующие коммитеры: {committers}. Еще есть {remaining} коммитеров",
        "committers_all": "Обнаружены следующие коммитеры: {committers}",
        "first_grepscan_line": "Первая строка, найденная grepscan: {match}",
        "leaks_found_by_scanner": "Найдено {count} утечек {scanner} сканером",
        "total_leaks_found": "Всего обнаружено утечек: {total_count}",
        "full_report_length": "Длина полного отчета: {length}",
        "commit_description": "Описание коммита: {commit}",
        "profitability_scores": "Оценка рентабельности утечки: Релевантность организации: {org_rel:.2f}, Чувствительные данные: {sens_data:.2f}, Истинно-положительный: {tp:.2f}, Ложно-положительный: {fp:.2f}",
        "ai_analysis_company_related": "🤖 ИИ Анализ: Обнаружена утечка, связанная с компанией (уверенность: {confidence:.2f})",
        "ai_analysis_company_unrelated": "🤖 ИИ Анализ: Не связано с компанией (уверенность: {confidence:.2f})",
        "ai_analysis_high_severity": "🤖 ИИ Анализ: Обнаружена утечка высокой степени серьезности (оценка: {score:.2f})",
        "ai_analysis_error": "🤖 ИИ Анализ: Произошла ошибка во время анализа",
        "ai_analysis_summary": "🤖 ИИ Резюме: {summary}",
        "auto_false_positive": "✅ Автоматически закрыто как false positive (очень низкая вероятность утечки)",
        "high_chance": "Высокая вероятность утечки",
        "medium_chance": "Средняя вероятность утечки",
        "low_chance": "Низкая вероятность утечки",
        "no_chance": "Нет вероятности утечки",
        "corporate_committer_target": "🎯 ВАЖНО: Найден коммитер с email ЦЕЛЕВОЙ КОМПАНИИ: {name} <{email}> - ПОЧТИ 100% релевантность!",
        "corporate_committer_other": "🏢 Коммитер с корпоративным email: {name} <{email}> (домен: {domain})",
        "repo_credibility_high": "✅ Достоверность репозитория: ВЫСОКАЯ ({score:.2f}) - вероятно реальный проект",
        "repo_credibility_medium": "⚠️ Достоверность репозитория: СРЕДНЯЯ ({score:.2f})",
        "repo_credibility_low": "❌ Достоверность репозитория: НИЗКАЯ ({score:.2f}) - вероятно тестовый/пример",
        "repo_is_tiny": "📦 Микро-репозиторий (<10KB) - возможно тестовый проект",
        "repo_is_personal": "👤 Персональный проект (один контрибутор, мало коммитов)",
        "repo_is_popular_oss": "🌟 Популярный OSS репозиторий - секреты могут быть примерами",
        "gist_clone_error": "Не удалось клонировать gist репозиторий",
        "grepscan_parsing_error": "Ошибка парсинга результатов grepscan: {error}",
        "unified_results_header": "═══ ОБЪЕДИНЕННЫЕ РЕЗУЛЬТАТЫ ВСЕХ СКАНЕРОВ ═══ ({count} уникальных находок)",
        "unified_result_item": "  #{num} [{scanner}]: {match}",
        "unified_results_more": "  ... и еще {additional} находок",
    },
}


def token_generator():
    while True:
        for token in token_tuple:
            yield token


class AutoVivification(dict):
    """
    class AutoVivification - get easy to append dict
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


RESULT_MASS = AutoVivification()  # array with results of scans

# =============================================================================
# LLM Providers Configuration (single source of truth)
# =============================================================================

# LLM Providers configuration with actual API keys from environment
LLM_PROVIDERS = [
    {
        "name": "together",
        "base_url": "https://api.together.xyz/v1",
        "model": "mistralai/Mistral-7B-Instruct-v0.2",
        "api_key_env": "TOGETHER_API_KEY",  # pragma: allowlist secret
        "api_key": env_variables.get("TOGETHER_API_KEY", ""),
        "daily_limit": 100000,
        "rpm": 30,
        "context": 120000,
        "temperature": 0.99,
    },
    {
        "name": "openrouter",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "openrouter/auto",
        "api_key_env": "OPENROUTER_API_KEY",  # pragma: allowlist secret
        "api_key": env_variables.get("OPENROUTER_API_KEY", ""),
        "daily_limit": 100000,
        "rpm": 30,
        "context": 120000,
        "temperature": 0.99,
    },
    {
        "name": "fireworks",
        "base_url": "https://api.fireworks.ai/inference/v1",
        "model": "accounts/fireworks/models/llama4-maverick-instruct-basic",
        "api_key_env": "FIREWORKS_API_KEY",  # pragma: allowlist secret
        "api_key": env_variables.get("FIREWORKS_API_KEY", ""),
        "daily_limit": 100000,
        "rpm": 30,
        "context": 120000,
        "temperature": 0.99,
    },
]

# AI_CONFIG для обратной совместимости - использует первый доступный провайдер
# (legacy interface для существующего кода AIObj)
_primary_provider = None
for provider in LLM_PROVIDERS:
    if provider.get("api_key") and provider["api_key"].strip():
        _primary_provider = provider
        break

if _primary_provider:
    AI_CONFIG = {
        "ai_enable": env_variables.get("AI_ANALYSIS_ENABLED", "true").lower() == "true",
        "token_limit": int(env_variables.get("AI_MAX_CONTEXT_LENGTH", "4000")),
        "temperature": _primary_provider.get("temperature", 0.99),
        "url": _primary_provider["base_url"],
        "api_key": _primary_provider["api_key"],
        "model": _primary_provider["model"],
    }
else:
    # Fallback если нет доступных провайдеров
    AI_CONFIG = {
        "ai_enable": False,
        "token_limit": int(env_variables.get("AI_MAX_CONTEXT_LENGTH", "4000")),
        "temperature": 0.99,
        "url": "https://api.together.xyz/v1",
        "api_key": "",
        "model": "mistralai/Mistral-7B-Instruct-v0.2",
    }

# =============================================================================
# Secret Detection Constants (used by LeakAnalyzer and filters)
# =============================================================================

# Классификация секретов по типам и их весам
SECRET_CLASSIFICATION: Dict[str, Tuple[frozenset, float]] = {
    "private_key": (frozenset(["private_key", "private-key", "rsa private", "ssh-rsa", "-----begin", "-----end"]), 1.0),
    "certificate": (frozenset(["certificate", "cert", "pkcs", "x509", "pem"]), 0.9),
    "database_password": (
        frozenset(["database_password", "db_password", "database_pass", "mysql_password", "postgres_password"]),
        0.85,
    ),
    "prod_password": (frozenset(["prod_password", "production_password", "prod_pass", "live_password"]), 0.85),
    "admin_password": (frozenset(["admin_password", "admin_pass", "root_password", "superuser_password"]), 0.85),
    "aws_key": (frozenset(["aws_access_key", "aws_secret", "akid", "akia"]), 0.95),
    "github_token": (frozenset(["ghp_", "gho_", "ghu_", "ghs_", "github_token"]), 0.95),
    "api_key": (frozenset(["api_key", "api-key", "apikey", "api_secret"]), 0.7),
    "access_token": (frozenset(["access_token", "access-token", "bearer", "oauth_token"]), 0.7),
    "secret_key": (frozenset(["secret_key", "secret-key", "secretkey"]), 0.7),
    "auth_token": (frozenset(["auth_token", "auth-token", "authtoken"]), 0.7),
    "jwt_token": (frozenset(["jwt", "eyj"]), 0.8),
    "test_password": (frozenset(["test_password", "test_pass", "testing_pass", "test_secret"]), 0.1),
    "dev_password": (frozenset(["dev_password", "dev_pass", "development_pass", "dev_key"]), 0.1),
    "dummy_password": (frozenset(["dummy", "example", "sample", "fake", "placeholder", "changeme", "xxx"]), 0.05),
    "password": (frozenset(["password", "pass", "pwd"]), 0.5),
    "token": (frozenset(["token"]), 0.5),
    "key": (frozenset(["key"]), 0.4),
}

# Известные placeholder значения для обнаружения false positive
KNOWN_PLACEHOLDER_PATTERNS: frozenset = frozenset(
    [
        "password",
        "your_password",
        "your-password",
        "yourpassword",
        "password123",
        "admin123",
        "root123",
        "test123",
        "123456",
        "12345678",
        "changeme",
        "change_me",
        "change-me",
        "replace_me",
        "replace-me",
        "your_api_key",
        "your-api-key",
        "your_token",
        "your-token",
        "your_secret",
        "your-secret",
        "insert_here",
        "insert-here",
        "xxx",
        "xxxx",
        "xxxxx",
        "xxxxxx",
        "xxxxxxxx",
        "example",
        "sample",
        "demo",
        "test",
        "testing",
        "dummy",
        "fake",
        "placeholder",
        "todo",
        "fixme",
        "temp",
        "temporary",
        "sk_test_",
        "pk_test_",
        "sk_live_",
        "pk_live_",
        "api_key_here",
        "secret_key_here",
        "token_here",
        "key_here",
        "your_api_key_here",
        "your_secret_here",
        "your_token_here",
        "abcdef",
        "abcdefgh",
        "abcdefghij",
        "0000000000",
        "1111111111",
        "aaaaaaaaaa",
        "mysecretpassword",
        "mypassword",
        "mysecret",
        "myapikey",
        "mytoken",
        "secretpassword",
        "adminpassword",
        "rootpassword",
        "userpassword",
    ]
)

# Паттерны путей, которые часто содержат примеры (false positive)
FALSE_POSITIVE_PATH_PATTERNS: frozenset = frozenset(
    [
        "example",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "test",
        "tests",
        "testing",
        "spec",
        "specs",
        "__tests__",
        "fixture",
        "fixtures",
        "mock",
        "mocks",
        "stub",
        "stubs",
        "tutorial",
        "tutorials",
        "guide",
        "guides",
        "doc",
        "docs",
        "documentation",
        "readme",
        "template",
        "templates",
        "boilerplate",
        "sandbox",
        "playground",
        "scratch",
        "tmp",
        "temp",
        "node_modules",
        "vendor",
        "third_party",
        "third-party",
        "external",
        "lib",
        ".github",
        ".gitlab",
        ".circleci",
        ".travis",
    ]
)

# Паттерны конфигураций популярных фреймворков (часто false positive)
FRAMEWORK_CONFIG_PATTERNS: frozenset = frozenset(
    [
        "django",
        "flask",
        "rails",
        "laravel",
        "spring",
        "express",
        "wordpress",
        "drupal",
        "joomla",
        "magento",
        "prestashop",
        "react",
        "angular",
        "vue",
        "next",
        "nuxt",
        "gatsby",
        "webpack",
        "babel",
        "eslint",
        "prettier",
        "jest",
        "mocha",
    ]
)

# Минимальная энтропия для разных типов секретов
MIN_ENTROPY_THRESHOLDS: Dict[str, float] = {
    "private_key": 3.0,
    "certificate": 3.0,
    "aws_key": 4.0,
    "github_token": 3.5,
    "api_key": 3.5,
    "access_token": 3.5,
    "jwt_token": 4.0,
    "password": 2.5,
    "default": 3.0,
}

# Расширения бинарных файлов (не должны содержать секреты)
BINARY_FILE_EXTENSIONS: frozenset = frozenset(
    [
        # Images
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".webp",
        ".tiff",
        ".tif",
        # Documents
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".odt",
        # Archives
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".bz2",
        ".xz",
        # Binary/Compiled
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".o",
        ".a",
        ".pyc",
        ".pyo",
        ".class",
        # Media
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wav",
        ".flac",
        ".ogg",
        ".mkv",
        ".webm",
        # Fonts
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
        # Notebooks (часто содержат base64 вывод)
        ".ipynb",
        # Other binary
        ".db",
        ".sqlite",
        ".sqlite3",
        ".pickle",
        ".pkl",
        ".npy",
        ".npz",
        ".parquet",
        ".feather",
        ".hdf5",
        ".h5",
    ]
)

# =============================================================================
# Known False Positive Secrets (exact values commonly found in documentation)
# =============================================================================

# Известные примеры секретов из документации (false positive)
KNOWN_EXAMPLE_SECRETS: frozenset = frozenset(
    [
        # AWS примеры из документации
        "akiaiosfodnn7example",
        "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
        "akiai44qh8dhbexample",
        # GitHub примеры
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # pragma: allowlist secret
        "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # pragma: allowlist secret
        # Stripe-like примеры (using safe patterns to avoid GitHub detection)
        # Real patterns: sk_test_, pk_test_, sk_live_, pk_live_
        "str_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "str_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        # JWT примеры из jwt.io
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",  # pragma: allowlist secret
        # Google примеры
        "aizasyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # pragma: allowlist secret
        # Slack-like примеры (using safe patterns)
        # Real patterns: xoxb-, xoxp-
        "slk_bot_xxxxxxxxxxxx_xxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxx",
        "slk_usr_xxxxxxxxxxxx_xxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxx",
        # Generic placeholders
        "1234567890abcdef",  # pragma: allowlist secret
        "0123456789abcdef",  # pragma: allowlist secret
        "abcdef1234567890",  # pragma: allowlist secret
    ]
)

# Паттерны названий "учебных" репозиториев (high FP probability)
TUTORIAL_REPO_PATTERNS: frozenset = frozenset(
    [
        "tutorial",
        "learn",
        "course",
        "homework",
        "assignment",
        "exercise",
        "practice",
        "lesson",
        "workshop",
        "training",
        "study",
        "education",
        "bootcamp",
        "academy",
        "school",
        "university",
        "college",
        "class",
        "starter",
        "boilerplate",
        "template",
        "scaffold",
        "seed",
        "skeleton",
        "example",
        "sample",
        "demo",
        "showcase",
        "prototype",
        "poc",
        "test-repo",
        "testing-repo",
        "my-first",
        "hello-world",
        "getting-started",
    ]
)

# Паттерны шаблонных файлов конфигурации
TEMPLATE_CONFIG_PATTERNS: frozenset = frozenset(
    [
        ".example",
        ".sample",
        ".template",
        ".dist",
        ".default",
        "-example",
        "-sample",
        "-template",
        "-dist",
        "-default",
        "_example",
        "_sample",
        "_template",
        "_dist",
        "_default",
        ".example.",
        ".sample.",
        ".template.",
        ".dist.",
        ".default.",
    ]
)

# Локальные/development хосты и адреса (не production)
LOCAL_HOST_PATTERNS: frozenset = frozenset(
    [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "192.168.",
        "10.0.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        ".local",
        ".localhost",
        ".test",
        ".example",
        ".invalid",
        "dev.local",
        "local.dev",
        "localhost.localdomain",
    ]
)

# Паттерны mock/fixture/stub данных в путях
MOCK_DATA_PATH_PATTERNS: frozenset = frozenset(
    [
        "mock",
        "mocks",
        "__mocks__",
        "stub",
        "stubs",
        "__stubs__",
        "fixture",
        "fixtures",
        "__fixtures__",
        "fake",
        "fakes",
        "dummy",
        "dummies",
        "seed",
        "seeds",
        "factory",
        "factories",
        "snapshots",
        "__snapshots__",
        "cassettes",
        "vcr_cassettes",
    ]
)

# Пороговые значения статистики репозитория для FP анализа
REPO_SIZE_TINY_KB: int = 10  # Очень маленький репозиторий (KB)
REPO_SIZE_SMALL_KB: int = 100  # Маленький репозиторий (KB)
REPO_AGE_VERY_OLD_YEARS: int = 8  # Очень старый репозиторий (лет) — вероятно неактуальный
REPO_MAX_STARS_FOR_PERSONAL: int = 50  # Максимум звёзд для личного проекта

# Пороговые значения популярности (high = likely FP from popular OSS)
REPO_STARS_HIGH: int = 500  # Высокая популярность
REPO_STARS_VERY_HIGH: int = 5000  # Очень высокая популярность
REPO_FORKS_HIGH: int = 100  # Много форков
REPO_CONTRIBUTORS_HIGH: int = 20  # Много контрибьюторов

# Пороговые значения для анализа форков
FORK_ACTIVE_COMMITS_MIN: int = 100  # Форк с таким количеством коммитов считается активным
FORK_LOW_FORKS_MAX: int = 2  # Если у форка мало дочерних форков — вероятнее оригинальный контент
