# -*- coding: utf-8 -*-
"""
GitSearch Custom Exceptions Module

Модуль содержит типизированные исключения для различных сценариев ошибок
в модуле анализа утечек. Использование типизированных исключений обеспечивает:

1. Лучшую обработку ошибок
2. Более понятные сообщения об ошибках
3. Возможность различать типы ошибок для разных стратегий восстановления
4. Улучшенное логирование и мониторинг
"""

from typing import Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    import requests


class GitSearchError(Exception):
    """Базовый класс для всех исключений GitSearch."""
    
    def __init__(self, message: str, details: Optional[dict] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


# =============================================================================
# Исключения сканирования
# =============================================================================

class ScanError(GitSearchError):
    """Базовый класс для ошибок сканирования."""
    
    def __init__(self, message: str, scanner_name: str = "", url: str = "", details: Optional[dict] = None):
        self.scanner_name = scanner_name
        self.url = url
        super().__init__(message, details)
    
    def __str__(self) -> str:
        parts = [self.message]
        if self.scanner_name:
            parts.append(f"Scanner: {self.scanner_name}")
        if self.url:
            parts.append(f"URL: {self.url}")
        if self.details:
            parts.append(f"Details: {self.details}")
        return " | ".join(parts)


class TimeoutScanError(ScanError):
    """Исключение при превышении таймаута сканирования."""
    
    def __init__(self, scanner_name: str, url: str, timeout_seconds: int, details: Optional[dict] = None):
        self.timeout_seconds = timeout_seconds
        message = f"Scan timeout after {timeout_seconds}s"
        super().__init__(message, scanner_name, url, details)


class RepositoryNotFoundError(ScanError):
    """Исключение когда репозиторий не найден."""
    
    def __init__(self, url: str, details: Optional[dict] = None):
        message = f"Repository not found: {url}"
        super().__init__(message, "", url, details)


class RepositoryAccessDeniedError(ScanError):
    """Исключение когда доступ к репозиторию запрещён."""
    
    def __init__(self, url: str, reason: str = "Access denied", details: Optional[dict] = None):
        self.reason = reason
        message = f"Repository access denied: {reason}"
        super().__init__(message, "", url, details)


class RepositoryOversizeError(ScanError):
    """Исключение когда репозиторий слишком большой."""
    
    def __init__(self, url: str, size_bytes: int, max_size_bytes: int, details: Optional[dict] = None):
        self.size_bytes = size_bytes
        self.max_size_bytes = max_size_bytes
        message = f"Repository oversize: {size_bytes} bytes > {max_size_bytes} bytes limit"
        super().__init__(message, "", url, details)


class CloneError(ScanError):
    """Исключение при ошибке клонирования репозитория."""
    
    def __init__(self, url: str, attempt: int = 1, max_attempts: int = 3, reason: str = "", details: Optional[dict] = None):
        self.attempt = attempt
        self.max_attempts = max_attempts
        message = f"Clone failed (attempt {attempt}/{max_attempts})"
        if reason:
            message += f": {reason}"
        super().__init__(message, "", url, details)


class ScannerNotInstalledError(ScanError):
    """Исключение когда сканер не установлен."""
    
    def __init__(self, scanner_name: str, details: Optional[dict] = None):
        message = f"Scanner not installed: {scanner_name}"
        super().__init__(message, scanner_name, "", details)


# =============================================================================
# Исключения API
# =============================================================================

class APIError(GitSearchError):
    """Базовый класс для ошибок API."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, 
                 provider: str = "", details: Optional[dict] = None):
        self.status_code = status_code
        self.provider = provider
        super().__init__(message, details)


class RateLimitError(APIError):
    """Исключение при превышении лимита запросов API."""
    
    def __init__(self, provider: str, retry_after: Optional[int] = None, details: Optional[dict] = None):
        self.retry_after = retry_after
        message = f"Rate limit exceeded for {provider}"
        if retry_after:
            message += f", retry after {retry_after}s"
        super().__init__(message, 429, provider, details)


class GitHubAPIError(APIError):
    """Исключение для ошибок GitHub API."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[dict] = None):
        super().__init__(message, status_code, "GitHub", details)


class LLMAPIError(APIError):
    """Исключение для ошибок LLM API."""
    
    def __init__(self, message: str, provider: str, status_code: Optional[int] = None, details: Optional[dict] = None):
        super().__init__(message, status_code, provider, details)


class LLMProviderUnavailableError(LLMAPIError):
    """Исключение когда все LLM провайдеры недоступны."""
    
    def __init__(self, details: Optional[dict] = None):
        message = "No available LLM providers"
        super().__init__(message, "All", None, details)


# =============================================================================
# Исключения анализа
# =============================================================================

class AnalysisError(GitSearchError):
    """Базовый класс для ошибок анализа."""
    pass


class LeakAnalysisError(AnalysisError):
    """Исключение при ошибке анализа утечки."""
    
    def __init__(self, message: str, repo_name: str = "", details: Optional[dict] = None):
        self.repo_name = repo_name
        super().__init__(message, details)


class AIAnalysisError(AnalysisError):
    """Исключение при ошибке AI-анализа."""
    
    def __init__(self, message: str, provider: str = "", details: Optional[dict] = None):
        self.provider = provider
        super().__init__(message, details)


class InvalidSecretDataError(AnalysisError):
    """Исключение при некорректных данных секрета."""
    
    def __init__(self, field: str, expected_type: str, actual_type: str, details: Optional[dict] = None):
        self.field = field
        self.expected_type = expected_type
        self.actual_type = actual_type
        message = f"Invalid secret data: field '{field}' expected {expected_type}, got {actual_type}"
        super().__init__(message, details)


# =============================================================================
# Исключения базы данных
# =============================================================================

class DatabaseError(GitSearchError):
    """Базовый класс для ошибок базы данных."""
    pass


class DatabaseConnectionError(DatabaseError):
    """Исключение при ошибке подключения к базе данных."""
    
    def __init__(self, message: str, host: str = "", port: int = 0, 
                 retry_count: int = 0, max_retries: int = 3, details: Optional[dict] = None):
        self.host = host
        self.port = port
        self.retry_count = retry_count
        self.max_retries = max_retries
        super().__init__(message, details)
    
    def __str__(self) -> str:
        parts = [self.message]
        if self.host:
            parts.append(f"Host: {self.host}:{self.port}")
        if self.retry_count > 0:
            parts.append(f"Attempt: {self.retry_count}/{self.max_retries}")
        return " | ".join(parts)


# Backward compatibility alias
ConnectionError = DatabaseConnectionError


class QueryError(DatabaseError):
    """Исключение при ошибке выполнения запроса."""
    
    def __init__(self, message: str, query: str = "", details: Optional[dict] = None):
        self.query = query[:200] if query else ""  # Ограничиваем длину для безопасности
        super().__init__(message, details)


# =============================================================================
# Исключения конфигурации
# =============================================================================

class ConfigurationError(GitSearchError):
    """Исключение при ошибке конфигурации."""
    
    def __init__(self, message: str, config_key: str = "", details: Optional[dict] = None):
        self.config_key = config_key
        super().__init__(message, details)


class MissingConfigError(ConfigurationError):
    """Исключение при отсутствии обязательного параметра конфигурации."""
    
    def __init__(self, config_key: str, details: Optional[dict] = None):
        message = f"Missing required configuration: {config_key}"
        super().__init__(message, config_key, details)


class InvalidConfigError(ConfigurationError):
    """Исключение при некорректном значении конфигурации."""
    
    def __init__(self, config_key: str, value: Any, expected: str, details: Optional[dict] = None):
        self.value = value
        self.expected = expected
        message = f"Invalid configuration for '{config_key}': expected {expected}, got {type(value).__name__}"
        super().__init__(message, config_key, details)


# =============================================================================
# Контекстные менеджеры для обработки исключений
# =============================================================================

from contextlib import contextmanager
import subprocess


@contextmanager
def scan_error_handler(scanner_name: str, url: str):
    """
    Контекстный менеджер для обработки ошибок сканирования.
    
    Преобразует стандартные исключения в типизированные ScanError.
    
    Пример использования:
        with scan_error_handler("gitleaks", url):
            # код сканирования
    
    Args:
        scanner_name: Название сканера
        url: URL сканируемого репозитория
    
    Raises:
        TimeoutScanError: При таймауте
        ScanError: При других ошибках сканирования
    """
    try:
        yield
    except subprocess.TimeoutExpired as e:
        raise TimeoutScanError(
            scanner_name=scanner_name,
            url=url,
            timeout_seconds=int(e.timeout) if e.timeout else 0,
            details={"cmd": str(e.cmd) if e.cmd else ""}
        ) from e
    except FileNotFoundError as e:
        raise ScannerNotInstalledError(
            scanner_name=scanner_name,
            details={"error": str(e)}
        ) from e
    except PermissionError as e:
        raise RepositoryAccessDeniedError(
            url=url,
            reason="Permission denied",
            details={"error": str(e)}
        ) from e
    except Exception as e:
        raise ScanError(
            message=f"Unexpected error during scan: {str(e)}",
            scanner_name=scanner_name,
            url=url,
            details={"error_type": type(e).__name__, "error": str(e)}
        ) from e


@contextmanager
def api_error_handler(provider: str):
    """
    Контекстный менеджер для обработки ошибок API.
    
    Args:
        provider: Название провайдера API
    
    Raises:
        RateLimitError: При превышении лимита
        APIError: При других ошибках API
    """
    import requests
    
    try:
        yield
    except requests.exceptions.Timeout as e:
        raise APIError(
            message=f"API request timeout for {provider}",
            provider=provider,
            details={"error": str(e)}
        ) from e
    except requests.exceptions.ConnectionError as e:
        raise APIError(
            message=f"Connection error for {provider}",
            provider=provider,
            details={"error": str(e)}
        ) from e
    except Exception as e:
        raise APIError(
            message=f"Unexpected API error for {provider}: {str(e)}",
            provider=provider,
            details={"error_type": type(e).__name__, "error": str(e)}
        ) from e
