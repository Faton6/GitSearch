# -*- coding: utf-8 -*-
"""
Structured Logging Module for GitSearch

Provides JSON-formatted logging for better integration with:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Grafana Loki
- CloudWatch, Datadog, etc.

Features:
- JSON and text format support
- Contextual fields (request_id, repo_url, etc.)
- Performance metrics
- Thread-safe context management
"""

import logging
import json
import time
import os
import threading
from typing import Any, Dict, Optional
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
from contextlib import contextmanager
from functools import wraps


class ContextFilter(logging.Filter):
    """Filter that adds contextual information to log records."""
    
    # Thread-local storage for context
    _context = threading.local()
    
    @classmethod
    def set_context(cls, **kwargs):
        """Set context values for current thread."""
        if not hasattr(cls._context, 'data'):
            cls._context.data = {}
        cls._context.data.update(kwargs)
    
    @classmethod
    def clear_context(cls):
        """Clear context for current thread."""
        cls._context.data = {}
    
    @classmethod
    def get_context(cls) -> Dict[str, Any]:
        """Get current context."""
        if not hasattr(cls._context, 'data'):
            cls._context.data = {}
        return cls._context.data.copy()
    
    def filter(self, record):
        """Add context to log record."""
        context = self.get_context()
        for key, value in context.items():
            setattr(record, key, value)
        return True


class JsonFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    
    Output format:
    {
        "timestamp": "2024-01-15T10:30:00.123Z",
        "level": "INFO",
        "logger": "gitsearch",
        "message": "Scan completed",
        "module": "scanner",
        "function": "scan_repo",
        "line": 42,
        "extra": {
            "repo_url": "https://github.com/user/repo",
            "duration_ms": 1234,
            "leaks_found": 5
        }
    }
    """
    
    # Fields to include from record
    STANDARD_FIELDS = {
        'name', 'levelname', 'levelno', 'pathname', 'filename',
        'module', 'lineno', 'funcName', 'created', 'thread',
        'threadName', 'process', 'message', 'exc_info', 'exc_text',
        'stack_info', 'msg', 'args'
    }
    
    def __init__(
        self,
        include_timestamp: bool = True,
        include_extra: bool = True,
        indent: Optional[int] = None,
        ensure_ascii: bool = False
    ):
        """
        Initialize JSON formatter.
        
        Args:
            include_timestamp: Include ISO timestamp
            include_extra: Include extra fields from record
            indent: JSON indentation (None for compact)
            ensure_ascii: Escape non-ASCII characters
        """
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_extra = include_extra
        self.indent = indent
        self.ensure_ascii = ensure_ascii
    
    def format(self, record: logging.LogRecord) -> str:
        """Format record as JSON string."""
        # Build base log entry
        log_entry = {
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add timestamp
        if self.include_timestamp:
            log_entry['timestamp'] = datetime.utcfromtimestamp(
                record.created
            ).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        # Add extra fields
        if self.include_extra:
            extra = {}
            for key, value in record.__dict__.items():
                if key not in self.STANDARD_FIELDS and not key.startswith('_'):
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(value)
                        extra[key] = value
                    except (TypeError, ValueError):
                        extra[key] = str(value)
            
            if extra:
                log_entry['extra'] = extra
        
        # Add exception info
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add stack info
        if record.stack_info:
            log_entry['stack'] = record.stack_info
        
        return json.dumps(
            log_entry,
            indent=self.indent,
            ensure_ascii=self.ensure_ascii,
            default=str
        )


class StructuredLogger:
    """
    Enhanced logger with structured logging support.
    
    Usage:
        logger = StructuredLogger('gitsearch')
        
        # Simple logging
        logger.info('Processing started')
        
        # Structured logging with extra fields
        logger.info('Scan completed', repo_url='https://...', leaks=5, duration=1.23)
        
        # With context
        with logger.context(company='Acme', scan_id='abc123'):
            logger.info('Processing company')
            logger.warning('Rate limit approaching')
        
        # Performance timing
        with logger.timed('clone_operation'):
            clone_repo(url)
    """
    
    def __init__(
        self,
        name: str = 'gitsearch',
        level: int = logging.INFO,
        json_format: bool = False,
        log_file: Optional[str] = None
    ):
        """
        Initialize structured logger.
        
        Args:
            name: Logger name
            level: Logging level
            json_format: Use JSON format for file output
            log_file: Path to log file (optional)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Capture all, handlers filter
        self.json_format = json_format
        
        # Add context filter
        self.context_filter = ContextFilter()
        self.logger.addFilter(self.context_filter)
        
        # Configure handlers if not already configured
        if not self.logger.handlers:
            self._setup_handlers(level, json_format, log_file)
    
    def _setup_handlers(
        self,
        level: int,
        json_format: bool,
        log_file: Optional[str]
    ):
        """Set up logging handlers."""
        # Console handler - always text format for readability
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_formatter = logging.Formatter(
            '%(asctime)s %(levelname)s %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler - JSON or text based on config
        if log_file:
            file_handler = TimedRotatingFileHandler(
                filename=log_file,
                when='midnight',
                interval=1,
                backupCount=7,
                encoding='utf-8'
            )
            file_handler.setLevel(level)
            
            if json_format:
                file_handler.setFormatter(JsonFormatter())
            else:
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s %(levelname)s %(message)s in %(filename)s:%(lineno)d'
                ))
            
            self.logger.addHandler(file_handler)
    
    def _log(self, level: int, msg: str, *args, **kwargs):
        """Internal log method with extra fields support."""
        # Extract extra fields from kwargs
        extra = {}
        log_kwargs = {}
        
        for key, value in list(kwargs.items()):
            if key in ('exc_info', 'stack_info', 'stacklevel'):
                log_kwargs[key] = value
            else:
                extra[key] = value
        
        if extra:
            log_kwargs['extra'] = extra
        
        self.logger.log(level, msg, *args, **log_kwargs)
    
    def debug(self, msg: str, *args, **kwargs):
        """Log debug message with optional extra fields."""
        self._log(logging.DEBUG, msg, *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs):
        """Log info message with optional extra fields."""
        self._log(logging.INFO, msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs):
        """Log warning message with optional extra fields."""
        self._log(logging.WARNING, msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        """Log error message with optional extra fields."""
        self._log(logging.ERROR, msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs):
        """Log critical message with optional extra fields."""
        self._log(logging.CRITICAL, msg, *args, **kwargs)
    
    def exception(self, msg: str, *args, **kwargs):
        """Log exception with traceback."""
        kwargs['exc_info'] = True
        self._log(logging.ERROR, msg, *args, **kwargs)
    
    @contextmanager
    def context(self, **kwargs):
        """
        Context manager for adding fields to all logs within scope.
        
        Usage:
            with logger.context(request_id='abc', user='john'):
                logger.info('Processing')  # Includes request_id and user
        """
        old_context = ContextFilter.get_context()
        ContextFilter.set_context(**kwargs)
        try:
            yield
        finally:
            ContextFilter.clear_context()
            ContextFilter.set_context(**old_context)
    
    @contextmanager
    def timed(self, operation: str, level: int = logging.DEBUG):
        """
        Context manager for timing operations.
        
        Usage:
            with logger.timed('clone_repo'):
                clone(url)
            # Logs: "clone_repo completed in 1.234s"
        """
        start_time = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start_time
            self._log(
                level,
                f'{operation} completed',
                operation=operation,
                duration_seconds=round(duration, 3),
                duration_ms=round(duration * 1000, 1)
            )
    
    def timed_decorator(self, operation: Optional[str] = None, level: int = logging.DEBUG):
        """
        Decorator for timing function execution.
        
        Usage:
            @logger.timed_decorator('scan_repo')
            def scan_repo(url):
                ...
        """
        def decorator(func):
            op_name = operation or func.__name__
            
            @wraps(func)
            def wrapper(*args, **kwargs):
                with self.timed(op_name, level):
                    return func(*args, **kwargs)
            
            return wrapper
        return decorator


def create_structured_logger(
    name: str = 'gitsearch',
    json_format: Optional[bool] = None,
    log_file: Optional[str] = None
) -> StructuredLogger:
    """
    Factory function to create configured structured logger.
    
    Args:
        name: Logger name
        json_format: Use JSON format (default: from env LOG_JSON_FORMAT)
        log_file: Log file path (default: auto-generated)
        
    Returns:
        Configured StructuredLogger instance
    """
    # Determine JSON format from environment if not specified
    if json_format is None:
        json_format = os.getenv('LOG_JSON_FORMAT', 'false').lower() in ('true', '1', 'yes')
    
    # Determine log level from environment
    level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
    level = getattr(logging, level_str, logging.INFO)
    
    # Auto-generate log file if not specified
    if log_file is None:
        logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        timestamp = time.strftime('%Y_%m_%d')
        suffix = '.json' if json_format else '.log'
        log_file = os.path.join(logs_dir, f'log_{timestamp}{suffix}')
    
    return StructuredLogger(
        name=name,
        level=level,
        json_format=json_format,
        log_file=log_file
    )


# Convenience functions for quick structured logging
def log_scan_event(
    event_type: str,
    repo_url: str,
    **kwargs
):
    """
    Log a scan-related event with standard fields.
    
    Args:
        event_type: Type of event (clone_start, clone_complete, scan_start, etc.)
        repo_url: Repository URL
        **kwargs: Additional fields
    """
    from src.logger import logger
    
    log_data = {
        'event_type': event_type,
        'repo_url': repo_url,
        **kwargs
    }
    
    # Convert to structured log message
    msg_parts = [f'{event_type}']
    if repo_url:
        msg_parts.append(f'repo={repo_url}')
    
    for key, value in kwargs.items():
        if key not in ('event_type', 'repo_url'):
            msg_parts.append(f'{key}={value}')
    
    logger.info(' | '.join(msg_parts))


def log_rate_limit_event(
    token: str,
    resource: str,
    remaining: int,
    reset_time: float,
    **kwargs
):
    """Log rate limit event."""
    from src.logger import logger
    
    logger.warning(
        f'Rate limit: token={token[:12]}... resource={resource} '
        f'remaining={remaining} reset_in={int(reset_time - time.time())}s'
    )


def log_performance_metric(
    metric_name: str,
    value: float,
    unit: str = 'seconds',
    **tags
):
    """
    Log a performance metric.
    
    Args:
        metric_name: Name of the metric
        value: Metric value
        unit: Unit of measurement
        **tags: Additional tags/dimensions
    """
    from src.logger import logger
    
    tag_str = ' '.join(f'{k}={v}' for k, v in tags.items())
    logger.info(f'METRIC {metric_name}={value}{unit} {tag_str}'.strip())


__all__ = [
    'StructuredLogger',
    'JsonFormatter',
    'ContextFilter',
    'create_structured_logger',
    'log_scan_event',
    'log_rate_limit_event',
    'log_performance_metric',
]
