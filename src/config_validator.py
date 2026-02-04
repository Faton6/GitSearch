# -*- coding: utf-8 -*-
"""
Configuration Validator Module

Provides pydantic-based validation for GitSearch configuration.
Validates config.json, environment variables, and runtime settings.

If pydantic is not installed, falls back to basic dict-based config.
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field

# Try to import pydantic
PYDANTIC_AVAILABLE = False
try:
    from pydantic import BaseModel, Field, ValidationError

    PYDANTIC_AVAILABLE = True
except ImportError:
    pass


# =============================================================================
# Dataclass-based config (always available, no pydantic required)
# =============================================================================


@dataclass
class AIConfigData:
    """AI Analysis configuration."""

    enabled: bool = True
    timeout: int = 30
    max_context_length: int = 4000
    company_relevance_threshold: float = 0.5
    true_positive_threshold: float = 0.6
    provider_check_interval: int = 5
    worker_pool_size: int = 2
    worker_queue_size: int = 100
    async_analysis: bool = True
    together_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    fireworks_api_key: Optional[str] = None


@dataclass
class ScanConfigData:
    """Scanning configuration."""

    max_time_to_scan_default: int = 100
    max_time_to_scan_deep: int = 3000
    max_time_to_clone: int = 500
    repo_max_size_kb: int = 300000
    max_try_to_clone: int = 3
    clone_method: str = "git"
    clone_fallback_to_git: bool = True


@dataclass
class TempFolderConfigData:
    """Temporary folder management configuration."""

    max_size_gb: float = 10.0
    max_repos_to_keep: int = 50
    cleanup_on_size_exceeded: bool = True
    cleanup_keep_newest: int = 20


@dataclass
class DatabaseConfigData:
    """Database configuration."""

    url: str = "172.32.0.97"
    port: int = 3306
    token: str = "-"
    max_retries: int = 3
    retry_delay: float = 2.0


@dataclass
class GitHubConfigData:
    """GitHub API configuration."""

    request_cooldown: float = 60.0
    request_rate_limit: float = 10.0
    repo_count_limit: int = 1000
    per_page: int = 100
    tokens: List[str] = field(default_factory=list)


@dataclass
class ReportConfigData:
    """Report generation configuration."""

    create_report: bool = False
    report_type: str = "business"
    start_date: Optional[str] = None
    end_date: Optional[str] = None


@dataclass
class LoggingConfigData:
    """Logging configuration."""

    level: str = "INFO"
    console_level: Optional[str] = None
    json_format: bool = False
    max_file_size_mb: int = 50
    backup_count: int = 7


@dataclass
class GitSearchConfigData:
    """Main GitSearch configuration."""

    target_list: Dict[str, List[str]] = field(default_factory=dict)
    leak_check_list: List[str] = field(default_factory=lambda: ["dork"])
    ai: AIConfigData = field(default_factory=AIConfigData)
    scan: ScanConfigData = field(default_factory=ScanConfigData)
    temp_folder: TempFolderConfigData = field(default_factory=TempFolderConfigData)
    database: DatabaseConfigData = field(default_factory=DatabaseConfigData)
    github: GitHubConfigData = field(default_factory=GitHubConfigData)
    report: ReportConfigData = field(default_factory=ReportConfigData)
    logging: LoggingConfigData = field(default_factory=LoggingConfigData)


# =============================================================================
# Pydantic models (only if pydantic is available)
# =============================================================================

if PYDANTIC_AVAILABLE:

    class AIConfig(BaseModel):
        """AI Analysis configuration."""

        enabled: bool = Field(default=True, description="Enable AI-powered analysis")
        timeout: int = Field(default=30, ge=5, le=300, description="AI API timeout in seconds")
        max_context_length: int = Field(default=4000, ge=500, le=100000, description="Max context length")
        company_relevance_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
        true_positive_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
        provider_check_interval: int = Field(default=5, ge=0, le=100)
        worker_pool_size: int = Field(default=2, ge=1, le=10)
        worker_queue_size: int = Field(default=100, ge=10, le=1000)
        async_analysis: bool = Field(default=True, description="Enable async AI analysis")
        together_api_key: Optional[str] = Field(default=None)
        openrouter_api_key: Optional[str] = Field(default=None)
        fireworks_api_key: Optional[str] = Field(default=None)

    class ScanConfig(BaseModel):
        """Scanning configuration."""

        max_time_to_scan_default: int = Field(default=100, ge=10, le=3600)
        max_time_to_scan_deep: int = Field(default=3000, ge=100, le=7200)
        max_time_to_clone: int = Field(default=500, ge=30, le=3600)
        repo_max_size_kb: int = Field(default=300000, ge=1000, le=10000000)
        max_try_to_clone: int = Field(default=3, ge=1, le=10)
        clone_method: str = Field(default="git", pattern="^(git|pygithub)$")
        clone_fallback_to_git: bool = Field(default=True)

    class TempFolderConfig(BaseModel):
        """Temporary folder management configuration."""

        max_size_gb: float = Field(default=10.0, ge=1.0, le=100.0)
        max_repos_to_keep: int = Field(default=50, ge=10, le=500)
        cleanup_on_size_exceeded: bool = Field(default=True)
        cleanup_keep_newest: int = Field(default=20, ge=5, le=100)

    class DatabaseConfig(BaseModel):
        """Database configuration."""

        url: str = Field(default="172.32.0.97")
        port: int = Field(default=3306, ge=1, le=65535)
        token: str = Field(default="-")
        max_retries: int = Field(default=3, ge=1, le=10)
        retry_delay: float = Field(default=2.0, ge=0.5, le=30.0)

    class GitHubConfig(BaseModel):
        """GitHub API configuration."""

        request_cooldown: float = Field(default=60.0, ge=1.0, le=300.0)
        request_rate_limit: float = Field(default=10.0, ge=1.0, le=100.0)
        repo_count_limit: int = Field(default=1000, ge=100, le=1000)
        per_page: int = Field(default=100, ge=10, le=100)
        tokens: List[str] = Field(default_factory=list)

    class ReportConfig(BaseModel):
        """Report generation configuration."""

        create_report: bool = Field(default=False)
        report_type: str = Field(default="business", pattern="^(business|technical|full)$")
        start_date: Optional[str] = Field(default=None)
        end_date: Optional[str] = Field(default=None)

    class LoggingConfig(BaseModel):
        """Logging configuration."""

        level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
        console_level: Optional[str] = Field(default=None)
        json_format: bool = Field(default=False)
        max_file_size_mb: int = Field(default=50, ge=1, le=500)
        backup_count: int = Field(default=7, ge=1, le=30)

    class GitSearchConfig(BaseModel):
        """Main GitSearch configuration model with validation."""

        target_list: Dict[str, List[str]] = Field(default_factory=dict)
        leak_check_list: List[str] = Field(default_factory=lambda: ["dork"])
        ai: AIConfig = Field(default_factory=AIConfig)
        scan: ScanConfig = Field(default_factory=ScanConfig)
        temp_folder: TempFolderConfig = Field(default_factory=TempFolderConfig)
        database: DatabaseConfig = Field(default_factory=DatabaseConfig)
        github: GitHubConfig = Field(default_factory=GitHubConfig)
        report: ReportConfig = Field(default_factory=ReportConfig)
        logging: LoggingConfig = Field(default_factory=LoggingConfig)

else:
    # Aliases for dataclass versions when pydantic not available
    AIConfig = AIConfigData
    ScanConfig = ScanConfigData
    TempFolderConfig = TempFolderConfigData
    DatabaseConfig = DatabaseConfigData
    GitHubConfig = GitHubConfigData
    ReportConfig = ReportConfigData
    LoggingConfig = LoggingConfigData
    GitSearchConfig = GitSearchConfigData


# =============================================================================
# Configuration Loading Functions
# =============================================================================


def load_and_validate_config(
    config_path: Optional[str] = None, env_prefix: str = "GITSEARCH_"
) -> Union["GitSearchConfig", GitSearchConfigData]:
    """
    Load and validate configuration from file and environment.

    Args:
        config_path: Path to config.json (auto-detected if None)
        env_prefix: Prefix for environment variables

    Returns:
        GitSearchConfig (pydantic) or GitSearchConfigData (dataclass)

    Raises:
        ValidationError: If configuration is invalid (pydantic only)
        FileNotFoundError: If config file not found
    """
    # Auto-detect config path
    if config_path is None:
        main_folder = Path(__file__).parent.parent
        config_path = main_folder / "config.json"

    # Load config file
    with open(config_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    # Load environment variables
    env_vars = _load_env_overrides(env_prefix)

    # Merge configs (env vars override file config)
    merged_config = _merge_configs(config_data, env_vars)

    # Transform to nested structure
    structured_config = _transform_to_structured(merged_config)

    if PYDANTIC_AVAILABLE:
        try:
            return GitSearchConfig(**structured_config)
        except ValidationError as e:
            logging.error(f"Configuration validation failed:\n{e}")
            raise
    else:
        logging.debug("pydantic not installed. Using dataclass config without validation.")
        return _create_dataclass_config(structured_config)


def _create_dataclass_config(data: Dict) -> GitSearchConfigData:
    """Create dataclass-based config from dict."""
    return GitSearchConfigData(
        target_list=data.get("target_list", {}),
        leak_check_list=data.get("leak_check_list", ["dork"]),
        ai=AIConfigData(**data.get("ai", {})) if "ai" in data else AIConfigData(),
        scan=ScanConfigData(**data.get("scan", {})) if "scan" in data else ScanConfigData(),
        temp_folder=TempFolderConfigData(**data.get("temp_folder", {}))
        if "temp_folder" in data
        else TempFolderConfigData(),
        database=DatabaseConfigData(**data.get("database", {})) if "database" in data else DatabaseConfigData(),
        github=GitHubConfigData(**data.get("github", {})) if "github" in data else GitHubConfigData(),
        report=ReportConfigData(**data.get("report", {})) if "report" in data else ReportConfigData(),
        logging=LoggingConfigData(**data.get("logging", {})) if "logging" in data else LoggingConfigData(),
    )


def _load_env_overrides(prefix: str) -> Dict[str, Any]:
    """Load configuration overrides from environment variables."""
    overrides = {}

    # Direct mappings
    env_mappings = {
        "URL_DB": ("database", "url"),
        "TOKEN_DB": ("database", "token"),
        "LOG_LEVEL": ("logging", "level"),
        "CONSOLE_LOG_LEVEL": ("logging", "console_level"),
        "LOG_JSON_FORMAT": ("logging", "json_format"),
        "AI_ANALYSIS_ENABLED": ("ai", "enabled"),
        "AI_ANALYSIS_TIMEOUT": ("ai", "timeout"),
        "AI_MAX_CONTEXT_LENGTH": ("ai", "max_context_length"),
        "TOGETHER_API_KEY": ("ai", "together_api_key"),
        "OPENROUTER_API_KEY": ("ai", "openrouter_api_key"),
        "FIREWORKS_API_KEY": ("ai", "fireworks_api_key"),
        "REPO_MAX_SIZE": ("scan", "repo_max_size_kb"),
        "MAX_TIME_TO_CLONE": ("scan", "max_time_to_clone"),
        "CLONE_METHOD": ("scan", "clone_method"),
        "MAX_TEMP_FOLDER_SIZE_GB": ("temp_folder", "max_size_gb"),
    }

    for env_key, (section, field_name) in env_mappings.items():
        value = os.environ.get(env_key) or os.environ.get(f"{prefix}{env_key}")
        if value:
            if section not in overrides:
                overrides[section] = {}
            # Type conversion
            if field_name in ("enabled", "async_analysis", "cleanup_on_size_exceeded", "json_format"):
                overrides[section][field_name] = value.lower() in ("true", "1", "yes")
            elif field_name in (
                "timeout",
                "max_context_length",
                "repo_max_size_kb",
                "max_time_to_clone",
                "worker_pool_size",
                "worker_queue_size",
                "max_repos_to_keep",
            ):
                overrides[section][field_name] = int(value)
            elif field_name in ("company_relevance_threshold", "true_positive_threshold", "max_size_gb"):
                overrides[section][field_name] = float(value)
            else:
                overrides[section][field_name] = value

    # GitHub tokens (GITHUB_TOKEN_1, GITHUB_TOKEN_2, etc.)
    tokens = []
    for i in range(1, 20):
        token = os.environ.get(f"GITHUB_TOKEN_{i}")
        if token and token != "-":
            tokens.append(token)
        else:
            break
    if tokens:
        if "github" not in overrides:
            overrides["github"] = {}
        overrides["github"]["tokens"] = tokens

    return overrides


def _merge_configs(file_config: Dict, env_overrides: Dict) -> Dict:
    """Merge file config with environment overrides."""
    result = file_config.copy()

    for key, value in env_overrides.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = {**result[key], **value}
        else:
            result[key] = value

    return result


def _transform_to_structured(flat_config: Dict) -> Dict:
    """Transform flat config.json to structured format."""
    structured = {
        "target_list": flat_config.get("target_list", {}),
        "leak_check_list": flat_config.get("leak_check_list", ["dork"]),
        "database": {
            "url": flat_config.get("url_DB", "172.32.0.97"),
            "token": flat_config.get("token_DB", "-"),
        },
        "report": {
            "create_report": flat_config.get("create_report", "no") == "yes",
            "report_type": flat_config.get("report_type", "business"),
        },
        "github": {
            "tokens": flat_config.get("token_list", []),
        },
    }

    # Parse dates if present
    if "start_date" in flat_config and flat_config["start_date"]:
        structured["report"]["start_date"] = flat_config["start_date"]
    if "end_date" in flat_config and flat_config["end_date"]:
        structured["report"]["end_date"] = flat_config["end_date"]

    # Merge any existing nested configs
    for section in ("ai", "scan", "temp_folder", "database", "github", "report", "logging"):
        if section in flat_config and isinstance(flat_config[section], dict):
            if section in structured:
                structured[section] = {**structured[section], **flat_config[section]}
            else:
                structured[section] = flat_config[section]

    return structured


def validate_runtime_config() -> List[str]:
    """
    Validate runtime configuration and return list of warnings/errors.

    Returns:
        List of warning/error messages (empty if all OK)
    """
    warnings = []

    try:
        from src import constants

        # Check tokens
        if not constants.token_tuple or constants.token_tuple[0] == "-":
            warnings.append("WARNING: No GitHub tokens configured. API access will be limited.")

        # Check temp folder
        if not os.path.exists(constants.TEMP_FOLDER):
            warnings.append(f"WARNING: Temp folder does not exist: {constants.TEMP_FOLDER}")

        # Check database connection
        if constants.url_DB == "-":
            warnings.append("WARNING: Database URL not configured (url_DB = '-')")

        # Check AI configuration
        if constants.AI_ANALYSIS_ENABLED:
            env_keys = ["TOGETHER_API_KEY", "OPENROUTER_API_KEY", "FIREWORKS_API_KEY"]
            has_ai_key = any(os.environ.get(k) for k in env_keys)
            if not has_ai_key:
                warnings.append("WARNING: AI analysis enabled but no AI API keys found in environment")

    except ImportError as e:
        warnings.append(f"ERROR: Could not import constants module: {e}")

    return warnings


# Export for easy import
__all__ = [
    "GitSearchConfig",
    "GitSearchConfigData",
    "AIConfig",
    "AIConfigData",
    "ScanConfig",
    "ScanConfigData",
    "TempFolderConfig",
    "TempFolderConfigData",
    "DatabaseConfig",
    "DatabaseConfigData",
    "GitHubConfig",
    "GitHubConfigData",
    "ReportConfig",
    "ReportConfigData",
    "LoggingConfig",
    "LoggingConfigData",
    "load_and_validate_config",
    "validate_runtime_config",
    "PYDANTIC_AVAILABLE",
]
