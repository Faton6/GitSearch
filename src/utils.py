# Standard libs import
import os
import shutil
import re
import tracemalloc
import math
import string
from pathlib import Path
from collections import Counter

# Project lib's import
from src import Connector, constants
from src.logger import logger

# Load exclusions list once
exclusions: tuple[str]
with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", "r") as fd:
    exclusions = tuple(line.rstrip() for line in fd)


def count_nested_dict_len(input_dict):
    """Count total keys in nested dict/AutoVivification recursively."""
    if isinstance(input_dict, (dict, constants.AutoVivification)):
        return len(input_dict) + sum(
            count_nested_dict_len(v) for v in input_dict.values() if isinstance(v, (dict, constants.AutoVivification))
        )
    elif isinstance(input_dict, tuple):
        return sum(count_nested_dict_len(v) for v in input_dict if isinstance(v, (dict, constants.AutoVivification)))
    return 0


def check_temp_folder_size():
    """
    Check and clean TEMP_FOLDER directory if needed.

    Uses intelligent LRU (Least Recently Used) cleanup strategy:
    - Monitors folder size against MAX_TEMP_FOLDER_SIZE limit
    - Keeps most recently used repositories
    - Provides cache hit/miss statistics

    Returns:
        Tuple of (repos_removed, bytes_freed) or None on error
    """
    logger.debug("Checking TEMP_FOLDER directory")

    if not os.path.exists(constants.TEMP_FOLDER):
        logger.warning(f"TEMP_FOLDER does not exist: {constants.TEMP_FOLDER}")
        return None

    try:
        # Use new TempFolderManager for intelligent cleanup
        from src.temp_manager import get_temp_manager

        manager = get_temp_manager()
        stats = manager.get_stats()

        logger.debug(
            f'Temp folder stats: size={stats["total_size_gb"]:.2f}GB/{stats["max_size_gb"]:.1f}GB '
            f'({stats["usage_percent"]:.1f}%), repos={stats["repo_count"]}/{stats["max_repos"]}, '
            f'cache_hit_rate={stats["cache_hit_rate"]:.1f}%'
        )

        # Cleanup if needed
        repos_removed, bytes_freed = manager.cleanup_if_needed()

        if repos_removed > 0:
            logger.info(f"LRU cleanup: removed {repos_removed} repos, " f"freed {bytes_freed / (1024**3):.2f}GB")

        return repos_removed, bytes_freed

    except ImportError:
        # Fallback to legacy cleanup if temp_manager not available
        logger.debug("TempFolderManager not available, using legacy cleanup")
        return _legacy_temp_cleanup()
    except Exception as e:
        logger.error(f"Error in check_temp_folder_size: {e}")
        return None


def _legacy_temp_cleanup():
    """
    Legacy temp folder cleanup (fallback).
    Removes all directories except protected files.
    """
    temp_dir_list = os.listdir(constants.TEMP_FOLDER)

    # Protected files to keep
    protected = {"command_file", "list_to_scan.txt", ".gitkeep"}

    cleaned_count = 0
    bytes_freed = 0

    for item_name in temp_dir_list:
        if item_name in protected:
            continue

        item_path = os.path.join(constants.TEMP_FOLDER, item_name)

        if os.path.isdir(item_path):
            try:
                # Calculate size before deletion
                item_size = sum(
                    os.path.getsize(os.path.join(dirpath, filename))
                    for dirpath, _, filenames in os.walk(item_path)
                    for filename in filenames
                )
                shutil.rmtree(item_path)
                cleaned_count += 1
                bytes_freed += item_size
            except Exception as ex:
                logger.error(f"Error removing directory {item_path}: {ex}")

    if cleaned_count > 0:
        logger.info(f"Legacy cleanup: removed {cleaned_count} directories, freed {bytes_freed / (1024**2):.1f}MB")

    return cleaned_count, bytes_freed


def trace_monitor():
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.compare_to(constants.snap_backup, "lineno")
    logger.info("-" * 50)
    logger.info("Process info")
    size_count = 0
    counter = 0
    for stat in top_stats:
        size_count += stat.size_diff
        counter += 1
    logger.info("Diff size: %d MB", size_count / 1048576)
    constants.snap_backup = snapshot
    top_stats = snapshot.statistics("lineno")
    size_count = 0
    counter = 0
    for stat in top_stats:
        size_count += stat.size
        counter += 1
    logger.info("Totall size: %d MB", size_count / 1048576)
    logger.info("Totall counter: %d files", counter)
    logger.info("-" * 50)
    check_temp_folder_size()


def dumping_data():
    logger.info("-" * 50)
    logger.info("Trace monitor before dump and clearing:")
    trace_monitor()

    if any(len(elem) > 0 for elem in constants.RESULT_MASS.values()):
        Connector.dump_to_DB()
    if constants.url_from_DB != "-":
        for item in constants.RESULT_MASS.values():
            for scan_obj in item.keys():
                constants.url_from_DB[item[scan_obj].repo_url] = str(constants.RESULT_CODE_TO_SEND)
    constants.dork_search_counter = 0
    constants.RESULT_MASS = constants.AutoVivification()
    constants.quantity_obj_before_send = 0
    logger.info("Clear temp folder")
    if os.path.exists(constants.TEMP_FOLDER):
        for root, dirs, files in os.walk(constants.TEMP_FOLDER):
            for f in files:
                os.unlink(os.path.join(root, f))
            for d in dirs:
                shutil.rmtree(os.path.join(root, d))
    logger.info("Process info after dump to DB and clearing")
    trace_monitor()
    logger.info("-" * 50)


def exclude_list_update():
    # add urls to exclude_list.txt, which were have in DB result equal
    # 0 - leaks doesn't found, add to exclude list
    try:
        url_dump_from_db = constants.url_from_DB
        list_to_add = []
        for url_from_db, dump in url_dump_from_db.items():
            if dump == "0":
                list_to_add.append(url_from_db)
        if list_to_add:
            _add_repo_to_exclude(list_to_add)
    except Exception as ex:
        logger.error("Error in exclude_list_update: %s", {ex})


def _add_repo_to_exclude(url):  # TODO: add check existing repo name
    try:
        if isinstance(url, str):
            url = convert_to_regex_pattern(url)
            with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", "r+") as file:
                url_from_exclude_list = [line.rstrip() for line in file]
                if url not in url_from_exclude_list:
                    file.write(url + "\n")
        elif isinstance(url, list):
            with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", "r+") as file:
                url_from_exclude_list = [line.rstrip() for line in file]
                for new_url in url:
                    new_url = convert_to_regex_pattern(new_url)
                    if new_url not in url_from_exclude_list:
                        file.write(new_url + "\n")
        else:
            logger.error("Error in adding excludes in exclude_list.txt (_add_repo_to_exclude): Unknown data type!")
    except Exception as ex:
        logger.error("Error in adding excludes in exclude_list.txt (_add_repo_to_exclude): %s", ex)


def sanitize_company_name(company_name: str) -> str:
    """Return safe company name for detector usage."""
    if not isinstance(company_name, str):
        return ""
    return company_name.lower().replace(" ", "-").replace(".", "-").replace("(", "").replace(")", "").replace("/", "-")


def generate_company_search_terms(company_name: str) -> list[str]:
    """Generate search terms based on company name."""
    if not company_name:
        return []

    terms = []
    company_name = company_name.lower()

    # Full company name
    terms.append(company_name)

    # Split by common delimiters and add meaningful parts
    parts = re.split(r"[\s\-_.,()&]+", company_name)
    for part in parts:
        if len(part) > 2:
            terms.append(part)

    # Abbreviations
    if len(parts) > 1:
        abbr = "".join([p[0] for p in parts if p])
        if len(abbr) > 1:
            terms.append(abbr)

        stopwords = {"inc", "ltd", "llc", "corp", "corporation", "company", "co", "group", "gmbh", "ag", "sa"}
        significant_parts = [p for p in parts if p and p not in stopwords and len(p) > 2]
        if len(significant_parts) > 1:
            sig_abbr = "".join([p[0] for p in significant_parts])
            if len(sig_abbr) > 1:
                terms.append(sig_abbr)

    # Remove duplicates and very short terms
    return list({t for t in terms if len(t) > 1})


def filter_url_by_repo(urls: list[str] | tuple[str] | str):
    """
    This function excludes repos from exclude_list.txt
    Format: <account_name>/<repo_name>
    """

    if isinstance(urls, str):
        urls = (urls,)
    filtered_urls = []

    try:
        for url in urls:
            if not any(re.fullmatch(substring, url) for substring in exclusions):
                filtered_urls.append(url)
    except Exception as ex:
        logger.error("filter_url_by_repo: %s", ex)
        return []

    return filtered_urls


def convert_to_regex_pattern(input_string):
    """Convert string to regex pattern by escaping special characters."""
    return re.escape(input_string)


def filter_url_by_db(urls):
    """Filter URLs against existing database entries."""
    if isinstance(urls, str):
        urls = (urls,)

    if constants.url_from_DB == "-":
        return urls

    filtered = []
    for url in urls:
        # Normalize URL
        temp = url.split("github.com/")[-1]
        normalized = f"https://{'gist.github.com' if 'gist' in url else 'github.com'}/{'/'.join(temp.split('/')[:2])}"

        if normalized not in constants.url_from_DB:
            filtered.append(url)

    return filtered


def semantic_check_dork(string_check: str, dork: str):
    """
    semantic_check_dork return 1 if input string meaningfull and 0 if not

    Now based on RegEx rule, need change to NLP
    The need for the dork should be removed
    TODO change to NLP identification
    """
    # Define a pattern to match meaningful occurrences of string_check
    # This regex looks for the dork as a whole word or part of a word, allowing for common separators.
    # It tries to be more flexible than just exact word match.
    pattern = r"\b(?:" + re.escape(dork) + r")[\w.-]*\b"
    meaningful_pattern = re.compile(pattern, re.IGNORECASE)

    # Define a pattern to exclude gibberish or non-alphanumeric contexts around the dork.
    # This pattern looks for the dork surrounded by non-word characters, which might indicate
    # it's part of a hash, a random string, or other non-meaningful context.
    exclude_pattern = re.compile(r"[^a-zA-Z0-9\s]+" + re.escape(dork) + r"[^a-zA-Z0-9\s]+", re.IGNORECASE)

    # Filter lines with meaningful occurrences of string_check
    if meaningful_pattern.search(string_check) and not exclude_pattern.search(string_check):
        return 1
    else:
        return 0


# =============================================================================
# Safe Data Access Helpers
# =============================================================================


def safe_get_count(data: dict, key: str, default: int = 0) -> int:
    """
    Safely get totalCount from a nested structure.

    Works with:
    - {"key": {"totalCount": N}} -> N
    - {"key": [item1, item2]} -> len(list)
    - {"key": N} -> N (if int)

    Args:
        data: Dictionary to extract from
        key: Key to look up
        default: Default value if extraction fails

    Returns:
        Integer count value
    """
    value = data.get(key)
    if isinstance(value, dict):
        return value.get("totalCount", default)
    elif isinstance(value, list):
        return len(value)
    elif isinstance(value, int):
        return value
    return default


def safe_get_nested(data: dict, *keys, default=None):
    """
    Safely get a value from a nested dictionary structure.

    Example:
        safe_get_nested(data, 'level1', 'level2', 'value', default=0)
        is equivalent to:
        data.get('level1', {}).get('level2', {}).get('value', 0)

    Args:
        data: Dictionary to traverse
        *keys: Chain of keys to follow
        default: Value to return if any key is missing

    Returns:
        Value at the nested path or default
    """
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current if current is not None else default


def safe_encode_decode(data, operation: str = "encode") -> str:
    """
    Safely encode/decode data with proper error handling for different encodings.

    Args:
        data: String or bytes data to encode/decode
        operation: 'encode' or 'decode'

    Returns:
        Processed string with encoding errors handled
    """
    if not data:
        return str(data) if data is not None else ""

    try:
        if operation == "encode":
            # Convert string to proper UTF-8 encoded string
            if isinstance(data, bytes):
                return data.decode("utf-8", errors="replace")
            elif isinstance(data, str):
                # Ensure string is properly encoded
                return data.encode("utf-8", errors="replace").decode("utf-8")
            else:
                return str(data)

        elif operation == "decode":
            # Decode bytes to string using various encodings
            if isinstance(data, str):
                # If already string, just return it
                return data
            elif isinstance(data, bytes):
                # Try different encodings for bytes
                encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]
                for encoding in encodings:
                    try:
                        return data.decode(encoding)
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        continue
                # If all encodings fail, use UTF-8 with error replacement
                return data.decode("utf-8", errors="replace")
            else:
                return str(data)

    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        logger.warning(f"Encoding error in safe_encode_decode: {e}. Using replacement characters.")
        # Use replacement characters for problematic bytes
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        else:
            return str(data).encode("utf-8", errors="replace").decode("utf-8")
    except Exception as e:
        logger.error(f"Unexpected error in safe_encode_decode: {e}")
        return str(data) if data else ""


def remove_token_from_git_config(repos_dir: str, url: str):
    """Удаляет токен из .git/config файла после клонирования для предотвращения его обнаружения сканерами"""
    git_config_path = Path(repos_dir) / ".git" / "config"
    if git_config_path.exists():
        try:
            with open(git_config_path, "r") as f:
                config_content = f.read()

            # Удаляем токен из URL в конфиге (заменяем https://TOKEN@github.com на https://github.com)
            # Поддерживаем различные форматы токенов
            cleaned_content = re.sub(r"https://[^@\s]+@github\.com", "https://github.com", config_content)

            # Также удаляем токены из других Git хостингов если они есть
            cleaned_content = re.sub(
                r"https://[^@\s]+@[^/\s]+/", lambda m: "https://" + m.group(0).split("@")[1], cleaned_content
            )

            with open(git_config_path, "w") as f:
                f.write(cleaned_content)

            logger.debug(f"Token removed from .git/config for {url}")
        except Exception as exc:
            logger.warning(f"Failed to remove token from .git/config: {exc}")


# =============================================================================
# String Analysis and Entropy Helpers (Refactored from LeakAnalyzer)
# =============================================================================

# Cache compiled regex patterns to avoid repeated compilation cost
_regex_cache: dict[str, re.Pattern] = {}


def get_compiled_regex(pattern: str, flags: int = 0) -> re.Pattern:
    """Return cached compiled regex, compiling only once per pattern/flags pair."""
    cache_key = f"{pattern}:{flags}"
    compiled = _regex_cache.get(cache_key)
    if compiled is None:
        compiled = re.compile(pattern, flags)
        _regex_cache[cache_key] = compiled
    return compiled


def clear_regex_cache() -> None:
    """Clear cached compiled regex patterns."""
    _regex_cache.clear()


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy indicates more randomness (likely real secret).

    Args:
        text: String to analyze

    Returns:
        float: Entropy value (0.0 - ~4.7 for ASCII)
    """
    if not text:
        return 0.0

    # Check for memory limits for very large strings
    if len(text) > 10000:
        text = text[:10000]

    # Count character frequencies
    freq = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def has_repetitive_pattern(text: str, min_length: int = 3) -> bool:
    """Check if string contains repetitive patterns (aaa, 123123, abc)."""
    if not text or len(text) < min_length * 2:
        return False

    text_lower = text.lower()

    # Check for single char repetition
    for i in range(len(text_lower) - min_length):
        char = text_lower[i]
        if text_lower[i : i + min_length] == char * min_length:
            return True

    # Check for pattern repetition (limit to reasonable max pattern length)
    max_pattern_len = min(len(text_lower) // 2 + 1, 20)  # Don't check patterns > 20 chars
    for pattern_len in range(min_length, max_pattern_len):
        pattern = text_lower[:pattern_len]
        # Optimized check: construct expected string and compare
        repeats = len(text_lower) // pattern_len
        remainder = len(text_lower) % pattern_len
        expected = pattern * repeats + pattern[:remainder]
        if text_lower == expected:
            return True

    # Sequential patterns (abc, 123, xyz)
    try:
        sequential_patterns = (
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            string.digits[::-1],  # reverse digits
        )
        for seq in sequential_patterns:
            for i in range(len(seq) - min_length + 1):
                sub = seq[i : i + min_length]
                if sub in text_lower:
                    # Only consider sequential if it makes up significant part of string
                    if len(sub) >= len(text) // 2:
                        return True
    except Exception:
        pass

    return False


def looks_like_encoded_data(text: str, *, min_hex_length: int = 32, min_base64_length: int = 32) -> bool:
    """
    Check if text looks like encoded/serialized data (base64, hex, etc.).

    Args:
        text: String to analyze
        min_hex_length: Minimum length to treat a hex-only string as encoded data
        min_base64_length: Minimum length to treat a base64-looking string as encoded data

    Returns:
        bool: True if looks like encoded data
    """
    if not text:
        return False

    text_stripped = text.strip()

    # UUID check (len 36, 4 dashes)
    if len(text_stripped) == 36 and text_stripped.count("-") == 4:
        # Simple heuristic check before using regex
        return True

    # Pure hex string (likely hash: MD5=32, SHA1=40, SHA256=64)
    # Check if chars are valid hex
    if all(c in string.hexdigits for c in text_stripped):
        if len(text_stripped) >= min_hex_length:
            return True

    # Very long string with no spaces/separators
    if len(text_stripped) > 200 and " " not in text_stripped:
        alnum_ratio = sum(1 for c in text_stripped if c.isalnum()) / len(text_stripped)
        if alnum_ratio > 0.95:
            return True

    # Base64 check
    # Typical Base64: A-Z, a-z, 0-9, +, / (and = padding)
    if len(text_stripped) >= min_base64_length:
        # Check charset
        if all(c.isalnum() or c in "+/=" for c in text_stripped):
            # Heuristic: Base64 usually mixes types
            has_upper = any(c.isupper() for c in text_stripped)
            has_lower = any(c.islower() for c in text_stripped)
            has_digit = any(c.isdigit() for c in text_stripped)

            # If it has mixed case and digits, or ends with =, it's likely base64
            if (has_upper and has_lower and has_digit) or text_stripped.endswith("="):
                # Double check with Regex to ensure strict Base64 compliance
                # This reduces false positives for random alphanumeric strings
                if re.match(r"^[A-Za-z0-9+/]+={0,2}$", text_stripped):
                    return True

    return False


def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address."""
    if not email or "@" not in email:
        return ""

    try:
        return email.split("@")[-1].lower().strip()
    except Exception:
        return ""


def is_noreply_or_bot_domain(domain: str) -> bool:
    """Return True if an email domain is a noreply / bot / CI address.

    Checks explicit ``PUBLIC_EMAIL_DOMAINS`` set first, then falls back to
    substring matching against ``NOREPLY_DOMAIN_KEYWORDS``  so that novel
    noreply variants (e.g. ``noreply.bitbucket.org``) are also caught.
    """
    if not domain:
        return False
    domain = domain.lower().strip()
    if domain in constants.PUBLIC_EMAIL_DOMAINS:
        return True
    return any(kw in domain for kw in constants.NOREPLY_DOMAIN_KEYWORDS)


# =============================================================================
# Secret/Leak Validation Helpers (Moved from LeakAnalyzer for reuse)
# =============================================================================


def is_known_placeholder(text: str) -> bool:
    """Check if text is a known placeholder."""
    if not text:
        return False

    text_lower = text.lower().strip()

    if text_lower in constants.KNOWN_PLACEHOLDER_PATTERNS:
        return True

    # Placeholder prefixes
    placeholder_prefixes = (
        "your_",
        "your-",
        "my_",
        "my-",
        "test_",
        "test-",
        "example_",
        "example-",
        "sample_",
        "sample-",
        "dummy_",
        "dummy-",
        "fake_",
        "fake-",
    )
    if text_lower.startswith(placeholder_prefixes):
        return True

    placeholder_suffixes = ("_here", "-here", "_example", "-example", "_placeholder", "-placeholder", "_test", "-test")
    if text_lower.endswith(placeholder_suffixes):
        return True

    # Pre-compiled doc patterns
    doc_patterns = [
        get_compiled_regex(r"^<.*>$"),
        get_compiled_regex(r"^\[.*\]$"),
        get_compiled_regex(r"^\{.*\}$"),
        get_compiled_regex(r"^xxx+$"),
        get_compiled_regex(r"^\.{3,}$"),
        get_compiled_regex(r"^\*{3,}$"),
    ]

    for pattern in doc_patterns:
        if pattern.match(text_lower):
            return True

    return False


def is_binary_file(file_path: str) -> bool:
    """Check if file is binary/media type."""
    if not file_path:
        return False
    return file_path.lower().endswith(tuple(constants.BINARY_FILE_EXTENSIONS))


def is_known_example_secret(text: str) -> bool:
    """Check if text matches known docs examples."""
    if not text:
        return False

    text_lower = text.lower().strip()

    if text_lower in constants.KNOWN_EXAMPLE_SECRETS:
        return True

    # Partial matches
    for example in constants.KNOWN_EXAMPLE_SECRETS:
        if example in text_lower or (len(text_lower) > 10 and text_lower in example):
            return True

    return False


def is_template_config_file(file_path: str) -> bool:
    """Check if file is template config."""
    if not file_path:
        return False

    file_lower = file_path.lower()
    return any(pattern in file_lower for pattern in constants.TEMPLATE_CONFIG_PATTERNS)


def is_tutorial_repository(repo_name: str) -> bool:
    """Check if repository name suggests tutorial/learning project."""
    if not repo_name:
        return False
    return any(pattern in repo_name.lower() for pattern in constants.TUTORIAL_REPO_PATTERNS)


def contains_local_host(text: str) -> bool:
    """
    Check if text contains local/development host references.

    Secrets referencing localhost, 127.0.0.1, etc. are
    development configurations, not production leaks.

    Args:
        text: Text to check (could be URL, connection string, etc.)

    Returns:
        bool: True if contains local/development hosts
    """
    if not text:
        return False

    text_lower = text.lower()
    return any(host in text_lower for host in constants.LOCAL_HOST_PATTERNS)


def check_path_patterns(file_path: str, patterns: frozenset) -> bool:
    """Check if file path contains any of the given patterns."""
    if not file_path:
        return False

    path_lower = file_path.lower()
    if not path_lower:
        return False

    # Optimized: Use regex word boundaries for accurate matching
    # Patterns should match as path components (between / \ or .)
    for pattern in patterns:
        # Long patterns: direct substring match is sufficient
        if len(pattern) > 5:
            if pattern in path_lower:
                return True
        else:
            # Short patterns: use word boundary check to avoid partial matches
            # e.g., "test" should match "/test/" but not "/testing/"
            if re.search(
                rf"[/\\]{re.escape(pattern)}[/\\.]|^{re.escape(pattern)}[/\\.]|[/\\]{re.escape(pattern)}$", path_lower
            ):
                return True

    return False


def is_mock_data_path(file_path: str) -> bool:
    """Check if file path indicates mock/fixture test data."""
    return check_path_patterns(file_path, constants.MOCK_DATA_PATH_PATTERNS)


def is_false_positive_path(file_path: str) -> bool:
    """
    Check if file path indicates likely false positive (test/example files).

    Args:
        file_path: Path to file

    Returns:
        bool: True if path suggests false positive
    """
    if not file_path:
        return False

    if check_path_patterns(file_path, constants.FALSE_POSITIVE_PATH_PATTERNS):
        return True
    if check_path_patterns(file_path, constants.MOCK_DATA_PATH_PATTERNS):
        return True

    # File name patterns
    path_lower = file_path.lower()
    file_name = path_lower.split("/")[-1].split("\\")[-1]

    fp_file_patterns = [
        get_compiled_regex(r"test_.*"),
        get_compiled_regex(r".*_test\."),
        get_compiled_regex(r".*\.test\."),
        get_compiled_regex(r".*\.spec\."),
        get_compiled_regex(r"example.*"),
        get_compiled_regex(r"sample.*"),
        get_compiled_regex(r"demo.*"),
        get_compiled_regex(r"mock.*"),
        get_compiled_regex(r"fixture.*"),
        get_compiled_regex(r".*_mock\."),
        get_compiled_regex(r".*_stub\."),
    ]

    for pattern in fp_file_patterns:
        if pattern.match(file_name):
            return True

    return False


def is_random_string_with_keyword(text: str, keywords: list[str], min_keyword_len: int = 3) -> bool:
    """
    Check if text is a random/encoded string that happens to contain a keyword.

    This detects cases like "JKNDsdkjndssdjunJDNdkjfnskn32984vtbdsjsd887Vtbkdjdsnks"
    where "vtb" appears by coincidence in what looks like base64/random data.

    Args:
        text: String to analyze
        keywords: List of keywords to check (e.g., company tokens)
        min_keyword_len: Minimum keyword length to consider

    Returns:
        bool: True if appears to be random string with accidental keyword match
    """
    if not text or len(text) < 25 or not keywords:
        return False

    text_stripped = text.strip()

    # Skip if it has meaningful structure (API key patterns)
    if has_meaningful_structure(text_stripped):
        return False

    # Quick chaotic case check
    upper_count = sum(1 for c in text_stripped if c.isupper())
    lower_count = sum(1 for c in text_stripped if c.islower())
    total_alpha = upper_count + lower_count

    if total_alpha < 10:
        return False

    upper_ratio = upper_count / total_alpha
    # Only check if it's chaotically mixed (neither all upper nor all lower)
    if not (0.15 < upper_ratio < 0.85):
        return False

    # Check if keywords appear embedded in random-looking context
    text_lower = text_stripped.lower()
    for keyword in keywords:
        if len(keyword) < min_keyword_len:
            continue

        keyword_lower = keyword.lower()
        idx = text_lower.find(keyword_lower)
        if idx == -1:
            continue

        # Check if keyword is surrounded by alphanumeric chars (embedded)
        before_char = text_lower[idx - 1] if idx > 0 else ""
        after_char = text_lower[idx + len(keyword_lower)] if idx + len(keyword_lower) < len(text_lower) else ""

        if before_char.isalnum() and after_char.isalnum():
            return True

    return False


def has_meaningful_structure(text: str) -> bool:
    """
    Check if text has meaningful structure typical of real secrets.

    Real secrets often have:
    - Prefixes (sk_, pk_, ghp_, AKIA, etc.)
    - Separators (-, _, .)
    - Consistent patterns

    Args:
        text: String to analyze

    Returns:
        bool: True if has meaningful structure
    """
    if not text or len(text) < 8:
        return False

    text_stripped = text.strip()

    # Known prefixes indicate real secrets
    known_prefixes = (
        "sk_",
        "pk_",
        "rk_",  # Stripe
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",  # GitHub
        "xox",
        "xoxb",
        "xoxp",  # Slack
        "AKIA",
        "ABIA",
        "ACCA",
        "ASIA",  # AWS
        "eyJ",  # JWT
        "bearer ",
        "Bearer ",
        "api_",
        "api-",
        "key_",
        "key-",
        "token_",
        "token-",
        "secret_",
        "secret-",
        "-----BEGIN",  # PEM
    )

    if text_stripped.startswith(known_prefixes):
        return True

    if re.match(r"^[\w-]+\s*[:=]\s*.+$", text_stripped):
        return True

    separators = ("-", "_", ".")
    for sep in separators:
        parts = text_stripped.split(sep)
        if 2 <= len(parts) <= 6:
            # Multiple parts with separator = structured
            if all(len(p) >= 2 for p in parts):
                return True

    return False


# =============================================================================
# Company Pattern Matching Helpers
# =============================================================================


def check_company_pattern_in_text(
    text: str, company_terms: list[str], *, include_numbers: bool = True, include_email: bool = True
) -> bool:
    """
    Universal company pattern checker for text/credentials.

    Checks for various patterns:
    - Company name + digits (e.g., vtb123, company456)
    - Email patterns (user@company.domain)
    - Company tokens in text

    Args:
        text: Text to check
        company_terms: List of company search terms
        include_numbers: Check for company_name + numbers pattern
        include_email: Check for email patterns

    Returns:
        bool: True if any company pattern found
    """
    if not text or not company_terms:
        return False

    text_lower = text.lower()

    for term in company_terms:
        if len(term) < 3:
            continue

        term_escaped = re.escape(term)

        # Login pattern: company_name + numbers
        if include_numbers:
            if re.search(rf"(?i)\b{term_escaped}\d{{1,8}}\b", text_lower):
                return True

        # Email pattern: any_email@company.domain
        if include_email:
            if re.search(rf"(?i)\b[a-zA-Z0-9._-]+@{term_escaped}\.[a-zA-Z]{{2,}}\b", text_lower):
                return True

        # Direct match
        if term in text_lower:
            return True

    return False


def calculate_company_relevance_in_text(text: str, company_terms: list[str]) -> float:
    """
    Calculate how relevant a text is to the company (0.0 to 1.0).

    Args:
        text: Text to analyze
        company_terms: List of company search terms

    Returns:
        float: Relevance score
    """
    if not text or not company_terms:
        return 0.0

    score = 0.0
    text_lower = text.lower()

    for term in company_terms:
        if term in text_lower:
            # Weight depends on term length (longer terms are more specific)
            weight = min(len(term) / 10.0, 1.0)
            score += weight

    return min(score, 1.0)


def extract_context_around_term(text: str, term: str, context_len: int = 50) -> str:
    """
    Extract context around a found term in text.

    Args:
        text: Full text
        term: Found term
        context_len: Length of context on each side

    Returns:
        str: Extracted context with ellipsis if truncated
    """
    if len(text) <= context_len * 2:
        return text

    term_pos = text.lower().find(term.lower())
    if term_pos == -1:
        return text[: context_len * 2] + "..."

    start = max(0, term_pos - context_len)
    end = min(len(text), term_pos + len(term) + context_len)

    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""

    return prefix + text[start:end] + suffix
