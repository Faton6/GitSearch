# Standard libs import
import sys
import json
import os
import shutil
import subprocess
import re
import time
import tracemalloc
from pathlib import Path

# Project lib's import
from src import Connector, constants
from src.logger import logger, CLR

# Load exclusions list once
exclusions: tuple[str]
with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", 'r') as fd:
    exclusions = tuple(line.rstrip() for line in fd)


def count_nested_dict_len(input_dict):
    length = len(input_dict)
    if isinstance(input_dict, tuple):
        for value in input_dict:
            if isinstance(value, dict) or isinstance(value, constants.AutoVivification):
                length += count_nested_dict_len(value)
    elif isinstance(input_dict, constants.AutoVivification):
        for key, value in input_dict.items():
            if isinstance(value, dict) or isinstance(value, constants.AutoVivification):
                length += count_nested_dict_len(value)
    elif isinstance(input_dict, dict):
        pass
    else:
        logger.error("count_nested_dict_len: input_dict is not an AutoVivification instance: %s", type(input_dict))
        logger.error("input_dict: %s", str(input_dict))
    return length


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
    logger.info('Checking TEMP_FOLDER directory')
    
    if not os.path.exists(constants.TEMP_FOLDER):
        logger.warning(f'TEMP_FOLDER does not exist: {constants.TEMP_FOLDER}')
        return None
    
    try:
        # Use new TempFolderManager for intelligent cleanup
        from src.temp_manager import get_temp_manager
        
        manager = get_temp_manager()
        stats = manager.get_stats()
        
        logger.info(
            f'Temp folder stats: size={stats["total_size_gb"]:.2f}GB/{stats["max_size_gb"]:.1f}GB '
            f'({stats["usage_percent"]:.1f}%), repos={stats["repo_count"]}/{stats["max_repos"]}, '
            f'cache_hit_rate={stats["cache_hit_rate"]:.1f}%'
        )
        
        # Cleanup if needed
        repos_removed, bytes_freed = manager.cleanup_if_needed()
        
        if repos_removed > 0:
            logger.info(
                f'LRU cleanup: removed {repos_removed} repos, '
                f'freed {bytes_freed / (1024**3):.2f}GB'
            )
        
        return repos_removed, bytes_freed
        
    except ImportError:
        # Fallback to legacy cleanup if temp_manager not available
        logger.debug('TempFolderManager not available, using legacy cleanup')
        return _legacy_temp_cleanup()
    except Exception as e:
        logger.error(f'Error in check_temp_folder_size: {e}')
        return None


def _legacy_temp_cleanup():
    """
    Legacy temp folder cleanup (fallback).
    Removes all directories except protected files.
    """
    temp_dir_list = os.listdir(constants.TEMP_FOLDER)
    
    # Protected files to keep
    protected = {'command_file', 'list_to_scan.txt', '.gitkeep'}
    
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
                logger.error(f'Error removing directory {item_path}: {ex}')
    
    if cleaned_count > 0:
        logger.info(f'Legacy cleanup: removed {cleaned_count} directories, freed {bytes_freed / (1024**2):.1f}MB')
    
    return cleaned_count, bytes_freed


def trace_monitor():
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.compare_to(constants.snap_backup, "lineno")
    logger.info('-' * 50)
    logger.info('Process info')
    size_count = 0
    counter = 0
    for stat in top_stats:
        size_count += stat.size_diff
        counter += 1
    logger.info('Diff size: %d MB', size_count / 1048576)
    constants.snap_backup = snapshot
    top_stats = snapshot.statistics('lineno')
    size_count = 0
    counter = 0
    for stat in top_stats:
        size_count += stat.size
        counter += 1
    logger.info('Totall size: %d MB', size_count / 1048576)
    logger.info('Totall counter: %d files', counter)
    logger.info('-' * 50)
    check_temp_folder_size()


def dumping_data():
    logger.info('-' * 50)
    logger.info('Trace monitor before dump and clearing:')
    trace_monitor()
    result_unempty = False
    for elem in constants.RESULT_MASS.values():
        if len(elem) > 0:
            result_unempty = True
            break
    if result_unempty:
        Connector.dump_to_DB()
    if constants.url_from_DB != '-':
        for item in constants.RESULT_MASS.values():
            for scan_obj in item.keys():
                constants.url_from_DB[item[scan_obj].repo_url] = str(
                    constants.RESULT_CODE_TO_SEND)
    constants.dork_search_counter = 0
    constants.RESULT_MASS = constants.AutoVivification()
    constants.quantity_obj_before_send = 0
    logger.info('Clear temp folder')
    if os.path.exists(constants.TEMP_FOLDER):
        for root, dirs, files in os.walk(constants.TEMP_FOLDER):
            for f in files:
                os.unlink(os.path.join(root, f))
            for d in dirs:
                shutil.rmtree(os.path.join(root, d))
    logger.info('Process info after dump to DB and clearing')
    trace_monitor()
    logger.info('-' * 50)


def pywhat_analyze(match, cwd):
    pipe_pywhat = subprocess.Popen(['pywhat', '--json', '--include', "Bug Bounty", match],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL,
                                   cwd=cwd)
    while pipe_pywhat.poll() is None:
        time.sleep(0.5)
    result_pywhat = json.loads(pipe_pywhat.communicate()[
                                   0].decode('utf-8').replace('\n', ''))
    res_report = []
    if result_pywhat['Regexes'] is not None:
        for i in result_pywhat['Regexes']['text']:
            res_report.append(
                {'Match': match, 'Name': i['Regex Pattern']['Name']})
    return res_report


def exclude_list_update():
    # add urls to exclude_list.txt, which were have in DB result equal
    # 0 - leaks doesn't found, add to exclude list
    try:
        url_dump_from_db = constants.url_from_DB
        list_to_add = []
        for url_from_db, dump in url_dump_from_db.items():
            if dump == '0':
                list_to_add.append(url_from_db)
        if list_to_add:
            _add_repo_to_exclude(list_to_add)
    except Exception as ex:
        logger.error('Error in exclude_list_update: %s', {ex})


def _add_repo_to_exclude(url):  # TODO: add check existing repo name
    try:
        if isinstance(url, str):
            url = convert_to_regex_pattern(url)
            with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", "r+") as file:
                url_from_exclude_list = [line.rstrip() for line in file]
                if not (url in url_from_exclude_list):
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
        logger.error('Error in adding excludes in exclude_list.txt (_add_repo_to_exclude): %s', ex)

def sanitize_company_name(company_name: str) -> str:
    """Return safe company name for detector usage."""
    if not isinstance(company_name, str):
        return ""
    return (company_name.lower()
            .replace(" ", "-")
            .replace(".", "-")
            .replace("(", "")
            .replace(")", "")
            .replace("/", "-"))


def generate_company_search_terms(company_name: str) -> list[str]:
    """Generate search terms based on company name."""
    if not company_name:
        return []

    terms = []
    company_name = company_name.lower()

    # Full company name
    terms.append(company_name)

    # Split by common delimiters and add meaningful parts
    parts = re.split(r'[\s\-_.,()&]+', company_name)
    for part in parts:
        if len(part) > 2:
            terms.append(part)

    # Abbreviations
    if len(parts) > 1:
        abbr = ''.join([p[0] for p in parts if p])
        if len(abbr) > 1:
            terms.append(abbr)

        stopwords = {'inc', 'ltd', 'llc', 'corp', 'corporation', 'company',
                     'co', 'group', 'gmbh', 'ag', 'sa'}
        significant_parts = [p for p in parts if p and p not in stopwords and len(p) > 2]
        if len(significant_parts) > 1:
            sig_abbr = ''.join([p[0] for p in significant_parts])
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
            flag = False
            for substring in exclusions:
                if re.fullmatch(substring, url):  # check is found url in exclude_list with regexp
                    flag = True
                    break
            if not flag:
                filtered_urls.append(url)
    except Exception as ex:
        logger.error('filter_url_by_repo: %s', ex)
        return []

    return filtered_urls


def is_time_format(input_str):
    if type(input_str) is str:
        try:
            time.strptime(input_str, '%Y-%m-%d')
            return True
        except ValueError:
            return False


def convert_to_regex_pattern(input_string):
    escaped_string = re.escape(input_string)
    escaped_string = escaped_string.replace('/', '\\/')
    regex_pattern = escaped_string
    return regex_pattern


def filter_url_by_db(urls):
    if isinstance(urls, str):
        urls = (urls,)
    filtered_urls = []
    url_dump_from_db = constants.url_from_DB  # list with dict: {url:final_resul}
    if url_dump_from_db == '-':
        return urls

    for url in urls:
        to_add = True

        temp_del = url.split('github.com/')[1]
        if 'gist' in url:
            url = 'https://gist.github.com/' + temp_del.split('/')[0] + '/' + temp_del.split('/')[1]
        else:
            url = 'https://github.com/' + temp_del.split('/')[0] + '/' + temp_del.split('/')[1]
        for url_from_db, value in url_dump_from_db.items():
            if url == url_from_db: # and not value in constants.RESULT_CODES:
                to_add = False
                break

        if to_add:
            filtered_urls.append(url)

    return filtered_urls


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
    pattern = r'\b(?:' + re.escape(dork) + r')[\w.-]*\b'
    meaningful_pattern = re.compile(pattern, re.IGNORECASE)

    # Define a pattern to exclude gibberish or non-alphanumeric contexts around the dork.
    # This pattern looks for the dork surrounded by non-word characters, which might indicate
    # it's part of a hash, a random string, or other non-meaningful context.
    exclude_pattern = re.compile(r'[^a-zA-Z0-9\s]+' + re.escape(dork) + r'[^a-zA-Z0-9\s]+', re.IGNORECASE)

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
        return value.get('totalCount', default)
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


def safe_encode_decode(data, operation: str = 'encode') -> str:
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
        if operation == 'encode':
            # Convert string to proper UTF-8 encoded string
            if isinstance(data, bytes):
                return data.decode('utf-8', errors='replace')
            elif isinstance(data, str):
                # Ensure string is properly encoded
                return data.encode('utf-8', errors='replace').decode('utf-8')
            else:
                return str(data)
        
        elif operation == 'decode':
            # Decode bytes to string using various encodings
            if isinstance(data, str):
                # If already string, just return it
                return data
            elif isinstance(data, bytes):
                # Try different encodings for bytes
                encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
                for encoding in encodings:
                    try:
                        return data.decode(encoding)
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        continue
                # If all encodings fail, use UTF-8 with error replacement
                return data.decode('utf-8', errors='replace')
            else:
                return str(data)
                
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        logger.warning(f'Encoding error in safe_encode_decode: {e}. Using replacement characters.')
        # Use replacement characters for problematic bytes
        if isinstance(data, bytes):
            return data.decode('utf-8', errors='replace')
        else:
            return str(data).encode('utf-8', errors='replace').decode('utf-8')
    except Exception as e:
        logger.error(f'Unexpected error in safe_encode_decode: {e}')
        return str(data) if data else ""
    
def remove_token_from_git_config(repos_dir: str, url: str):
    """Удаляет токен из .git/config файла после клонирования для предотвращения его обнаружения сканерами"""
    git_config_path = Path(repos_dir) / '.git' / 'config'
    if git_config_path.exists():
        try:
            with open(git_config_path, 'r') as f:
                config_content = f.read()
            
            # Удаляем токен из URL в конфиге (заменяем https://TOKEN@github.com на https://github.com)
            # Поддерживаем различные форматы токенов
            cleaned_content = re.sub(
                r'https://[^@\s]+@github\.com',
                'https://github.com',
                config_content
            )
            
            # Также удаляем токены из других Git хостингов если они есть
            cleaned_content = re.sub(
                r'https://[^@\s]+@[^/\s]+/',
                lambda m: 'https://' + m.group(0).split('@')[1],
                cleaned_content
            )
            
            with open(git_config_path, 'w') as f:
                f.write(cleaned_content)
            
            logger.debug(f'Token removed from .git/config for {url}')
        except Exception as exc:
            logger.warning(f'Failed to remove token from .git/config: {exc}')