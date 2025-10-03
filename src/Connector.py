# Standart libs import
import base64
import bz2
import json
import time
import os
import requests
import pymysql
from typing import Any, Dict, Union, Set, Tuple

# Project lib's import
from src import constants
from src.logger import logger
from src import api_client
from src import utils

"""
    Dump scan result to Data Base
    Fields to dump:
    0. ID
    1. repo_url
    2. Risk level
    3. Author
    4. Founded date
    5. Repo creation date
    6. Report
    8. Result of human check (0 - not seen, 1 - leaks aprove, 2 - leak doesn't found
    9. Type of leaks (if it leaks)
    10. Finale result  (0 - leaks doesn't found, add to exclude list
                        1 - leaks found, sent request to block
                        2 - leaks found, was more scanned 
                        3 - leaks found, blocked
                        4 - not set
                        5 - need more scan)
    constants.RESULT_MASS[i][k] - CodeObj, RepoObj, CommitObj or GlistObj
    k = [self.repo_url, self.level(), self.author_name, self.found_time, self.created_date,
        self.updated_date, base64.b64encode(bz2.compress(json.dumps(self.secrets, indent=4).encode('utf-8'))),
        res_human_check, founded_leak, res_check]



"""

requests.urllib3.disable_warnings()
APIClient = api_client.GitSearchAPIClient()

def is_this_need_to_analysis(leak_obj):
    is_this_need_to_analysis_flag = True

    if not getattr(leak_obj, "ready_to_send", False):
        if hasattr(leak_obj, "_check_status"):
            leak_obj._check_status()

    scan_error = getattr(leak_obj, "secrets", {}).get("Scan error") or getattr(
        leak_obj, "secrets", {}
    ).get("Error")
    if scan_error and any(
        keyword in str(scan_error).lower() for keyword in ["oversize", "not analyze"]
    ):
        is_this_need_to_analysis_flag = False

    if scan_error and any(
        keyword in str(scan_error).lower() for keyword in ["failed to clone", "clone"]
    ) and ('gist.github.com' in leak_obj.repo_url or int(leak_obj.stats.repo_stats_leak_stats_table['size']) == 0):
        is_this_need_to_analysis_flag = False

    ai_analysis = getattr(leak_obj, "ai_analysis", {}) or {}
    company_rel = ai_analysis.get("company_relevance", {})
    if not isinstance(company_rel, dict):
        company_rel = {}

    confidence = company_rel.get("confidence", 0.0)

    profitability = getattr(leak_obj, "profitability_scores", {})
    if not isinstance(profitability, dict):
        profitability = {}

    org_rel = profitability.get("org_relevance", 0.0)
    false_pos = profitability.get("false_positive_chance", 0.0)
    true_pos = profitability.get("true_positive_chance", 1.0)

    if org_rel < 0.25 and confidence < 0.25 and not company_rel.get("is_related", True):
        is_this_need_to_analysis_flag = False

    if false_pos > 0.25 and true_pos < 0.35:
        is_this_need_to_analysis_flag = False

    if false_pos == 1.0:
        is_this_need_to_analysis_flag = False
    
    if leak_obj.ai_configence >= 0.7:
        is_this_need_to_analysis_flag = True
    return is_this_need_to_analysis_flag

def dump_to_DB(mode=0, result_deepscan=None):  # mode=0 - add obj to DB, mode=1 - update obj in DB
    res_backup = constants.AutoVivification()
    counter = 1
    dumped_repo_list = []

    # Early exit if there's nothing to do
    if mode == 0 and not constants.RESULT_MASS:
        logger.info("RESULT_MASS is empty, nothing to dump.")
        return
    if mode == 1 and not result_deepscan:
        logger.info("result_deepscan is empty, nothing to update.")
        return

    report_filename = f'{constants.MAIN_FOLDER_PATH}/reports/result_res-{time.strftime("%Y-%m-%d-%H-%M")}.json'

    if constants.url_DB != '-':
        try:
            if mode == 0:
                existing_urls = dump_from_DB(mode=1)
                new_leaks_backup = constants.AutoVivification()
                new_leak_counter = 1

                for scan_key in constants.RESULT_MASS:
                    for scanObj in constants.RESULT_MASS[scan_key].keys():
                        leak_obj = constants.RESULT_MASS[scan_key][scanObj]
                        leak_id_existing = existing_urls.get(leak_obj.repo_url)

                        if not is_this_need_to_analysis(leak_obj):
                            leak_obj.res_check = constants.RESULT_CODE_LEAK_NOT_FOUND
                        if leak_id_existing and leak_id_existing != 0:
                            logger.info(f"Updating existing leak for URL: {leak_obj.repo_url} (Leak ID: {leak_id_existing[1]})")
                            update_existing_leak(leak_id_existing[1], leak_obj)
                            continue
                        if (leak_obj.write_obj()['leak_type'] == 'None'
                                or leak_obj.repo_url in dumped_repo_list):
                            continue
                        
                        logger.info(f"Preparing new leak for URL: {leak_obj.repo_url}")
                        data_leak = {
                            'tname': 'leak', 'dname': 'GitLeak', 'action': 'add',
                            'content': leak_obj.write_obj()
                        }
                        data_row_report = {
                            'tname': 'raw_report', 'dname': 'GitLeak', 'action': 'add',
                            'content': {
                                'leak_id': new_leak_counter, 'report_name': leak_obj.repo_url,
                                'raw_data': str(base64.b64encode(bz2.compress(json.dumps(leak_obj.secrets, indent=4).encode('utf-8'))))[2:-1],
                                'ai_report': str(base64.b64encode(bz2.compress(json.dumps(leak_obj.ai_analysis, indent=4).encode('utf-8'))))[2:-1]
                            }
                        }
                        leak_stats_table, accounts_table, commiters_table = leak_obj.get_stats()
                        new_leaks_backup[new_leak_counter] = [data_leak, data_row_report, leak_stats_table, accounts_table, commiters_table]
                        dumped_repo_list.append(leak_obj.repo_url)
                        new_leak_counter += 1
                
                if new_leaks_backup:
                    with open(report_filename, 'w') as file:
                        json.dump({'scan': new_leaks_backup}, file, ensure_ascii=False, indent=8)
                    logger.info(f'New leaks report created: {report_filename}')
                    dump_to_DB_req(report_filename)

            else:  # mode == 1
                for url in result_deepscan.keys():
                    time.sleep(1)
                    data_to_request = {
                        'tname': 'leak', 'dname': 'GitLeak', 'action': 'upd',
                        'content': {'id': result_deepscan[url][0], 'result': '3'}
                    }
                    data_row_report = {
                        'tname': 'raw_report', 'dname': 'GitLeak', 'action': 'add',
                        'content': {
                            'leak_id': result_deepscan[url][0], 'report_name': url,
                            'raw_data': str(base64.b64encode(bz2.compress(json.dumps(result_deepscan[url][1], indent=4).encode('utf-8'))))[2:-1],
                            'ai_report': str(base64.b64encode(bz2.compress(json.dumps(result_deepscan[url][2], indent=4).encode('utf-8'))))[2:-1]
                        }
                    }
                    res_backup[counter] = [{'DeepScan': 'DeepScan'}, data_row_report]
                    counter += 1
                
                if res_backup:
                    with open(report_filename, 'w') as file:
                        json.dump({'scan': res_backup}, file, ensure_ascii=False, indent=8)
                    logger.info(f'Deep scan report created: {report_filename}')
                    update_leaks_from_report(report_filename)

            logger.info("Database operations completed successfully.")

        except Exception as e:
            logger.error(f"Database operations failed: {e}")
            # Fallback to file-only dump on transaction failure
            dump_to_file_only(mode, result_deepscan, report_filename)
    else:
        # No DB configured, just write to file
        dump_to_file_only(mode, result_deepscan, report_filename)


def dump_to_file_only(mode, result_deepscan, report_filename):
    """Dumps scan results to a JSON file without DB interaction."""
    logger.info("Dumping results to file only (DB not configured or connection failed).")
    res_backup = constants.AutoVivification()
    counter = 1

    if mode == 0:
        for scan_key, scan_dict in constants.RESULT_MASS.items():
            for scanObj, leak_obj in scan_dict.items():
                data_leak = {'tname': 'leak', 'content': leak_obj.write_obj()}
                data_row_report = {'tname': 'raw_report', 'content': {'raw_data': '...', 'ai_report': '...'}}
                leak_stats_table, accounts_table, commiters_table = leak_obj.get_stats()
                res_backup[counter] = [data_leak, data_row_report, leak_stats_table, accounts_table, commiters_table]
                counter += 1
    elif mode == 1:
        for url, data in result_deepscan.items():
            res_backup[counter] = [{'DeepScan': 'DeepScan'}, {'content': {'leak_id': data[0], 'report_name': url}}]
            counter += 1

    if res_backup:
        with open(report_filename, 'w') as file:
            json.dump({'scan': res_backup}, file, ensure_ascii=False, indent=8)
        logger.info(f'Result report (file only): {report_filename}')


def connect_to_database():
    try:
        conn = pymysql.connect(
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', 'changeme'),
            host=constants.url_DB,
            port=3306,
            database="Gitsearch"
        )
        cursor = conn.cursor()
        return conn, cursor
    except pymysql.Error as e:
        logger.error(f"Error connecting to MariaDB Platform: {e}")
        return None, None


def leak_stats_prepare(leak_stats_table: dict, actual_leak_id: int) -> dict:
    leak_stats_table['leak_id'] = actual_leak_id
    # Валидация и преобразование числовых полей
    int_fields = [
        'size', 'stargazers_count', 'forks_count', 'open_issues_count',
        'subscribers_count', 'topics', 'contributors_count',
        'commits_count', 'commiters_count', 'ai_result'
    ]
    
    for field in int_fields:
        value = leak_stats_table.get(field)
        if value == '' or value is None:
            leak_stats_table[field] = 0
        elif isinstance(value, str) and value.isdigit():
            leak_stats_table[field] = int(value)
        elif not isinstance(value, int):
            leak_stats_table[field] = 0  # Значение по умолчанию
    
    # Обработка булевых полей
    bool_fields = [
        'has_issues', 'has_projects', 'has_downloads',
        'has_wiki', 'has_pages'
    ]
    
    for field in bool_fields:
        value = leak_stats_table.get(field)
        if isinstance(value, str):
            leak_stats_table[field] = 1 if value.lower() in ['true', '1', 'yes'] else 0
        elif isinstance(value, bool):
            leak_stats_table[field] = 1 if value else 0
        else:
            leak_stats_table[field] = 0  # Значение по умолчанию
    
    # Гарантируем наличие description
    leak_stats_table.setdefault('description', '')
    return leak_stats_table 


def decode_legacy_data(encoded_data):
    if not encoded_data:
        return {}

    try:
        # Декодируем base64
        decoded_bytes = base64.b64decode(encoded_data)
    except Exception as ex:
        return {}
    try:
        decompressed = bz2.decompress(decoded_bytes)
        json_str = decompressed.decode('utf-8')
        return json.loads(json_str)
    except Exception as bz2_error:
        logger.debug(f"BZ2 decompression failed, trying raw decode: {bz2_error}")
        
        # Если не получилось, пробуем как новый формат (без сжатия)
        try:
            json_str = decoded_bytes.decode('utf-8')
            return json.loads(json_str)
        except Exception as json_error:
            logger.error(f"JSON decoding failed: {json_error}")
        return {}


def dump_target_from_DB():
    logger.info(f'Dumping target words from DB...')
    dork_dict = {}
    
    dumped_data = APIClient.get_data('dorks', {}, limit=100, offset=0)
    for i in dumped_data:
        dork_dict[i['company_id']] = base64.b64decode(i['dork']).decode('utf-8').split(', ')

    return dork_dict


def dump_from_DB(mode=0):
    # mode=0 - return [..{'url':'result'}..]
    # mode=1 - return [..{'url':['result', 'id', 'leak_id']}..]
    checked_repos = {}
    logger.info(f'Dumping data from DB...')
    
    dumped_data = APIClient.get_data('leak', {}, limit=500, offset=0)
    if mode == 1:
        for i in dumped_data:
            checked_repos[i['url']] = [i['result'], i['id']]
    else:
        for i in dumped_data:
            checked_repos[i['url']] = i['result']

    return checked_repos



def dump_to_DB_req(filename, conn=None, cursor=None):  # mode=0 - add obj to DB, mode=1 - add only report in DB
    with open(filename, 'r') as file:
        backup_rep = json.load(file)

    for i in backup_rep['scan'].keys():
        content = backup_rep['scan'][i][0]['content']
        
        # Проверяем существование компании для leak записи
        company_id = content.get('company_id', 0)
        if company_id and not company_exists(company_id):
            logger.warning(f"Company with id {company_id} does not exist for leak {content['url']}, setting to 0")
            content['company_id'] = 0
        
        # Добавляем leak через API клиент
        leak_data = {
            'url': content['url'],
            'level': content['level'],
            'author_info': content['author_info'],
            'found_at': content['found_at'],
            'created_at': content['created_at'],
            'updated_at': content['updated_at'],
            'approval': content['approval'],
            'leak_type': content['leak_type'],
            'result': content['result'],
            'company_id': content['company_id']
        }
        leak_id = APIClient.add_data('leak', leak_data)
        
        if not leak_id:
            logger.error(f"Failed to add leak for {content['url']}")
            continue

        # Добавляем raw_report
        data_row_report = backup_rep['scan'][i][1]['content']
        raw_report_data = {
            'leak_id': leak_id,
            'report_name': data_row_report['report_name'],
            'raw_data': data_row_report['raw_data'],
            'ai_report': data_row_report['ai_report']
        }
        APIClient.add_data('raw_report', raw_report_data)

        # Добавляем leak_stats
        leak_stats_table = backup_rep['scan'][i][2]
        leak_stats_data = {
            'leak_id': leak_id,
            'size': leak_stats_table['size'],
            'stargazers_count': leak_stats_table['stargazers_count'],
            'has_issues': leak_stats_table['has_issues'],
            'has_projects': leak_stats_table['has_projects'],
            'has_downloads': leak_stats_table['has_downloads'],
            'has_wiki': leak_stats_table['has_wiki'],
            'has_pages': leak_stats_table['has_pages'],
            'forks_count': leak_stats_table['forks_count'],
            'open_issues_count': leak_stats_table['open_issues_count'],
            'subscribers_count': leak_stats_table['subscribers_count'],
            'topics': leak_stats_table['topics'],
            'contributors_count': leak_stats_table['contributors_count'],
            'commits_count': leak_stats_table['commits_count'],
            'commiters_count': leak_stats_table['commiters_count'],
            'ai_result': leak_stats_table['ai_result'],
            'description': leak_stats_table.get('description', '')
        }
        APIClient.add_data('leak_stats', leak_stats_data)

        # Обрабатываем аккаунты
        accounts_table = backup_rep['scan'][i][3]
        accounts_from_DB = dump_account_from_DB()
        accounts_ids = []
        for account in accounts_table:
            if account['account'] not in accounts_from_DB:
                # Проверяем существование компании перед вставкой
                company_id = account.get('related_company_id', 0)
                if company_id and not company_exists(company_id):
                    logger.warning(f"Company with id {company_id} does not exist, setting to 0 for account {account['account']}")
                    company_id = 0
                
                account_data = {
                    'account': account['account'],
                    'need_monitor': account['need_monitor'],
                    'related_company_id': company_id
                }
                account_id = APIClient.add_data('accounts', account_data)
                if account_id:
                    accounts_ids.append(account_id)

        # Связываем аккаунты с утечкой
        for account_id in accounts_ids:
            relation_data = {
                'leak_id': leak_id,
                'account_id': account_id
            }
            APIClient.add_data('related_accounts_leaks', relation_data)
        
        # Обрабатываем коммитеров
        commiters_table = backup_rep['scan'][i][4]
        for commiter in commiters_table:
            # Проверяем существование связанного аккаунта перед вставкой
            related_account_id = commiter.get('related_account_id', 0)
            if related_account_id and not account_exists(related_account_id):
                logger.warning(f"Account with id {related_account_id} does not exist, setting to 0 for commiter {commiter['commiter_name']}")
                related_account_id = 0
            
            commiter_data = {
                'leak_id': leak_id,
                'commiter_name': commiter['commiter_name'],
                'commiter_email': commiter['commiter_email'],
                'need_monitor': commiter['need_monitor'],
                'related_account_id': related_account_id
            }
            APIClient.add_data('commiters', commiter_data)

def account_exists(account_id: int) -> bool:
    """Проверяет существование аккаунта с указанным ID в базе данных."""
    accounts = APIClient.get_data('accounts', {'id': account_id}, limit=1)
    return len(accounts) > 0


def company_exists(company_id: int) -> bool:
    """Проверяет существование компании с указанным ID в базе данных."""
    companies = APIClient.get_data('companies', {'id': company_id}, limit=1)
    return len(companies) > 0

def get_compnay_id(leak_id: int) -> int:
    logger.info(f'Dumping company_id from DB...')
    leak_info = APIClient.get_data('leak', {'id': leak_id})
    leak_info = leak_info[0] if leak_info else {}
    company_id = leak_info.get('company_id', 0)    
    return int(company_id)

def get_company_name(company_id: int) -> str:
    """Return company name for given id or empty string on failure."""
    logger.info(f'Getting company name for ID {company_id}...')
    company_info = APIClient.get_data('companies', {'id': company_id})
    if company_info:
        return company_info[0].get('company_name', '')
    return ""

def update_result_filed_in_DB():
    """Update result field in DB based on URL accessibility check."""
    data_from_DB = dump_from_DB(mode=1)

    for url in data_from_DB.keys():
        leak_data = data_from_DB[url]
        result_code = leak_data[0]
        leak_id = leak_data[1]
        
        try:
            if int(result_code) == constants.RESULT_CODE_STILL_ACCESS:
                # Check if URL is still accessible
                response = requests.get(url, headers={'Authorization': f'Token {constants.token_list[0]}'}, timeout=10)
                if not response.ok:
                    APIClient.upd_data('leak', {'id': leak_id, 'result': '3'})
                    logger.info(f'Updated leak {leak_id} from result 1 to 3 (blocked)')

            elif int(result_code) == constants.RESULT_CODE_TO_DEEPSCAN:
                # Check if URL is still accessible  
                response = requests.get(url, headers={'Authorization': f'Token {constants.token_list[0]}'}, timeout=10)
                if not response.ok:
                    APIClient.upd_data('leak', {'id': leak_id, 'result': '2'})
                    logger.info(f'Updated leak {leak_id} from result 5 to 2')
        except Exception as e:
            logger.error(f"Error checking URL {url}: {e}")
            continue

def dump_account_from_DB():
    logger.info(f'Dumping accounts from DB...')
    dumped_data = APIClient.get_data('accounts', {}, limit=100, offset=0)
    dumped_accounts = []
    for account in dumped_data:
        dumped_accounts.append(account['account'])

    return dumped_accounts


def dump_row_data_from_DB(target_leak_id):
    logger.info(f'Dumping leak {target_leak_id} from DB...')
    dumped_data = APIClient.get_data('raw_report', {'leak_id': target_leak_id})
    if not dumped_data:
        return None
    try:
        raw_data = dumped_data[0].get('raw_data')
        if raw_data:
            return json.loads(bz2.decompress(base64.b64decode(raw_data)))
        return None
    except (json.JSONDecodeError, Exception, base64.binascii.Error) as e:
        logger.error(f"Data decoding/decompression error for leak_id {target_leak_id}: {e}")
        return None


def dump_ai_report_from_DB(target_leak_id):
    logger.info(f'Dumping AI report for leak {target_leak_id} from DB...')
    dumped_data = APIClient.get_data('raw_report', {'leak_id': target_leak_id})
    if not dumped_data:
        return None
    try:
        ai_report = dumped_data[0].get('ai_report')
        if ai_report:
            return json.loads(bz2.decompress(base64.b64decode(ai_report)))
        return None
    except (json.JSONDecodeError, Exception, base64.binascii.Error) as e:
        logger.error(f"AI report decoding/decompression error for leak_id {target_leak_id}: {e}")
        return None

def get_leak_id_by_url(url: str):
    """Get leak ID by URL."""
    leaks = APIClient.get_data('leak', {'url': url}, limit=1)
    return leaks[0]['id'] if leaks else None


def load_existing_leak_urls() -> dict:
    """Return mapping of URL to leak id."""
    leaks = APIClient.get_data('leak', {}, limit=500, offset=0)
    return {leak['url']: leak['id'] for leak in leaks}


def get_commiters_from_DB(leak_id: int):
    """Get commiters for a specific leak."""
    commiters = APIClient.get_data('commiters', {'leak_id': leak_id})
    return [(c['commiter_name'], c['commiter_email']) for c in commiters]


def get_accounts_from_DB(leak_id: int):
    """Get accounts linked to a specific leak."""
    related = APIClient.get_data('related_accounts_leaks', {'leak_id': leak_id})
    if not related:
        return []
    
    account_ids = [r['account_id'] for r in related]
    accounts = []
    for acc_id in account_ids:
        acc_data = APIClient.get_data('accounts', {'id': acc_id})
        if acc_data:
            accounts.append(acc_data[0]['account'])
    
    return accounts


def update_existing_leak(leak_id: int, leak_obj):
    """
    Update existing leak with improved encoding error handling.
    Handles 'utf-8' codec decode errors and other encoding issues.
    """
    try:
        logger.info(f'Начало обновления утечки ID: {leak_id}')
        
        # Получаем текущую запись утечки из БД
        existing_leak = APIClient.get_data('leak', {'id': leak_id})
        if not existing_leak:
            logger.warning(f'Утечка ID {leak_id} не найдена в БД. Пропуск обновления.')
            return
        if existing_leak[0].get('result', '4') in ['0', '1', '2', '3']:
            logger.warning(f'Утечка ID {leak_id} уже обработана. Пропуск обновления.')
            return
        
        # Сравниваем updated_at and report с улучшенной обработкой ошибок
        try:
            raw_report_data = APIClient.get_data('raw_report', {'leak_id': leak_id})
            raw_report = raw_report_data[0] if raw_report_data else {}
            existing_updated_at = existing_leak[0].get('updated_at', '')
            new_updated_at = leak_obj.write_obj().get('updated_at', '')
            
        except UnicodeDecodeError as decode_error:
            logger.error(f'Unicode decode error in update_existing_leak: {decode_error}. Attempting recovery.')
            # Try to recover with safe encoding
            try:
                existing_updated_at = utils.safe_encode_decode(existing_leak[0].get('updated_at', ''), 'decode')
                new_updated_at = utils.safe_encode_decode(leak_obj.write_obj().get('updated_at', ''), 'decode')
            except Exception as recovery_error:
                logger.error(f'Failed to recover from encoding error: {recovery_error}')
                existing_updated_at = ''
                new_updated_at = ''
        except Exception as ex:
            logger.error(f'Error in update_existing_leak in report compare: {ex}')
            return
    
        old_raw_id = raw_report.get('id', '')
        
        # Safe decoding of legacy data with encoding error handling
        try:
            old_raw = decode_legacy_data(raw_report.get('raw_data', ''))
        except UnicodeDecodeError as decode_error:
            logger.warning(f'Unicode decode error in legacy data: {decode_error}. Using safe decoding.')
            old_raw = {}
        
        # Safe decoding of AI report with encoding error handling  
        try:
            ai_report_data = raw_report.get('ai_report', '') or '{}'
            old_ai = json.loads(base64.b64decode(ai_report_data.encode('utf-8')).decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError, Exception) as ai_error:
            logger.warning(f'Error decoding AI report: {ai_error}. Using empty dict.')
            old_ai = {}
          
        try:
            if existing_updated_at == new_updated_at and leak_obj.secrets == old_raw:
                logger.info(f'Утечка ID {leak_id} не изменилась (updated_at и отчет совпадают). Пропуск обновления.')
                return
            
            leak_data = leak_obj.write_obj()
            accounts_table = leak_obj.stats.contributors_stats_accounts_table
        except Exception as ex:
            logger.error(f'Error in update_existing_leak in s report compare: {ex}')
            
        # Обновление аккаунтов
        if hasattr(leak_obj.stats, 'contributors_stats_accounts_table'):
            _update_accounts(leak_id, leak_obj.stats.contributors_stats_accounts_table, leak_obj)
        
        # Обновление отчетов с улучшенной обработкой кодировки
        try:
            merged_raw = merge_reports(old_raw, leak_obj.secrets)
            merged_ai = merge_reports(old_ai, leak_obj.ai_analysis)
            
            # Safe encoding with error handling
            try:
                enc_raw = base64.b64encode(json.dumps(merged_raw, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                enc_ai = base64.b64encode(json.dumps(merged_ai, ensure_ascii=False).encode('utf-8')).decode('utf-8')
            except UnicodeEncodeError as encode_error:
                logger.warning(f'Unicode encode error in reports: {encode_error}. Using safe encoding.')
                # Use safe encoding with replacement characters
                enc_raw = base64.b64encode(json.dumps(merged_raw, ensure_ascii=True).encode('utf-8', errors='replace')).decode('utf-8')
                enc_ai = base64.b64encode(json.dumps(merged_ai, ensure_ascii=True).encode('utf-8', errors='replace')).decode('utf-8')

            if raw_report.get('raw_data', '') != enc_raw:
                if raw_report_data:
                    APIClient.upd_data('raw_report', {
                        'id': old_raw_id,
                        'leak_id': leak_id,
                        'report_name': utils.safe_encode_decode(leak_obj.repo_url, 'encode'),
                        'raw_data': enc_raw,
                        'ai_report': enc_ai
                    })
                else:
                    APIClient.add_data('raw_report', {
                        'leak_id': leak_id,
                        'report_name': leak_obj.repo_url,
                        'raw_data': enc_raw,
                        'ai_report': enc_ai
                    })
        except Exception as ex:
            logger.error(f'AI report not utf-8: {merged_ai}')
            enc_ai = old_ai
        # Обновление статистики
        leak_stats_table, accounts_table, commiters_table = leak_obj.get_stats()
        try:
            commiters_count = len(set(
                (c.get('commiter_name'), c.get('commiter_email'))
                for c in leak_obj.stats.commits_stats_commiters_table
            ))
            
            related_accounts = APIClient.get_data('related_accounts_leaks', {'leak_id': leak_id}) or []
            accounts_in_db = {acc['id']: acc['account'] for acc in (APIClient.get_data('accounts') or [])}
            existing_accounts = {
                accounts_in_db[r['account_id']] 
                for r in related_accounts 
                if r['account_id'] in accounts_in_db
            }
            
            contributors_count = max(
                leak_obj.stats.repo_stats_leak_stats_table.get('contributors_count', 0),
                len(existing_accounts | {a['account'] for a in accounts_table})
            )

            leak_stats_data = APIClient.get_data('leak_stats', {'leak_id': leak_id})
            leak_stats_data = leak_stats_data[0] if leak_stats_data else {}
            old_leak_stats_id = leak_stats_data.get('id', '')
                
            if str(contributors_count) != str(leak_stats_data.get('contributors_count', 0)) or str(commiters_count) != str(leak_stats_data.get('commiters_count', 0)):   
                
                if old_leak_stats_id != '':
                    APIClient.upd_data('leak_stats', {
                        'id': old_leak_stats_id,
                        'leak_id': leak_id,
                        'contributors_count': contributors_count,
                        'commiters_count': commiters_count
                    })
                else:
                    leak_stats_table = leak_stats_prepare(leak_stats_table, leak_id)
                    APIClient.add_data('leak_stats', leak_stats_table)
        except Exception as ex:
            logger.error(f'Error in update_existing_leak in statistic update: {ex}')
            
        try:
            
            # Обновление основных данных
            APIClient.upd_data('leak', {
                'id': leak_id,
                'level': leak_data['level'],
                'author_info': leak_data['author_info'],
                'leak_type': leak_data['leak_type'],
                'result': leak_data['result'],
                'updated_at': leak_data['updated_at']
            })
        except Exception as ex:
            logger.error(f'Error in update_existing_leak in leak info update: {ex}')
            
            
        logger.info(f'Успешно обновлена утечка ID: {leak_id}')
        
    except Exception as e:
        logger.error(f"Ошибка при обновлении утечки {leak_id}: {e}")
        return

def _update_accounts(leak_id: int, accounts_table: list, leak_obj) -> None:
    """Обновляет информацию о связанных аккаунтах."""
    try:
        # Получаем все связанные аккаунты для утечки
        related_accounts = APIClient.get_data('related_accounts_leaks', {'leak_id': leak_id}) or []
        existing_account_ids = {ra['account_id'] for ra in related_accounts}
        
        for account in accounts_table:
            acc_name = account['account']
            
            # Ищем существующий аккаунт в БД
            existing_accounts = APIClient.get_data('accounts', {'account': acc_name}) or []
            
            if existing_accounts:
                acc_id = existing_accounts[0]['id']
            else:
                # Создаем новый аккаунт
                acc_data = {
                    'account': acc_name,
                    'need_monitor': account.get('need_monitor', 0),
                    'company_id': account.get('company_id', 0)
                }
                acc_id = APIClient.add_data('accounts', acc_data)
                if not acc_id:
                    logger.error(f"Ошибка создания аккаунта: {acc_name}")
                    continue
            
            # Связываем аккаунт с утечкой если нужно
            if acc_id not in existing_account_ids:
                relation_data = {
                    'leak_id': leak_id,
                    'account_id': acc_id
                }
                relation_response = APIClient.add_data('related_accounts_leaks', relation_data)
                if not relation_response:
                    logger.error(f"Ошибка создания связи аккаунта {acc_id} с утечкой {leak_id}")
    
    except Exception as e:
        logger.error(f"Ошибка в _update_accounts: {e}")
        return

def update_leaks_from_report(filename: str):
    with open(filename, 'r') as file:
        backup_rep = json.load(file)

    for i in backup_rep['scan'].keys():
        item = backup_rep['scan'][i]
        if 'DeepScan' in item[0]:
            report_content = item[1]['content']
            leak_id = report_content['leak_id']

            # Обновляем leak
            APIClient.upd_data('leak', {
                'id': leak_id,
                'result': '3'
            })

            enc_raw = report_content['raw_data']
            enc_ai = report_content['ai_report']

            # Проверяем наличие raw_report
            raw_report_data = APIClient.get_data('raw_report', {'leak_id': leak_id})
            raw_report = raw_report_data[0] if raw_report_data else {}
            old_raw_report_id = raw_report.get('id', '')
            if enc_raw != raw_report.get('raw_data', ''):
                if raw_report:
                    APIClient.upd_data('raw_report', {
                        'id': old_raw_report_id,
                        'leak_id': leak_id,
                        'raw_data': enc_raw,
                        'ai_report': enc_ai
                    })
                else:
                    APIClient.add_data('raw_report', {
                        'leak_id': leak_id,
                        'report_name': report_content['report_name'],
                        'raw_data': enc_raw,
                        'ai_report': enc_ai
                    })
                
def merge_reports(
    old: Union[Dict[str, Any], constants.AutoVivification],
    new: Union[Dict[str, Any], constants.AutoVivification]
) -> Union[Dict[str, Any], constants.AutoVivification]:
    """
    Merge two report dictionaries (or constants.AutoVivification instances).
    
    Preserves existing data in 'old' and merges new data from 'new'.
    """

    if not isinstance(old, (dict, constants.AutoVivification)) or not isinstance(new, (dict, constants.AutoVivification)):
        return old if old else new

    # Определяем тип результирующего объекта (сохраняем тип `old`)
    result_class = type(old)
    if not isinstance(old, type(new)):
        # Если типы разные, можно выбрать более общий (dict), или оставить тип `old`
        pass  # можно добавить логику выбора, если нужно

    merge_keys = {'gitsecrets', 'trufflehog', 'grepscan', 'deepsecrets', 'gitleaks'}

    for key in merge_keys:
        if key in new:
            if key not in old or not isinstance(old[key], (dict, constants.AutoVivification)):
                old[key] = result_class() if isinstance(old, constants.AutoVivification) else {}

            # Рекурсивное объединение внутренних структур
            if isinstance(new[key], (dict, constants.AutoVivification)):
                # Если значение тоже словарь, рекурсивно мерджим
                if isinstance(old[key], (dict, constants.AutoVivification)):
                    merge_reports(old[key], new[key])
                else:
                    old[key] = new[key]  # заменяем, если старое не словарь
            elif new[key]:  # простые значения — перезаписываем, если не пусто
                old[key] = new[key]

    # Перезаписываем message, если есть
    if 'message' in new and new['message']:
        old['message'] = new['message']

    # Полная замена ai_report, если новое не пустое
    if 'ai_report' in new and new['ai_report']:
        old['ai_report'] = new['ai_report']
