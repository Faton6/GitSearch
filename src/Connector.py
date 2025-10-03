# Standart libs import
import os
import time
import requests
import json
import base64
import bz2
from src.logger import logger
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
    if mode == 0:
        existing_urls = dump_from_DB(mode=1)
        for scan_key in constants.RESULT_MASS.keys():
            for scanObj in constants.RESULT_MASS[scan_key].keys():
                leak_obj = constants.RESULT_MASS[scan_key][scanObj]
                leak_id_existing = existing_urls.get(leak_obj.repo_url)
                
                # Определяем, требуется ли анализ и устанавливаем статус ДО обновления
                if not is_this_need_to_analysis(leak_obj):
                    leak_obj.res_check = constants.RESULT_CODE_LEAK_NOT_FOUND
                    logger.info(f"Leak marked as false positive (status 0): {leak_obj.repo_url}")
                
                if leak_id_existing and leak_id_existing != 0:
                    logger.info(f"Updating existing leak for URL: {leak_obj.repo_url} (Leak ID: {leak_id_existing[1]})")
                    update_existing_leak(leak_id_existing[1], leak_obj)
                    continue
                # Вызываем write_obj() один раз для использования в проверках и создании данных
                leak_write_data = leak_obj.write_obj()
                
                if (leak_write_data['leak_type'] == 'None'
                        or leak_obj.repo_url in dumped_repo_list):
                    continue
                
                # Логируем статус для отладки
                leak_status = leak_write_data.get('result', 4)
                if leak_status == 0:
                    logger.info(f"Adding new leak with status 0 (false positive): {leak_obj.repo_url}")
                elif leak_status == 5:
                    logger.info(f"Adding new leak with status 5 (need more scan): {leak_obj.repo_url}")
                else:
                    logger.info(f"Adding new leak with status {leak_status}: {leak_obj.repo_url}")
                
                data_leak = {
                    'tname': 'leak',
                    'dname': 'GitSearch',
                    'action': 'add',
                    'content': leak_write_data
                }
                data_raw_report = {
                    'tname': 'raw_report',
                    'dname': 'GitSearch',
                    'action': 'add',
                    'content': {
                        'leak_id': counter,
                        'report_name': leak_obj.repo_url,
                        'raw_data': base64.b64encode(
                            bz2.compress(json.dumps(leak_obj.secrets, indent=4).encode('utf-8'))
                        ),
                        'ai_report': base64.b64encode(
                            bz2.compress(json.dumps(leak_obj.ai_analysis, indent=4).encode('utf-8'))
                        )
                    }
                }
                leak_stats_table, accounts_table, commiters_table = leak_obj.get_stats()

                dumped_repo_list.append(leak_obj.repo_url)
                res_backup[counter] = [data_leak, data_raw_report, leak_stats_table, accounts_table, commiters_table]
                counter += 1
    elif mode == 1:
        for url in result_deepscan.keys():
            time.sleep(1)
            data_to_request = {
                'tname': 'leak',
                'dname': 'GitSearch',
                'action': 'upd',
                'content': {
                    'id': result_deepscan[url][0],
                    'result': '3'
                }
            }
            data_raw_report = {
                'tname': 'raw_report',
                'dname': 'GitSearch',
                'action': 'add',
                'content': {
                    'leak_id': result_deepscan[url][0],
                    'report_name': url,
                    'raw_data': base64.b64encode(
                        bz2.compress(json.dumps(result_deepscan[url][1], indent=4).encode('utf-8'))
                    )
                }
            }

            res_backup[counter] = [{'DeepScan': 'DeepScan'}, data_raw_report]
            counter += 1

    report_filename = f'{constants.MAIN_FOLDER_PATH}/reports/result_res-{time.strftime("%Y-%m-%d-%H-%M")}.json'
    with open(report_filename, 'w') as file:
        json.dump({'scan': res_backup}, file, ensure_ascii=False, indent=8)
    logger.info(
        f'Result report: {constants.MAIN_FOLDER_PATH}/reports/result_res-{time.strftime("%Y-%m-%d-%H-%M")}.json')
    if constants.url_DB != '-':
        dump_to_DB_req(report_filename, mode=mode)


def dump_target_from_DB():
    logger.info(f'Dumping target words from DB...')
    dork_dict = {}

    dumped_data = APIClient.get_data('dork', {}, limit=100, offset=0)
    for i in dumped_data:
        dork_value = i['dork']
        # Если dork уже bytes, декодируем напрямую
        if isinstance(dork_value, bytes):
            dork_dict[i['company_id']] = base64.b64decode(dork_value).decode('utf-8').split(', ')
        else:
            # Если строка, сначала кодируем в bytes
            dork_dict[i['company_id']] = base64.b64decode(dork_value.encode('utf-8')).decode('utf-8').split(', ')

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


def dump_to_DB_req(filename, mode=0):
    with open(filename, 'r') as file:
        backup_rep = json.load(file)
    
    for i in backup_rep['scan'].keys():
        if mode == 0:
            # 1. Обработка утечки
            leak_response = APIClient._make_request(backup_rep['scan'][i][0])
            logger.info(f'\nResponse dump data to DB.leak: {leak_response}')
            
            # Проверка и извлечение ID утечки
            if not leak_response.get('auth') or not leak_response.get('content') or 'id' not in leak_response['content']:
                logger.error(f"Invalid leak response: {leak_response}")
                continue
                
            actual_leak_id = int(leak_response['content']['id'])
            
            # 2. Обработка raw_report
            data_raw_report = backup_rep['scan'][i][1]
            data_raw_report['content']['leak_id'] = actual_leak_id
            
            raw_report_response = APIClient._make_request(data_raw_report)

            # 3. Обработка leak_stats
            leak_stats_table = leak_stats_prepare(backup_rep['scan'][i][2], actual_leak_id)
            
            # Отправка исправленных данных
            leak_stat_response = APIClient.add_data('leak_stats', leak_stats_table)
            if leak_stat_response is None or not isinstance(leak_stat_response, (int, str)):
                logger.error(f'Error in leak_stat add request: {leak_stat_response}')

            # 4. Обработка аккаунтов
            accounts_table = backup_rep['scan'][i][3]
            account_ids = []
            
            for account in accounts_table:
                # Исправление возможных проблем с типами данных
                account.setdefault('company_id', 0)
                
                # Проверка существования аккаунта
                existing_accounts = APIClient.get_data('accounts', {'account': account['account']})
                
                if existing_accounts:
                    account_id = existing_accounts[0]['id']
                else:
                    # Создание нового аккаунта
                    account_id = APIClient.add_data('accounts', {
                        'account': account['account'],
                        'need_monitor': account.get('need_monitor', 0),
                        'company_id': account.get('company_id', 0)
                    })
                    
                    # Обработка ответа
                    if account_id is None:
                        logger.error(f'Error creating account: {account_id}')
                        continue
                    elif isinstance(account_id, dict) and 'id' in account_id.get('content', {}):
                        account_id = account_id['content']['id']
                
                if account_id:
                    account_ids.append(account_id)
                
                # Связь аккаунта с утечкой
                if account_id:
                    relation_data = {
                        'leak_id': actual_leak_id,
                        'account_id': account_id
                    }
                    relation_response = APIClient.add_data('related_accounts_leaks', relation_data)
                    if relation_response is None:
                        logger.error(f'Error creating account-leak relation: {relation_response}')

        elif mode == 1:
            # Режим обновления (deepscan)
            raw_report_response = APIClient._make_request(backup_rep['scan'][i][1])
            logger.info(f'Response dump data to DB.raw_report: {raw_report_response}')

    logger.info(f'\nEnd dump data to DB\n---------------------------------------')


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

def dump_account_from_DB():
    logger.info(f'Dumping accounts from DB...')
    dumped_data = []
    
    dumped_data = APIClient.get_data('accounts', {}, limit=100, offset=0)
    dumped_accounts = []
    for account in dumped_data:
        dumped_accounts.append(account['account'])

    return dumped_accounts


def dump_raw_data_from_DB(leak_id):
    logger.info(f'Dumping leak {leak_id} from DB...')
    dumped_data = APIClient.get_data('raw_report', {'leak_id': leak_id}, limit=100, offset=0)['raw_data']
    dumped_data = str(json.loads(base64.b64decode(dumped_data)))
    return dumped_data


def update_result_filed_in_DB():
    data_from_DB = dump_from_DB(mode=1)

    for i in data_from_DB.keys():
        if int(data_from_DB[i][0]) == constants.RESULT_CODE_STILL_ACCESS:
            if not requests.get(data_from_DB[i], headers={'Authorization': f'Token {constants.token_list[0]}'}).ok:
                leak_id = APIClient.upd_data('leak', {'id': data_from_DB[i][1], 'result': '3'})

        if int(data_from_DB[i][0]) == constants.RESULT_CODE_TO_DEEPSCAN:
            if not requests.get(data_from_DB[i], headers={'Authorization': f'Token {constants.token_list[0]}'}).ok:
                leak_id = APIClient.upd_data('leak', {'id': data_from_DB[i][1], 'result': '2'})
                logger.info('Was change result')

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
        
        current_status = existing_leak[0].get('result', '4')
        new_status = str(leak_obj.res_check)
        
        # Проверяем, нужно ли обновлять статус
        # Статусы 0 (false positive) и 5 (need more scan) должны ВСЕГДА обновляться
        if current_status in ['1', '2', '3']:
            logger.warning(f'Утечка ID {leak_id} уже обработана со статусом {current_status}. Пропуск обновления.')
            return
        
        # Если статус изменился на 0 (false positive), обновляем его в БД
        if new_status == '0' and current_status != '0':
            logger.info(f'Обновление статуса утечки ID {leak_id}: {current_status} -> 0 (false positive)')
            try:
                APIClient.upd_data('leak', {'id': leak_id, 'result': '0'})
                logger.info(f'Статус утечки ID {leak_id} успешно обновлен на 0')
            except Exception as status_update_error:
                logger.error(f'Ошибка обновления статуса утечки ID {leak_id}: {status_update_error}')
        
        # Если статус изменился на 5 (need more scan), обновляем его в БД
        if new_status == '5' and current_status != '5':
            logger.info(f'Обновление статуса утечки ID {leak_id}: {current_status} -> 5 (need more scan)')
            try:
                APIClient.upd_data('leak', {'id': leak_id, 'result': '5'})
                logger.info(f'Статус утечки ID {leak_id} успешно обновлен на 5')
            except Exception as status_update_error:
                logger.error(f'Ошибка обновления статуса утечки ID {leak_id}: {status_update_error}')
        
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

    return old

def get_company_id(leak_id: int) -> int:
    
    logger.info(f'Dumping company_id from DB...')
    leak_info = APIClient.get_data('leak', {'id': leak_id})
    leak_info = leak_info[0] if leak_info else {}
    company_id = leak_info.get('company_id', 1)    
    return int(company_id)
            
def get_company_name(company_id: int) -> str:
    """Get company name by company_id from dork_dict_from_DB or use fallback names."""
    company_id_to_name = {
        1: "vtb",
        2: "inno", 
        3: "t1",
    }
    
    try:
        data = {
            'tname': 'company',
            'dname': 'tenant_info',
            'action': 'get',
            'content': {'id': company_id},
            'limit': 100,
            'offset': 0
        }

        company_info = APIClient._make_request(data)
        company_name = company_info['content'][0]['name']
        return company_name
    except Exception as e:
        logger.error(f"Ошибка в get_company_name: {e}")
        if company_id in company_id_to_name:
            return company_id_to_name[company_id]
        else:
            return f"company_{company_id}"

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
