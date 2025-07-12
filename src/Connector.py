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

def is_this_need_to_analysis(leak_obj):
    is_this_need_to_analysis_flag = True
    if not leak_obj.ready_to_send:
        leak_obj._check_status()
    scan_error = leak_obj.secrets.get("Scan error") or leak_obj.secrets.get("Error")
    if scan_error and any(keyword in str(scan_error).lower() for keyword in ["error", "oversize", "not analyze"]):
        is_this_need_to_analysis_flag = False
        
    company_rel = leak_obj.ai_analysis.get('company_relevance', {})
    if not isinstance(company_rel, dict):
        company_rel = {}
    
    confidence = company_rel.get('confidence', 0.0)
    
    if leak_obj.profitability_scores['org_relevance'] < 0.25 and confidence < 0.25 and not company_rel.get('is_related', True):
        is_this_need_to_analysis_flag = False
        
    if leak_obj.profitability_scores['false_positive_chance'] > 0.25 and leak_obj.profitability_scores['true_positive_chance'] < 0.35:
        is_this_need_to_analysis_flag = False    
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
        conn, cursor = None, None
        try:
            conn, cursor = connect_to_database()
            if not conn or not cursor:
                logger.error("Failed to connect to database. Aborting dump.")
                # Fallback to file-only dump if DB connection fails
                dump_to_file_only(mode, result_deepscan, report_filename)
                return

            if mode == 0:
                existing_urls = dump_from_DB(mode=1)
                new_leaks_backup = constants.AutoVivification()
                new_leak_counter = 1

                for scan_key in constants.RESULT_MASS:
                    for scanObj in constants.RESULT_MASS[scan_key].keys():
                        leak_obj = constants.RESULT_MASS[scan_key][scanObj]
                        leak_id_existing = existing_urls.get(leak_obj.repo_url)

                        if leak_id_existing and leak_id_existing != 0:
                            logger.info(f"Updating existing leak for URL: {leak_obj.repo_url} (Leak ID: {leak_id_existing[1]})")
                            update_existing_leak(leak_id_existing[1], leak_obj)
                            continue
                        if not is_this_need_to_analysis(leak_obj):
                            leak_obj.res_check = constants.RESULT_CODE_LEAK_NOT_FOUND
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
                    dump_to_DB_req(report_filename, conn, cursor)

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
                    update_leaks_from_report(report_filename, conn, cursor)

            conn.commit()
            logger.info("Database transaction committed successfully.")

        except pymysql.Error as e:
            logger.error(f"Database transaction failed: {e}")
            if conn:
                conn.rollback()
                logger.info("Database transaction rolled back.")
            # Fallback to file-only dump on transaction failure
            dump_to_file_only(mode, result_deepscan, report_filename)

        finally:
            if conn:
                conn.close()
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


def dump_target_from_DB():
    logger.info(f'Dumping target words from DB...')
    dork_dict = {}
    conn, cursor = connect_to_database()
    if not conn or not cursor:
        return {}
    try:
        cursor.execute("SELECT dork, company_id FROM dorks")
        dumped_data = cursor.fetchall()

        for i in dumped_data:
            #dork_dict[i[1]] = base64.b64decode(i[0].encode('utf-8')).decode('utf-8').split(', ')
            dork_dict[i[1]] = base64.b64decode(i[0]).decode('utf-8').split(', ')

        return dork_dict
    except pymysql.Error as e:
        logger.error(f"Error: {e}")
        return {}
    finally:
        if conn:
            conn.close()


def dump_from_DB(mode=0):
    # mode=0 - return [..{'url':'result'}..]
    # mode=1 - return [..{'url':['result', 'id', 'leak_id']}..]
    checked_repos = {}
    logger.info(f'Dumping data from DB...')

    conn, cursor = connect_to_database()
    if not conn or not cursor:
        return {}
    try:
        cursor.execute("SELECT id, url, result FROM leak")
        dumped_data = cursor.fetchall()

        if mode == 1:
            for i in dumped_data:
                checked_repos[i[1]] = [i[2], i[0]]  # checked_repos[i['url']] = [i['result'], i['id']]
        else:
            for i in dumped_data:
                checked_repos[i[1]] = i[2]  # checked_repos[i['url']] = i['result']
        return checked_repos
    except pymysql.Error as e:
        logger.error(f"Error in dump_from_DB: {e}")
        return {}
    finally:
        if conn:
            conn.close()



def dump_to_DB_req(filename, conn, cursor):  # mode=0 - add obj to DB, mode=1 - add only report in DB
    with open(filename, 'r') as file:
        backup_rep = json.load(file)

    for i in backup_rep['scan'].keys():
        content = backup_rep['scan'][i][0]['content']
        
        # Проверяем существование компании для leak записи
        company_id = content.get('company_id', 0)
        if company_id and not company_exists(company_id, cursor):
            logger.warning(f"Company with id {company_id} does not exist for leak {content['url']}, setting to 0")
            content['company_id'] = 0
        
        leak_id = None
        cursor.execute(
            "INSERT INTO leak (url, level, author_info, found_at, created_at, updated_at, approval,"             " leak_type, result, company_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (content['url'], content['level'], content['author_info'], content['found_at'],
             content['created_at'], content['updated_at'], content['approval'], content['leak_type'],
             content['result'], content['company_id']))
        leak_id = cursor.lastrowid

        data_row_report = backup_rep['scan'][i][1]['content']
        cursor.execute("INSERT INTO raw_report (leak_id, report_name, raw_data, ai_report) VALUES (%s, %s, %s, %s)",
                       (leak_id, data_row_report['report_name'], data_row_report['raw_data'], data_row_report['ai_report']))

        leak_stats_table = backup_rep['scan'][i][2]
        cursor.execute(
            "INSERT INTO leak_stats (leak_id, size, stargazers_count, has_issues, has_projects, has_downloads,"            "has_wiki, has_pages, forks_count, open_issues_count, subscribers_count, topics, contributors_count, "            "commits_count, commiters_count, ai_result, description) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (leak_id, leak_stats_table['size'], leak_stats_table['stargazers_count'], leak_stats_table['has_issues'],
             leak_stats_table['has_projects'], leak_stats_table['has_downloads'], leak_stats_table['has_wiki'],
             leak_stats_table['has_pages'], leak_stats_table['forks_count'], leak_stats_table['open_issues_count'],
             leak_stats_table['subscribers_count'], leak_stats_table['topics'], leak_stats_table['contributors_count'],
             leak_stats_table['commits_count'], leak_stats_table['commiters_count'], leak_stats_table['ai_result'], leak_stats_table['description']))

        accounts_table = backup_rep['scan'][i][3]
        accounts_from_DB = dump_account_from_DB(cursor)
        accounts_ids = []
        for account in accounts_table:
            if account['account'] not in accounts_from_DB:
                # Проверяем существование компании перед вставкой
                company_id = account.get('related_company_id', 0)
                if company_id and not company_exists(company_id, cursor):
                    logger.warning(f"Company with id {company_id} does not exist, setting to 0 for account {account['account']}")
                    company_id = 0
                
                cursor.execute(
                    "INSERT INTO accounts (account, need_monitor, related_company_id) VALUES (%s, %s, %s)",
                    (account['account'], account['need_monitor'], company_id))
                accounts_ids.append(cursor.lastrowid)

        for account_id in list(accounts_ids):
            cursor.execute(
                "INSERT INTO related_accounts_leaks (leak_id, account_id) VALUES (%s, %s)",
                (leak_id, account_id))
        commiters_table = backup_rep['scan'][i][4]
        for commiter in commiters_table:
            # Проверяем существование связанного аккаунта перед вставкой
            related_account_id = commiter.get('related_account_id', 0)
            if related_account_id and not account_exists(related_account_id, cursor):
                logger.warning(f"Account with id {related_account_id} does not exist, setting to 0 for commiter {commiter['commiter_name']}")
                related_account_id = 1
            
            cursor.execute(
                "INSERT INTO commiters (leak_id, commiter_name, commiter_email, need_monitor, related_account_id) VALUES (%s, %s, %s, %s, %s)",
                (leak_id, commiter['commiter_name'], commiter['commiter_email'],
                 commiter['need_monitor'], related_account_id))

def account_exists(account_id: int, cursor) -> bool:
    """Проверяет существование аккаунта с указанным ID в базе данных."""
    try:
        cursor.execute("SELECT COUNT(*) FROM accounts WHERE id=%s", (account_id,))
        result = cursor.fetchone()
        return result[0] > 0 if result else False
    except pymysql.Error as e:
        logger.error(f"Error checking account existence: {e}")
        return False


def company_exists(company_id: int, cursor) -> bool:
    """Проверяет существование компании с указанным ID в базе данных."""
    try:
        cursor.execute("SELECT COUNT(*) FROM companies WHERE id=%s", (company_id,))
        result = cursor.fetchone()
        if result and len(result) > 0:
            return result[0] > 0
        return False
    except pymysql.Error as e:
        logger.error(f"Error checking company existence: {e}")
        return False


def get_company_name(company_id: int) -> str:
    """Return company name for given id or empty string on failure."""
    conn, cursor = connect_to_database()
    if not conn or not cursor:
        return ""
    try:
        cursor.execute("SELECT company_name FROM companies WHERE id=%s", (company_id,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return ""
    except pymysql.Error as e:
        logger.error(f"Error: {e}")
        return ""
    finally:
        if conn:
            conn.close()

def dump_account_from_DB(cursor):
    try:
        cursor.execute("SELECT account FROM accounts")
        dumped_data = cursor.fetchall()
        return [row[0] for row in dumped_data]
    except pymysql.Error as e:
        logger.error(f"Error in dump_account_from_DB: {e}")
        return []


def dump_row_data_from_DB(target_leak_id):
    logger.info(f'Dumping leak {target_leak_id} from DB...')
    conn, cursor = connect_to_database()
    if not conn:
        return None
    try:
        cursor.execute("SELECT raw_data FROM raw_report WHERE leak_id=%s", (target_leak_id,))
        result = cursor.fetchone()
        if result and result[0]:
            return json.loads(bz2.decompress(base64.b64decode(result[0])))
        return None
    except pymysql.Error as e:
        logger.error(f"Error: {e}")
        return None
    except (json.JSONDecodeError, Exception, base64.binascii.Error) as e:
        logger.error(f"Data decoding/decompression error for leak_id {target_leak_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()



def dump_ai_report_from_DB(target_leak_id):
    logger.info(f'Dumping leak {target_leak_id} from DB...')
    conn, cursor = connect_to_database()
    if not conn:
        return None
    try:
        cursor.execute("SELECT ai_report FROM raw_report WHERE leak_id=%s", (target_leak_id,))
        result = cursor.fetchone()
        if result and result[0]:
            return json.loads(bz2.decompress(base64.b64decode(result[0])))
        return None
    except pymysql.Error as e:
        logger.error(f"Error: {e}")
        return None
    except (json.JSONDecodeError, Exception, base64.binascii.Error) as e:
        logger.error(f"Data decoding/decompression error for leak_id {target_leak_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()

def get_leak_id_by_url(url: str, conn=None, cursor=None):
    close_conn = False
    if not conn or not cursor:
        conn, cursor = connect_to_database()
        if not conn or not cursor:
            return None
        close_conn = True
    try:
        cursor.execute("SELECT id FROM leak WHERE url=%s", (url,))
        res = cursor.fetchone()
        return res[0] if res else None
    except pymysql.Error as e:
        logger.error(f"Error fetching leak id: {e}")
        return None
    finally:
        if close_conn and conn:
            conn.close()


def load_existing_leak_urls(conn=None, cursor=None) -> dict:
    """Return mapping of URL to leak id."""
    close_conn = False
    if not conn or not cursor:
        conn, cursor = connect_to_database()
        if not conn or not cursor:
            return {}
        close_conn = True

    try:
        cursor.execute("SELECT id, url FROM leak")
        rows = cursor.fetchall()
        return {row[1]: row[0] for row in rows}
    except pymysql.Error as e:
        logger.error(f"Error fetching existing leaks: {e}")
        return {}
    finally:
        if close_conn and conn:
            conn.close()


def get_commiters_from_DB(leak_id: int, conn=None, cursor=None):
    close_conn = False
    if not conn or not cursor:
        conn, cursor = connect_to_database()
        if not conn or not cursor:
            return []
        close_conn = True
    try:
        cursor.execute("SELECT commiter_name, commiter_email FROM commiters WHERE leak_id=%s", (leak_id,))
        res = cursor.fetchall()
        return [(r[0], r[1]) for r in res]
    except pymysql.Error as e:
        logger.error(f"Error fetching commiters: {e}")
        return []
    finally:
        if close_conn and conn:
            conn.close()


def get_accounts_from_DB(leak_id: int, conn=None, cursor=None):
    close_conn = False
    if not conn or not cursor:
        conn, cursor = connect_to_database()
        if not conn or not cursor:
            return []
        close_conn = True
    try:
        cursor.execute(
            "SELECT a.account FROM accounts a JOIN related_accounts_leaks r ON a.id=r.account_id WHERE r.leak_id=%s",
            (leak_id,),
        )
        res = cursor.fetchall()
        return [r[0] for r in res]
    except pymysql.Error as e:
        logger.error(f"Error fetching accounts: {e}")
        return []
    finally:
        if close_conn and conn:
            conn.close()


def merge_reports(old: dict, new: dict) -> dict:
    if not isinstance(old, dict):
        old = {}
    if not isinstance(new, dict):
        return old
    for scan, leaks in new.items():
        if scan not in old or not isinstance(old.get(scan), dict):
            old[scan] = leaks
            continue
        if not isinstance(leaks, dict):
            old[scan] = leaks
            continue
        existing = old[scan]
        for leak in leaks.values():
            match = leak.get('Match')
            file_ = leak.get('File')
            dup = False
            for ex in existing.values():
                if ex.get('Match') == match and ex.get('File') == file_:
                    dup = True
                    break
            if not dup:
                key = f"Leak #{len(existing) + 1}"
                existing[key] = leak
    return old


def update_existing_leak(leak_id: int, leak_obj, conn, cursor):
    try:
        leak_data = leak_obj.write_obj()

        existing_comm = set(get_commiters_from_DB(leak_id, conn, cursor))
        new_comm = set((c.get('commiter_name'), c.get('commiter_email')) for c in leak_obj.stats.commits_stats_commiters_table)
        for name, email in new_comm - existing_comm:
            cursor.execute(
                "INSERT INTO commiters (leak_id, commiter_name, commiter_email, need_monitor, related_account_id) VALUES (%s, %s, %s, %s, %s)",
                (leak_id, name, email, 0, 0),
            )

        existing_accounts = set(get_accounts_from_DB(leak_id, conn, cursor))
        accounts_from_db = set(dump_account_from_DB(cursor))
        for acc in leak_obj.stats.contributors_stats_accounts_table:
            acc_name = acc['account']
            if acc_name not in accounts_from_db:
                # Проверяем существование компании перед вставкой
                company_id = acc.get('related_company_id', 0)
                if company_id and not company_exists(company_id, cursor):
                    logger.warning(f"Company with id {company_id} does not exist, setting to 0 for account {acc_name}")
                    company_id = 0
                
                cursor.execute(
                    "INSERT INTO accounts (account, need_monitor, related_company_id) VALUES (%s, %s, %s)",
                    (acc_name, acc['need_monitor'], company_id),
                )
                acc_id = cursor.lastrowid
                cursor.execute("INSERT INTO related_accounts_leaks (leak_id, account_id) VALUES (%s, %s)", (leak_id, acc_id))
                accounts_from_db.add(acc_name)
            elif acc_name not in existing_accounts:
                cursor.execute("SELECT id FROM accounts WHERE account=%s", (acc_name,))
                res = cursor.fetchone()
                if res:
                    acc_id = res[0]
                    cursor.execute("INSERT INTO related_accounts_leaks (leak_id, account_id) VALUES (%s, %s)", (leak_id, acc_id))

        cursor.execute("SELECT raw_data, ai_report FROM raw_report WHERE leak_id=%s", (leak_id,))
        try:
            res = cursor.fetchone()
        except StopIteration:
            res = None
            
        if res:
            old_raw = json.loads(bz2.decompress(base64.b64decode(res[0])))
            old_ai = json.loads(bz2.decompress(base64.b64decode(res[1])))
        else:
            old_raw = {}
            old_ai = {}

        merged_raw = merge_reports(old_raw, leak_obj.secrets)
        merged_ai = merge_reports(old_ai, leak_obj.ai_report)
        enc_raw = base64.b64encode(bz2.compress(json.dumps(merged_raw).encode('utf-8')))
        enc_ai = base64.b64encode(bz2.compress(json.dumps(merged_ai).encode('utf-8')))

        if res:
            cursor.execute("UPDATE raw_report SET raw_data=%s, ai_report=%s WHERE leak_id=%s", (enc_raw, enc_ai, leak_id))
        else:
            cursor.execute(
                "INSERT INTO raw_report (leak_id, report_name, raw_data, ai_report) VALUES (%s, %s, %s, %s)",
                (leak_id, leak_obj.repo_url, enc_raw, enc_ai),
            )

        commiters_count = len(existing_comm | new_comm)
        contributors_count = max(
            leak_obj.stats.repo_stats_leak_stats_table.get('contributors_count', 0),
            len(existing_accounts | {a['account'] for a in leak_obj.stats.contributors_stats_accounts_table}),
        )
        cursor.execute(
            "UPDATE leak_stats SET contributors_count=%s, commiters_count=%s WHERE leak_id=%s",
            (contributors_count, commiters_count, leak_id),
        )

        cursor.execute(
            "UPDATE leak SET level=%s, author_info=%s, leak_type=%s, result=%s, updated_at=%s WHERE id=%s",
            (
                leak_data['level'],
                leak_data['author_info'],
                leak_data['leak_type'],
                leak_data['result'],
                leak_data['updated_at'],
                leak_id,
            ),
        )
    except pymysql.Error as e:
        logger.error(f"Error updating leak: {e}")
        if conn:
            conn.rollback()
        raise  # Re-raise the exception to be caught by the caller

def update_leaks_from_report(filename: str, conn, cursor):
    with open(filename, 'r') as file:
        backup_rep = json.load(file)
    
    for i in backup_rep['scan'].keys():
        item = backup_rep['scan'][i]
        if 'DeepScan' in item[0]:
            report_content = item[1]['content']
            leak_id = report_content['leak_id']
            
            cursor.execute("UPDATE leak SET result='3' WHERE id=%s", (leak_id,))
            
            enc_raw = report_content['raw_data']
            enc_ai = report_content['ai_report']
            
            cursor.execute("SELECT 1 FROM raw_report WHERE leak_id=%s", (leak_id,))
            if cursor.fetchone():
                cursor.execute("UPDATE raw_report SET raw_data=%s, ai_report=%s WHERE leak_id=%s", (enc_raw, enc_ai, leak_id))
            else:
                cursor.execute(
                    "INSERT INTO raw_report (leak_id, report_name, raw_data, ai_report) VALUES (%s, %s, %s, %s)",
                    (leak_id, report_content['report_name'], enc_raw, enc_ai),
                )
                
def merge_reports(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two report dictionaries. Preserves existing data in 'old' and merges new data from 'new'.
    
    - Merges content of keys like 'gitsecrets', 'trufflehog', etc.
    - Overwrites 'message' if new one is present.
    - For AI reports, replaces the whole structure if new is not empty.
    """
    if not isinstance(old, dict) or not isinstance(new, dict):
        return old if old else new

    # Список ключей, которые нужно слить по содержимому
    merge_keys = {'gitsecrets', 'trufflehog', 'grepscan', 'deepsecrets', 'gitleaks'}

    for key in merge_keys:
        if key in new:
            if key not in old or not isinstance(old[key], dict):
                old[key] = {}
            # Объединяем внутренние структуры (например, списки найденных утечек)
            if isinstance(new[key], dict):
                # Пример: merge по типам утечек
                for subkey, value in new[key].items():
                    if value:  # Не добавляем пустые значения
                        old[key][subkey] = value
            elif new[key]:  # Если не dict, просто заменяем, если не пусто
                old[key] = new[key]

    # Перезаписываем сообщение, если оно есть в new
    if 'message' in new and new['message']:
        old['message'] = new['message']

    # Для ai_report — полная замена, если в new что-то есть
    if 'ai_report' in new and new['ai_report']:
        old['ai_report'] = new['ai_report']

    return old
