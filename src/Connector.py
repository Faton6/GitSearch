# Standart libs import
import base64
import bz2
import json
import time

import requests
import mariadb

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
# TODO Change config to class Config

requests.urllib3.disable_warnings()


def dump_to_DB(mode=0, result_deepscan=None):  # mode=0 - add obj to DB, mode=1 - update obj in DB
    res_backup = constants.AutoVivification()
    counter = 1
    dumped_repo_list = []
    if mode == 0:
        for scan_key in constants.RESULT_MASS.keys():
            for scanObj in constants.RESULT_MASS[scan_key].keys():
                if (constants.RESULT_MASS[scan_key][scanObj].write_obj()['leak_type'] == 'None'
                        or constants.RESULT_MASS[scan_key][scanObj].repo_url in dumped_repo_list):
                    continue
                data_leak = {
                    'tname': 'leak',
                    'dname': 'GitLeak',
                    'action': 'add',
                    'content': constants.RESULT_MASS[scan_key][scanObj].write_obj()
                }
                data_row_report = {
                    'tname': 'raw_report',
                    'dname': 'GitLeak',
                    'action': 'add',
                    'content': {
                        'leak_id': counter,
                        'report_name': constants.RESULT_MASS[scan_key][scanObj].repo_url,
                        'raw_data':
                            str(base64.b64encode(bz2.compress(json.dumps(constants.RESULT_MASS[scan_key][scanObj].
                                                                         secrets, indent=4).encode('utf-8'))))[2:-1],
                            
                        'ai_report':
                            str(base64.b64encode(bz2.compress(json.dumps(constants.RESULT_MASS[scan_key][scanObj].
                                                                         ai_report, indent=4).encode('utf-8'))))[2:-1]
                    }
                }
                leak_stats_table, accounts_table, commiters_table = constants.RESULT_MASS[scan_key][scanObj].get_stats()


                dumped_repo_list.append(constants.RESULT_MASS[scan_key][scanObj].repo_url)
                res_backup[counter] = [data_leak, data_row_report, leak_stats_table, accounts_table, commiters_table]
                counter += 1
    elif mode == 1:
        for url in result_deepscan.keys():
            time.sleep(1)
            data_to_request = {
                'tname': 'leak',
                'dname': 'GitLeak',
                'action': 'upd',
                'content': {
                    'id': result_deepscan[url][0],
                    'result': '3'
                }
            }
            data_row_report = {
                'tname': 'raw_report',
                'dname': 'GitLeak',
                'action': 'add',
                'content': {
                    'leak_id': result_deepscan[url][0],
                    'report_name': url,
                    'raw_data':
                        str(base64.b64encode(bz2.compress(json.dumps(result_deepscan[url][1],
                                                                     indent=4).encode('utf-8'))))[2:-1],
                    'ai_report':
                        str(base64.b64encode(bz2.compress(json.dumps(result_deepscan[url][2],
                                                                     indent=4).encode('utf-8'))))[2:-1]
                }
            }

            res_backup[counter] = [{'DeepScan': 'DeepScan'}, data_row_report]
            counter += 1

    report_filename = f'{constants.MAIN_FOLDER_PATH}/reports/result_res-{time.strftime("%Y-%m-%d-%H-%M")}.json'
    with open(report_filename, 'w') as file:
        json.dump({'scan': res_backup}, file, ensure_ascii=False, indent=8)
    logger.info(
        f'Result report: {constants.MAIN_FOLDER_PATH}/reports/result_res-{time.strftime("%Y-%m-%d-%H-%M")}.json')
    if constants.url_DB != '-':
        dump_to_DB_req(report_filename, mode=mode)


def connect_to_database():
    try:
        conn = mariadb.connect(
            user="root",
            password="changeme",
            host=constants.url_DB,
            port=3306,
            database="Gitsearch"
        )
        cursor = conn.cursor()
        return conn, cursor
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")


def dump_target_from_DB():
    logger.info(f'Dumping target words from DB...')
    dork_dict = {}
    conn, cursor = connect_to_database()
    try:
        cursor.execute("SELECT dork, company_id FROM dorks")
        dumped_data = cursor.fetchall()
        conn.commit()

        for i in dumped_data:
            dork_dict[i[1]] = base64.b64decode(i[0].encode('utf-8')).decode('utf-8').split(', ')

        return dork_dict
    except mariadb.Error as e:
        return logger.error(f"Error: {e}")
    finally:
        if conn:
            conn.close()


def dump_from_DB(mode=0):
    # mode=0 - return [..{'url':'result'}..]
    # mode=1 - return [..{'url':['result', 'id', 'leak_id']}..]
    checked_repos = {}
    logger.info(f'Dumping data from DB...')

    conn, cursor = connect_to_database()
    try:
        cursor.execute("SELECT id, url, result FROM leak")
        dumped_data = cursor.fetchall()
        conn.commit()

        if mode == 1:
            for i in dumped_data:
                checked_repos[i[1]] = [i[2], i[0]]  # checked_repos[i['url']] = [i['result'], i['id']]
        else:
            for i in dumped_data:
                checked_repos[i[1]] = i[2]  # checked_repos[i['url']] = i['result']
        return checked_repos
    except mariadb.Error as e:
        return logger.error(f"Error: {e}")
    finally:
        if conn:
            conn.close()



def dump_to_DB_req(filename, mode=0):  # mode=0 - add obj to DB, mode=1 - add only report in DB
    with open(filename, 'r') as file:
        backup_rep = json.load(file)

    for i in backup_rep['scan'].keys():
        if mode == 0:
            content = backup_rep['scan'][i][0]['content']
            leak_id = None
            try:
                conn, cursor = connect_to_database()
                cursor.execute(
                    "INSERT INTO leak (url, level, author_info, found_at, created_at, updated_at, approval," \
                    " leak_type, result, company_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (content['url'], content['level'], content['author_info'], content['found_at'],
                     content['created_at'], content['updated_at'], content['approval'], content['leak_type'],
                     content['result'], content['company_id']))
                conn.commit()
                leak_id = cursor.lastrowid

                data_row_report = backup_rep['scan'][i][1]['content']
                cursor.execute("INSERT INTO raw_report (leak_id, report_name, raw_data, ai_report) VALUES (?, ?, ?, ?)",
                               (leak_id, data_row_report['report_name'], data_row_report['raw_data'], data_row_report['ai_report']))
                conn.commit()

                leak_stats_table = backup_rep['scan'][i][2]

                cursor.execute(
                    "INSERT INTO leak_stats (leak_id, size, stargazers_count, has_issues, has_projects, has_downloads,"
                    "has_wiki, has_pages, forks_count, open_issues_count, subscribers_count, topics, contributors_count, "
                    "commits_count, commiters_count, ai_result, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (leak_id, leak_stats_table['size'], leak_stats_table['stargazers_count'], leak_stats_table['has_issues'],
                     leak_stats_table['has_projects'], leak_stats_table['has_downloads'], leak_stats_table['has_wiki'],
                     leak_stats_table['has_pages'], leak_stats_table['forks_count'], leak_stats_table['open_issues_count'],
                     leak_stats_table['subscribers_count'], leak_stats_table['topics'], leak_stats_table['contributors_count'],
                     leak_stats_table['commits_count'], leak_stats_table['commiters_count'], leak_stats_table['ai_result'], leak_stats_table['description']))
                conn.commit()

                accounts_table = backup_rep['scan'][i][3]
                accounts_from_DB = dump_account_from_DB()
                accounts_ids = []
                for account in accounts_table:
                    if account['account'] not in accounts_from_DB:
                        cursor.execute(
                            "INSERT INTO accounts (account, need_monitor, related_company_id) VALUES (?, ?, ?)",
                            (account['account'], account['need_monitor'], account['related_company_id']))
                        conn.commit()
                        accounts_ids.append(cursor.lastrowid)
                # conn.commit()
                # account_id = cursor.lastrowid

                for account_id in list(accounts_ids):
                    cursor.execute(
                        "INSERT INTO related_accounts_leaks (leak_id, account_id) VALUES (?, ?)",
                        (leak_id, account_id))
                    conn.commit()
                commiters_table = backup_rep['scan'][i][4]
                for commiter in commiters_table:
                    cursor.execute(
                        "INSERT INTO commiters (leak_id, commiter_name, commiter_email, need_monitor, related_account_id) VALUES (?, ?, ?, ?, ?)",
                        (leak_id, commiter['commiter_name'], commiter['commiter_email'],
                         commiter['need_monitor'], commiter['related_account_id']))
                    conn.commit()

            except mariadb.Error as e:
                return logger.error(f"Error: {e}")
            finally:
                if conn:
                    conn.close()

    logger.info('End dump data to DB')
    logger.info('#' * 80)

def dump_account_from_DB():

    conn, cursor = connect_to_database()
    try:
        cursor.execute("SELECT account FROM accounts")
        conn.commit()

        dumped_data = list(cursor.fetchall())
        #id_account = {}
        #for data in dumped_data:
        #    id_account[data[0]] = data[1]
        return dumped_data
    except mariadb.Error as e:
        return logger.error(f"Error: {e}")
    finally:
        if conn:
            conn.close()


def dump_row_data_from_DB(target_leak_id):
    logger.info(f'Dumping leak {target_leak_id} from DB...')

    conn, cursor = connect_to_database()
    try:
        cursor.execute("SELECT raw_data FROM raw_report WHERE leak_id=target_leak_id")
        conn.commit()
        dumped_data = str(json.loads(bz2.decompress(base64.b64decode(cursor.fetchall()))))
        return dumped_data
    except mariadb.Error as e:
        return logger.error(f"Error: {e}")
    finally:
        if conn:
            conn.close()


def dump_ai_report_from_DB(target_leak_id):
    logger.info(f'Dumping leak {target_leak_id} from DB...')

    conn, cursor = connect_to_database()
    try:
        cursor.execute("SELECT ai_report FROM raw_report WHERE leak_id=target_leak_id")
        conn.commit()
        dumped_data = str(json.loads(bz2.decompress(base64.b64decode(cursor.fetchall()))))
        return dumped_data
    except mariadb.Error as e:
        return logger.error(f"Error: {e}")
    finally:
        if conn:
            conn.close()
