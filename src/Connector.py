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

requests.urllib3.disable_warnings()


def dump_to_DB(mode=0, result_deepscan=None):  # mode=0 - add obj to DB, mode=1 - update obj in DB

    res_backup = constants.AutoVivification()
    counter = 1
    if mode == 0:
        for scan_key in constants.RESULT_MASS.keys():
            for scanObj in constants.RESULT_MASS[scan_key].keys():
                time.sleep(1)
                if constants.RESULT_MASS[scan_key][scanObj].write_obj()['leak_type'] == 'None':
                    continue
                data_leak = {
                    'tname': 'leak',
                    'dname': 'GitLeak',
                    'action': 'add',
                    'content': constants.RESULT_MASS[scan_key][scanObj].write_obj()
                }

                data_row_report = {
                    'tname': 'row_report',
                    'dname': 'GitLeak',
                    'action': 'add',
                    'content': {
                        'leak_id': counter,
                        'report_name': constants.RESULT_MASS[scan_key][scanObj].repo_url,
                        'row_data':
                            str(base64.b64encode(bz2.compress(json.dumps(constants.RESULT_MASS[scan_key][scanObj].
                                                                         secrets, indent=4).encode('utf-8'))))[2:-1]
                    }
                }
                res_backup[counter] = [data_leak, data_row_report]

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
                'tname': 'row_report',
                'dname': 'GitLeak',
                'action': 'add',
                'content': {
                    'leak_id': result_deepscan[url][0],
                    'report_name': url,
                    'row_data':
                        str(base64.b64encode(bz2.compress(json.dumps(result_deepscan[url][1],
                                                                     indent=4).encode('utf-8'))))[2:-1]
                }
            }
            res_backup[counter] = [{'DeepScan': 'DeepScan'}, data_row_report]
            counter += 1

    logger.info(f'\nDumped backup data')
    report_filename = f'{constants.MAIN_FOLDER_PATH}/reports/result_res-{time.strftime("%Y-%m-%d-%H-%M")}.json'
    with open(report_filename, 'w') as file:
        json.dump({'scan': res_backup}, file, ensure_ascii=False, indent=8)
    print(
        f'Result report: {constants.MAIN_FOLDER_PATH}/reports/result_res-{time.strftime("%Y-%m-%d-%H-%M")}.json')
    if constants.url_DB != '-':
        dump_to_DB_req(report_filename, mode=mode)


def dump_from_DB(mode=0):
    # mode=0 - return [..{'url':'result'}..]
    # mode=1 - return [..{'url':['result', 'id', 'leak_id']}..]
    checked_repos = {}
    logger.info(f'Dumping data from DB...')
    dumped_data = []
    DB_offset = 0
    DB_limit = 100  # quantity of rows to dump from one request
    dumping_while = True  # while offset not get null (end of the DB)

    while dumping_while:
        data_to_request = {
            'tname': 'leak',
            'dname': 'GitLeak',
            'action': 'get',
            'content': {},
            'limit': DB_limit,
            'offset': DB_offset
        }

        headers = {'token': constants.token_DB}
        request_to_get_data = requests.post(url=constants.url_DB,
                                            json=data_to_request,
                                            headers=headers,
                                            verify=False)
        if type(request_to_get_data.json()['content'][0]) == int:
            dumping_while = False
        else:
            dumped_data.extend(request_to_get_data.json()['content'])
        DB_offset += DB_limit
    if mode == 1:
        for i in dumped_data:
            checked_repos[i['url']] = [i['result'], i['id']]
    else:
        for i in dumped_data:
            checked_repos[i['url']] = i['result']

    return checked_repos


def dump_target_from_DB():
    logger.info(f'Dumping target words from DB...')
    dumped_data = []
    DB_offset = 0
    DB_limit = 100  # quantity of rows to dump from one request
    dumping_while = True  # while offset not get null (end of the DB)
    dork_dict = {}
    while dumping_while:

        data_to_request = {
            'tname': 'GitLeak_dork',
            'dname': 'tennant_info',
            'action': 'get',
            'content': {},
            'limit': DB_limit,
            'offset': DB_offset
        }

        headers = {'token': constants.token_DB}
        request_to_get_data = requests.post(url=constants.url_DB,
                                            json=data_to_request,
                                            headers=headers,
                                            verify=False)
        if type(request_to_get_data.json()['content'][0]) == int:
            dumping_while = False
        else:
            dumped_data.extend(request_to_get_data.json()['content'])
        DB_offset += DB_limit
    for i in dumped_data:
        dork_dict[i['company_id']] = base64.b64decode(i['dork'][1:-1]).decode('utf-8').split(', ')

    return dork_dict


def connect_to_database():
    try:
        conn = mariadb.connect(
            user="your_username",
            password="your_password",
            host="localhost",
            port=3306,
            database="Gitsearch"
        )
        cursor = conn.cursor()
        return conn, cursor
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")


def dump_to_DB_req(filename, mode=0):  # mode=0 - add obj to DB, mode=1 - add only report in DB
    with open(filename, 'r') as file:
        backup_rep = json.load(file)
        # print(backup_rep)
    # mode
    for i in backup_rep['scan'].keys():
        if mode == 0:
            content = backup_rep['scan'][i][0]
            leak_id = None
            try:
                conn, cursor = connect_to_database()
                cursor.execute(
                    "INSERT INTO leak (url, level, author_info, found_at, created_at, updated_at, approval, leak_type, result, company_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (content['url'], content['level'], content['author_info'], content['found_at'],
                     content['created_at'], content['updated_at'], content['approval'], content['leak_type'],
                     content['result'], content['company_id']))
                conn.commit()
                leak_id = cursor.lastrowid
                data_row_report = backup_rep['scan'][i][1]
                cursor.execute("INSERT INTO row_report (leak_id, report_name, row_data) VALUES (?, ?, ?)",
                               (leak_id, data_row_report['report_name'], data_row_report['row_data']))
                conn.commit()
            except mariadb.Error as e:
                return logger.error(f"Error: {e}")
            finally:
                if conn:
                    conn.close()

    logger.info(f'\nEnd dump data to DB\n---------------------------------------')


'''         
            headers = {'token': constants.token_DB}   
            responce_obj_add = requests.post(url=constants.url_DB, headers=headers, json=data_leak, verify=False,
                                             timeout=1000)

            logger.info(f'\nResponce dump data to DB.leak: {responce_obj_add.text}')
            data_row_report = backup_rep['scan'][i][1]
            data_row_report['content']['leak_id'] = responce_obj_add.json()['content']['id']

            responce_secrets_add = requests.post(url=constants.url_DB, headers=headers, json=data_row_report,
                                                 verify=False, timeout=1000)
            logger.info(f'\nResponce dump data to DB.row_report: {responce_secrets_add.text}')
        elif mode == 1:
            headers = {'token': constants.token_DB}
            data_row_report = backup_rep['scan'][i][1]
            responce_secrets_add = requests.post(url=constants.url_DB, headers=headers, json=data_row_report,
                                                 verify=False, timeout=1000)
            logger.info(f'\nResponce dump data to DB.row_report: {responce_secrets_add.text}')
'''


def dump_raw_data_from_DB(leak_id):
    # plus
    checked_repos = {}
    logger.info(f'Dumping leak {leak_id} from DB...')
    dumped_data = ''

    data_to_request = {
        'tname': 'row_report',
        'dname': 'GitLeak',
        'action': 'get',
        'content': {'leak_id': leak_id}
    }

    headers = {'token': constants.token_DB}
    request_to_get_data = requests.post(url=constants.url_DB,
                                        json=data_to_request,
                                        headers=headers,
                                        verify=False)

    dumped_data = request_to_get_data.json()['content'][0]['row_data']

    dumped_data = str(json.loads(bz2.decompress(base64.b64decode(dumped_data))))
    return dumped_data


def update_result_filed_in_DB():
    data_from_DB = dump_from_DB(mode=1)

    for i in data_from_DB.keys():
        if data_from_DB[i][0] == '1':
            if not requests.get(data_from_DB[i], headers={'Authorization': f'Token {constants.token_list[0]}'}).ok:
                data_to_request = {
                    'tname': 'leak',
                    'dname': 'GitLeak',
                    'action': 'upd',
                    'content': {
                        'id': data_from_DB[i][1],
                        'result': '3'
                    }
                }

                headers = {'token': constants.token_DB}
                request_to_get_data = requests.post(url=constants.url_DB,
                                                    json=data_to_request,
                                                    headers=headers,
                                                    verify=False)

                logger.info('Repository allowed')
            else:
                logger.info('Repository not allowed')

        if data_from_DB[i][0] == '5':
            if not requests.get(data_from_DB[i], headers={'Authorization': f'Token {constants.token_list[0]}'}).ok:
                data_to_request = {
                    'tname': 'leak',
                    'dname': 'GitLeak',
                    'action': 'upd',
                    'content': {
                        'id': data_from_DB[i][1],
                        'result': '2'
                    }
                }

                headers = {'token': constants.token_DB}
                request_to_get_data = requests.post(url=constants.url_DB,
                                                    json=data_to_request,
                                                    headers=headers,
                                                    verify=False)

                logger.info('Was change result')
