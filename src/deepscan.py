import os
import sys
from src.logger import logger

from src import Connector
from src import constants
from src.searcher.RepoObj import RepoObj
from src import filters

checked_list = {}

# TODO need fix
def deep_scan():
    url_to_deepscan = constants.AutoVivification()
    mode_for_dump_from_DB = 1  # type of returned dump_from_DB data
    url_dump = constants.dork_dict  # list with dict: {url:final_resul}
    for url_from_DB in url_dump.keys():
        if type(url_dump[url_from_DB][0]) is str and int(url_dump[url_from_DB][0]) == constants.RESULT_CODE_TO_DEEPSCAN:
            url_to_deepscan[url_from_DB] = [url_dump[url_from_DB][1], None]
            # url_to_deepscan[url_from_DB] = [ leak_id, Obj]
            # url_dump[url_from_DB][1] - id in DB, url_dump[url_from_DB][2] - leak_id in DB, [] - obj

    for url in url_to_deepscan.keys():
        mode_for_scan = 3
        url_to_deepscan[url][1] = filters.CheckRepo.run(url, 'None', mode_for_scan)
    mode_for_dump_to_DB = 1

    for url in list(url_to_deepscan.keys()):
        raw_report = Connector.dump_raw_data_from_DB(url_to_deepscan[url][0])
        temp_data = url_to_deepscan[url][1]
        if (len(raw_report['grepscan']) == len(temp_data['grepscan'])
                and len(raw_report['whispers']) == len(temp_data['whispers'])
                and len(raw_report['trufflehog']) == len(temp_data['trufflehog'])
                and len(raw_report['deepsecrets']) == len(temp_data['deepsecrets'])):
            del url_to_deepscan[url]
            continue
    # ioc_finder
    Connector.dump_to_DB(mode_for_dump_to_DB, url_to_deepscan)


f'''
Add List scan - scanning github by input urls.
For this you need create file
And get file name as arg:
python gitsearch /path/to/file 
OR you can input github url to /temp/list_to_scan.txt
'''


def list_search():  # TODO: add gist.github
    if len(sys.argv) > 1:
        logger.info(f'Got {len(sys.argv)}')
        if os.path.exists(f'{sys.argv[1]}'):
            with open(f'{sys.argv[1]}', 'r') as list_file:
                url_list = [line.rstrip() for line in list_file]
            url_list = list(set(url_list))
            if len(url_list) > 0:
                _list_scan(url_list)
    else:
        if os.path.exists(f'{constants.MAIN_FOLDER_PATH}/temp/list_to_scan.txt'):
            with open(f'{constants.MAIN_FOLDER_PATH}/temp/list_to_scan.txt', 'r') as list_file:
                url_list = [line.rstrip() for line in list_file]
            res_url_list = list()
            for i in range(len(url_list)):
                if url_list[i][:2] != '//' and url_list[i] != '':
                    res_url_list.append(url_list[i])

            if res_url_list:
                _list_scan(res_url_list)

            for i in range(len(url_list)):
                if url_list[i][:2] != '//':
                    url_list[i] = '//' + url_list[i]

            with open(f'{constants.MAIN_FOLDER_PATH}/temp/list_to_scan.txt', 'w') as list_file:
                for url in url_list:
                    list_file.write(url)
                    list_file.write('\n')


def _list_scan(url_list):
    rep_obj_list = []

    # url_list = filters.filter_url_by_repo(url_list)
    url_list = list(set(url_list))
    if len(url_list) == 0:
        logger.info(f'Not founded any new urls')
        return
    for i in url_list:
        responce_repo = {'full_name': i, 'owner': {'login': i.split('/')[-2]}}
        rep_obj_list.append(RepoObj(i, responce_repo, 'None'))
    for i in rep_obj_list:
        if i.repo_name not in checked_list:
            checked_list.update({f'{i.repo_name}': ''})
        logger.info(f'Current repository: {i.repo_url}')
        if checked_list[i.repo_name] == '':
            mode_for_scan = 1
            check_repo_res = filters.CheckRepo.run(i.repo_url, 'None', mode_for_scan)
            if type(check_repo_res) == int and check_repo_res == 1:
                for j in rep_obj_list:
                    constants.RESULT_MASS['Repo_res'][j.repo_name] = j
                return []
            elif type(check_repo_res) == constants.AutoVivification:
                i.secrets = check_repo_res
                checked_list[i.repo_name] = check_repo_res
        else:
            i.secrets = checked_list[i.repo_name]

    for j in rep_obj_list:
        if type(j) is RepoObj:
            constants.RESULT_MASS['Repo_res'][j.repo_name] = j
    filters.dumping_data()
