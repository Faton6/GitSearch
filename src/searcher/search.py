# Standart libs import
import signal
import sys
from urllib.parse import unquote
import requests

# Project lib's import
from src.searcher.CodeObj import CodeObj
from src.searcher.CommitObj import CommitObj
from src.searcher.RepoObj import RepoObj
from src.filters import *
from src.logger import logger, CLR

# TODO Need to translate
# TODO command file description
checked_list = {}  # Используется для временного хранения проверяемых репозитоориев для исключения повторной проверки
rep_res = []
commit_res = []


def stopping_prog():
    print('Stopping program...')
    Connector.dump_to_DB()
    sys.exit(0)


def signal_handler(signum, frame):
    if signum == signal.SIGINT:
        signal.signal(signum, signal.SIG_IGN)
        stopping_prog()


def code_scan(token: str, dork, organization):
    logger.info(f'Time: {time.strftime("%Y-%m-%d")} code_scan')
    url_list = []
    page_counter = 1
    max_page = 1
    while page_counter <= max_page:
        try:
            # TODO: проверка наличия в БД 30го "кода" , если нет - меняем страницу
            time.sleep(2)
            if token != '-':
                header = {
                    'Authorization': f'Token {token}'}
            else:
                time.sleep(2)
                header = {}
            response_code_search = requests.get(
                f'https://api.github.com/search/code',
                params={'q': dork, 'sort': 'indexed', 'order': 'desc', 'per_page': 30, 'page': page_counter},
                headers=header, timeout=1000)
            constants.dork_search_counter += 1
        except Exception as ex:
            logger.info(f'Request Error in code_scan:\n{ex}')
            return [{'Error': f'{ex}'}]
        else:
            if response_code_search.status_code == 401:
                logger.error('Token may was expired!')
                return
            time.sleep(1)
            total_count = response_code_search.json()['total_count']
            if total_count > 1000:
                total_count = 990
            max_page = total_count // 30 + 1
            page_counter += 1
            url_list += [i['repository']['html_url'] for i in response_code_search.json()['items']]

        code_obj_list = []
        url_list = filter_url_by_repo(url_list)
        url_list = filter_url_by_DB(url_list)
        if len(url_list) == 0:
            logger.info(f'Not founded any new results for {dork} dork in code scan')
            return

        for i in response_code_search.json()['items']:
            if i['repository']['html_url'] in url_list:
                code_obj_list.append(
                    CodeObj(i['html_url'], i, dork.encode().decode('utf-8'), organization))
                url_list.remove(i['repository']['html_url'])

        logger.info('Start code\'s repositories scan\n')
        for i in code_obj_list:
            if i.repo_name not in checked_list:
                checked_list.update({f'{i.repo_name}': ''})
            logger.info(f'Current repository: {i.repo_url}')
            if checked_list[i.repo_name] == '':
                check_repo_res = CheckRepo.run(i.repo_url, dork)
                if type(check_repo_res) == int and check_repo_res == 1:
                    for j in code_obj_list:
                        constants.RESULT_MASS['Code_res'][j.repo_name] = j
                    stopping_prog()
                elif type(check_repo_res) == constants.AutoVivification:
                    i.secrets = check_repo_res
                    checked_list[i.repo_name] = check_repo_res
            else:
                i.secrets = checked_list[i.repo_name]

        return code_obj_list


def rep_scan(token: str, dork, organization):
    logger.info(f'Time: {time.strftime("%Y-%m-%d")} rep_scan')
    page_counter = 1
    max_page = 1
    while page_counter <= max_page:
        try:
            time.sleep(2)
            if token != '-':
                header = {
                    'Authorization': f'Token {token}'}
            else:
                time.sleep(2)
                header = {}
            response_repo_search = requests.get('https://api.github.com/search/repositories',
                                                params={'q': dork, 'sort': 'updated', 'order': 'desc',
                                                        'per_page': 30, 'page': page_counter},
                                                headers=header, timeout=1000)
            constants.dork_search_counter += 1
        except Exception as ex:
            logger.error(f'Request Error in rep_scan:\n{ex}')
            return [{'Error': f'{ex}'}]
        else:
            if response_repo_search.status_code == 401:
                logger.error('Token may was expired!')
                return
            time.sleep(1)
            total_count = response_repo_search.json()['total_count']
            if total_count > 1000:
                total_count = 990
            max_page = total_count // 30 + 1
            page_counter += 1
            url_list = [i['html_url'] for i in response_repo_search.json()['items']]

        rep_obj_list = []
        url_list = filter_url_by_repo(url_list)
        url_list = filter_url_by_DB(url_list)
        if len(url_list) == 0:
            logger.info(f'Not founded any new results for {dork} dork in repo scan')
            return

        for i in response_repo_search.json()['items']:
            if i['html_url'] in url_list:
                rep_obj_list.append(
                    RepoObj(i['html_url'], i, dork.encode().decode('utf-8'), organization))
                url_list.remove(i['html_url'])

        logger.info('Start repositories scan')
        for i in rep_obj_list:
            if i.repo_name not in checked_list:
                checked_list.update({f'{i.repo_name}': ''})
            logger.info(f'Current repository: {i.repo_url}')
            if checked_list[i.repo_name] == '':
                check_repo_res = CheckRepo.run(i.repo_url, dork)
                if type(check_repo_res) == int and check_repo_res == 1:
                    for j in rep_obj_list:
                        constants.RESULT_MASS['Repo_res'][j.repo_name] = j
                    stopping_prog()
                elif type(check_repo_res) == constants.AutoVivification:
                    i.secrets = check_repo_res
                    checked_list[i.repo_name] = check_repo_res
            else:
                i.secrets = checked_list[i.repo_name]

        return rep_obj_list


def commits_scan(token: str, dork, organization):
    cur_dir = os.getcwd()
    page_counter = 1
    max_page = 1
    repo_url_list = []
    commit_url_list = []
    while page_counter <= max_page:
        try:
            time.sleep(2)
            if token != '-':
                header = {
                    'Authorization': f'Token {token}'}
            else:
                time.sleep(2)
                header = {}
            response_commit_search = requests.get('https://api.github.com/search/commits',
                                                  params={'q': dork, 'sort': 'committer-date', 'order': 'desc',
                                                          'per_page': 30, 'page': page_counter},
                                                  headers=header, timeout=1000)
            time.sleep(4)
            constants.dork_search_counter += 1
        except Exception as ex:
            logger.error(f'Request Error in commits_scan:\n{ex}')
            return [{'Error': f'{ex}'}]
        else:

            if response_commit_search.status_code == 401:
                logger.error('Token may was expired!')
                return
            time.sleep(1)
            total_count = response_commit_search.json()['total_count']
            if total_count > 1000:
                total_count = 990
            max_page = total_count // 30 + 1
            page_counter += 1
            repo_url_list = [i['repository']['html_url'] for i in response_commit_search.json()['items']]
            commit_url_list = [i['url'] for i in response_commit_search.json()['items']]

    com_obj_list = []
    repo_url_list = filter_url_by_repo(repo_url_list)
    repo_url_list = filter_url_by_DB(repo_url_list)
    result_commit_url_list = []
    for commit_url in commit_url_list:
        for repo_url in repo_url_list:
            if repo_url.split('/')[-2] + '/' + repo_url.split('/')[-1] in commit_url:
                result_commit_url_list.append(commit_url)
    if len(repo_url_list) == 0:
        logger.info(f'Not founded any new results for {dork} dork in commit scan')
        return

    for i in range(len(repo_url_list)):
        time.sleep(4)
        try:
            responce_commit = requests.get(result_commit_url_list[i], headers={
                'Authorization': f'Token {token}'})
            print(responce_commit.json())
        except Exception as ex:
            logger.error(f'Request Error in commits_scan:\n{ex}')
            os.chdir(cur_dir)
            return [{'Error': f'{ex}'}]
        else:
            com_obj_list.append(CommitObj(
                repo_url_list[i], responce_commit.json(), dork.encode().decode('utf-8'), organization))

    logger.info("Start scan commit's repositories")

    for i in com_obj_list:
        print(f'Current repository: {i.repo_url}')
        if i.repo_name not in checked_list:
            checked_list.update({f'{i.repo_name}': ''})

        if checked_list[i.repo_name] == '':
            check_repo_res = CheckRepo.run(i.repo_url, dork)
            if type(check_repo_res) == int and check_repo_res == 1:
                for j in com_obj_list:
                    constants.RESULT_MASS['Commit_res'][j.repo_name] = j
                stopping_prog()
            elif type(check_repo_res) == constants.AutoVivification:
                i.secrets = check_repo_res
                checked_list[i.repo_name] = check_repo_res
        else:
            i.secrets = checked_list[i.repo_name]

    return com_obj_list


def gitscan(organization):
    signal.signal(signal.SIGINT, signal_handler)  # start signal handling
    print(f'Start scan at {time.strftime("%Y-%m-%d-%H-%M")}')
    try:
        for organization in constants.dork_dict.keys():
            for i in range(len(constants.dork_dict[organization])):
                # For optimyze resources and decrease risk of problem with DB
                # We dump founded data, clean RESULT_MASS and return to scan
                if (constants.quantity_obj_before_send >= constants.MAX_OBJ_BEFORE_SEND or
                        (constants.dork_search_counter > constants.MAX_SEARCH_BEFORE_DUMP and len(constants.RESULT_MASS))):
                    dumping_data()
                constants.all_dork_search_counter += 1
                constants.dork_search_counter += 1
                logger.info(
                    f'Current dork: {CLR["BOLD"]}{unquote(constants.dork_dict[organization][i])}{CLR["RESET"]} {constants.all_dork_search_counter}/{constants.all_dork_counter}')

                # TODO change to generator it
                var = code_scan(constants.token_list[i % len(
                        constants.token_list)], constants.dork_dict[organization][i], organization)


                if type(var) is list:
                    for j in var:
                        if type(j) is CodeObj:
                            constants.RESULT_MASS['Code_res'][j.repo_name] = j
                elif type(var) is Exception:
                    logger.error(f'Accured exception in code_scan: {var}')
                logger.info(
                    f'Current dork: {CLR["BOLD"]}{unquote(constants.dork_dict[organization][i])}{CLR["RESET"]} ({constants.all_dork_search_counter}/{constants.all_dork_counter})')

                if constants.quantity_obj_before_send >= constants.MAX_OBJ_BEFORE_SEND:
                    dumping_data()
                var = rep_scan(constants.token_list[i % len(
                    constants.token_list)], constants.dork_dict[organization][i], organization)

                if type(var) is list:
                    for j in var:
                        if type(j) is RepoObj:
                            constants.RESULT_MASS['Rep_res'][j.repo_name] = j
                elif type(var) is Exception:
                    logger.error(f'Exception in repo_scan: {var}')


                logger.info(
                    f'Current dork: {CLR["BOLD"]}{unquote(constants.dork_dict[organization][i])}{CLR["RESET"]} {constants.all_dork_search_counter}/{constants.all_dork_counter}')
                if constants.quantity_obj_before_send >= constants.MAX_OBJ_BEFORE_SEND:
                    dumping_data()
                var = commits_scan(constants.token_list[i % len(
                    constants.token_list)], constants.dork_dict[organization][i], organization)

                if type(var) is list:
                    for j in var:
                        if type(j) is CommitObj:
                            constants.RESULT_MASS['Commit_res'][j.repo_name] = j
                elif type(var) is Exception:
                    logger.error(f'Exception in commit_scan: {var}')

    except Exception as ex:
        logger.error(f'Error in gitscan: {ex}')
