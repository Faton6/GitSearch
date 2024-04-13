# Standart libs import
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import shutil
import subprocess
from pathlib import Path
import re
import base64
import time
import tracemalloc
import logging

# Project lib's import
from src import constants
from ioc_finder import find_iocs
from src.logger import logger, CLR
from src import Connector


def trace_monitor():
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.compare_to(constants.snap_backup, "lineno")
    logging.info("---------------------------------------------------------")
    logging.info('Process info')
    size_count = 0
    counter = 0
    for stat in top_stats:
        size_count += stat.size_diff
        counter += 1
    logger.info(f'Diff size: {size_count / 1048576} MB')
    constants.snap_backup = snapshot
    top_stats = snapshot.statistics('lineno')
    size_count = 0
    counter = 0
    for stat in top_stats:
        size_count += stat.size
        counter += 1
    logger.info(f'Totall size: {size_count / 1048576} MB')
    logger.info(f'Totall counter: {counter} files')
    logging.info("---------------------------------------------------------")


def dumping_data():
    logging.info(f'---------------------------------\n')
    logging.info(f'Trace monitor before dump and clearing:\n')
    trace_monitor()
    result_unempty = False
    for elem in constants.RESULT_MASS.values():
        if len(elem):
            result_unempty = True
            break
    if result_unempty:
        Connector.dump_to_DB()

    for scan_key in constants.RESULT_MASS.keys():
        for scanObj in constants.RESULT_MASS[scan_key].keys():
            constants.url_from_DB[constants.RESULT_MASS[scan_key][scanObj].repo_url] = str(
                constants.RESULT_CODE_TO_SEND)
    constants.dork_search_counter = 0
    constants.RESULT_MASS = constants.AutoVivification()
    constants.quantity_obj_before_send = 0
    logging.info('Clear temp folder')
    if os.path.exists(constants.TEMP):
        for root, dirs, files in os.walk('constants.TEMP'):
            for f in files:
                os.unlink(os.path.join(root, f))
            for d in dirs:
                shutil.rmtree(os.path.join(root, d))
    logging.info('Process info after dump to DB and clearing')
    trace_monitor()
    logging.info(f'---------------------------------\n')


def pywhat_analyze(match):
    pipe_pywhat = subprocess.Popen(['pywhat', '--json', '--include', "Bug Bounty", match],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
    # add urls to exclude_list.txt, which were have in DB result euqal 0 - leaks doesn't found, add to exclude list
    try:
        url_dump_from_DB = constants.url_from_DB
        list_to_add = []
        for url_from_DB in url_dump_from_DB.keys():
            if url_dump_from_DB[url_from_DB] == '0':
                list_to_add.append(url_from_DB)
        if list_to_add:
            _add_repo_to_exclude(list_to_add)
    except Exception as ex:
        logger.error(f'Error in exclude_list_update: {ex}')


def _add_repo_to_exclude(url):  # TODO: add check existing repo name
    try:
        if type(url) is str:
            url = convert_to_regex_pattern(url)
            with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'r') as file:
                url_from_exclude_list = [line.rstrip() for line in file]
            if not (url in url_from_exclude_list):
                url_from_exclude_list.append(url)
                with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'w') as file:
                    for url_from_list in url_from_exclude_list:
                        file.write(url_from_list + '\n')
        elif type(url) is list:
            url = [convert_to_regex_pattern(str_to_regexp) for str_to_regexp in url]
            with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'r') as file:
                url_from_exclude_list = [line.rstrip() for line in file]
            is_need_to_upd = False
            for new_url in url:
                if not (new_url in url_from_exclude_list):
                    url_from_exclude_list.append(new_url)
                    is_need_to_upd = True
            if is_need_to_upd:
                with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'w') as file:
                    for url_from_list in url_from_exclude_list:
                        file.write(url_from_list + '\n')
        else:
            logging.error("Error in adding excludes in exclude_list.txt (_add_repo_to_exclude): Unknown data type!\n")
    except Exception as ex:
        logging.error(f'Error in adding excludes in exclude_list.txt (_add_repo_to_exclude): {ex}\n')


def filter_url_by_repo(url_list):
    """
        TODO Translate it
        def filter_url_by_repo - функцию исключающая репозитории из списка исключений,
        список находится в файле exclude_list.txt
        формат добавления исключений в список: \n<account_name>/<repo_name>
    """
    try:
        filtered_urls = []
        if not os.path.exists(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt'):
            logger.info('File exclude_list.txt is not found. No urls will be excepted.')
            # print(f'File exclude_list.txt not found in directory: {os.getcwd()}')
            # sys.exit(1)
        else:
            with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'r') as fd:
                substring_list = [line.rstrip() for line in fd]
                for url in url_list:
                    flag = False
                    for substring in substring_list:
                        if re.fullmatch(substring, url):  # check is found url in exclude_list with regexp
                            flag = True
                            break
                    if not flag and url not in filtered_urls:
                        filtered_urls.append(url)
        return list(set(filtered_urls))
    except Exception as ex:
        logger.error(f'Error in filter_url_by_repo: {ex}')
        return []


def is_time_format(input_str):
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


def filter_url_by_DB(url_list):
    filtered_urls = []
    url_dump_from_DB = constants.url_from_DB  # list with dict: {url:final_resul}

    for url_leak in url_list:
        is_need_to_add = True
        for url_from_DB in url_dump_from_DB.keys():
            if url_leak == url_from_DB and not (url_dump_from_DB[url_from_DB] in constants.RESULT_CODES):
                is_need_to_add = False
                break
        if is_need_to_add:
            filtered_urls.append(url_leak)
    return list(set(filtered_urls))


def _exc_catcher(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as ex:
            logger.error(
                f"Exception occured in {func.__name__}. \nException: {ex}")
            return 2

    return wrapper


class CheckRepo:
    dork = None
    SECRETS = None
    old_dir = None
    url = None
    repo_dir = None

    @classmethod
    def _clean_repo_dirs(cls):
        if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}"):
            shutil.rmtree(f"{constants.TEMP}/{cls.repo_dir}")
        if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}---reports"):
            shutil.rmtree(f"{constants.TEMP}/{cls.repo_dir}---reports")

    @classmethod
    def _pywhat_analyze_names(cls, match):
        all_names = []
        res_analyze = pywhat_analyze(match)
        for i in res_analyze:
            all_names.append(i['Name'])
        if not len(all_names):
            all_names.append('None')
        return all_names

    @classmethod
    def _clone(cls):
        try:
            cls._clean_repo_dirs()
            os.makedirs(f"{constants.TEMP}/{cls.repo_dir}---reports")

            gitclone_proc = subprocess.Popen(['git', 'clone', f'{cls.url}', f'/{constants.TEMP}/{cls.repo_dir}'],
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            while gitclone_proc.poll() is None:
                if os.path.exists(constants.COMMAND_FILE):
                    fd = open(constants.COMMAND_FILE, 'r')
                    command_line = fd.readline()
                    if command_line == 'skip' or command_line == 'skip\n':
                        fd.close()
                        open(constants.COMMAND_FILE, 'w').close()
                        time.sleep(1)
                        gitclone_proc.kill()
                        logger.info(f'\nGit clone skipped')
                        print(
                            f'Canceling git clonning repo: {cls.url.split("/")[-2] + "/" + cls.url.split("/")[-1]}')
                        cls._clean_repo_dirs()
                        return {'Skipped': 'git clonning'}
                    elif command_line == 'stop' or command_line == 'stop\n':
                        fd.close()
                        open(constants.COMMAND_FILE, 'w').close()
                        time.sleep(1)
                        gitclone_proc.kill()
                        logger.info(f'\nSend stop-command')
                        cls._clean_repo_dirs()
                        return 1
                    else:
                        fd.close()
        except Exception as ex:
            logger.error(f'\nERROR in cloning repository: {ex}')
            if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}"):
                os.chdir(cls.old_dir)
                cls._clean_repo_dirs()
            return {'Error': 'Exception in git clonning'}

        ''' 
   @classmethod
    def _pydriller_scan(cls):
        foundSet = set()  # нужен был для поиска base64 строк в коде ниже

        # Scan for commiters and base64 by pydriller
        cls.SECRETS['Base64_strings'] = None
        cls.SECRETS['Commiters'] = None

        try:
            for commit in Repository(f'./{cls.repo_dir}').traverse_commits():
                # Scan for base64 strings and commits authors by Pydriller
                if cls.SECRETS['Commiters'] is None:
                    cls.SECRETS['Commiters'] = [str(commit.author.name)]
                # Add uniq names of commiters
                elif commit.author.name not in cls.SECRETS['Commiters']:
                    cls.SECRETS['Commiters'].append(  # type: ignore
                        str(commit.author.name))

                for mod in commit.modified_files:
                    if mod.source_code_before is not None:
                        regex = re.findall(
                            r"<text encoding=\"base64\">[^>]+</text>", mod.source_code_before)
                        for result in regex:
                            based = str(base64.b64decode(
                                result[len("<text encoding='base64'>"):-len("</text>")]))
                            if based not in foundSet:
                                # type: ignore
                                cls.SECRETS['Base64_strings'] += based
                                foundSet.add(based + "\n")
            logger.info('Commiters and base64 strings added')
        except Exception as ex:
            logger.error(f'Error in PyDriller:\n{ex}\n')
        '''

    @classmethod
    def _grep_scan(cls):
        counter = 1
        try:
            for folder, _, files in os.walk('./'):
                for file in files:
                    fullpath = os.path.join(folder, file)
                    with open(fullpath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f.readlines():
                            for leak in constants.leak_check_list:
                                if cls.dork in line or leak in line:
                                    cls.SECRETS['grepscan'][f'Leak #{counter}']['Match'] = str(
                                        line[0:120])
                                    cls.SECRETS['grepscan'][f'Leak #{counter}']['File'] = str(
                                        fullpath)
                                counter += 1
        except Exception as ex:
            logger.error(f'Error in grepscan: {ex}\n')
            return 2
        return 0

    @classmethod
    # @_exc_catcher
    def _scan(cls, mode=1):
        if mode == 3:
            constants.MAX_TIME_TO_SCAN_BY_UTIL = 3000

        create_date_proc = subprocess.Popen('git log --reverse --format=\"format:%as\" --all | head -n 1',
                                            shell=True, stdout=subprocess.PIPE)

        cls.SECRETS['created_at'] = \
            create_date_proc.communicate(
            )[0].decode('utf-8').split('\n')[0].split('T')[0]

        update_date_proc = subprocess.Popen('git log --format=\"format:%as\" --all | head -n 1',
                                            shell=True, stdout=subprocess.PIPE)

        cls.SECRETS['updated_at'] = update_date_proc.communicate(
        )[0].decode('utf-8').split('\n')[0].split('T')[0]

        os.chdir(f"{constants.TEMP}/{cls.repo_dir}")
        for file_name in os.listdir('.'):
            if file_name.endswith('.ipynb'):
                cls.SECRETS['status'] = ['Тип файла ipynb (Jupyther).']
                os.remove(file_name)
            if file_name.endswith('.png'):
                cls.SECRETS['status'] = ['Тип файла PNG картинка.']
                os.remove(file_name)
            if file_name.endswith('.svg'):
                cls.SECRETS['status'] = ['Тип файла SVG картинка.']
                os.remove(file_name)

        scans = {
            'gitleaks': cls._gitleaks_scan,
            'gitsecrets': cls._gitsecrets_scan,
            'whispers': cls._whispers_scan,
            'trufflehog': cls._trufflehog_scan,
            'grepscan': cls._grep_scan,
            'deepsecrets': cls._deepsecrets_scan
        }
        deep_scans = {
            'gitleaks': cls._gitleaks_scan,
            'gitsecrets': cls._gitsecrets_scan,
            'whispers': cls._whispers_scan,
            'trufflehog': cls._trufflehog_scan,
            'grepscan': cls._grep_scan,
            'deepsecrets': cls._deepsecrets_scan,
            'ioc_finder': cls._ioc_finder_scan
            # ,'ioc_extractor': cls._ioc_extractor
        }

        num_of_methods = len(scans)
        with ThreadPoolExecutor(max_workers=num_of_methods) as executor:
            futures = {executor.submit(method): name for name, method in scans.items()}

            for future in as_completed(futures):
                res, method = future.result(), futures[future]
                if res == 1:
                    return 1
                elif res == 2:
                    logger.error(
                        f'Excepted error in {method} scan, check log file!')
                elif res == 3:
                    print(
                        f'Canceling {method} scan in repo: {"/".join(cls.url.split("/")[-2:])}')
                elif res == 4:
                    cls.SECRETS[method] = f'{method} has\'t found any leaks.'
                else:
                    logger.info(f'Finished {CLR["BOLD"]}{method}{CLR["RESET"]}')

        if mode == 3:
            num_of_deep_methods = len(deep_scans)
            with ThreadPoolExecutor(max_workers=num_of_deep_methods) as executor:
                futures = {executor.submit(method): name for name, method in deep_scans.items()}

                for future in as_completed(futures):
                    res, method = future.result(), futures[future]
                    if res == 1:
                        return 1
                    elif res == 2:
                        logger.error(f'Excepted error in {method} scan, check log file!')
                    elif res == 3:
                        print(
                            f'Canceling {method} scan in repo: {"/".join(cls.url.split("/")[-2:])}')
                    elif res == 4:
                        cls.SECRETS[method] = f'{method} has\'t found any leaks.'
                    else:
                        logger.info(f'Finished {CLR["BOLD"]}{method}{CLR["RESET"]}')

        os.chdir(cls.old_dir)
        shutil.rmtree(f"{constants.TEMP}/{cls.repo_dir}")
        shutil.rmtree(f"{constants.TEMP}/{cls.repo_dir}---reports")

        if mode == 3:
            constants.MAX_TIME_TO_SCAN_BY_UTIL = 1000

        return cls.SECRETS

    @classmethod
    @_exc_catcher
    def _gitleaks_scan(cls):
        try:
            tr = time.perf_counter()

            gitleaks_proc = subprocess.Popen(['gitleaks', 'detect', '--no-banner', '--no-color',
                                              '--report-format', 'json', '-r', './gitleaks_rep.json'],
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            while gitleaks_proc.poll() is None:
                if time.perf_counter() - tr > constants.MAX_TIME_TO_SCAN_BY_UTIL:
                    gitleaks_proc.kill()
                    logger.info(f'\nTimeout occured')
                    if os.path.exists('gitleaks_rep.json'):
                        os.remove(f'gitleaks_rep.json')
                    return 3
                if os.path.exists(constants.COMMAND_FILE):
                    fd = open(constants.COMMAND_FILE, 'r')
                    command_line = fd.readline()
                    if command_line == 'skip' or command_line == 'skip\n':
                        fd.close()
                        open(constants.COMMAND_FILE, 'w').close()
                        time.sleep(1)
                        gitleaks_proc.kill()
                        if os.path.exists('gitleaks_rep.json'):
                            os.remove(f'gitleaks_rep.json')
                        return 3
                    elif command_line == 'stop' or command_line == 'stop\n':
                        fd.close()
                        open(constants.COMMAND_FILE, 'w').close()
                        time.sleep(1)
                        gitleaks_proc.kill()
                        logger.info(f'\nSend stop-command')
                        if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}"):
                            shutil.rmtree(
                                f"{constants.TEMP}/{cls.repo_dir}")
                            shutil.rmtree(
                                f"{constants.TEMP}/{cls.repo_dir}---reports")
                        return 1
                    else:
                        fd.close()
        except Exception as ex:
            if 'status 1' not in str(ex):
                logger.error(f'Error in gitleaks:\n{ex}\n')
                return 2

            if os.path.exists('gitleaks_rep.json'):
                with open('gitleaks_rep.json', 'r') as file:
                    js = json.load(file)
                    is_first = True
                    counter = 1
                    for i in range(len(js)):
                        a = True
                        if not is_first:
                            for _, v in cls.SECRETS['gitleaks'].items():
                                if str(js[i]['Match']) == v['Match']:
                                    a = False
                                    break
                                else:
                                    a = True
                        if a:
                            is_first = False
                            cls.SECRETS['gitleaks'][f'Leak #{counter}']['Match'] = str(
                                js[i]['Match'][0:120])
                            cls.SECRETS['gitleaks'][f'Leak #{counter}']['File'] = str(
                                js[i]['File'])
                            cls.SECRETS['gitleaks'][f'Leak #{counter}']['Email'] = str(
                                js[i]['Email'])
                            cls.SECRETS['gitleaks'][f'Leak #{counter}']['Names'] = cls._pywhat_analyze_names(str(
                                cls.SECRETS['gitleaks'][f'Leak #{counter}']['Match']))
                            counter += 1
                if cls.SECRETS['gitleaks'] is None:
                    cls.SECRETS['gitleaks'] = 'Not founded any leaks'
                Path(f"{constants.TEMP}/{cls.repo_dir}/gitleaks_rep.json").rename(
                    f"{constants.TEMP}/{cls.repo_dir}---reports/gitleaks_rep.json")
                return 0

    @classmethod
    @_exc_catcher
    def _gitsecrets_scan(cls):
        subprocess.run(['git', 'secrets', '--install', '-f'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=1000)
        subprocess.run(['git', 'secrets', '--register-aws'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=1000)
        subprocess.run(['git', 'secrets', '--aws-provider'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=1000)
        tr = time.perf_counter()
        gitsecret_proc = subprocess.Popen(['git', 'secrets', '--scan', '-r', '.'], stderr=subprocess.STDOUT,
                                          stdout=subprocess.PIPE)

        while gitsecret_proc.poll() is None:
            if time.perf_counter() - tr > constants.MAX_TIME_TO_SCAN_BY_UTIL:
                gitsecret_proc.kill()
                logger.info(f'\nTimeout occured')
                logger.info('gitleaks scan skipped')
                return 3
            if os.path.exists(constants.COMMAND_FILE):
                fd = open(constants.COMMAND_FILE, 'r')
                command_line = fd.readline()
                if command_line == 'skip' or command_line == 'skip\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    gitsecret_proc.kill()
                    logger.info('gitleaks scan skipped')
                    return 3
                elif command_line == 'stop' or command_line == 'stop\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    gitsecret_proc.kill()
                    logger.info(f'\nSend stop-command')
                    if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}"):
                        shutil.rmtree(f"{constants.TEMP}/{cls.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{cls.repo_dir}---reports")
                    return 1
                else:
                    fd.close()
        is_first = True
        counter = 1

        with open('gitsecrets_rep.json', 'w') as file:
            for i in str(gitsecret_proc.communicate()[0].decode('utf-8')).split('\n'):
                file.write(i)
                if '\"Match\"' in i:
                    gitsecret = i.split('\"Match\"')
                elif ' - ' in i:
                    gitsecret = i.split(' - ')
                else:
                    cls.SECRETS['gitsecrets'] = 'Not founded any leaks'
                    return 0
                a = True
                if not is_first:
                    for _, v in cls.SECRETS['gitsecrets'].items():
                        if str(gitsecret[1]) == v['Match']:
                            a = False
                            break
                        else:
                            a = True
                if a:
                    is_first = False
                    cls.SECRETS['gitsecrets'][f'Leak #{counter}']['Match'] = str(
                        gitsecret[1][0:120])
                    cls.SECRETS['gitsecrets'][f'Leak #{counter}']['Names'] = cls._pywhat_analyze_names(str(
                        cls.SECRETS['gitsecrets'][f'Leak #{counter}']['Match']))
                    cls.SECRETS['gitsecrets'][f'Leak #{counter}']['File'] = str(
                        gitsecret[0].split(':')[0])
                    counter += 1
        Path(f"{constants.TEMP}/{cls.repo_dir}/gitsecrets_rep.json").rename(
            f"{constants.TEMP}/{cls.repo_dir}---reports/gitsecrets_rep.json")

    @classmethod
    @_exc_catcher
    def _whispers_scan(cls):
        tr = time.perf_counter()

        whisper = subprocess.Popen(
            ['whispers', './'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        while whisper.poll() is None:
            if time.perf_counter() - tr > constants.MAX_TIME_TO_SCAN_BY_UTIL:
                whisper.kill()
                logger.info(f'\nTimeout occured')
                logger.info('Whisper scan skipped')
                return 3
            if os.path.exists(constants.COMMAND_FILE):
                fd = open(constants.COMMAND_FILE, 'r')
                command_line = fd.readline()
                if command_line == 'skip' or command_line == 'skip\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    whisper.kill()
                    logger.info('Whisper scan skipped')
                    return 3
                elif command_line == 'stop' or command_line == 'stop\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    whisper.kill()
                    logger.info(f'\nSend stop-command')
                    if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}"):
                        shutil.rmtree(f"{constants.TEMP}/{cls.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{cls.repo_dir}---reports")
                    return 1
                else:
                    fd.close()

        with open('whisper_rep.txt', 'wb') as file:
            file.write(whisper.communicate()[0])
        whisper_list = []
        with open('whisper_rep.txt', 'r') as file:
            for line in file:
                whisper_list.append(json.loads(line))

        is_first = True
        counter = 1
        for i in whisper_list:
            if len(i) < 50 or len(i) == 125:  # 125 - false - whispers.log
                break
            a = True
            if not is_first:
                for _, v in cls.SECRETS['whispers'].items():
                    if f'{i["key"]} {i["value"]}' == v['Match']:
                        a = False
                        break
                    else:
                        a = True
            if a:
                is_first = False
                cls.SECRETS['whispers'][f'Leak #{counter}']['Match'] = str(
                    f'{i["key"] + " " + i["value"]}'[0:120])
                cls.SECRETS['whispers'][f'Leak #{counter}']['Names'] = cls._pywhat_analyze_names(str(
                    cls.SECRETS['whispers'][f'Leak #{counter}']['Match']))
                cls.SECRETS['whispers'][f'Leak #{counter}']['File'] = str(
                    i["file"])
                counter += 1

            if cls.SECRETS['whispers'] is None:
                cls.SECRETS['whispers'] = 'Not founded any leaks'
            Path(f"{constants.TEMP}/{cls.repo_dir}/whisper_rep.txt").rename(
                f"{constants.TEMP}/{cls.repo_dir}---reports/whisper_rep.txt")
            return 0

    @classmethod
    @_exc_catcher
    def _trufflehog_scan(cls):
        tr = time.perf_counter()

        trufflehog = subprocess.Popen(['trufflehog', 'git', '--json', '--no-update', 'file://.'],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        while trufflehog.poll() is None:
            if time.perf_counter() - tr > constants.MAX_TIME_TO_SCAN_BY_UTIL:
                trufflehog.kill()
                logger.info(f'\nTimeout occured')
                logger.info('trufflehog scan skipped')
                return 3
            if os.path.exists(constants.COMMAND_FILE):
                fd = open(constants.COMMAND_FILE, 'r')
                command_line = fd.readline()
                if command_line == 'skip' or command_line == 'skip\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    trufflehog.kill()
                    logger.info('trufflehog scan skipped')
                    return 3
                elif command_line == 'stop' or command_line == 'stop\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    trufflehog.kill()
                    logger.info(f'\nSend stop-command')
                    if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}"):
                        shutil.rmtree(f"{constants.TEMP}/{cls.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{cls.repo_dir}---reports")
                    return 1
                else:
                    fd.close()

        with open('trufflehog_rep.txt', 'wb') as file:
            var = trufflehog.communicate()[0]
            file.write(var)

        trufflehog_list = []
        with open('trufflehog_rep.txt', 'r') as file:
            for line in file:
                trufflehog_list.append(json.loads(line))
        is_first = True
        counter = 1
        for i in trufflehog_list:
            a = True

            if i['RawV2'] != '':
                match = i['RawV2']
            elif i['Raw'] != '':
                match = i['Raw']
            else:
                match = ''
            if not is_first:
                for _, v in cls.SECRETS['trufflehog'].items():
                    if match == '' or str(match) == v['Match']:
                        a = False
                        break
                    else:
                        a = True
            if a and match != '':
                is_first = False
                cls.SECRETS['trufflehog'][f'Leak #{counter}']['Match'] = str(
                    match[0:120])
                cls.SECRETS['trufflehog'][f'Leak #{counter}']['Name'] = cls._pywhat_analyze_names(str(
                    cls.SECRETS['trufflehog'][f'Leak #{counter}']['Match']))
                cls.SECRETS['trufflehog'][f'Leak #{counter}']['File'] = str(
                    i['SourceMetadata']['Data']['Filesystem'][
                        'file'])
                counter += 1
            if cls.SECRETS['trufflehog'] is None:
                cls.SECRETS['trufflehog'] = 'Not founded any leaks'
            Path(f"{constants.TEMP}/{cls.repo_dir}/trufflehog_rep.txt").rename(
                f"{constants.TEMP}/{cls.repo_dir}---reports/trufflehog_rep.txt")
            return 0

    @classmethod
    @_exc_catcher
    def _deepsecrets_scan(cls):

        tr = time.perf_counter()
        deepsecrets_proc = subprocess.Popen(['deepsecrets', '--target-dir', '.', '--outfile',
                                             'deepsecrets_rep.json'],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        while deepsecrets_proc.poll() is None:
            if time.perf_counter() - tr > constants.MAX_TIME_TO_SCAN_BY_UTIL:
                deepsecrets_proc.kill()
                logger.info(f'\nTimeout occured')
                if os.path.exists('deepsecrets_rep.json'):
                    os.remove(f'deepsecrets_rep.json')
                return 3
            if os.path.exists(constants.COMMAND_FILE):
                fd = open(constants.COMMAND_FILE, 'r')
                command_line = fd.readline()
                if command_line == 'skip' or command_line == 'skip\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    deepsecrets_proc.kill()
                    if os.path.exists('deepsecrets_rep.json'):
                        os.remove(f'deepsecrets_rep.json')
                    return 3
                elif command_line == 'stop' or command_line == 'stop\n':
                    fd.close()
                    open(constants.COMMAND_FILE, 'w').close()
                    time.sleep(1)
                    deepsecrets_proc.kill()
                    logger.info(f'\nSend stop-command')
                    if os.path.exists(f"{constants.TEMP}/{cls.repo_dir}"):
                        shutil.rmtree(
                            f"{constants.TEMP}/{cls.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{cls.repo_dir}---reports")
                    return 1
                else:
                    fd.close()
        if os.path.exists('deepsecrets_rep.json'):
            with open('deepsecrets_rep.json', 'r') as file:
                js = json.load(file)
                is_first = True
                counter = 1

                for i in js:
                    for j in js[i]:
                        a = True
                        if not is_first:
                            for _, v in cls.SECRETS['deepsecrets'].items():
                                if str(j['line'][:120]) == v['Match']:
                                    a = False
                                    break
                                else:
                                    a = True
                        if a:
                            is_first = False
                            cls.SECRETS['deepsecrets'][f'Leak #{counter}']['Match'] = str(
                                j['line'][:120])
                            cls.SECRETS['deepsecrets'][f'Leak #{counter}']['Name'] = cls._pywhat_analyze_names(str(
                                cls.SECRETS['deepsecrets'][f'Leak #{counter}']['Match']))
                            cls.SECRETS['deepsecrets'][f'Leak #{counter}']['File'] = str(
                                i)
                            counter += 1
            if cls.SECRETS['deepsecrets'] is None:
                cls.SECRETS['deepsecrets'] = 'Not founded any leaks'

            Path(f"{constants.TEMP}/{cls.repo_dir}/deepsecrets_rep.json").rename(
                f"{constants.TEMP}/{cls.repo_dir}---reports/deepsecrets_rep.json")
            return 0
        else:
            logger.error('File deepsecrets_rep.json not founded\n')
            return 2

    @classmethod
    @_exc_catcher
    def _ioc_finder_scan(cls):
        try:
            all_iocs = {'urls': [], 'xmpp_addresses': [], 'email_addresses_complete': [], 'email_addresses': [],
                        'ipv4_cidrs': [],
                        'imphashes': [], 'authentihashes': [], 'domains': [], 'ipv4s': [], 'ipv6s': [], 'sha512s': [],
                        'sha256s': [],
                        'sha1s': [], 'md5s': [], 'ssdeeps': [], 'asns': [], 'cves': [], 'registry_key_paths': [],
                        'google_adsense_publisher_ids': [], 'google_analytics_tracker_ids': [], 'bitcoin_addresses': [],
                        'monero_addresses': [], 'mac_addresses': [], 'user_agents': [], 'tlp_labels': [],
                        'attack_mitigations': {'enterprise': [], 'mobile': []},
                        'attack_tactics': {'pre_attack': [], 'enterprise': [], 'mobile': []},
                        'attack_techniques': {'pre_attack': [], 'enterprise': [], 'mobile': []}, 'file_paths': []}
            for folder, _, files in os.walk('./'):
                for file in files:
                    fullpath = os.path.join(folder, file)
                    with open(fullpath, 'r', encoding='utf-8', errors='ignore') as f:
                        text = f.read()
                        iocs = find_iocs(text)
                        for key in iocs.keys():
                            if type(iocs[key]) is dict:
                                for i in iocs[key].keys():
                                    if len(iocs[key][i]):
                                        if type(iocs[key][i]) is list:
                                            for j in iocs[key][i]:
                                                all_iocs[key].append(j)
                                        else:
                                            all_iocs[key].append(iocs[key][i])
                            elif len(iocs[key]):
                                if type(iocs[key]) is list:
                                    for i in iocs[key]:
                                        all_iocs[key].append(i)
                                else:
                                    all_iocs[key].append(iocs[key])
            res_dict = constants.AutoVivification()
            for key in all_iocs.keys():
                if all_iocs[key]:
                    all_iocs[key] = list(set(all_iocs[key]))
                    res_dict[key] = []
                    for i in all_iocs[key]:
                        if len(i) > 6:  # clear false like dw.gz
                            res_dict[key].append(i)

            cls.SECRETS['ioc_finder'] = res_dict
            return 0
        except Exception as ex:
            logger.error(f'Error in ioc_finder: {ex}\n')
            return 2

    @classmethod
    @_exc_catcher
    def _ioc_extractor(cls):
        all_iocs = {"asns": [], "btcs": [], "cves": [], "domains": [], "emails": [],
                    "eths": [], "gaPubIDs": [], "gaTrackIDs": [], "ipv4s": [],
                    "ipv6s": [], "macAddresses": [], "md5s": [], "sha1s": [],
                    "sha256s": [], "sha512s": [], "ssdeeps": [], "urls": [],
                    "xmrs": []}

        tr = time.perf_counter()
        try:
            for folder, _, files in os.walk('.'):
                for file in files:
                    fullpath = os.path.join(folder, file)
                    with open(fullpath, 'rb') as f:
                        text_file = f.read()
                        ioc_extractor_proc = subprocess.Popen(['ioc-extractor'], stdin=subprocess.PIPE,
                                                              stdout=subprocess.PIPE,
                                                              stderr=subprocess.DEVNULL)
                        while ioc_extractor_proc.poll() is None:
                            if time.perf_counter() - tr > constants.MAX_TIME_TO_SCAN_BY_UTIL:
                                ioc_extractor_proc.kill()
                                logger.info(f'\nTimeout occured')
                                return 3
                        res = ioc_extractor_proc.communicate(input=text_file)[
                            0].decode('utf-8')
                        iocs = json.loads(res)
                        for key in iocs.keys():
                            if type(iocs[key]) is list and len(iocs[key]):
                                for i in iocs[key]:
                                    all_iocs[key].append(i)

        except Exception as ex:
            logger.error(f'Exception in ioc_extractor: {ex}\n')
            return 2
        else:
            res_dict = constants.AutoVivification()
            all_iocs['ipv4s'] = list(
                filter(lambda item: item != '127.0.0.1', all_iocs['ipv4s']))
            all_iocs['urls'] = list(
                filter(lambda item: '127.0.0.1' not in item and 'localhost' not in item, all_iocs['urls']))
            all_iocs['ipv6s'] = list(
                filter(lambda item: item != '::', all_iocs['ipv6s']))
            for key in all_iocs.keys():
                if len(all_iocs[key]):
                    res_dict[key] = all_iocs[key]
            cls.SECRETS['ioc_extractor'] = res_dict
            return 0

    @classmethod
    def run(cls, url, dork, mode=1):  # DEBUG (in normal mode = 500
        """
            скачивает репозиторий по ссылке из url и проверяет с помощью сканеров TODO
            в конце, скаченный репозиторий удаляется,
            а обнаруженные секреты добавляются в словарь secrets
        """

        cls.old_dir = os.getcwd()
        cls.SECRETS = constants.AutoVivification()
        cls.url = url
        cls.dork = dork

        logger.info(f'{CLR["GREEN"]}\n{url}{CLR["RESET"]}')

        # logger.info('Time in check_repo func: ' + str(datetime.now()) + '\n')
        # Commented because logger shows time and date as well

        cls.repo_dir = url.split('/')[-2] + '---' + url.split('/')[-1]
        res = {'Result': 'Not founded'}
        cls._clone()
        if mode == 1:
            # cls._pydriller_scan()
            res = cls._scan()
        elif mode == 2 or mode == 3:
            res = cls._scan(mode)
        return res
