# Standart libs import
import random
import json
from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import subprocess
from pathlib import Path
import re
import time
import datetime
import tracemalloc

import git

# Project lib's import
from ioc_finder import find_iocs

from src import Connector, constants
from src.logger import logger, CLR
from src.searcher.GitStats import GitParserStats

exclusions: tuple[str]

with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'r') as fd:
    exclusions = tuple(line.rstrip() for line in fd)


def trace_monitor():
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.compare_to(constants.snap_backup, "lineno")
    logger.info("---------------------------------------------------------")
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
    logger.info("---------------------------------------------------------")


def dumping_data():
    logger.info('---------------------------------n')
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
    if os.path.exists(constants.TEMP):
        for root, dirs, files in os.walk('constants.TEMP'):
            for f in files:
                os.unlink(os.path.join(root, f))
            for d in dirs:
                shutil.rmtree(os.path.join(root, d))
    logger.info('Process info after dump to DB and clearing')
    trace_monitor()
    logger.info('---------------------------------')


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
    # add urls to exclude_list.txt, which were have in DB result euqal
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
            with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'r') as file:
                url_from_exclude_list = [line.rstrip() for line in file]
            if not (url in url_from_exclude_list):
                url_from_exclude_list.append(url)
                with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'w') as file:
                    for url_from_list in url_from_exclude_list:
                        file.write(url_from_list + '\n')
        elif isinstance(url, list):
            url = [convert_to_regex_pattern(str_to_regexp) for str_to_regexp in url]
            with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'r') as file:
                url_from_exclude_list = [line.rstrip() for line in file]
            is_need_to_upd = False
            for new_url in url:
                if not new_url in url_from_exclude_list:
                    url_from_exclude_list.append(new_url)
                    is_need_to_upd = True
            if is_need_to_upd:
                with open(f'{constants.MAIN_FOLDER_PATH}/src/exclude_list.txt', 'w') as file:
                    for url_from_list in url_from_exclude_list:
                        file.write(url_from_list + '\n')
        else:
            logger.error("Error in adding excludes in exclude_list.txt (_add_repo_to_exclude): Unknown data type!")
    except Exception as ex:
        logger.error('Error in adding excludes in exclude_list.txt (_add_repo_to_exclude): %s', ex)


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


def filter_url_by_db(urls: list[str] | tuple[str] | str):
    if isinstance(urls, str):
        urls = (urls,)
    filtered_urls = []

    url_dump_from_db = constants.url_from_DB  # list with dict: {url:final_resul}
    if url_dump_from_db == '-':
        return urls

    for url in urls:
        to_add = True
        temp_del = url.split('https://github.com/')[1]
        url = 'https://github.com/' + temp_del.split('/')[0] + '/' + temp_del.split('/')[1]

        for url_from_db, value in url_dump_from_db.items():
            if url == url_from_db and not value in constants.RESULT_CODES:
                to_add = False
                break

        if to_add:
            filtered_urls.append(url)

    return filtered_urls


def _exc_catcher(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as exc:
            logger.error("Exception in %s: %s", func.__name__, exc)
            return 2

    return wrapper


class CheckerException(Exception):
    pass


INITED = 0x0001
CLONED = 0x0002
SCANNED = 0x0004
NOT_CLONED = 0x0008


class Checker:
    file_ignore = ('.ipynb', '.png', '.svg')

    def __init__(self, url: str, dork: str, obj: any, mode: int = 1, token: str = '') -> None:
        self.url = url
        self.obj = obj
        self.dork = dork
        self.mode = mode
        self.repo_dir = url.split('/')[-2] + '---' + url.split('/')[-1]
        self.secrets = constants.AutoVivification()
        self.secrets['status'] = []
        self.repo: git.Repo
        self.status = INITED
        self.token: str = token

        self.scan_time_limit = 3000 if self.mode == 3 else 1000

        self.scans = {
            'gitleaks': self.gitleaks_scan,
            'gitsecrets': self.gitsecrets_scan,
            'whispers': self.whispers_scan,
            # 'trufflehog': Checker._trufflehog_scan, TODO some problems 'Filesystem'
            'grepscan': self.grep_scan,
            'deepsecrets': self.deepsecrets_scan
        }

        self.deep_scans = {
            'ioc_finder': self.ioc_finder_scan
            # ,'ioc_extractor': self._ioc_extractor
        }
        self.obj.stats = GitParserStats(self.url, self.token).get_stats()

    def _clean_repo_dirs(self):
        if os.path.exists(f"{constants.TEMP}/{self.repo_dir}"):
            shutil.rmtree(f"{constants.TEMP}/{self.repo_dir}")
        if os.path.exists(f"{constants.TEMP}/{self.repo_dir}---reports"):
            shutil.rmtree(f"{constants.TEMP}/{self.repo_dir}---reports")

    def _pywhat_analyze_names(self, match):
        all_names = []
        res_analyze = pywhat_analyze(match, f'{constants.TEMP}/{self.repo_dir}')
        for i in res_analyze:
            all_names.append(i['Name'])
        if len(all_names) < 1:
            all_names.append('None')
        return all_names

    def clone(self):
        logger.info(f'Repository {self.url} size: {self.obj.stats["size"]}')
        if self.obj.stats['size'] > constants.REPO_MAX_SIZE:
            logger.info('Repository %s oversize, code not analyze', self.url)
            self.obj.secrets['status'].append(f'Repository {self.url} is oversize, code not analyze')
            self._clean_repo_dirs()
            self.status |= NOT_CLONED
            logger.info('Clonning %s', self.url)

            for try_clone in range(3):
                try:
                    self._clean_repo_dirs()
                    self.repo = git.Repo.clone_from(
                        self.url, f'/{constants.TEMP}/{self.repo_dir}')
                    self.clean_excluded_files()
                    os.makedirs(f"{constants.TEMP}/{self.repo_dir}---reports")
                    self.get_dates()
                    break
                except Exception as exc:
                    time.sleep(1)
                    pass
            else:
                logger.error('Failed to clone repo %s', self.url)
                self._clean_repo_dirs()
        else:
            self.status |= CLONED

    def grep_scan(self):
        counter = 1
        try:
            for folder, _, files in os.walk(f"{constants.TEMP}/{self.repo_dir}"):
                for file in files:
                    fullpath = os.path.join(folder, file)
                    with open(fullpath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f.readlines():
                            for leak in constants.leak_check_list:
                                if self.dork in line or leak in line:
                                    self.secrets['grepscan'][f'Leak #{counter}']['Match'] = str(
                                        line[:120])
                                    self.secrets['grepscan'][f'Leak #{counter}']['File'] = str(
                                        fullpath)
                                counter += 1
        except Exception as ex:
            logger.error('Error in grepscan: %s', ex)
            return 2

        return 0

    def get_dates(self):
        if self.repo is None:
            raise CheckerException(
                "In get_dates(): repositiory must be clone()-ed")

        first_commit = next(self.repo.iter_commits('--all', reverse=True))
        self.secrets['created_at'] = first_commit.authored_datetime.timetuple()

        last_commit = next(self.repo.iter_commits('--all'))
        self.secrets['updated_at'] = last_commit.authored_datetime.timetuple()

    def clean_excluded_files(self):
        repo_path: str = f"{constants.TEMP}/{self.repo_dir}"

        for file_name in os.listdir(repo_path):
            for ext in self.file_ignore:
                if file_name.endswith(ext):
                    self.secrets['status'].append(f'File extension: {ext}')
                    os.remove(f'{repo_path}/{file_name}')

    def scan(self):
        log_color = random.choice(tuple(CLR.values()))
        logger.info('Started scan: %s | %s %s %s ', self.dork, log_color,
                    self.url, CLR["RESET"])

        # TODO take max_workers from config
        with ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(lambda method:
                                        (self.scans[method], method),
                                        (self.scans | self.deep_scans
                                         if self.mode == 3
                                         else self.scans).keys()))

        for res, method_name in results:
            if res == 1:
                return 1

            if res == 2:
                logger.error('Excepted error in %s scan, check log file!',
                             method_name)
            elif res == 3:
                print(f'Canceling {method_name} scan in repo: {"/".join(self.url.split("/")[-2:])}')
            elif res == 4:
                self.secrets[method_name] = f'{method_name} hasn\'t found any leaks.'

        logger.info('Scanned: %s | %s %s %s ', self.dork, log_color, self.url,
                    CLR["RESET"])

        return self.secrets

    @_exc_catcher
    def gitleaks_scan(self):
        try:
            tr = time.perf_counter()

            gitleaks_proc = subprocess.Popen([
                'gitleaks detect --no-banner --no-color --report-format json \
                    -r ./gitleaks_rep.json'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=f'{constants.TEMP}/{self.repo_dir}')
            while gitleaks_proc.poll() is None:
                if time.perf_counter() - tr > self.scan_time_limit:
                    gitleaks_proc.kill()
                    logger.info('Timeout occured')
                    if os.path.exists('gitleaks_rep.json'):
                        os.remove('gitleaks_rep.json')
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
                            os.remove('gitleaks_rep.json')
                        return 3
                    elif command_line == 'stop' or command_line == 'stop\n':
                        fd.close()
                        open(constants.COMMAND_FILE, 'w').close()
                        time.sleep(1)
                        gitleaks_proc.kill()
                        logger.info('Send stop-command')
                        if os.path.exists(f"{constants.TEMP}/{self.repo_dir}"):
                            shutil.rmtree(
                                f"{constants.TEMP}/{self.repo_dir}")
                            shutil.rmtree(
                                f"{constants.TEMP}/{self.repo_dir}---reports")
                        return 1
                    else:
                        fd.close()
        except Exception as ex:
            if 'status 1' not in str(ex):
                logger.error('Error in gitleaks: %s', ex)
                return 2

            if os.path.exists('gitleaks_rep.json'):
                with open('gitleaks_rep.json', 'r') as file:
                    js = json.load(file)
                    is_first = True
                    counter = 1
                    for elem in js:
                        a = True
                        if not is_first:
                            for _, v in self.secrets['gitleaks'].items():
                                if str(elem['Match']) == v['Match']:
                                    a = False
                                    break
                                a = True
                        if a:
                            is_first = False
                            self.secrets['gitleaks'][f'Leak #{counter}']['Match'] = str(
                                elem['Match'][0:120])
                            self.secrets['gitleaks'][f'Leak #{counter}']['File'] = str(
                                elem['File'])
                            self.secrets['gitleaks'][f'Leak #{counter}']['Email'] = str(
                                elem['Email'])
                            self.secrets['gitleaks'][f'Leak #{counter}']['Names'] = self._pywhat_analyze_names(str(
                                self.secrets['gitleaks'][f'Leak #{counter}']['Match']))
                            counter += 1
                if self.secrets['gitleaks'] is None:
                    self.secrets['gitleaks'] = 'Not founded any leaks'
                Path(f"{constants.TEMP}/{self.repo_dir}/gitleaks_rep.json").rename(
                    f"{constants.TEMP}/{self.repo_dir}---reports/gitleaks_rep.json")
                return 0

    @_exc_catcher
    def gitsecrets_scan(self):
        subprocess.run(['git', 'secrets', '--install', '-f'],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       timeout=1000)
        subprocess.run(['git', 'secrets', '--register-aws'],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       timeout=1000)
        subprocess.run(['git', 'secrets', '--aws-provider'],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       timeout=1000)
        tr = time.perf_counter()
        gitsecret_proc = subprocess.Popen(['git', 'secrets', '--scan', '-r',
                                           '.'],
                                          stderr=subprocess.STDOUT,
                                          stdout=subprocess.PIPE,
                                          cwd=f'{constants.TEMP}/{self.repo_dir}')

        while gitsecret_proc.poll() is None:
            if time.perf_counter() - tr > self.scan_time_limit:
                gitsecret_proc.kill()
                logger.info('Timeout occured')
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
                    logger.info('Send stop-command')
                    if os.path.exists(f"{constants.TEMP}/{self.repo_dir}"):
                        shutil.rmtree(f"{constants.TEMP}/{self.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{self.repo_dir}---reports")
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
                    self.secrets['gitsecrets'] = 'Not founded any leaks'
                    return 0
                a = True
                if not is_first:
                    for _, v in self.secrets['gitsecrets'].items():
                        if str(gitsecret[1]) == v['Match']:
                            a = False
                            break
                        else:
                            a = True
                if a:
                    is_first = False
                    self.secrets['gitsecrets'][f'Leak #{counter}']['Match'] = str(
                        gitsecret[1][0:120])
                    self.secrets['gitsecrets'][f'Leak #{counter}']['Names'] = self._pywhat_analyze_names(str(
                        self.secrets['gitsecrets'][f'Leak #{counter}']['Match']))
                    self.secrets['gitsecrets'][f'Leak #{counter}']['File'] = str(
                        gitsecret[0].split(':')[0])
                    counter += 1
        Path(f"{constants.TEMP}/{self.repo_dir}/gitsecrets_rep.json").rename(
            f"{constants.TEMP}/{self.repo_dir}---reports/gitsecrets_rep.json")

    @_exc_catcher
    def whispers_scan(self):
        tr = time.perf_counter()

        whisper = subprocess.Popen(
            ['whispers', './'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=f'{constants.TEMP}/{self.repo_dir}')

        while whisper.poll() is None:
            if time.perf_counter() - tr > self.scan_time_limit:
                whisper.kill()
                logger.info('Timeout occured')
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
                    logger.info('Send stop-command')
                    if os.path.exists(f"{constants.TEMP}/{self.repo_dir}"):
                        shutil.rmtree(f"{constants.TEMP}/{self.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{self.repo_dir}---reports")
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
                for _, v in self.secrets['whispers'].items():
                    if f'{i["key"]} {i["value"]}' == v['Match']:
                        a = False
                        break
                    a = True
            if a:
                is_first = False
                self.secrets['whispers'][f'Leak #{counter}']['Match'] = str(
                    f'{i["key"] + " " + i["value"]}'[0:120])
                self.secrets['whispers'][f'Leak #{counter}']['Names'] = \
                    self._pywhat_analyze_names(str(
                        self.secrets['whispers'][f'Leak #{counter}']['Match']))
                self.secrets['whispers'][f'Leak #{counter}']['File'] = str(
                    i["file"])
                counter += 1

            if self.secrets['whispers'] is None:
                self.secrets['whispers'] = 'Not founded any leaks'
            Path(f"{constants.TEMP}/{self.repo_dir}/whisper_rep.txt").rename(
                f"{constants.TEMP}/{self.repo_dir}---reports/whisper_rep.txt")
            return 0

    @_exc_catcher
    def trufflehog_scan(self):
        tr = time.perf_counter()

        trufflehog = subprocess.Popen(['trufflehog', 'git', '--json',
                                       '--no-update', 'file://.'],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL,
                                      cwd=f'{constants.TEMP}/{self.repo_dir}')

        while trufflehog.poll() is None:
            if time.perf_counter() - tr > self.scan_time_limit:
                trufflehog.kill()
                logger.info('Timeout occured')
                logger.info('trufflehog scan skipped')
                return 3
            if os.path.exists(constants.COMMAND_FILE):
                fd = open(constants.COMMAND_FILE, 'r')
                command_line = fd.readline()
                if command_line in ('skip', 'skip\n'):
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
                    logger.info('Send stop-command')
                    if os.path.exists(f"{constants.TEMP}/{self.repo_dir}"):
                        shutil.rmtree(f"{constants.TEMP}/{self.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{self.repo_dir}---reports")
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
                for _, v in self.secrets['trufflehog'].items():
                    if match == '' or str(match) == v['Match']:
                        a = False
                        break
                    a = True
            if a and match != '':
                is_first = False
                self.secrets['trufflehog'][f'Leak #{counter}']['Match'] = str(
                    match[0:120])
                self.secrets['trufflehog'][f'Leak #{counter}']['Name'] = \
                    self._pywhat_analyze_names(str(
                        self.secrets['trufflehog'][f'Leak #{counter}']['Match'])
                    )
                self.secrets['trufflehog'][f'Leak #{counter}']['File'] = str(
                    i['SourceMetadata']['Data']['Filesystem'][
                        'file'])
                counter += 1
            if self.secrets['trufflehog'] is None:
                self.secrets['trufflehog'] = 'Not founded any leaks'
            Path(f"{constants.TEMP}/{self.repo_dir}/trufflehog_rep.txt").rename(
                f"{constants.TEMP}/{self.repo_dir}---reports/trufflehog_rep.txt")
            return 0

    @_exc_catcher
    def deepsecrets_scan(self):
        tr = time.perf_counter()
        deepsecrets_proc = subprocess.Popen(['deepsecrets', '--target-dir', '.', '--outfile',
                                             'deepsecrets_rep.json'],
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL,
                                            cwd=f'{constants.TEMP}/{self.repo_dir}')
        while deepsecrets_proc.poll() is None:
            if time.perf_counter() - tr > self.scan_time_limit:
                deepsecrets_proc.kill()
                logger.info('Timeout occured')
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
                    logger.info('Send stop-command')
                    if os.path.exists(f"{constants.TEMP}/{self.repo_dir}"):
                        shutil.rmtree(
                            f"{constants.TEMP}/{self.repo_dir}")
                        shutil.rmtree(
                            f"{constants.TEMP}/{self.repo_dir}---reports")
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
                            for _, v in self.secrets['deepsecrets'].items():
                                if str(j['line'][:120]) == v['Match']:
                                    a = False
                                    break
                                a = True
                        if a:
                            is_first = False
                            self.secrets['deepsecrets'][f'Leak #{counter}'] \
                                ['Match'] = str(j['line'][:120])

                            self.secrets['deepsecrets'] \
                                [f'Leak #{counter}'] \
                                ['Name'] = self._pywhat_analyze_names(str(
                                self.secrets['deepsecrets'] \
                                    [f'Leak #{counter}']['Match'])
                            )

                            self.secrets['deepsecrets'] \
                                [f'Leak #{counter}']['File'] = str(i)
                            counter += 1
            if self.secrets['deepsecrets'] is None:
                self.secrets['deepsecrets'] = 'Not founded any leaks'

            Path(f"{constants.TEMP}/{self.repo_dir}/deepsecrets_rep.json").rename(
                f"{constants.TEMP}/{self.repo_dir}---reports/deepsecrets_rep.json")
            return 0
        else:
            logger.error('File deepsecrets_rep.json not founded\n')
            return 2

    @_exc_catcher
    def ioc_finder_scan(self):
        try:
            all_iocs = {'urls': [], 'xmpp_addresses': [],
                        'email_addresses_complete': [], 'email_addresses': [],
                        'ipv4_cidrs': [], 'imphashes': [], 'authentihashes': [],
                        'domains': [], 'ipv4s': [], 'ipv6s': [], 'sha512s': [],
                        'sha256s': [], 'sha1s': [], 'md5s': [], 'ssdeeps': [],
                        'asns': [], 'cves': [], 'registry_key_paths': [],
                        'google_adsense_publisher_ids': [],
                        'google_analytics_tracker_ids': [],
                        'bitcoin_addresses': [], 'monero_addresses': [],
                        'mac_addresses': [], 'user_agents': [],
                        'tlp_labels': [],
                        'attack_mitigations': {'enterprise': [], 'mobile': []},
                        'attack_tactics': {'pre_attack': [], 'enterprise': [],
                                           'mobile': []},
                        'attack_techniques': {'pre_attack': [],
                                              'enterprise': [], 'mobile': []},
                        'file_paths': []}

            for folder, _, files in os.walk('./'):
                for file in files:
                    fullpath = os.path.join(folder, file)
                    with open(fullpath, 'r',
                              encoding='utf-8', errors='ignore') as f:
                        text = f.read()
                        iocs = find_iocs(text)

                        for key, values in iocs.items():
                            if isinstance(values, dict):
                                for i in values.keys():
                                    if len(values[i]) > 0:
                                        if isinstance(values[i], list):
                                            for j in values[i]:
                                                all_iocs[key].append(j)
                                        else:
                                            all_iocs[key].append(values[i])
                            elif len(values):
                                if isinstance(values, list):
                                    for i in values:
                                        all_iocs[key].append(i)
                                else:
                                    all_iocs[key].append(values)

            res_dict = constants.AutoVivification()
            for key, ioc in all_iocs.items():
                if ioc:
                    ioc = list(set(ioc))
                    res_dict[key] = []
                    for i in ioc:
                        if len(i) > 6:  # clear false like dw.gz
                            res_dict[key].append(i)

            self.secrets['ioc_finder'] = res_dict
            return 0
        except Exception as ex:
            logger.error('Error in ioc_finder: %s', ex)
            return 2

    @_exc_catcher
    def ioc_extractor(self):
        all_iocs = {"asns": [], "btcs": [], "cves": [], "domains": [],
                    "emails": [],
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
                        ioc_extractor_proc = \
                            subprocess.Popen(['ioc-extractor'],
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL,
                                             cwd=f'{constants.TEMP}/{self.repo_dir}')
                        while ioc_extractor_proc.poll() is None:
                            if time.perf_counter() - tr > self.scan_time_limit:
                                ioc_extractor_proc.kill()
                                logger.info('Timeout occured')
                                return 3
                        res = ioc_extractor_proc.communicate(input=text_file)[
                            0].decode('utf-8')
                        iocs = json.loads(res)
                        for key in iocs.keys():
                            if isinstance(iocs[key], list) and len(iocs[key]):
                                for i in iocs[key]:
                                    all_iocs[key].append(i)

        except Exception as ex:
            logger.error('Exception in ioc_extractor: %s', ex)
            return 2

        res_dict = constants.AutoVivification()
        all_iocs['ipv4s'] = list(
            filter(lambda item: item != '127.0.0.1', all_iocs['ipv4s']))
        all_iocs['urls'] = list(
            filter(lambda item:
                   '127.0.0.1' not in item
                   and 'localhost' not in item,
                   all_iocs['urls']))
        all_iocs['ipv6s'] = list(
            filter(lambda item: item != '::', all_iocs['ipv6s']))

        for key, iocs in all_iocs.items():
            if len(iocs) > 0:
                res_dict[key] = all_iocs[key]
        self.secrets['ioc_extractor'] = res_dict
        return 0

    def run(self):  # DEBUG (in normal mode = 500
        """
        скачивает репозиторий по ссылке из url и проверяет с помощью сканеров TODO
        в конце, скаченный репозиторий удаляется,
        а обнаруженные секреты добавляются в словарь secrets
        """

        # logger.info(': ' + str(datetime.now()) + '\n')
        # Commented because logger shows time and date as well
        if self.status & NOT_CLONED:
            self.status |= SCANNED
        elif self.status & CLONED == 0:
            raise CheckerException(
                "You forgot call checker.clone() before scan()!")
        else:
            # self._pydriller_scan() TODO repair dependities
            self.scan()
            self.status |= SCANNED
            self._clean_repo_dirs()

        return self.secrets