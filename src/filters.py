# Standart libs import
import sys
from random import choice
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import shutil
import subprocess
from pathlib import Path
import re
import time
import tracemalloc
import hashlib
import git

# Project lib's import
from ioc_finder import find_iocs

from src import Connector, constants
from src.logger import logger, CLR

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
    logger.info('Checking TEMP_FOLDER directory')
    temp_dir_list = os.listdir(constants.TEMP_FOLDER)
    if len(temp_dir_list) > 2:
        if 'command_file' in temp_dir_list:
            temp_dir_list.remove('command_file')

        if 'list_to_scan.txt' in temp_dir_list:
            temp_dir_list.remove('list_to_scan.txt')
        for dir_now in temp_dir_list:
            if os.path.isdir(constants.TEMP_FOLDER + '/' + dir_now):
                shutil.rmtree(constants.TEMP_FOLDER + '/' + dir_now)
        logger.info(f'Cleared {len(temp_dir_list) - 1} directory in TEMP_FOLDER directory')


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
        for root, dirs, files in os.walk('constants.TEMP_FOLDER'):
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
                is_need_to_upd = False
                for new_url in url:
                    new_url = convert_to_regex_pattern(new_url)
                    if not new_url in url_from_exclude_list:
                        file.write(new_url + "\n")
                        is_need_to_upd = True
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


def _exc_catcher(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except subprocess.TimeoutExpired:
            logger.error("TimeoutExpired exception in %s", func.__name__)
        except Exception as exc:
            logger.error("Exception in %s: %s", func.__name__, exc)
            return 2

    return wrapper


''' 
    _semantic_check_dork return 1 if input string meaningfull and 0 if not

    Now based on RegEx rule, need change to NLP
    The need for the dork should be removed
    TODO change to NLP identification

'''


def _semantic_check_dork(string_check: str, dork: str):
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
        scan_type = 'None'
        self.repos_dir = constants.TEMP_FOLDER + '/' + url.split('/')[-2] + '---' + url.split('/')[-1]
        self.report_dir = self.repos_dir + '---reports/'
        self.secrets = constants.AutoVivification()
        self.ai_report = {'Thinks': 'AI not used'}
        self.ai_results = -1
        self.repo: git.Repo
        self.status = INITED
        self.scan_time_limit = constants.MAX_TIME_TO_SCAN_BY_UTIL_DEEP if self.mode == 3 else constants.MAX_TIME_TO_SCAN_BY_UTIL_DEFAULT
        self.log_color = choice(tuple(CLR.values()))
        self.scans = {
            'gitleaks': self.gitleaks_scan,
            'gitsecrets': self.gitsecrets_scan,
            'trufflehog': self.trufflehog_scan,
            'grepscan': self.grep_scan,
            'deepsecrets': self.deepsecrets_scan
        }

        self.deep_scans = {
            'gitleaks': self.gitleaks_scan,
            'gitsecrets': self.gitsecrets_scan,
            'grepscan': self.grep_scan,
            'deepsecrets': self.deepsecrets_scan,
            'ioc_finder': self.ioc_finder_scan,
            'ai_deep_scan': self.ai_deep_scan,
            # ,'ioc_extractor': self._ioc_extractor
        }

    def _clean_repo_dirs(self):
        if os.path.exists(self.repos_dir):
            shutil.rmtree(self.repos_dir)
        if os.path.exists(self.report_dir):
            shutil.rmtree(self.report_dir)

    def _pywhat_analyze_names(self, match):
        all_names = []
        res_analyze = pywhat_analyze(match, self.repos_dir)
        for i in res_analyze:
            all_names.append(i['Name'])
        if len(all_names) < 1:
            all_names.append('None')
        return all_names

    def clone(self):

        logger.info(f'Repository %s %s %s size: %s %s %s', self.log_color, self.url, CLR["RESET"],
                    self.log_color, self.obj.stats.repo_stats_leak_stats_table["size"], CLR["RESET"])
        if self.obj.stats.repo_stats_leak_stats_table['size'] > constants.REPO_MAX_SIZE:
            logger.info(
                f'Repository %s %s %s oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]} > {constants.REPO_MAX_SIZE} limit), code not analyze',
                self.log_color, self.url, CLR["RESET"]) # TODO: in report write oversize instead of "not state"
            self.obj.status.append(
                f'Repository {self.url} is oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]}), code not analyze')
            self.secrets = {'Scan error':f'Repository {self.url} is oversize ({self.obj.stats.repo_stats_leak_stats_table["size"]}), code not analyze'}
            self._clean_repo_dirs()
            self.status |= NOT_CLONED
        else:
            logger.info('Clonning %s %s %s', self.log_color, self.url, CLR["RESET"])

            for try_clone in range(constants.MAX_TRY_TO_CLONE):
                try:
                    self._clean_repo_dirs()
                    self.repo = git.Repo.clone_from(
                        self.url, self.repos_dir)
                    os.makedirs(self.report_dir)
                    self.clean_excluded_files()
                    break
                except Exception as exc:
                    time.sleep(1)
                    pass
            else:
                logger.error('Failed to clone repo %s', self.url)
                self.secrets = {'Scan error': f'Failed to clone repo {self.url}'}
                self._clean_repo_dirs()

            self.status |= CLONED
        self.obj.stats.get_contributors_stats()  # get stats this to optimize token usage

    def clean_excluded_files(self):
        repo_path: str = self.repos_dir

        for file_name in os.listdir(repo_path):
            for ext in self.file_ignore:
                if file_name.endswith(ext):
                    self.obj.status.append(f'File extension: {ext}')
                    (repo_path / file_name).unlink()

    def scan(self):
        logger.info('Started scan: %s | %s %s %s ', self.dork, self.log_color,
                    self.url, CLR["RESET"])
        cur_dir = os.getcwd()
        os.chdir(self.repos_dir)
        with ThreadPoolExecutor(max_workers=len(self.scans)) as executor:
            futures = {executor.submit(method): name for name, method in self.scans.items()}
            for future in as_completed(futures):
                res, method = future.result(), futures[future]
                if res == 1:
                    return 1
                if res == 2:
                    logger.error('Excepted error in scan, check privious log!')
                elif res == 3:
                    logger.info(f'Canceling scan in repo: {"/".join(self.url.split("/")[-2:])}')

        os.chdir(cur_dir)
        logger.info('Scanned: %s | %s %s %s ', self.dork, self.log_color, self.url,
                    CLR["RESET"])

        return self.secrets

    @_exc_catcher
    def grep_scan(self):  # TODO : check is this work correctly, add semantic check,
        scan_type = 'grepscan'
        self.secrets[scan_type] = constants.AutoVivification()
        try:
            grep_command = ["grep", "-r", self.dork, str(self.repos_dir)]
            grep_proc = subprocess.run(grep_command, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       shell=True, timeout=self.scan_time_limit, text=True)

            dork_list = list(set(grep_proc.stdout.split('\n')))[:constants.MAX_UTIL_RES_LINES]
            for index, leak in enumerate(dork_list):
                if len(leak) < 2:
                    continue
                fullpath = leak.split(':')[0]
                leak = ''.join(leak.split(':')[1:])
                self.secrets[scan_type][f'Leak #{index}']['meaningfull'] = _semantic_check_dork(leak, self.dork)

                if len(leak) > constants.MAX_LINE_LEAK_LEN:
                    ind = leak.index(self.dork)
                    leak = '...' + leak[int(ind - constants.MAX_LINE_LEAK_LEN / 2):ind] + leak[ind:int(
                        ind + constants.MAX_LINE_LEAK_LEN / 2)] + '...'
                self.secrets[scan_type][f'Leak #{index}']['Match'] = leak
                self.secrets[scan_type][f'Leak #{index}']['File'] = str(fullpath)
        except subprocess.TimeoutExpired:
            logger.error(f'\t- {scan_type} timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2
        logger.info(f'\t- {scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
        return 0

    # @_exc_catcher
    def gitleaks_scan(self):
        scan_type = 'gitleaks'
        self.secrets[scan_type] = constants.AutoVivification()

        try:

            gitleaks_com = (
                    '/usr/local/bin/gitleaks detect --no-banner --no-color --report-format json --exit-code 0 --report-path "'
                    + self.report_dir + scan_type + '_rep.json"')
            ll = os.curdir
            os.chdir(self.repos_dir)
            gitleaks_proc = subprocess.run(gitleaks_com, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           shell=True, timeout=self.scan_time_limit, text=True, cwd=self.repos_dir)

            os.chdir(ll)
        except subprocess.TimeoutExpired:
            logger.error('\t- ' + scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2
        if os.path.exists(self.report_dir + scan_type + '_rep.json'):
            with open(self.report_dir + scan_type + '_rep.json', 'r') as file:
                js = json.load(file)
                matched_secrets = {}
                for index, elem in enumerate(js):
                    if index > constants.MAX_UTIL_RES_LINES:
                        break
                    if elem['Match'] not in matched_secrets.keys():
                        matched_secrets[elem['Match']] = 1
                    elif matched_secrets[elem['Match']] > 3:
                        continue
                    # Position of match: StartColumn-EndColumn and StartLine-EndLine
                    elem['Position'] = 'V:' + str(elem['StartColumn']) + '-' + str(elem['EndColumn']) + ';H:' + str(
                        elem[
                            'StartLine']) + '-' + str(elem['EndLine']) + ';'

                    elem.pop('Fingerprint', None)

                    elem.pop('StartLine', None)
                    elem.pop('EndLine', None)
                    elem.pop('StartColumn', None)
                    elem.pop('EndColumn', None)
                    elem.pop('SymlinkFile', None)

                    elem.pop('Secret', None)
                    elem.pop('Entropy', None)
                    elem.pop('Message', None)
                    if len(elem['Match']) > constants.MAX_LINE_LEAK_LEN:
                        elem['Match'] = elem['Match'][:constants.MAX_LINE_LEAK_LEN] + '...'
                    self.secrets[scan_type][f'Leak #{index}'] = elem
                    self.secrets[scan_type][f'Leak #{index}']['meaningfull'] = _semantic_check_dork(elem['Match'],
                                                                                                    self.dork)
            logger.info(f'\t- {scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
        return 0

    @_exc_catcher
    def gitsecrets_scan(self):
        scan_type = 'gitsecrets'
        self.secrets[scan_type] = constants.AutoVivification()
        subprocess.run(['git', 'secrets', '--install', '-f'],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit,
                       shell=True)
        subprocess.run(['git', 'secrets', '--register-aws'],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit,
                       shell=True)
        subprocess.run(['git', 'secrets', '--aws-provider'],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit,
                       shell=True)
        gitsecret_com = 'git secrets --scan -r ' + self.repos_dir
        try:
            old_dir = os.curdir
            os.chdir(constants.TEMP_FOLDER)
            gitsecret_proc = subprocess.run(gitsecret_com, capture_output=True,
                                            shell=True, timeout=self.scan_time_limit, text=True, check=False)

            os.chdir(old_dir)
        except subprocess.TimeoutExpired:
            logger.error(f'\t- {scan_type} timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            print(f'ERROR: {ex}')
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2

        with open(self.report_dir + scan_type + '_rep.json', 'w') as file:
            for line in gitsecret_proc.stderr.split('\n'):
                file.write(line)
                file.write('\n')
        with open(self.report_dir + scan_type + '_rep.json', 'r') as file:
            matched_secrets = constants.AutoVivification()
            for index, line in enumerate(file.readlines()[:constants.MAX_UTIL_RES_LINES]):
                if '[ERROR] Matched one or more prohibited patterns' in line:
                    break
                match_str = ''.join(line.split(':')[2:]).strip()

                if match_str not in matched_secrets.keys():
                    matched_secrets[match_str] = 1
                else:
                    continue
                if len(match_str) > constants.MAX_LINE_LEAK_LEN:
                    match_str = match_str[:constants.MAX_LINE_LEAK_LEN]
                self.secrets['gitsecrets'][f'Leak #{index}']['Match'] = str(match_str)
                self.secrets['gitsecrets'][f'Leak #{index}']['File'] = ''.join(line.split(':')[:2]).strip()
            logger.info(f'\t- {scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
        return 0

    @_exc_catcher
    def trufflehog_scan(self):
        scan_type = 'trufflehog'
        self.secrets[scan_type] = constants.AutoVivification()
        try:
            truf_com = 'trufflehog git --json --no-update file://' + self.repos_dir
            trufflehog_proc = subprocess.run(truf_com, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                             shell=True, timeout=self.scan_time_limit, text=True)
        except subprocess.TimeoutExpired:
            logger.error('\t- ' + scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2

        with open(self.report_dir + scan_type + '_rep.txt', 'w') as file:
            var = trufflehog_proc.stdout  # trufflehog_proc.communicate()[0]
            file.write(var)

        trufflehog_list = []
        with open(self.report_dir + scan_type + '_rep.txt', 'r') as file:
            for line in file:
                trufflehog_list.append(json.loads(line))
        appended_list_hashes = []
        for index, elem in enumerate(trufflehog_list[:constants.MAX_UTIL_RES_LINES]):
            md5_dict_hash = hashlib.md5(json.dumps(elem['SourceMetadata'], sort_keys=True).encode('utf-8')).hexdigest()
            if md5_dict_hash in appended_list_hashes:
                continue
            else:
                appended_list_hashes.append(md5_dict_hash)
            elem.pop('SourceID', None)
            elem.pop('SourceType', None)
            elem.pop('SourceName', None)
            elem.pop('DetectorType', None)
            elem.pop('DecoderName', None)
            elem.pop('Redacted', None)
            elem.pop('ExtraData', None)
            elem.pop('StructuredData', None)
            self.secrets['trufflehog'][f'Leak #{index}'] = elem
            self.secrets['trufflehog'][f'Leak #{index}']['Match'] = elem['RawV2'] if elem['RawV2'] != "" else elem[
                'Raw']
            self.secrets['trufflehog'][f'Leak #{index}'].pop('Raw')
            self.secrets['trufflehog'][f'Leak #{index}'].pop('RawV2')
        logger.info(f'\t- {scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
        return 0

    @_exc_catcher
    def deepsecrets_scan(self):
        scan_type = 'deepsecrets'
        self.secrets[scan_type] = constants.AutoVivification()
        try:
            deep_com = 'deepsecrets --target-dir ' + self.repos_dir + ' --outfile ' + self.report_dir + scan_type + '_rep.json'
            deepsecrets_proc = subprocess.run(deep_com, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                              shell=True, timeout=self.scan_time_limit, text=True)
        except subprocess.TimeoutExpired:
            logger.error('\t- ' + scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url,
                         CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"],
                         ex)
            return 2

        if os.path.exists(self.report_dir + scan_type + '_rep.json'):
            with open(self.report_dir + scan_type + '_rep.json', 'r') as file:
                js = json.load(file)
                is_first = True
                counter = 1

                for i in js:
                    for j in js[i]:
                        a = True
                        if not is_first:
                            for _, v in self.secrets['deepsecrets'].items():
                                if str(j['line'][:constants.MAX_LINE_LEAK_LEN]) == v['Match']:
                                    a = False
                                    break
                                a = True
                        if a:
                            is_first = False

                            if len(j['line']) > constants.MAX_LINE_LEAK_LEN:
                                j['line'] = j['line'][:constants.MAX_LINE_LEAK_LEN]
                            self.secrets['deepsecrets'][f'Leak #{counter}']['Match'] = str(j['line'])

                            self.secrets['deepsecrets'][f'Leak #{counter}']['File'] = str(i)
                            counter += 1
            logger.info(f'\t- {scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
            return 0
        else:
            logger.error('\t- File deepsecrets_rep.json not founded\n')
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
            logger.error('\t- Error in ioc_finder: %s', ex)
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
                                             cwd=self.repos_dir)
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
            logger.error('\t- Exception in ioc_extractor: %s', ex)
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

    
    @_exc_catcher
    def ai_deep_scan(self):
        #self.ai_report        
        if not constants.AI_CONFIG['ai_enable']:
            pass
        return 0
        
        
    @_exc_catcher
    def ai_scan(self):
        # AI анализ теперь выполняется напрямую в LeakObj
        # Эта функция оставлена для обратной совместимости
        if constants.AI_CONFIG['ai_enable']:
            self.obj.ai_report = {'Thinks': 'AI analysis performed in LeakObj'}
            # AI анализ будет выполнен в LeakObj при записи объекта
        return 0
        
    def run(self):
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
            time.sleep(2)  # for MultiThread control
            self._clean_repo_dirs()

        self.obj.stats.get_commits_stats()  # get stats this to optimize token usage
        self.obj.secrets = self.secrets
        if constants.AI_CONFIG['ai_enable']:
            self.ai_scan()
        return self.secrets, self.obj.ai_report
