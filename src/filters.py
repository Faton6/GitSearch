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
import hashlib
import git
import math
from ioc_finder import find_iocs

# Project lib's import
from src import Connector, constants
from src.logger import logger, CLR
from src import utils

exclusions: tuple[str]
with open(constants.MAIN_FOLDER_PATH / "src" / "exclude_list.txt", 'r') as fd:
    exclusions = tuple(line.rstrip() for line in fd)

def _exc_catcher(func):
    """Decorator for catching exceptions in scan methods"""
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
        self.repo: git.Repo
        self.status = INITED
        self.company_name = Connector.get_company_name(self.obj.company_id)
        self.company_terms = utils.generate_company_search_terms(self.company_name)
        self.safe_company_name = utils.sanitize_company_name(self.company_name)
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
        res_analyze = utils.pywhat_analyze(match, self.repos_dir)
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
        """Очищает исключенные файлы из репозитория"""
        repo_path = Path(self.repos_dir)  # DEBUG

        for file_path in repo_path.iterdir():
            if file_path.is_file():
                for ext in self.file_ignore:
                    if file_path.name.endswith(ext):
                        self.obj.status.append(f'File extension: {ext}')
                        file_path.unlink()
                        break

    def scan(self):
        logger.info('Started scan: %s | %s %s %s ', self.dork, self.log_color,
                    self.url, CLR["RESET"])
        cur_dir = os.getcwd()
        os.chdir(self.repos_dir)
        
        scan_results = {}
        with ThreadPoolExecutor(max_workers=len(self.scans)) as executor:
            futures = {executor.submit(method): name for name, method in self.scans.items()}
            for future in as_completed(futures):
                res, method = future.result(), futures[future]
                scan_results[method] = res
                if res == 1:
                    return 1
                if res == 2:
                    logger.error('Excepted error in scan, check privious log!')
                elif res == 3:
                    logger.info(f'Canceling scan in repo: {"/".join(self.url.split("/")[-2:])}')

        os.chdir(cur_dir)
        
        # Проверяем, есть ли хотя бы один сканер с результатами
        has_results = any(
            scan_type in self.secrets and 
            len(self.secrets[scan_type]) > 0 and
            not (len(self.secrets[scan_type]) == 1 and 'Info' in self.secrets[scan_type])
            for scan_type in self.secrets
        )
        
        if not has_results:
            logger.info(f'No meaningful results found in {self.url} by any scanner')
            # Добавляем информативную запись вместо пустого результата
            self.secrets['scan_summary'] = {
                'message': f'No leaks found for dork "{self.dork}" in repository',
                'scanners_used': list(self.scans.keys()),
                'scan_results': scan_results
            }
        
        logger.info('Scanned: %s | %s %s %s ', self.dork, self.log_color, self.url,
                    CLR["RESET"])

        return self.secrets

    @_exc_catcher
    def grep_scan(self):
        """
        Улучшенный поиск по ключевым словам в репозитории.
        Ищет как по основному dork, так и по названию компании.
        Использует более качественный поиск слов с учетом границ слов.
        """
        scan_type = 'grepscan'
        self.secrets[scan_type] = constants.AutoVivification()
        
        try:
         
            # Создаем список поисковых терминов
            search_terms = [self.dork]
            if self.company_name:
                # Добавляем название компании и его части
                search_terms.extend(self.company_terms)
            
            # Используем Python для более качественного поиска
            found_matches = self._enhanced_file_search(search_terms)
            
            # Обрабатываем найденные совпадения
            meaningful_count = 0
            for index, match_info in enumerate(found_matches[:constants.MAX_UTIL_RES_LINES]):
                leak_text = match_info['text']
                file_path = match_info['file']
                search_term = match_info['term']
                
                # Проверяем семантическую осмысленность
                meaningfulness = self._enhanced_semantic_check(leak_text, search_term)
                
                if meaningfulness > 0:
                    meaningful_count += 1
                
                # Обрезаем слишком длинные строки
                if len(leak_text) > constants.MAX_LINE_LEAK_LEN:
                    leak_text = self._get_context(leak_text, search_term, constants.MAX_LINE_LEAK_LEN)
                
                self.secrets[scan_type][f'Leak #{index}']['meaningfull'] = meaningfulness
                self.secrets[scan_type][f'Leak #{index}']['Match'] = leak_text
                self.secrets[scan_type][f'Leak #{index}']['File'] = file_path
                # Дополнительная информация для анализа (не влияет на совместимость)
                self.secrets[scan_type][f'Leak #{index}']['SearchTerm'] = search_term
                self.secrets[scan_type][f'Leak #{index}']['IsCompanyRelated'] = search_term != self.dork
            
            logger.debug(f'Meaningful matches: {meaningful_count}/{len(found_matches)} for {self.url}')
            
            # Если не найдено ни одного совпадения, добавляем информативную запись
            if len(found_matches) == 0:
                self.secrets[scan_type]['Info'] = f'No matches found for terms: {", ".join(search_terms)}'
                logger.info(f'No matches found in {self.url} for terms: {", ".join(search_terms)}')
            elif meaningful_count == 0:
                self.secrets[scan_type]['Info'] = f'Found {len(found_matches)} matches but none were meaningful'
                logger.info(f'Found {len(found_matches)} matches in {self.url} but none were meaningful')
                
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2
            
        logger.info(f'\t- {scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
        return 0

    

    def _enhanced_file_search(self, search_terms):
        """Улучшенный поиск в файлах с учетом размера файлов"""
        found_matches = []
                
        # Размер файла в байтах (10 МБ)
        MAX_FILE_SIZE_FOR_PYTHON = 10 * 1024 * 1024  # 10 MB
        
        try:
            for root, dirs, files in os.walk('.'):
                # Исключаем системные папки
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d not in {'node_modules', '__pycache__', 'venv', 'env'}]
                
                for file in files:
                    # Проверяем расширение или известные файлы без расширений
                    _, ext = os.path.splitext(file.lower())
                    filename_lower = file.lower()
                    
                    # Проверяем расширение или известные файлы без расширений
                    is_text_file = (
                        ext in constants.TEXT_FILE_EXTS or 
                        filename_lower in {
                            'readme', 'license', 'makefile', 'changelog', 'authors', 'contributors',
                            'dockerfile', 'gemfile', 'rakefile', 'gruntfile', 'gulpfile',
                            'package', 'requirements', 'setup', 'build', 'install'
                        } or
                        filename_lower.startswith(('readme.', 'license.', 'changelog.', 'install.')) or
                        filename_lower.endswith(('.example', '.sample', '.template', '.dist'))
                    )
                    
                    if not is_text_file:
                        continue
                    
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Проверяем размер файла
                        file_size = os.path.getsize(file_path)
                        
                        if file_size > MAX_FILE_SIZE_FOR_PYTHON:
                            # Для больших файлов используем grep
                            matches = self._search_large_file_with_grep(file_path, search_terms)
                            found_matches.extend(matches)
                        else:
                            # Для маленьких файлов используем Python
                            matches = self._search_small_file_with_python(file_path, search_terms)
                            found_matches.extend(matches)
                        
                        # Ограничиваем количество результатов
                        if len(found_matches) >= constants.MAX_UTIL_RES_LINES * 2:
                            return found_matches[:constants.MAX_UTIL_RES_LINES]
                            
                    except Exception as ex:
                        logger.debug(f'Error processing file {file_path}: {ex}')
                        continue
                        
        except Exception as ex:
            logger.debug(f'Error in file search: {ex}')
        
        return found_matches

    def _search_small_file_with_python(self, file_path, search_terms):
        """Поиск в небольших файлах с помощью Python"""
        matches = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or len(line) > 1000:  # Пропускаем слишком длинные строки
                        continue
                    
                    for term in search_terms:
                        if self._find_term_in_line(line, term):
                            context = self._get_context(line, term, 100)
                            matches.append({
                                'text': context,
                                'file': file_path,
                                'term': term,
                                'line_num': line_num
                            })
                            
                            # Ограничиваем количество находок на файл
                            if len(matches) >= 50:
                                return matches
        except Exception:
            pass
            
        return matches

    def _search_large_file_with_grep(self, file_path, search_terms):
        """Поиск в больших файлах с помощью grep"""
        matches = []
        
        try:
            for term in search_terms:
                # Используем grep с ограничением количества результатов
                grep_command = [
                    'grep', '-n', '-i', '--text', '--max-count=20',
                    term, file_path
                ]
                
                try:
                    result = subprocess.run(
                        grep_command, 
                        capture_output=True, 
                        text=True, 
                        timeout=10  # Таймаут для больших файлов
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if not line.strip():
                                continue
                                
                            # Разбираем вывод grep: номер_строки:содержимое
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                line_num = parts[0]
                                content = parts[1]
                                
                                # Обрезаем контекст
                                context = self._get_context(content, term, 100)
                                
                                matches.append({
                                    'text': context,
                                    'file': file_path,
                                    'term': term,
                                    'line_num': int(line_num) if line_num.isdigit() else 0
                                })
                                
                except subprocess.TimeoutExpired:
                    logger.debug(f'Grep timeout for file {file_path} with term {term}')
                    continue
                except Exception as ex:
                    logger.debug(f'Grep error for file {file_path}: {ex}')
                    continue
                    
        except Exception as ex:
            logger.debug(f'Error in grep search for {file_path}: {ex}')
            
        return matches

    def _find_term_in_line(self, line, term):
        """Проверяет наличие термина в строке с учетом границ слов"""
        # Точное совпадение слова (приоритет)
        if re.search(rf'\b{re.escape(term)}\b', line, re.IGNORECASE):
            return True
        
        # Термин как часть слова (для названий компаний)
        if len(term) > 2 and re.search(rf'{re.escape(term)}', line, re.IGNORECASE):
            # Проверяем, что это не длинная случайная строка
            # Исключаем только очевидные хеши/случайные строки
            if re.search(r'[a-f0-9]{30,}|[A-Za-z0-9+/]{25,}={0,2}', line):
                return False
            
            # Проверяем, что строка содержит осмысленные символы
            if re.search(r'[a-zA-Z]{2,}', line):
                return True
                
        return False

    def _get_context(self, line, term, max_length):
        """Получает контекст вокруг найденного термина"""
        if len(line) <= max_length:
            return line
        
        term_pos = line.lower().find(term.lower())
        if term_pos == -1:
            return line[:max_length] + '...'
        
        half_length = max_length // 2
        start = max(0, term_pos - half_length)
        end = min(len(line), term_pos + len(term) + half_length)
        
        result = line[start:end]
        if start > 0:
            result = '...' + result
        if end < len(line):
            result = result + '...'
        
        return result

    def _enhanced_semantic_check(self, text, term):
        """Улучшенная семантическая проверка"""
        if not text or not term or term.lower() not in text.lower():
            return 0
        
        # Сначала используем оригинальную проверку для совместимости
        original_check = utils.semantic_check_dork(text, term)
        if original_check:
            return original_check
        
        # Проверяем на очевидные хеши/случайные строки (более мягко)
        # Только длинные хеши считаем подозрительными
        if re.search(r'[a-f0-9]{40,}|[A-Za-z0-9+/]{30,}={0,2}', text):
            return 0
        
        # Проверяем, что строка не состоит только из случайных символов
        if len(text) > 50 and not re.search(r'[a-zA-Z]{3,}', text):
            return 0
        
        # Проверяем наличие контекстных слов в тексте
        context_score = sum(1 for word in constants.CONTEXT_WORDS if word in text.lower())
        
        # Если термин длинный (вероятно, название компании), то менее строгая проверка
        if len(term) > 4:
            # Для длинных терминов достаточно быть в осмысленном контексте
            if context_score > 0 or re.search(r'[a-zA-Z]{3,}', text):
                return 1
        
        # Для коротких терминов требуем контекст
        return min(context_score, 1)

    def _truncate_around_match(self, text, term, max_length):
        """Обрезает текст вокруг найденного термина"""
        return self._get_context(text, term, max_length)

    #    @_exc_catcher
    def gitleaks_scan(self):
        scan_type = 'gitleaks'
        
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
                
                def process_gitleaks_result(elem, index):
                    # Создаем позиционную информацию
                    position = f"V:{elem['StartColumn']}-{elem['EndColumn']};H:{elem['StartLine']}-{elem['EndLine']};"
                    
                    # Очищаем данные и создаем результат
                    match_str = elem.get('Match') or elem.get('Secret', '')
                    file_path = elem.get('File', '')
                    self._clean_result_data(elem)
                    elem['Position'] = position
                    elem['Match'] = match_str
                    elem['File'] = file_path
                    
                    return elem
                
                processed_count = self._process_scan_results(scan_type, js, process_gitleaks_result)
                logger.info(f'\t- {scan_type} scan %s %s %s success, processed {processed_count} results', 
                           self.log_color, self.url, CLR["RESET"])
        
        return 0

    @_exc_catcher
    def gitsecrets_scan(self):
        scan_type = 'gitsecrets'
        self.secrets[scan_type] = constants.AutoVivification()
        
        # Инициализация git secrets
        subprocess.run(['git', 'secrets', '--install', '-f'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit, shell=True)
        subprocess.run(['git', 'secrets', '--register-aws'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit, shell=True)
        subprocess.run(['git', 'secrets', '--aws-provider'],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       timeout=self.scan_time_limit, shell=True)
        
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
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2

        # git-secrets выводит результаты в stderr, это нормальное поведение
        stderr_output = gitsecret_proc.stderr.strip()
        
        # Проверяем, есть ли найденные утечки
        if not stderr_output or len(stderr_output) == 0:
            # Нет найденных утечек
            self.secrets[scan_type]['Info'] = 'No secrets found by git-secrets'
            logger.info(f'\t- {scan_type} scan %s %s %s success, no secrets found', 
                       self.log_color, self.url, CLR["RESET"])
            return 0
        
        # Сохраняем результаты в текстовый файл
        with open(self.report_dir + scan_type + '_rep.txt', 'w') as file:
            file.write(stderr_output)
        
        # Обрабатываем результаты построчно
        lines = stderr_output.split('\n')
        
        def process_gitsecrets_result(line, index):
            line = line.strip()
            if not line:
                return None
            
            # Пропускаем служебные сообщения
            if any(skip_phrase in line for skip_phrase in [
                '[ERROR] Matched one or more prohibited patterns',
                'Syntax error:', 'newline unexpected', 'Usage:', 'git-secrets'
            ]):
                return None
            
            # git-secrets выводит в формате: file:line:match или file:match
            if ':' in line:
                parts = line.split(':', 2)
                if len(parts) >= 2:
                    if len(parts) == 3:
                        # Формат: файл:строка:содержимое
                        file_path = parts[0].strip()
                        line_num = parts[1].strip()
                        match_str = parts[2].strip()
                        full_file_path = f"{file_path}:{line_num}"
                    else:
                        # Формат: файл:содержимое
                        file_path = parts[0].strip()
                        match_str = parts[1].strip()
                        full_file_path = file_path
                    
                    # Фильтруем пустые и слишком короткие совпадения
                    if len(match_str) < 3:
                        return None
                    
                    return self._create_standard_result(match_str, full_file_path)
            else:
                # Строка без разделителей - возможно, это найденный секрет
                if len(line) >= 6:  # Минимальная длина для секрета
                    return self._create_standard_result(line, "unknown")
                
            return None
        
        processed_count = self._process_scan_results(scan_type, lines, process_gitsecrets_result)
        
        if processed_count == 0:
            self.secrets[scan_type]['Info'] = 'Git-secrets completed but no meaningful results found'
        
        logger.info(f'\t- {scan_type} scan %s %s %s success, processed {processed_count} results', 
                   self.log_color, self.url, CLR["RESET"])
        
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
            logger.error(scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url,
                         CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"],
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
            logger.info(f'{scan_type} scan %s %s %s success', self.log_color, self.url, CLR["RESET"])
            return 0
        else:
            logger.error('File deepsecrets_rep.json not founded\n')
            return 2

    @_exc_catcher
    def ioc_finder_scan(self):
        """Сканирование с помощью IOC finder"""
        scan_type = 'ioc_finder'
        self.secrets[scan_type] = constants.AutoVivification()
        
        if not IOC_FINDER_AVAILABLE:
            self.secrets[scan_type]['Info'] = 'IOC finder library not available'
            logger.info(f'\t- {scan_type} scan %s %s %s success (library not available)', self.log_color, self.url, CLR["RESET"])
            return 0
        
        try:
            # Собираем текст из файлов репозитория
            repo_text = self._collect_repo_text()
            
            # Ищем IOC с помощью ioc_finder
            iocs = find_iocs(repo_text)
            
            processed_count = 0
            for ioc_type, ioc_list in iocs.items():
                for ioc in ioc_list:
                    if processed_count >= constants.MAX_UTIL_RES_LINES:
                        break
                    
                    result = self._create_standard_result(
                        match=str(ioc),
                        extra_data={'IOC_Type': ioc_type}
                    )
                    
                    result['meaningfull'] = utils.semantic_check_dork(str(ioc), self.dork)
                    self.secrets[scan_type][f'IOC #{processed_count}'] = result
                    processed_count += 1
            
            logger.info(f'\t- {scan_type} scan %s %s %s success, found {processed_count} IOCs', 
                       self.log_color, self.url, CLR["RESET"])
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2
        
        return 0

    @_exc_catcher
    def ai_deep_scan(self):
        """AI глубокое сканирование"""
        scan_type = 'ai_deep_scan'
        # Заглушка для AI сканирования - можно реализовать позже
        self.secrets[scan_type] = constants.AutoVivification()
        self.secrets[scan_type]['Info'] = 'AI deep scan not implemented'
        logger.info(f'\t- {scan_type} scan %s %s %s success (not implemented)', self.log_color, self.url, CLR["RESET"])
        return 0
    
    @_exc_catcher
    def trufflehog_scan(self):
        scan_type = 'trufflehog'
        self.secrets[scan_type] = constants.AutoVivification()
        
        try:
            # Создаем кастомный конфиг для TruffleHog
            config_path = self._create_trufflehog_config()
            
            # Улучшенная команда TruffleHog с учетом компании
            truf_com = self._build_trufflehog_command(config_path)
            
            trufflehog_proc = subprocess.run(truf_com, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             shell=True, timeout=self.scan_time_limit, text=True)
        except subprocess.TimeoutExpired:
            logger.error('\t- ' + scan_type + ' timeout occured in repository %s %s %s', self.log_color, self.url, CLR["RESET"])
            return 2
        except Exception as ex:
            logger.error(f'\t- Error in repository %s %s %s {scan_type}: %s', self.log_color, self.url, CLR["RESET"], ex)
            return 2

        # Обработка результатов
        return self._process_trufflehog_results(trufflehog_proc.stdout, scan_type)

    def _create_trufflehog_config(self):
        """Создает конфигурационный файл для TruffleHog с кастомными детекторами"""
        config_path = os.path.join(self.report_dir, 'trufflehog_config.json')
        
        # Получаем название компании для кастомных детекторов
        company_name = Connector.get_company_name(self.obj.company_id)
        
        # Создаем кастомные детекторы
        custom_detectors = self._generate_company_detectors(self.company_name, self.company_terms, self.safe_company_name)
        
        config_content = {
            'detectors': custom_detectors
        }
        
        # Сохраняем конфигурацию в JSON формате
        try:
            with open(config_path, 'w') as f:
                json.dump(config_content, f, indent=2)
            logger.debug(f'Created TruffleHog JSON config: {config_path}')
        except Exception as ex:
            logger.error(f'Failed to create TruffleHog config: {ex}')
            return None
            
        return config_path

    def _generate_company_detectors(self, company_name, company_terms, safe_name):
        """Генерирует кастомные детекторы на основе названия компании"""
        detectors = []
        
        # Всегда добавляем универсальный детектор для общих утечек
        detectors.append(self._create_universal_detector())
        detectors.append(self._create_config_detector())
        
        # Если есть название компании, добавляем специфичные детекторы
        if company_name: 
            # Создаем детекторы для компании
            detectors.extend([
                self._create_company_credentials_detector(safe_name, company_terms),
                self._create_company_api_detector(safe_name, company_terms),
                self._create_company_login_detector(safe_name, company_terms),
                self._create_company_email_detector(safe_name, company_terms)
            ])
        
        return detectors
    
    def _create_universal_detector(self):
        """Создает универсальный детектор для общих утечек"""
        return {
            'name': 'universal-secrets',
            'keywords': [
                'password', 'pwd', 'pass', 'secret', 'key', 'token', 'auth', 'api',
                'credential', 'cred', 'access', 'private', 'confidential', 'sensitive'
            ],
            'regex': {
                'secret': r'(?i)(?:password|pwd|pass|secret|key|token|auth|api|credential|cred|access|private)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9@#$%^&*()_+\-=\[\]{};:,.<>?/~`|\\!]{6,})\1',
                'base64_secret': r'(?i)(?:password|pwd|pass|secret|key|token|auth|api)[_\-\s]*[:=]\s*(["\']?)([A-Za-z0-9+/]{20,}={0,2})\1',
                'hex_secret': r'(?i)(?:password|pwd|pass|secret|key|token|auth|api)[_\-\s]*[:=]\s*(["\']?)([a-fA-F0-9]{16,})\1'
            },
            'entropy': 2.0,
            'exclude_words': [
                'example', 'test', 'demo', 'sample', 'placeholder', 'dummy', 'fake',
                'password', 'secret', 'key', 'token',
                '123456', 'password123', 'admin123', 'root123', 'test123'
            ]
        }
    
    def _create_config_detector(self):
        """Создает детектор для конфигурационных файлов"""
        return {
            'name': 'config-files-secrets',
            'keywords': [
                'config', 'env', 'settings', 'database', 'db', 'server', 'host',
                'url', 'uri', 'endpoint', 'connection', 'dsn'
            ],
            'regex': {
                'config_value': r'(?i)(?:database|db|server|host|url|uri|endpoint|connection|dsn)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9@._\-:\/]{5,})\1',
                'env_var': r'(?i)[A-Z_]{2,}[_]?(?:PASSWORD|PWD|PASS|SECRET|KEY|TOKEN|AUTH|API)[_A-Z0-9]*\s*[:=]\s*(["\']?)([a-zA-Z0-9@#$%^&*()_+\-=\[\]{};:,.<>?/~`|\\!]{6,})\1'
            },
            'entropy': 1.5,
            'exclude_words': [
                'localhost', '127.0.0.1', 'example.com', 'test.com', 'demo.com',
                'your_host_here', 'your_database_here'
            ]
        }
    
    def _create_company_credentials_detector(self, safe_name, company_terms):
        """Создает детектор для паролей, связанных с компанией"""
        return {
            'name': f'company-credentials-{safe_name}',
            'keywords': company_terms + ['password', 'pwd', 'pass', 'secret', 'key', 'token', 'auth', 'api'],
            'regex': {
                'credential': r'(?i)(?:' + '|'.join(re.escape(term) for term in company_terms) + r')[_\-\s]*(?:password|pwd|pass|secret|key|token|auth|api)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9@#$%^&*()_+\-=\[\]{};:,.<>?/~`|\\!]{6,})\1'
            },
            'entropy': 2.0,
            'exclude_words': [
                'example', 'test', 'demo', 'sample', 'placeholder', 'your_password_here',
                'change_me', 'replace_me', 'password123', 'admin123', 'root123'
            ]
        }
    
    def _create_company_api_detector(self, safe_name, company_terms):
        """Создает детектор для API ключей компании"""
        return {
            'name': f'company-api-keys-{safe_name}',
            'keywords': company_terms + ['api', 'key', 'token', 'access', 'secret'],
            'regex': {
                'api_key': r'(?i)(?:' + '|'.join(re.escape(term) for term in company_terms) + r')[_\-\s]*(?:api[_\-\s]*key|access[_\-\s]*token|secret[_\-\s]*key)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9]{15,})\1'
            },
            'entropy': 2.5,
            'exclude_words': [
                'example', 'test', 'demo', 'sample', 'placeholder', 'your_api_key_here'
            ]
        }
    
    def _create_company_login_detector(self, safe_name, company_terms):
        """Создает детектор для логинов компании"""
        company_terms_filtered = [term for term in company_terms if '\\d+' not in term]
        
        return {
            'name': f'company-login-pattern-{safe_name}',
            'keywords': company_terms + ['login', 'user', 'username', 'account'],
            'regex': {
                'company_login': r'(?i)(?:' + '|'.join(re.escape(term) for term in company_terms_filtered) + r')\d{1,8}',
                'company_login_config': r'(?i)(?:login|user|username|account)[_\-\s]*[:=]\s*(["\']?)(' + '|'.join(re.escape(term) for term in company_terms_filtered) + r')\d{1,8}\1'
            },
            'entropy': 1.0,
            'exclude_words': ['example', 'test', 'demo', 'sample']
        }
    
    def _create_company_email_detector(self, safe_name, company_terms):
        """Создает детектор для email доменов компании"""
        email_terms = [term for term in company_terms if '@' in term]
        if not email_terms:
            # Если нет явных email доменов, создаем на основе названия компании
            email_terms = [f"{term}.com" for term in company_terms[:3] if len(term) > 2]
        
        if email_terms:
            email_terms_clean = [term.replace('@', '') for term in email_terms]
            return {
                'name': f'company-email-pattern-{safe_name}',
                'keywords': company_terms + ['email', 'mail', 'address'],
                'regex': {
                    'company_email': r'(?i)\b([a-zA-Z0-9._-]+@(?:' + '|'.join(re.escape(term) for term in email_terms_clean) + r'))\b',
                    'company_email_config': r'(?i)(?:email|mail|address)[_\-\s]*[:=]\s*(["\']?)([a-zA-Z0-9._-]+@(?:' + '|'.join(re.escape(term) for term in email_terms_clean) + r'))\1'
                },
                'entropy': 1.0,
                'exclude_words': ['example@', 'test@', 'demo@']
            }
        else:
            return {
                'name': f'company-email-pattern-{safe_name}',
                'keywords': company_terms + ['email', 'mail', 'address'],
                'regex': {
                    'company_email': r'(?i)\b([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
                },
                'entropy': 1.0,
                'exclude_words': ['example@', 'test@', 'demo@']
            }
    
    def _build_trufflehog_command(self, config_path):
        """Строит улучшенную команду TruffleHog"""
        base_command = [
            'trufflehog', 'git',
            '--json',
            '--no-update',
            '--results=verified,unknown,unverified',  # Включаем все типы результатов для максимального покрытия
            '--concurrency=3',  # Уменьшаем для стабильности
            '--archive-max-size=100MB',  # Увеличиваем лимит архивов
            '--archive-max-depth=5',  # Увеличиваем глубину архивов
            '--no-verification',  # Отключаем верификацию для ускорения и полноты покрытия
            f'file://{self.repos_dir}'
        ]
        
        # Добавляем кастомную конфигурацию если она создана
        if config_path and os.path.exists(config_path):
            base_command.extend(['--config', config_path])
        
        # Минимальный набор исключений - только действительно ненужные файлы
        exclude_patterns = [
            '*.log', '*.tmp', '*.cache', '*.ipynb'
            '*.jpg', '*.png', '*.gif', '*.zip'
        ]
        
        for pattern in exclude_patterns:
            base_command.extend(['--exclude-globs', pattern])
        
        return ' '.join(base_command)

    def _process_trufflehog_results(self, stdout_data, scan_type):
        """Обрабатывает результаты TruffleHog с улучшенной фильтрацией"""
        # Сохраняем результаты в файл
        with open(self.report_dir + scan_type + '_rep.txt', 'w') as file:
            file.write(stdout_data)

        # Обрабатываем результаты
        trufflehog_list = []
        try:
            with open(self.report_dir + scan_type + '_rep.txt', 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        try:
                            result = json.loads(line)
                            trufflehog_list.append(result)
                        except json.JSONDecodeError:
                            continue
        except Exception as ex:
            logger.error(f'Error reading TruffleHog results: {ex}')
            return 2

        # Фильтруем и обрабатываем результаты
        processed_results = self._filter_and_enhance_results(trufflehog_list)
        
        def process_trufflehog_result(elem, index):
            # Создаем уникальный хеш для дедупликации
            source_data = elem.get('SourceMetadata', {})
            md5_dict_hash = hashlib.md5(json.dumps(source_data, sort_keys=True).encode('utf-8')).hexdigest()
            
            # Очищаем данные для экономии места
            self._clean_result_data(elem)
            
            # Добавляем данные о совпадении для совместимости
            raw_match = elem.get('RawV2') or elem.get('Raw', '')
            elem['Match'] = raw_match
            elem['meaningfull'] = self._evaluate_meaningfulness(elem)
            elem['dedup_hash'] = md5_dict_hash
            
            return elem
        
        # Дедупликация результатов
        processed_results_dedup = []
        seen_hashes = set()
        
        for result in processed_results:
            source_data = result.get('SourceMetadata', {})
            md5_dict_hash = hashlib.md5(json.dumps(source_data, sort_keys=True).encode('utf-8')).hexdigest()
            
            if md5_dict_hash not in seen_hashes:
                seen_hashes.add(md5_dict_hash)
                processed_results_dedup.append(result)
        
        # Обрабатываем финальные результаты
        processed_count = self._process_scan_results(scan_type, processed_results_dedup, process_trufflehog_result)
        
        logger.info(f'\t- {scan_type} scan %s %s %s success, processed {processed_count} results', 
                   self.log_color, self.url, CLR["RESET"])
        return 0

    def _filter_and_enhance_results(self, results):
        """Фильтрует и улучшает результаты TruffleHog"""
        enhanced_results = []
        
        for result in results:
            # Проверяем релевантность результата
            if self._is_result_relevant(result, self.company_name):
                # Добавляем дополнительную информацию
                result['CompanyRelevance'] = self._calculate_company_relevance(result, self.company_name)
                result['ContextualScore'] = self._calculate_contextual_score(result)
                enhanced_results.append(result)
        
        # Сортируем по релевантности
        enhanced_results.sort(key=lambda x: (
            x.get('Verified', False),
            x.get('CompanyRelevance', 0),
            x.get('ContextualScore', 0)
        ), reverse=True)
        
        return enhanced_results
    def _is_company_specific_pattern(self, text, company_name=None):
        """Проверяет наличие специфических паттернов компании в тексте"""
        if company_name is None:
            company_name = self.company_name

        if not company_name:
            return False

        company_terms = self.company_terms if company_name == self.company_name else utils.generate_company_search_terms(company_name)
        
        # Проверяем логины с цифрами (например, vtb123, company456)
        for term in company_terms:
            if len(term) > 2:
                # Логин паттерн: название_компании + цифры
                if re.search(rf'(?i)\b{re.escape(term)}\d{{1,8}}\b', text):
                    return True
                
                # Email паттерн: любой_email@компания.домен
                if re.search(rf'(?i)\b[a-zA-Z0-9._-]+@{re.escape(term)}\.[a-zA-Z]{{2,}}\b', text):
                    return True
                
                # Паттерн в кириллице (если применимо)
                if re.search(rf'(?i)\b{re.escape(term)}\d{{1,8}}\b', text):
                    return True
        
        return False

    def _calculate_company_relevance(self, result, company_name=None):
        """Вычисляет релевантность результата для компании"""
        if company_name is None:
            company_name = self.company_name
        if not company_name:
            return 0.0
        
        score = 0.0
        raw_data = result.get('RawV2') or result.get('Raw', '')
        source_metadata = result.get('SourceMetadata', {})
        
        # Анализируем различные части результата
        text_sources = [
            raw_data,
            source_metadata.get('Data', {}).get('Git', {}).get('file', ''),
            source_metadata.get('Data', {}).get('Git', {}).get('commit', ''),
        ]
        
        full_text = ' '.join(str(source) for source in text_sources if source).lower()
        
        # Проверяем наличие компанейских терминов
        company_terms = self.company_terms if company_name == self.company_name else generate_company_search_terms(company_name)
        for term in company_terms:
            if term.lower() in full_text:
                # Вес зависит от длины термина (длинные термины более специфичны)
                weight = min(len(term) / 10.0, 1.0)
                score += weight
        
        return min(score, 1.0)

    def _calculate_contextual_score(self, result):
        """Вычисляет контекстуальный скор результата"""
        score = 0.0
        raw_data = result.get('RawV2') or result.get('Raw', '')
        
        # Бонусы за проверенные результаты
        if result.get('Verified', False):
            score += 1.0
        
        # Бонусы за определенные типы детекторов
        detector_name = result.get('DetectorName', '').lower()
        high_value_detectors = ['aws', 'google', 'azure', 'github', 'gitlab', 'database']
        
        for detector in high_value_detectors:
            if detector in detector_name:
                score += 0.5
                break
        
        # Штрафы за тестовые данные
        test_indicators = ['test', 'demo', 'example', 'sample', 'dummy']
        for indicator in test_indicators:
            if indicator in raw_data.lower():
                score -= 0.3
        
        return max(score, 0.0)

    def _evaluate_meaningfulness(self, result):
        """Оценивает осмысленность результата для совместимости с существующим кодом"""
        # Проверенные результаты всегда считаются осмысленными
        if result.get('Verified', False):
            return 1
        
        # Проверяем детектор - компанейские детекторы получают максимальный приоритет
        detector_name = result.get('DetectorName', '').lower()
        
        # Компанейские детекторы - максимальный приоритет
        company_detectors = [
            'company-credentials-', 'company-api-keys-', 'company-login-pattern-',
            'company-email-pattern-'
        ]
        
        for detector in company_detectors:
            if detector in detector_name:
                return 1
        
        # Высокое значение релевантности к компании
        company_relevance = result.get('CompanyRelevance', 0)
        if company_relevance > 0.2:
            return 1
        
        # Высокий контекстуальный скор
        contextual_score = result.get('ContextualScore', 0)
        if contextual_score > 0.3:
            return 1
        
        # Проверяем детектор - для важных детекторов снижаем требования
        important_detectors = [
            'aws', 'google', 'azure', 'github', 'gitlab', 'slack', 'discord',
            'stripe', 'paypal', 'twilio', 'sendgrid', 'mailgun', 'custom'
        ]
        
        for detector in important_detectors:
            if detector in detector_name:
                return 1
        
        # Анализируем сам секрет
        raw_data = result.get('RawV2') or result.get('Raw', '')
        if raw_data:
            # Получаем название компании для универсальных проверок
            company_name = Connector.get_company_name(self.obj.company_id)
            
            # Проверяем специфические паттерны компании
            if self._is_company_specific_pattern(raw_data, self.company_name):
                return 1
            
            # Длинные секреты более вероятно реальные
            if len(raw_data) > 20:
                return 1
            
            # Секреты с хорошей энтропией
            if self._calculate_entropy(raw_data) > 3.0:
                return 1
            
            # Секреты в base64 формате
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', raw_data):
                return 1
            
            # Hex секреты
            if re.match(r'^[a-fA-F0-9]{16,}$', raw_data):
                return 1
        
        # Проверяем контекст на наличие компанейских паттернов
        source_metadata = result.get('SourceMetadata', {})
        if isinstance(source_metadata, dict):
            data_text = str(source_metadata.get('Data', ''))
            if self._is_company_specific_pattern(data_text, self.company_name):
                return 1
        
        # По умолчанию считаем осмысленным (лучше ложное срабатывание, чем пропуск)
        return 1

    def _calculate_entropy(self, data):
        """Вычисляет энтропию строки"""
        if not data:
            return 0
        
        import math
        from collections import Counter
        
        # Подсчитываем частоты символов
        counter = Counter(data)
        length = len(data)
        
        # Вычисляем энтропию
        entropy = 0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy

    def _is_result_relevant(self, result, company_name=None):
        """Проверяет релевантность результата"""
        if company_name is None:
            company_name = self.company_name
        # Всегда включаем проверенные результаты
        if result.get('Verified', False):
            return True
        
        # Проверяем контекст на наличие компанейских терминов
        raw_data = result.get('RawV2') or result.get('Raw', '')
        source_metadata = result.get('SourceMetadata', {})
        
        # Собираем весь контекст для анализа
        context_data = [
            raw_data,
            source_metadata.get('Data', {}).get('Git', {}).get('file', ''),
            source_metadata.get('Data', {}).get('Git', {}).get('commit', ''),
        ]
        
        context_text = ' '.join(str(data) for data in context_data if data).lower()
        
        # Проверяем наличие компанейских терминов
        if company_name:
            company_terms = self.company_terms if company_name == self.company_name else utils.generate_company_search_terms(company_name)
            for term in company_terms:
                if term.lower() in context_text:
                    return True
            
            # Проверяем специфические паттерны компании
            if self._is_company_specific_pattern(context_text, company_name):
                return True
        
        # Проверяем наличие основного dork
        if self.dork.lower() in context_text:
            return True
        
        # Исключаем явно тестовые/демонстрационные данные
        exclude_patterns = [
            'test', 'demo', 'example', 'sample', 'placeholder',
            'lorem', 'ipsum', 'dummy', 'fake', 'mock'
        ]
        
        for pattern in exclude_patterns:
            if pattern in context_text:
                return False
        
        return True

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
        # AI анализ теперь выполняется автоматически в LeakObj._check_status()
        return self.secrets

    def _process_scan_results(self, scan_type, results, process_func):
        """Универсальная функция для обработки результатов сканирования"""
        self.secrets[scan_type] = constants.AutoVivification()
        
        processed_count = 0
        seen_matches = set()
        
        for index, result in enumerate(results[:constants.MAX_UTIL_RES_LINES]):
            # Обрабатываем результат через переданную функцию
            processed_result = process_func(result, index)
            
            if processed_result is None:
                continue
                
            # Проверяем на дублирование
            match_key = processed_result.get('Match', '')
            file_key = processed_result.get('File', '')
            dedup_key = f"{match_key}|{file_key}"
            if dedup_key in seen_matches:
                continue
            seen_matches.add(dedup_key)
            
            # Обрезаем слишком длинные строки
            if len(match_key) > constants.MAX_LINE_LEAK_LEN:
                processed_result['Match'] = match_key[:constants.MAX_LINE_LEAK_LEN] + '...'
            
            # Добавляем семантическую проверку
            processed_result['meaningfull'] = utils.semantic_check_dork(processed_result['Match'], self.dork)
            
            # Сохраняем результат
            self.secrets[scan_type][f'Leak #{processed_count}'] = processed_result
            processed_count += 1
        
        return processed_count

    def _create_standard_result(self, match, file_path="", extra_data=None):
        """Создает стандартную структуру результата"""
        result = {
            'Match': match,
            'File': file_path
        }
        
        if extra_data:
            result.update(extra_data)
            
        return result

    def _clean_result_data(self, result, fields_to_remove=None):
        """Очищает данные результата, удаляя ненужные поля"""
        if fields_to_remove is None:
            fields_to_remove = [
                'Fingerprint', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn', 
                'SymlinkFile', 'Secret', 'Entropy', 'Message', 'SourceID', 
                'SourceType', 'SourceName', 'DetectorType', 'DecoderName', 
                'Redacted', 'ExtraData', 'StructuredData', 'Raw', 'RawV2'
            ]
        
        for field in fields_to_remove:
            result.pop(field, None)
            
        return result

    

    def _collect_repo_text(self):
        """Собирает текст из всех файлов репозитория"""
        repo_text = ""
        
        try:
            for root, dirs, files in os.walk(self.repos_dir):
                for file in files:
                    _, ext = os.path.splitext(file.lower())
                    if ext in constants.TEXT_FILE_EXTS:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                repo_text += f.read()[:10000]  # Ограничиваем размер
                        except Exception:
                            continue
        except Exception:
            pass
        
        return repo_text

    # Метод ai_scan() удален - AI анализ теперь выполняется автоматически 
    # в LeakObj._check_status() через интеграцию с AIObj.py
