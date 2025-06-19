# Standart libs import
from pathlib import Path
import os
import json
import tracemalloc

# Project lib's import
# from src.logger import logger, CLR
RUN_TESTS: bool = False


__NAME__ = "GitSearch"
DEFAULT_CONFIG_FILE = f".{__NAME__}.yml"
MAIN_FOLDER_PATH = Path(Path(__file__).parent).parent
SEARCH_FOLDER_PATH = f"{str(MAIN_FOLDER_PATH)}/src/searcher"
COMMAND_FILE = str(SEARCH_FOLDER_PATH) + '/command_file'
LOGS_PATH = str(MAIN_FOLDER_PATH) + '/logs'
LIBS_PATH = str(MAIN_FOLDER_PATH) + '/lib'
TEMP_FOLDER = str(MAIN_FOLDER_PATH) + '/temp'
RESULTS = str(MAIN_FOLDER_PATH) + '/results'
if not os.path.exists(LOGS_PATH):
    os.makedirs(LOGS_PATH)
if not os.path.exists(TEMP_FOLDER):
    os.makedirs(TEMP_FOLDER)
if not os.path.exists(RESULTS):
    os.makedirs(RESULTS)
# seconds to scan by git-secrets/gitleaks/whisper/trufflehpg/deepsecret
MAX_TIME_TO_SCAN_BY_UTIL_DEFAULT = 100
MAX_TIME_TO_SCAN_BY_UTIL_DEEP = 3000
MAX_TIME_TO_SEARCH_GITHUB_REQUEST = 500  # seconds to search by github API
GITHUB_REQUEST_COOLDOWN: float = 60.0
GITHUB_REQUEST_RATE_LIMIT: float = 10.0
GITHUB_REPO_COUNT_AT_REQUEST_LIMIT: int = 1000  # Github api restriction https://docs.github.com/rest/search/search#search-code
GITHUB_REQUEST_REPO_PER_PAGE: int = 100
RESULT_CODES = ['1', '2', '3']  # Field from DB that conatain status if founded leak
RESULT_CODE_TO_DEEPSCAN = 5
RESULT_CODE_TO_SEND = 4
all_dork_counter = 0 # quantity of all dorks
# Dork counterts
dork_search_counter = 0  # quantity of searches in gihtub
all_dork_search_counter = 0  # stable quantity of searches in gihtub
# quantity of MAX searches in gihtub before neccessary dump to DB
MAX_SEARCH_BEFORE_DUMP = 15
quantity_obj_before_send = 0
MAX_OBJ_BEFORE_SEND = 5
REPO_MAX_SIZE = 300000
MAX_UTIL_RES_LINES = 200  # максимальное число строк результата работы каждого из сканеров, которое будет отправлено в отчет
MAX_LINE_LEAK_LEN = 100  # максимальная длина строки с найденной утечкой
MAX_TRY_TO_CLONE = 3
MAX_COMMITERS_DISPLAY = 5 # max number of commiters to display in report
MAX_DESCRIPTION_LEN = 50 # max length of description in report
LOW_LVL_THRESHOLD = 5  # low lvl of leaks - from 0 to LVL_LOW_THRESHOLD - 1
# medium lvl of leaks - from LVL_LOW_THRESHOLD to LVL_LOW_THRESHOLD - 1
MEDIUM_LOW_THRESHOLD = 15
LANGUAGE = 'ru'  # default language for messages

COUNTRY_PROFILING: bool = True
COMPANY_COUNTRY_MAP_DEFAULT: str = "ru"  # Default country for companies without specific mapping
COMPANY_COUNTRY_MAP: dict[str, str] = {
    "Yandex": "ru",
    "Alpha-Bet": "en",
}

dork_dict_from_DB: dict = {}
dork_list_from_file: list = []
url_from_DB: dict = {}

AI_TYPE = {'Deepseek': 0, 'Qwen': 1, 'ChatGPT': 2}  
AI_CONFIG = {
    "model": "Qwen/Qwen2-14B-Chat",
    "ai_enable": False,
    "url": "",
    "api_key_need": True,
    "api_key": "lm-studio",
    "ai_type": AI_TYPE["Qwen"],
    "token_limit": 15000,
    "temperature": 0.01 # Added default temperature
}


tracemalloc.start()
snap_backup = tracemalloc.take_snapshot()
# Load configuration from config.json
with open(f'{MAIN_FOLDER_PATH}/config.json') as config_file:
    CONFIG_FILE = json.load(config_file)

def load_env_variables(file_path=f'{MAIN_FOLDER_PATH}/.env'):
    env_variables = {}
    with open(file_path, 'r') as f:
        for line in f.readlines():
            key, value = line.strip().split('=')
            env_variables[key] = value
    return env_variables

leak_check_list = CONFIG_FILE['leak_check_list']
url_DB = CONFIG_FILE['url_DB']
token_DB = CONFIG_FILE['token_DB']
if CONFIG_FILE['token_list'] != ['-']:
    token_tuple = tuple(CONFIG_FILE["token_list"])
elif os.path.exists(f'{MAIN_FOLDER_PATH}/.env'):
    env_variables = load_env_variables()
    token_tuple = tuple([value for key, value in env_variables.items() if key.startswith('GITHUB_TOKEN')])

    



LEAK_OBJ_MESSAGES = {
    "en": {
        "leak_found_in_section": "Leak detected in {obj_type} section for search {dork}",
        "leak_in_author_name": "Leak in author name, found by keyword: {leak_type}, leak: {author_name}",
        "leak_in_committers": "Leak in committer name/email, found by keyword: {leak_type}",
        "leak_in_repo_name": "Leak in repository name, found by keyword: {leak_type}, leak: {repo_name}",
        "repo_stats": "Repository statistics: Size: {size}, Forks: {forks}, Stars: {stars}, Downloaded: {has_downloads}, Issues: {issues}",
        "short_description": "Brief description: {description}",
        "no_description": "Brief description: none",
        "topics": "Topics: {topics}",
        "no_topics": "Topics: none",
        "committers_found": "Found the following committers: {committers}. There are {remaining} more committers",
        "committers_all": "Found the following committers: {committers}",
        "first_grepscan_line": "First line found by grepscan: {match}",
        "leaks_found_by_scanner": "Found {count} leaks by {scanner} scanner",
        "total_leaks_found": "Total leaks found: {total_count}",
        "full_report_length": "Full report length: {length}",
        "commit_description": "Commit description: {commit}",
        "profitability_scores": "Leak Profitability Scores: Org Relevance: {org_rel:.2f}, Sensitive Data: {sens_data:.2f}, True Positive: {tp:.2f}, False Positive: {fp:.2f}"
    },
    "ru": {
        "leak_found_in_section": "Обнаружена утечка в разделе {obj_type} по поиску {dork}",
        "leak_in_author_name": "Утечка в имени автора, найдена по слову: {leak_type}, утечка: {author_name}",
        "leak_in_committers": "Утечка в имени/почте коммитеров, найдена по слову: {leak_type}",
        "leak_in_repo_name": "Утечка в имени репозитория, найдена по слову: {leak_type}, утечка: {repo_name}",
        "repo_stats": "Статистика по репозиторию: Размер: {size}, форки: {forks}, звезды: {stars}, был ли скачен: {has_downloads}, кол-во issue: {issues}",
        "short_description": "Краткое описание: {description}",
        "no_description": "Краткое описание: отсутствует",
        "topics": "Топики: {topics}",
        "no_topics": "Топики: отсутствуют",
        "committers_found": "Обнаружены следующие коммитеры: {committers}. Еще есть {remaining} коммитеров",
        "committers_all": "Обнаружены следующие коммитеры: {committers}",
        "first_grepscan_line": "Первая строка, найденная grepscan: {match}",
        "leaks_found_by_scanner": "Найдено {count} утечек {scanner} сканером",
        "total_leaks_found": "Всего обнаружено утечек: {total_count}",
        "full_report_length": "Длина полного отчета: {length}",
        "commit_description": "Описание коммита: {commit}",
        "profitability_scores": "Оценка рентабельности утечки: Релевантность организации: {org_rel:.2f}, Чувствительные данные: {sens_data:.2f}, Истинно-положительный: {tp:.2f}, Ложно-положительный: {fp:.2f}"
    }
}



def token_generator():
    while True:
        for token in token_tuple:
            yield token

class AutoVivification(dict):
    """
        class AutoVivification - get easy to append dict
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


RESULT_MASS = AutoVivification()  # array with results of scans

