# Standart libs import
from pathlib import Path
import os
import json
import tracemalloc

# Project lib's import
from src import Connector
from src import filters

__NAME__ = "GitSearch"
# TODO: need to move in yaml format of filters
DEFAULT_CONFIG_FILE = f".{__NAME__}.yml"
# path: (user_folder)/GitSearch/src/searcher
SEARCH_FOLDER_PATH = f"{Path(__file__).parent}/searcher"
# path: (user_folder)/GitSearch/
MAIN_FOLDER_PATH = Path(Path(__file__).parent).parent
COMMAND_FILE = str(SEARCH_FOLDER_PATH) + '/command_file'
LOGS_PATH = str(MAIN_FOLDER_PATH) + '/logs'
if not os.path.exists(LOGS_PATH):
    os.makedirs(LOGS_PATH)
TEMP = str(MAIN_FOLDER_PATH) + '/temp'
if not os.path.exists(TEMP):
    os.makedirs(TEMP)

# seconds to scan by git-secrets/gitleaks/whisper/trufflehpg/deepsecret
MAX_TIME_TO_SCAN_BY_UTIL = 1000
RESULT_CODES = ['1', '2', '3']  # Field from DB that conatain status if founded leak
RESULT_CODE_TO_DEEPSCAN = 5
RESULT_CODE_TO_SEND = 4


class AutoVivification(dict):
    """
        class AutoVivification - get easy to append dict
    """

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


RESULT_MASS = AutoVivification()  # array with results of scans



with open(f'{MAIN_FOLDER_PATH}/src/config') as config_file:
    config = json.load(config_file)
leak_check_list = config['leak_check_list']
url_DB = config['url_DB']
token_DB = config['token_DB']
token_list = config['token_list']
if url_DB != '-':
    url_from_DB = Connector.dump_from_DB()
    filters.exclude_list_update()
    dork_dict = Connector.dump_target_from_DB()
else:
    dork_dict = config['target_list']
all_dork_counter = 0  # quantity of all dorks
with open(f'{MAIN_FOLDER_PATH}/src/dorks.txt') as dorks_file:
    dorks = [line.rstrip() for line in dorks_file]
    for company in dork_dict:
        for j in range(len(dork_dict[company])):
            all_dork_counter += 1
            for i in dorks:
                all_dork_counter += 1
                dork_dict[company].append(dork_dict[company][j] + ' ' + i)
                leak_check_list.append(i)
all_dork_counter *= 2

# Dork counterts
dork_search_counter = 0  # quantity of searches in gihtub
all_dork_search_counter = 0  # stable quantity of searches in gihtub
# quantity of MAX searches in gihtub before neccessary dump to DB
MAX_SEARCH_BEFORE_DUMP = 10

quantity_obj_before_send = 0
MAX_OBJ_BEFORE_SEND = 50

LOW_LVL_THRESHOLD = 5  # low lvl of leaks - from 0 to LVL_LOW_THRESHOLD - 1
# medium lvl of leaks - from LVL_LOW_THRESHOLD to LVL_LOW_THRESHOLD - 1
MEDIUM_LOW_THRESHOLD = 15
# high lvl of leaks - from LVL_LOW_THRESHOLD

tracemalloc.start()
snap_backup = tracemalloc.take_snapshot()
