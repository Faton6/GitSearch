# Standart libs import
import sys
import os
import subprocess
import signal

# Project lib's import
from src import constants
from src import Connector
from src.logger import logger
from src.searcher import Scanner
# from src.glist.glist_scan import GlistScan
# from src import deepscan
from src import filters

def signal_shutdown():
    logger.info('Stopping gently. Ctrl+C again to force')
    Connector.dump_to_DB()
    sys.exit(0)


if __name__ == "__main__":
    subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', '/app'])

    if constants.token_list[0] == '-':
        logger.warning('Warning: Token not set. Open config.json and put token to token_list')
    if constants.url_DB != '-':
        constants.url_from_DB = Connector.dump_from_DB()
        filters.exclude_list_update()
        constants.dork_dict = Connector.dump_target_from_DB()
        # sys.exit(0)
    else:
        constants.url_from_DB = '-'
        constants.dork_dict = constants.config['target_list']

    constants.all_dork_counter = 0  # quantity of all dorks
    with open(f'{constants.MAIN_FOLDER_PATH}/src/dorks.txt', 'r') as dorks_file:
        constants.dorks = [line.rstrip() for line in dorks_file]
        for company in constants.dork_dict:
            for j in range(len(constants.dork_dict[company])):
                constants.all_dork_counter += 1
                for i in constants.dorks:
                    constants.all_dork_counter += 1
                    constants.dork_dict[company].append(constants.dork_dict[company][j] + ' ' + i)
                    constants.leak_check_list.append(i)
    constants.all_dork_counter *= 2

    signal.signal(signal.SIGINT, signal_shutdown)

    # Changing directory to project root folder
    old_dir = os.getcwd()
    os.chdir(constants.SEARCH_FOLDER_PATH)
    logger.info('Curent directory: %s', constants.SEARCH_FOLDER_PATH)

    # List scan
    # logger.info('Start List scan')
    # deepscan.list_search()

    # Github Gist scan
    # logger.info('Start Gist scan')
    # GlistScan.run(filter_='updated', quantity=30)
    # filters.dumping_data()

    # Github scan
    logger.info('Start Github scan')
    for org in constants.dork_dict:
        Scanner(org).gitscan()
    filters.dumping_data()

    # Deepscan - repeat deep scan of found leaks
    # TODO Not it work only for DB version

    # logger.info('Start Deepscan scan')
    # constants.RESULT_MASS = constants.AutoVivification()
    # deepscan.deep_scan()

    os.chdir(old_dir)
    print(f'Back to directory: {old_dir}')
