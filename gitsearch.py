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

from src.glist.glist_scan import GlistScan
from src import deepscan
from src import filters
from src import reports

def signal_shutdown():
    logger.info('Stopping gently. Ctrl+C again to force')
    Connector.dump_to_DB()
    sys.exit(0)


if __name__ == "__main__":
    subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', '/app'])
    # DEBUG TESTS:
    if constants.RUN_TESTS:
        logger.info('Running tests...')
        # Install pytest if not already installed
        if not subprocess.run(['pip', 'show', 'pytest'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            logger.info('Installing pytest...')
        subprocess.run(['pip', 'install', 'pytest'])
        logger.info('Running pytest...')
        subprocess.run([sys.executable, '-m', 'pytest', '-q'])
        sys.exit(0)
    
    if constants.CONFIG_FILE['create_report'] == 'yes':        
        logger.info('Creating report from config')
        reports.generate_report_from_config()
        logger.info('Report created')
        sys.exit(0)   
    
    if constants.token_tuple[0] == '-':
        logger.warning('Warning: Token not set. Open config.json and put token to token_list')
    
    if constants.url_DB != '-':
        constants.url_from_DB = Connector.dump_from_DB()
        filters.exclude_list_update()
        constants.dork_dict_from_DB = Connector.dump_target_from_DB()
    else:
        constants.url_from_DB = '-'
        constants.dork_dict_from_DB = constants.CONFIG_FILE['target_list']


    
    constants.all_dork_counter = 0  # quantity of all dorks
    with open(f'{constants.MAIN_FOLDER_PATH}/src/dorks.txt', 'r') as dorks_file:
        constants.dork_list_from_file = [line.rstrip() for line in dorks_file]
    for company in constants.dork_dict_from_DB:
        initial_company_dorks = list(constants.dork_dict_from_DB[company])[3:] # Create a copy to iterate over
        for initial_dork in initial_company_dorks:
            constants.all_dork_counter += 1
            for base_dork in constants.dork_list_from_file:
                combined_dork = f"{initial_dork} {base_dork}"
                if combined_dork not in constants.dork_dict_from_DB[company]: # Avoid duplicates
                    constants.dork_dict_from_DB[company].append(combined_dork)
                    constants.all_dork_counter += 1
                    constants.leak_check_list.append(base_dork) # Assuming base_dorks are also leak_check_list items

    constants.all_dork_counter *= 2

    signal.signal(signal.SIGINT, signal_shutdown)

    # Changing directory to project root folder
    old_dir = os.getcwd()
    os.chdir(constants.SEARCH_FOLDER_PATH)
    logger.info('Curent directory: %s', constants.SEARCH_FOLDER_PATH)

    # List scan
    logger.info('Start List scan')
    deepscan.list_search()

    # Github Gist scan
    logger.info('Start Gist scan')
    GlistScan.run(filter_='updated', quantity=30)
    filters.dumping_data()

    # Github scan
    logger.info('Start Github scan')
    print(constants.dork_dict_from_DB)
    
    for org in constants.dork_dict_from_DB:
        Scanner(org).gitscan()
    filters.dumping_data()

    # Deepscan - repeat deep scan of found leaks
    # TODO Not it work only for DB version

    # logger.info('Start Deepscan scan')
    # constants.RESULT_MASS = constants.AutoVivification()
    # deepscan.deep_scan()

    os.chdir(old_dir)
    print(f'Back to directory: {old_dir}')
