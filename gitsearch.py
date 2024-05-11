# Standart libs import
import os

# Project lib's import
from src import constants
from src import Connector
from src.logger import logger
from src.searcher import gitscan
from src.glist.glist_scan import GlistScan
from src import deepscan
from src import filters


if __name__ == "__main__":
    # Changing directory to project root folder
    old_dir = os.getcwd()
    os.chdir(constants.SEARCH_FOLDER_PATH)
    logger.info(f'Curent directory: {constants.SEARCH_FOLDER_PATH}')

    # List scan
    logger.info('Start List scan')
    deepscan.list_search()

    # Github Gist scan
    logger.info('Start Gist scan')
    #GlistScan.run(filter_='updated', quantity=30)
    filters.dumping_data()

    # Github scan
    logger.info('Start Github scan')
    gitscan(constants.dork_dict)
    filters.dumping_data()

    # Deepscan - repeat deep scan of found leaks
    # TODO Not it work only for DB version
    '''
    logger.info('Start Deepscan scan')
    constants.RESULT_MASS = constants.AutoVivification()
    deepscan.deep_scan()
    '''
    os.chdir(old_dir)
    print(f'Back to directory: {old_dir}')
